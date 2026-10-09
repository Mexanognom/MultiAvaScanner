"""VirusTotal API client."""

import logging
import time

import requests
from django.conf import settings

from .exceptions import VTRateLimitError

logger = logging.getLogger(__name__)


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"
    POLL_DELAY = 2
    POLL_MAX_ATTEMPTS = 25

    RATE_LIMIT_RETRIES = 3
    RATE_LIMIT_DELAY = 20

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": settings.VIRUSTOTAL_API_KEY})

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Wrapper around session.request with automatic retry on 429.
        Raises VTRateLimitError if all attempts are exhausted.
        """
        for attempt in range(1, self.RATE_LIMIT_RETRIES + 1):
            resp = self.session.request(method, url, **kwargs)

            if resp.status_code != 429:
                resp.raise_for_status()
                return resp

            retry_after = int(resp.headers.get("Retry-After", self.RATE_LIMIT_DELAY))
            logger.warning(
                "VT rate limit hit (attempt %d/%d), waiting %ds...",
                attempt, self.RATE_LIMIT_RETRIES, retry_after,
            )

            if attempt < self.RATE_LIMIT_RETRIES:
                time.sleep(retry_after)

        raise VTRateLimitError(
            "Превышен лимит запросов VirusTotal. "
            "Бесплатный план позволяет 4 запроса в минуту — попробуйте через минуту."
        )

    def submit_url(self, url: str) -> str:
        """Submit URL for analysis, return analysis_id."""
        resp = self._request(
            "POST",
            f"{self.BASE_URL}/urls",
            data={"url": url},
            timeout=15,
        )
        return resp.json()["data"]["id"]

    def submit_file(self, filename: str, file_bytes: bytes) -> str:
        """Upload file for analysis, return analysis_id."""
        resp = self._request(
            "POST",
            f"{self.BASE_URL}/files",
            files={"file": (filename, file_bytes, "application/octet-stream")},
            timeout=60,
        )
        return resp.json()["data"]["id"]

    def get_by_hash(self, sha256: str) -> dict | None:
        """Lookup file by SHA256. Returns data or None if not found."""
        resp = self.session.get(
            f"{self.BASE_URL}/files/{sha256}",
            timeout=10,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            raise VTRateLimitError(
                "Превышен лимит запросов VirusTotal — попробуйте через минуту."
            )
        resp.raise_for_status()
        return resp.json()

    def wait_for_analysis(self, analysis_id: str) -> dict | None:
        """
        Poll until analysis completes.
        Returns data or None on timeout.
        """
        for attempt in range(self.POLL_MAX_ATTEMPTS):
            time.sleep(self.POLL_DELAY)
            try:
                resp = self.session.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data["data"]["attributes"]["status"] == "completed":
                        return data
                elif resp.status_code == 429:
                    logger.warning("VT rate limit during polling, sleeping 20s")
                    time.sleep(20)
            except requests.RequestException:
                logger.warning(
                    "VT polling attempt %d/%d failed for %s",
                    attempt + 1, self.POLL_MAX_ATTEMPTS, analysis_id,
                )
        return None
