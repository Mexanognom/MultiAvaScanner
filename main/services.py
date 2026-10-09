"""Business logic / service layer for scanning."""

import hashlib
import logging
import os
import tempfile
from datetime import timedelta

from django.utils import timezone

from .models import ScanResult
from .utils import decode_qr
from .virustotal import VirusTotalClient

logger = logging.getLogger(__name__)

CACHE_TTL_HOURS = 24


class ScanService:
    def __init__(self):
        self.vt = VirusTotalClient()

    def _get_cached_scan(self, **filters) -> ScanResult | None:
        """Find a fresh completed scan by filters."""
        cutoff = timezone.now() - timedelta(hours=CACHE_TTL_HOURS)
        return (
            ScanResult.objects
            .filter(status="done", created_at__gte=cutoff, **filters)
            .order_by("-created_at")
            .first()
        )

    def _save_vt_result(
        self,
        scan: ScanResult,
        analysis_id: str,
        stats: dict,
        raw_data: dict,
    ) -> ScanResult:
        """Write VirusTotal result into the model."""
        scan.vt_scan_id = analysis_id
        scan.malicious_count = stats.get("malicious", 0)
        scan.suspicious_count = stats.get("suspicious", 0)
        scan.harmless_count = stats.get("harmless", 0)
        scan.undetected_count = stats.get("undetected", 0)
        scan.total_engines = sum(stats.values())
        scan.is_phishing = scan.malicious_count >= 3
        scan.raw_result = raw_data
        scan.status = "done"
        scan.finished_at = timezone.now()
        scan.save()
        return scan

    def _fail_scan(self, scan: ScanResult, reason: str = "") -> None:
        scan.status = "error"
        if reason:
            scan.raw_result = {"error": reason}
        scan.save()

    def _poll_or_fail(
        self,
        scan: ScanResult,
        analysis_id: str,
    ) -> dict | None:
        """
        Wait for VT result. On timeout mark scan as error and return None.
        """
        result = self.vt.wait_for_analysis(analysis_id)
        if result is None:
            self._fail_scan(scan, "VirusTotal analysis timeout")
            return None
        return result

    def scan_url(self, url: str, user_ip: str) -> ScanResult:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        cached = self._get_cached_scan(url=url, scan_type="url")
        if cached:
            return cached

        scan = ScanResult.objects.create(
            scan_type="url",
            url=url,
            status="scanning",
            user_ip=user_ip,
        )

        analysis_id = self.vt.submit_url(url)

        result = self._poll_or_fail(scan, analysis_id)
        if result is None:
            return scan

        stats = result["data"]["attributes"]["stats"]
        return self._save_vt_result(scan, analysis_id, stats, result)

    def scan_apk(self, filename: str, file_bytes: bytes, user_ip: str) -> ScanResult:
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        cached = self._get_cached_scan(file_hash_sha256=sha256)
        if cached:
            return cached

        scan = ScanResult.objects.create(
            scan_type="apk",
            file_name=filename,
            file_size=len(file_bytes),
            file_hash_sha256=sha256,
            status="scanning",
            user_ip=user_ip,
        )

        # Prefer hash lookup — faster than uploading
        hash_result = self.vt.get_by_hash(sha256)
        if hash_result:
            stats = hash_result["data"]["attributes"]["last_analysis_stats"]
            return self._save_vt_result(scan, sha256, stats, hash_result)

        analysis_id = self.vt.submit_file(filename, file_bytes)

        result = self._poll_or_fail(scan, analysis_id)
        if result is None:
            return scan

        stats = result["data"]["attributes"]["stats"]
        return self._save_vt_result(scan, analysis_id, stats, result)

    def scan_qr(self, file, user_ip: str) -> tuple[ScanResult | None, str | None]:
        """
        Returns (scan, decoded_text).
        scan may be None if QR was not recognized.
        """
        scan = ScanResult.objects.create(
            scan_type="qr",
            status="scanning",
            user_ip=user_ip,
        )

        suffix = os.path.splitext(file.name)[1] or ".png"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            for chunk in file.chunks():
                tmp.write(chunk)
            tmp.flush()
            decoded = decode_qr(tmp.name)

        if not decoded:
            self._fail_scan(scan, "QR not recognized")
            return None, None

        if decoded.startswith(("http://", "https://")):
            scan.url = decoded
            scan.save(update_fields=["url"])

            analysis_id = self.vt.submit_url(decoded)
            result = self._poll_or_fail(scan, analysis_id)
            if result is None:
                return scan, decoded

            stats = result["data"]["attributes"]["stats"]
            return self._save_vt_result(scan, analysis_id, stats, result), decoded

        scan.status = "done"
        scan.raw_result = {"decoded": decoded}
        scan.finished_at = timezone.now()
        scan.save()
        return scan, decoded
