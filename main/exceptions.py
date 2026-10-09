"""Custom exceptions for MultiAvaScanner."""


class VTRateLimitError(Exception):
    """VirusTotal returned 429 — rate limit exceeded."""


class VTTimeoutError(Exception):
    """Analysis did not complete within the allotted time."""
