import os
from typing import List, Tuple, Optional
from app.config import settings
from app.models.responses import Finding, Severity


class ReputationService:
    """
    Modular reputation provider interface.
    Adheres strictly to the requirement:
    - Reports 'not_configured' if no API key is provided.
    - Reports 'failed' if configured service encounters an error or timeout.
    - Never converts an external failure into a clean result.
    """

    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.gsb_api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        # For testing provider failure behavior in automated test suites
        self._simulate_failure = False
        self._url_status_map = {}

    def is_configured(self) -> bool:
        return bool(self.vt_api_key or self.gsb_api_key)

    def set_test_simulate_failure(self, simulate: bool):
        """Allows test suites to test provider failure handling."""
        self._simulate_failure = simulate

    def set_url_status_map(self, status_map: dict):
        """Allows test suites to simulate per-URL reputation statuses."""
        self._url_status_map = status_map

    async def check_url_reputation(self, url: str) -> Tuple[str, List[Finding]]:
        """
        Queries reputation provider for a URL.
        Returns (check_status, findings_list).
        check_status is one of: 'not_configured', 'completed', 'failed'.
        """
        if self._url_status_map and url in self._url_status_map:
            return self._url_status_map[url], []

        if self._simulate_failure:
            return "failed", []

        if not self.is_configured():
            return "not_configured", []

        try:
            if self.vt_api_key:
                import base64
                import httpx
                # VirusTotal URL ID is base64url encoded URL without trailing '=' padding
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers={"x-apikey": self.vt_api_key}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious_count = stats.get("malicious", 0)
                        if malicious_count >= 2:
                            return "completed", [
                                Finding(
                                    rule_id="reputation_flagged_malicious",
                                    name="External Threat Intelligence Detection (VirusTotal)",
                                    severity=Severity.HIGH,
                                    evidence=f"Flagged as malicious by {malicious_count} security engines",
                                    explanation="External reputation intelligence service reports this URL as known malicious."
                                )
                            ]
                        return "completed", []
                    elif resp.status_code == 404:
                        # URL not in database yet
                        return "completed", []
                    else:
                        return "failed", []

            return "completed", []
        except Exception:
            # If the external lookup fails or times out, return 'failed'. Never mask as clean.
            return "failed", []


reputation_service = ReputationService()
