"""
detection/spa_detector.py

Detects Single Page Applications that use catch-all routing (e.g. /* -> index.html).
When a SPA catch-all is detected, file exposure checks are suppressed because
every URL returns 200 with the app shell — not actual files.

Strategy:
  1. Request a random UUID path that cannot exist.
  2. If it returns 200 with HTML that matches the homepage, it's a SPA catch-all.
  3. Also compute a "baseline fingerprint" (content hash of homepage) for
     comparison use by the exposure detector.
"""

import hashlib
import logging
import uuid
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)


@dataclass
class SPAProfile:
    is_spa:            bool
    baseline_hash:     str   # MD5 of homepage body
    baseline_size:     int   # bytes of homepage
    baseline_snippet:  str   # first 200 chars for logging
    framework_hint:    str   # react | vue | angular | unknown


class SPADetector:
    """
    Call detect() once per target before running exposure checks.
    Pass the resulting SPAProfile to ConfigExposureDetector so it can
    skip findings where the response matches the SPA shell.
    """

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def detect(self, origin: str) -> SPAProfile:
        # Fetch homepage baseline
        try:
            home = await self.client.get(origin, timeout=10)
            home_body  = home.text
            home_size  = len(home_body)
            home_hash  = hashlib.md5(home_body.encode()).hexdigest()
            home_snip  = home_body[:200]
            framework  = _detect_framework(home_body)
        except Exception as exc:
            log.debug("SPA baseline fetch failed: %s", exc)
            return SPAProfile(False, "", 0, "", "unknown")

        # Request a path that provably doesn't exist
        canary = f"/{uuid.uuid4().hex}/webscan-canary-probe"
        try:
            probe = await self.client.get(origin + canary, timeout=10)
        except Exception:
            return SPAProfile(False, home_hash, home_size, home_snip, framework)

        if probe.status_code != 200:
            # Proper 404 — not a catch-all SPA
            return SPAProfile(False, home_hash, home_size, home_snip, framework)

        probe_hash = hashlib.md5(probe.text.encode()).hexdigest()
        is_spa     = probe_hash == home_hash or (
            "html" in probe.headers.get("content-type", "").lower()
            and abs(len(probe.text) - home_size) < 500
        )

        if is_spa:
            log.info(
                "SPA catch-all detected at %s (%s). "
                "File exposure probes will filter false positives.",
                origin, framework,
            )

        return SPAProfile(
            is_spa=is_spa,
            baseline_hash=home_hash,
            baseline_size=home_size,
            baseline_snippet=home_snip,
            framework_hint=framework,
        )


def _detect_framework(html: str) -> str:
    lower = html.lower()
    if "react" in lower or "_react" in lower or "react-dom" in lower:
        return "react"
    if "vue" in lower or "__vue" in lower:
        return "vue"
    if "ng-version" in lower or "angular" in lower:
        return "angular"
    if "svelte" in lower:
        return "svelte"
    if "next.js" in lower or "__next" in lower:
        return "next.js"
    return "unknown"
