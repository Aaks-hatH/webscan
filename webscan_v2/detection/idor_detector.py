"""
detection/idor_detector.py — IDOR detection for path params AND query params.
"""
import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs

import httpx

from config import DEFAULT_TIMEOUT
from detection.finding import Finding
from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)

_NUMERIC_SEGMENT = re.compile(r"/(\d{1,10})(/|$)")
_SIMILARITY_THRESHOLD = 0.15


class IDORDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.timeout = timeout

    async def test_vector(self, vector: InputVector) -> list[Finding]:
        if vector.param_type == "path":
            return await self._test_path_idor(vector)
        if vector.param_type == "query":
            return await self._test_query_idor(vector)
        return []

    # ── Path-segment IDOR: /users/42 → try /users/41, /users/43 ──────────────
    async def _test_path_idor(self, vector: InputVector) -> list[Finding]:
        try:
            numeric_id = int(vector.example_value)
        except (ValueError, TypeError):
            return []

        baseline = await self._fetch(vector.url)
        if not baseline or baseline[0] not in (200, 201, 206):
            return []
        base_status, base_size, base_body = baseline

        for test_id in [numeric_id + 1, numeric_id - 1]:
            if test_id <= 0:
                continue
            test_url = re.sub(
                r"/" + re.escape(str(numeric_id)) + r"(/|$)",
                f"/{test_id}\\1",
                vector.url, count=1,
            )
            result = await self._fetch(test_url)
            if not result or result[0] not in (200, 201):
                continue
            r_status, r_size, r_body = result

            if r_size < 50:
                continue
            size_diff = abs(r_size - base_size) / max(base_size, 1)
            if size_diff > _SIMILARITY_THRESHOLD and r_size > 100:
                return [_make_finding(
                    vector.url, test_url, "path", str(numeric_id), str(test_id),
                    base_size, r_size, r_body,
                )]
        return []

    # ── Query-param IDOR: ?user_id=1 → try ?user_id=2, ?user_id=3 ───────────
    async def _test_query_idor(self, vector: InputVector) -> list[Finding]:
        # Only test params that look like ID fields
        p = vector.param_name.lower()
        id_keywords = ("id", "user", "uid", "account", "profile", "order",
                       "customer", "client", "member", "owner", "record", "doc")
        if not any(kw in p for kw in id_keywords):
            return []

        try:
            orig_id = int(vector.example_value)
        except (ValueError, TypeError):
            return []

        baseline = await self._fetch(vector.url)
        if not baseline or baseline[0] not in (200, 201):
            return []
        base_status, base_size, base_body = baseline

        parsed = urlparse(vector.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        for test_id in [orig_id + 1, orig_id + 2, orig_id - 1, 1, 2]:
            if test_id <= 0 or test_id == orig_id:
                continue
            test_qs  = {**qs, vector.param_name: [str(test_id)]}
            test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
            result   = await self._fetch(test_url)
            if not result or result[0] not in (200, 201):
                continue
            r_status, r_size, r_body = result

            if r_size < 80:
                continue
            # Different content → different object returned → IDOR
            size_diff = abs(r_size - base_size) / max(base_size, 1)
            if size_diff > 0.05 and r_size > 100:  # >5% different
                return [_make_finding(
                    vector.url, test_url, "query", str(orig_id), str(test_id),
                    base_size, r_size, r_body,
                )]
        return []

    async def _fetch(self, url: str):
        try:
            r = await self.client.get(url, timeout=self.timeout, follow_redirects=True)
            return r.status_code, len(r.text), r.text
        except Exception as exc:
            log.debug("IDOR fetch failed (%s): %s", url, exc)
            return None


def _make_finding(orig_url, test_url, param_type, orig_id, test_id,
                  base_size, test_size, evidence) -> Finding:
    return Finding(
        vuln_type="Insecure Direct Object Reference (IDOR)",
        severity="HIGH",
        url=orig_url,
        param=f"ID={orig_id} → {test_id}" if param_type == "path" else orig_url.split("?")[-1],
        method="GET",
        request_example=f"# Original:\nGET {orig_url}\n\n# Modified ID:\nGET {test_url}",
        response_indicator=(
            f"ID {orig_id}: {base_size}B response | "
            f"ID {test_id}: {test_size}B response (different object returned)"
        ),
        evidence_snippet=evidence[:300],
        description=(
            f"Changing a {'path-segment' if param_type=='path' else 'query parameter'} ID "
            f"from {orig_id} to {test_id} returned a valid {test_size}B response. "
            "No server-side ownership check prevents accessing other users' objects."
        ),
        mitigation=(
            "Verify server-side that the authenticated user owns the requested "
            "object before returning it. Use indirect references (map session ID → "
            "real DB ID server-side). Never trust client-supplied object identifiers."
        ),
        cwe="CWE-639",
        confidence="MEDIUM",
    )
