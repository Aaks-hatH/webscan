"""
detection/idor_detector.py

Insecure Direct Object Reference (IDOR) detection.

Strategy
--------
The crawler's input discovery already identifies URLs containing numeric path
segments (e.g. /users/42, /orders/1001). For each such URL, we:

1. Record the authenticated response (size, status, key tokens).
2. Request an adjacent ID (ID+1 and ID-1) using the SAME session/cookies.
3. Compare responses:
   - Different status but still 200 → potential IDOR (different user's data)
   - Similar size but different content → potential IDOR
   - 403/401 on adjacent → access control appears to be working

This test requires the scanner session to be authenticated (or the endpoint
to be public). It will miss IDOR in authenticated-only sections unless you
pass a session cookie via ScanConfig.
"""

import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx

from config import DEFAULT_TIMEOUT
from detection.finding import Finding
from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)

_NUMERIC_SEGMENT = re.compile(r"/([\d]{1,10})(/|$)")
_SIMILARITY_THRESHOLD = 0.15   # 15% size difference → potentially different resource


class IDORDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.timeout = timeout

    async def test_vector(self, vector: InputVector) -> list[Finding]:
        if vector.param_type != "path":
            return []
        try:
            numeric_id = int(vector.example_value)
        except (ValueError, TypeError):
            return []

        base_url = vector.url
        findings  = []

        # Get baseline response for the original ID
        baseline = await self._fetch(base_url)
        if not baseline or baseline[0] not in (200, 201, 206):
            return []

        base_status, base_len, base_snippet = baseline

        # Try adjacent IDs
        candidates = [numeric_id + 1, numeric_id - 1] if numeric_id > 0 else [numeric_id + 1]

        for candidate_id in candidates:
            candidate_url = _swap_id(base_url, str(numeric_id), str(candidate_id))
            if not candidate_url:
                continue

            result = await self._fetch(candidate_url)
            if not result:
                continue

            status, length, snippet = result

            if status not in (200, 201, 206):
                continue   # 404, 403, etc. — access control may be working

            # Flag if we got a 200 with meaningfully different content
            if _size_differs(base_len, length) or _content_differs(base_snippet, snippet):
                findings.append(Finding(
                    vuln_type="Potential IDOR (Insecure Direct Object Reference)",
                    severity="HIGH",
                    url=candidate_url,
                    param=f"<path-id> ({numeric_id} → {candidate_id})",
                    method="GET",
                    request_example=(
                        f"# Original resource:\nGET {base_url}\n\n"
                        f"# Adjacent ID (different object, still accessible):\n"
                        f"GET {candidate_url}"
                    ),
                    response_indicator=(
                        f"Original ID={numeric_id}: HTTP {base_status}, {base_len} bytes\n"
                        f"Adjacent ID={candidate_id}: HTTP {status}, {length} bytes"
                    ),
                    evidence_snippet=snippet[:300],
                    description=(
                        f"Accessing {candidate_url!r} (ID {candidate_id}) returned a "
                        f"200 response with content that differs from ID {numeric_id}. "
                        "If these represent distinct user-owned resources, this indicates "
                        "the application relies solely on the ID in the URL to authorise "
                        "access, without verifying ownership. Attackers can enumerate IDs "
                        "to access or modify other users' data."
                    ),
                    mitigation=(
                        "Validate object ownership on every request: "
                        "confirm that the authenticated user has permission to access "
                        "the specific resource identified by the path parameter. "
                        "Never rely solely on an opaque or sequential ID for authorisation. "
                        "Consider using UUIDs or signed references instead of sequential "
                        "integers to make enumeration harder. Apply rate limiting to "
                        "resource-access endpoints."
                    ),
                    cwe="CWE-639",
                    confidence="MEDIUM",
                ))
                break  # one finding per URL

        return findings

    async def _fetch(self, url: str) -> Optional[tuple[int, int, str]]:
        try:
            resp = await self.client.get(url, timeout=self.timeout)
            body = resp.text[:2000]
            return resp.status_code, len(resp.text), body
        except Exception as exc:
            log.debug("IDOR fetch failed (%s): %s", url, exc)
            return None


def _swap_id(url: str, old_id: str, new_id: str) -> Optional[str]:
    """Replace the first occurrence of old_id in the URL path with new_id."""
    parsed = urlparse(url)
    old_path = parsed.path
    new_path = old_path.replace(f"/{old_id}/", f"/{new_id}/", 1)
    if new_path == old_path:
        new_path = old_path.replace(f"/{old_id}", f"/{new_id}", 1)
    if new_path == old_path:
        return None
    return urlunparse(parsed._replace(path=new_path))


def _size_differs(len_a: int, len_b: int) -> bool:
    if len_a == 0 and len_b == 0:
        return False
    larger = max(len_a, len_b)
    return abs(len_a - len_b) / larger > _SIMILARITY_THRESHOLD


def _content_differs(a: str, b: str) -> bool:
    """Rough token-based similarity check."""
    tokens_a = set(a.split())
    tokens_b = set(b.split())
    if not tokens_a or not tokens_b:
        return False
    intersection = tokens_a & tokens_b
    union        = tokens_a | tokens_b
    jaccard = len(intersection) / len(union)
    return jaccard < 0.7   # less than 70% token overlap → different content
