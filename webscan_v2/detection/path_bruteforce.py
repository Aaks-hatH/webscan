"""
detection/path_bruteforce.py — Wordlist-based path and endpoint discovery.

Probes the target for hidden routes that the crawler never found.
Focus is on admin panels, API namespaces, config endpoints, and
authentication bypass paths — the routes most relevant to privilege
escalation.

Stealth design:
  - Randomises request order so paths are not probed alphabetically
  - Adds a small configurable jitter between requests
  - Uses realistic browser headers on every request
  - Skips paths that Planit's FUZZ_PATTERNS would catch (configurable)
  - Groups by response code so FOUND paths stand out immediately

Finding severity:
  200 / 201      → HIGH   (data returned without auth)
  401 / 403      → MEDIUM (endpoint exists, auth enforced — still informational)
  301 / 302      → LOW    (redirect may reveal internal path)
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from config import DEFAULT_TIMEOUT, get_browser_headers
from detection.finding import Finding

log = logging.getLogger(__name__)


# ── Wordlists ─────────────────────────────────────────────────────────────────

# Generic admin / panel paths
_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/administrator", "/administration",
    "/panel", "/cp", "/control-panel", "/controlpanel",
    "/manage", "/management", "/manager",
    "/superadmin", "/super-admin", "/superuser",
    "/backend", "/backoffice", "/back-office",
    "/staff", "/internal", "/ops",
    "/dashboard", "/dash",
    "/portal", "/secure", "/restricted",
]

# API discovery — common versioning patterns
_API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
    "/api/v3", "/api/v0", "/v1", "/v2",
    "/graphql", "/graphiql", "/gql",
    "/rest", "/rpc", "/service", "/services",
    "/api/admin", "/api/admin/", "/api/admin/users",
    "/api/admin/login", "/api/admin/stats", "/api/admin/config",
    "/api/admin/dashboard", "/api/admin/events",
    "/api/users", "/api/user", "/api/accounts",
    "/api/auth", "/api/auth/login", "/api/login",
    "/api/register", "/api/signup",
    "/api/config", "/api/settings", "/api/info",
    "/api/health", "/api/status", "/api/ping",
    "/api/debug", "/api/test", "/api/echo",
    "/api/token", "/api/refresh", "/api/verify",
    "/api/me", "/api/profile", "/api/self",
    "/api/events", "/api/events/",
    "/api/employees", "/api/employee",
]

# Auth / session paths
_AUTH_PATHS = [
    "/login", "/signin", "/sign-in", "/sign_in",
    "/logout", "/signout", "/sign-out",
    "/register", "/signup", "/sign-up",
    "/auth", "/auth/login", "/auth/token",
    "/oauth", "/oauth/token", "/oauth/authorize",
    "/forgot", "/forgot-password", "/reset-password",
    "/verify", "/confirm", "/activate",
    "/2fa", "/mfa", "/otp",
    "/sso", "/saml", "/oidc",
]

# Debug / info disclosure paths
_INFO_PATHS = [
    "/robots.txt", "/sitemap.xml", "/sitemap.html",
    "/manifest.json", "/manifest.webmanifest",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/security.txt",
    "/humans.txt",
    "/crossdomain.xml",
    "/browserconfig.xml",
    "/favicon.ico",
    "/_debug", "/_debug_toolbar", "/__debug__",
    "/__status__", "/__health__",
    "/healthz", "/readyz", "/livez",
    "/metrics", "/stats",
    "/version", "/build",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/docs",
    "/redoc",
    "/.git/HEAD",
    "/server-status", "/server-info",
]

# Planit-specific paths (derived from reading the source code)
_PLANIT_PATHS = [
    "/api/admin/login",
    "/api/admin/users",
    "/api/admin/stats",
    "/api/admin/events",
    "/api/admin/config",
    "/api/admin/employees",
    "/api/admin/audit",
    "/api/admin/blocklist",
    "/api/admin/incidents",
    "/api/admin/whitelabel",
    "/api/admin/cc",
    "/api/admin/cc/maintenance",
    "/api/admin/demo",
    "/api/events/public",
    "/api/mesh/health",
    "/api/mesh/seen",
    "/api/uptime/ping",
    "/api/uptime",
    "/api/public",
    "/api/support",
    "/api/polls",
    "/api/files",
    "/api/seating",
    "/api/chat",
    "/api/checkin",
    "/api/whitelabel",
    "/api/wl-portal",
    "/api/discovery",
]

# All paths combined
ALL_PATHS = list(dict.fromkeys(
    _ADMIN_PATHS + _API_PATHS + _AUTH_PATHS + _INFO_PATHS + _PLANIT_PATHS
))

# Status codes that mean "something is here"
_INTERESTING_CODES = {200, 201, 204, 206, 301, 302, 307, 401, 403, 405, 422, 429, 500}
_HIGH_VALUE_CODES  = {200, 201, 204, 206}
_AUTH_GATED_CODES  = {401, 403}
_REDIRECT_CODES    = {301, 302, 307}
_ERROR_CODES       = {500, 502, 503}


@dataclass
class BruteResult:
    url:          str
    status_code:  int
    content_type: str
    body_size:    int
    redirect_to:  str = ""
    snippet:      str = ""


class PathBruteforcer:
    """
    Probes the target with a wordlist of paths, reporting any that
    return interesting (non-404) responses.
    """

    def __init__(
        self,
        client:     httpx.AsyncClient,
        origin:     str,
        paths:      Optional[list[str]] = None,
        delay:      float = 0.4,
        jitter:     float = 0.2,
        concurrency: int  = 4,
        timeout:    int   = DEFAULT_TIMEOUT,
        stealth:    bool  = True,
    ):
        self.client      = client
        self.origin      = origin.rstrip("/")
        self.paths       = paths if paths is not None else ALL_PATHS
        self.delay       = delay
        self.jitter      = jitter
        self.concurrency = concurrency
        self.timeout     = timeout
        self.stealth     = stealth

    async def _fingerprint_spa(self) -> Optional[tuple[int, str]]:
        """
        Detect a React/SPA catch-all by requesting two random UUIDs.
        If both return 200 with the same body size and HTML content-type,
        the app serves a catch-all index.html — record (size, content_type)
        as the fingerprint to filter out later.
        Returns (body_size, content_type_prefix) or None.
        """
        import uuid
        fingerprints = []
        for _ in range(2):
            fake = f"/{uuid.uuid4().hex}/nonexistent-wscan-probe"
            url  = self.origin + fake
            try:
                resp = await self.client.get(
                    url, timeout=self.timeout, follow_redirects=True,
                    headers=get_browser_headers(url),
                )
                ct = resp.headers.get("content-type", "").lower()
                if resp.status_code == 200 and "html" in ct:
                    fingerprints.append((len(resp.content), ct.split(";")[0].strip()))
            except Exception:
                pass

        # Both probes hit 200 HTML with the same size → confirmed SPA catch-all
        if len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]:
            log.info("[PathBrute] SPA catch-all detected — size=%d, ct=%s",
                     fingerprints[0][0], fingerprints[0][1])
            return fingerprints[0]
        return None

    async def run(
        self,
        progress_cb=None,   # optional async callable(current, total, url, status)
    ) -> list[Finding]:
        """
        Run the bruteforce and return a list of Findings.
        """
        # Step 0: fingerprint SPA catch-all so we don't flag every React route
        spa_catchall: Optional[tuple[int, str]] = await self._fingerprint_spa()

        paths = list(self.paths)
        if self.stealth:
            random.shuffle(paths)

        sem     = asyncio.Semaphore(self.concurrency)
        results: list[BruteResult] = []

        async def probe(idx: int, path: str):
            async with sem:
                r = await self._probe_path(path, spa_catchall)
                if r:
                    results.append(r)
                if progress_cb:
                    await progress_cb(idx + 1, len(paths), self.origin + path,
                                      r.status_code if r else 404)
                # Stealth jitter
                if self.stealth:
                    await asyncio.sleep(self.delay + random.uniform(0, self.jitter))

        await asyncio.gather(*[probe(i, p) for i, p in enumerate(paths)],
                             return_exceptions=True)

        return _results_to_findings(results, self.origin)

    async def _probe_path(
        self, path: str, spa_catchall: Optional[tuple[int, str]] = None
    ) -> Optional[BruteResult]:
        url = self.origin + path
        try:
            resp = await self.client.get(
                url,
                timeout=self.timeout,
                follow_redirects=False,
                headers=get_browser_headers(url),
            )
            if resp.status_code not in _INTERESTING_CODES:
                return None

            ct           = resp.headers.get("content-type", "")
            ct_lower     = ct.lower()
            location     = resp.headers.get("location", "")
            body_bytes   = resp.content
            body_size    = len(body_bytes)
            body         = ""
            try:
                body = resp.text[:400]
            except Exception:
                pass

            # ── SPA catch-all filter ──────────────────────────────────────────
            # If the app serves a React/SPA index.html for every unknown path,
            # responses that match the fingerprint (same size + HTML content-type)
            # are NOT real endpoints — skip them entirely.
            # Exception: API paths that return JSON are always real regardless.
            if spa_catchall and resp.status_code in _HIGH_VALUE_CODES:
                catchall_size, catchall_ct = spa_catchall
                is_html = "html" in ct_lower
                is_json = "json" in ct_lower
                size_matches = abs(body_size - catchall_size) < 64  # ±64 bytes tolerance

                if is_html and size_matches and not is_json:
                    log.debug("[PathBrute] SPA catch-all filtered: %s (%dB)", url, body_size)
                    return None

            return BruteResult(
                url=url,
                status_code=resp.status_code,
                content_type=ct,
                body_size=body_size,
                redirect_to=location,
                snippet=body,
            )
        except httpx.TimeoutException:
            log.debug("Timeout probing %s", url)
        except Exception as exc:
            log.debug("Error probing %s: %s", url, exc)
        return None


def _results_to_findings(results: list[BruteResult], origin: str) -> list[Finding]:
    findings: list[Finding] = []

    for r in results:
        if r.status_code in _HIGH_VALUE_CODES:
            severity = "HIGH"
            vuln     = "Hidden Endpoint — Unauthenticated Access"
            desc = (
                f"A path not linked from the application returned HTTP {r.status_code} "
                f"with {r.body_size} bytes of content. This endpoint is accessible "
                "without authentication and was not discovered during crawling."
            )
        elif r.status_code in _AUTH_GATED_CODES:
            severity = "MEDIUM"
            vuln     = "Hidden Endpoint — Auth-Gated (Exists)"
            desc = (
                f"Path returned HTTP {r.status_code}. The endpoint exists and is "
                "protected by authentication — confirming the route is active and "
                "a valid target for credential or token attacks."
            )
        elif r.status_code in _REDIRECT_CODES:
            severity = "LOW"
            vuln     = "Hidden Redirect Path"
            desc = (
                f"Path returned HTTP {r.status_code} redirecting to "
                f"{r.redirect_to!r}. This may reveal internal routing."
            )
        elif r.status_code in _ERROR_CODES:
            severity = "MEDIUM"
            vuln     = "Hidden Endpoint — Server Error (Exists)"
            desc = (
                f"Path returned HTTP {r.status_code}. The server error confirms "
                "the route exists and may disclose stack information."
            )
        elif r.status_code == 405:
            severity = "LOW"
            vuln     = "Hidden Endpoint — Wrong Method (Exists)"
            desc = (
                "HTTP 405 (Method Not Allowed) confirms the endpoint exists — "
                "the server recognises the path but rejected the GET method."
            )
        elif r.status_code == 429:
            severity = "INFO"
            vuln     = "Rate-Limited Endpoint (Exists)"
            desc     = "HTTP 429 confirms the endpoint exists and has rate limiting."
        else:
            continue

        request_ex = f"GET {r.url}\n"
        if r.redirect_to:
            request_ex += f"\n→ Redirects to: {r.redirect_to}"

        findings.append(Finding(
            vuln_type=vuln,
            severity=severity,
            url=r.url,
            param="(path)",
            method="GET",
            request_example=request_ex,
            response_indicator=f"HTTP {r.status_code} — {r.body_size}B — {r.content_type[:60]}",
            evidence_snippet=r.snippet[:300],
            description=desc,
            mitigation=(
                "Ensure all non-public endpoints enforce authentication. "
                "Remove or disable debug/internal endpoints in production. "
                "Return 404 (not 401/403) for sensitive paths to avoid confirming their existence."
            ),
            cwe="CWE-284",
            confidence="HIGH" if r.status_code in _HIGH_VALUE_CODES else "MEDIUM",
        ))

    return findings
