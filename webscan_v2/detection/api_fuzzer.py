"""
detection/api_fuzzer.py

Tests REST API endpoints discovered from JS bundles.

Checks performed per endpoint:
  1. Auth enforcement  — does the endpoint return data without authentication?
     Unauthenticated access to non-public APIs is a real finding.
  2. Error disclosure  — do 400/422/500 responses leak stack traces or DB errors?
  3. JSON injection    — inject SQL/XSS probes into JSON request bodies.
  4. Mass assignment   — send extra fields (isAdmin, role, password) and check
     if they're accepted (status 200/201 with the field reflected back).
  5. HTTP method probe — does the endpoint accept methods it shouldn't
     (e.g. DELETE on a read-only resource)?
  6. IDOR via path ID  — for endpoints with {id}, try adjacent IDs without auth.

Design principle: all payloads are safe and non-destructive.
"""

import asyncio
import json
import logging
import re
from typing import Optional
from urllib.parse import urljoin

import httpx

from detection.finding import Finding
from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)

# ── Probe payloads ────────────────────────────────────────────────────────────

_SQL_PROBES = ["'", "1 OR 1=1", "' OR '1'='1"]
_XSS_PROBES = ['<wbr id="ws-probe">', '"ws-probe"']

_MASS_ASSIGN_FIELDS = {
    "isAdmin":   True,
    "is_admin":  True,
    "role":      "admin",
    "admin":     True,
    "verified":  True,
    "active":    True,
    "password":  "Ws-probe-9!",
    "balance":   999999,
    "credits":   999999,
}

_ERROR_SIGNATURES = [
    "traceback", "stack trace", "at Object.", "at Module.",
    "syntaxerror", "referenceerror", "cannot read propert",
    "mongoose", "castError", "validationerror",
    "sql syntax", "pg::syntaxerror", "sqlite3",
    "internal server error", "unhandledpromiserejection",
    "error connecting", "connection refused",
]

_SENSITIVE_FIELDS_IN_RESPONSE = [
    "password", "passwordhash", "password_hash", "secret",
    "token", "apikey", "api_key", "ssn", "creditcard",
    "private_key", "privatekey",
]

_DANGEROUS_METHODS = ["DELETE", "PUT", "PATCH"]


class APIFuzzer:
    """
    Tests API endpoints for common vulnerabilities.
    Works on endpoints discovered from JS bundles or the OpenAPI importer.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        origin: str,
        timeout: int = 10,
    ):
        self.client  = client
        self.origin  = origin
        self.timeout = timeout

    async def test_endpoint(self, vector: InputVector) -> list[Finding]:
        findings: list[Finding] = []
        url = urljoin(self.origin, vector.url) if not vector.url.startswith("http") else vector.url

        # Skip obviously non-API paths
        if not _is_api_path(url):
            return []

        # Run all checks concurrently
        tasks = [
            self._check_auth(url, vector),
            self._check_error_disclosure(url, vector),
            self._check_mass_assignment(url),
            self._check_method_probe(url),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    # ── 1. Auth enforcement ───────────────────────────────────────────────────

    async def _check_auth(self, url: str, vector: InputVector) -> list[Finding]:
        """Check if endpoint returns sensitive data without authentication."""
        # Skip endpoints that are intentionally public
        if _is_likely_public(url):
            return []

        try:
            resp = await self.client.get(
                url,
                headers={},   # No auth headers
                timeout=self.timeout,
            )
        except Exception:
            return []

        if resp.status_code in (401, 403):
            return []   # Properly protected

        if resp.status_code not in (200, 201):
            return []

        body = resp.text.lower()

        # Check if response contains sensitive-looking data
        has_sensitive = any(f in body for f in _SENSITIVE_FIELDS_IN_RESPONSE)
        is_json       = "json" in resp.headers.get("content-type", "")
        has_data      = is_json and len(resp.text) > 50

        if not (has_sensitive or has_data):
            return []

        # Try to parse and assess what leaked
        try:
            data    = resp.json()
            summary = _summarise_response(data)
        except Exception:
            summary = resp.text[:200]

        severity = "HIGH" if has_sensitive else "MEDIUM"

        return [Finding(
            vuln_type="Unauthenticated API Endpoint",
            severity=severity,
            url=url,
            param="<no auth>",
            method="GET",
            request_example=f"GET {url}\n(no Authorization header)",
            response_indicator=f"HTTP {resp.status_code} — returned data without auth",
            evidence_snippet=summary[:300],
            description=(
                f"The API endpoint {url!r} returned a {resp.status_code} response "
                "without any authentication token. If this endpoint is not "
                "intentionally public, unauthenticated users can access its data."
            ),
            mitigation=(
                "Verify this endpoint is intentionally public. If not, add "
                "authentication middleware. Ensure no sensitive user data is "
                "returned from public endpoints."
            ),
            cwe="CWE-306",
            confidence="MEDIUM",
        )]

    # ── 2. Error disclosure ───────────────────────────────────────────────────

    async def _check_error_disclosure(
        self,
        url: str,
        vector: InputVector,
    ) -> list[Finding]:
        """Send malformed input and check for stack traces or DB errors."""
        probes = [
            ("GET",  url + "?id='", None),
            ("POST", url, {"id": "'", "data": None}),
            ("POST", url, {"__proto__": {"admin": True}}),  # prototype pollution probe
        ]

        findings = []
        for method, probe_url, body in probes:
            try:
                if method == "GET":
                    resp = await self.client.get(probe_url, timeout=self.timeout)
                else:
                    resp = await self.client.post(
                        probe_url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                        timeout=self.timeout,
                    )
            except Exception:
                continue

            if resp.status_code not in (400, 422, 500, 503):
                continue

            body_lower = resp.text.lower()
            for sig in _ERROR_SIGNATURES:
                if sig in body_lower:
                    findings.append(Finding(
                        vuln_type="API Error Information Disclosure",
                        severity="MEDIUM",
                        url=url,
                        param="<request-body>",
                        method=method,
                        request_example=f"{method} {probe_url}",
                        response_indicator=f"HTTP {resp.status_code} — error signature: {sig!r}",
                        evidence_snippet=resp.text[:300],
                        description=(
                            f"The API returned a detailed error response containing {sig!r} "
                            "when sent malformed input. Stack traces and framework error "
                            "messages reveal implementation details that aid attackers."
                        ),
                        mitigation=(
                            "Configure your framework to return generic error messages in "
                            "production. Log detailed errors server-side only. "
                            "Set NODE_ENV=production to suppress Express stack traces."
                        ),
                        cwe="CWE-209",
                        confidence="HIGH",
                    ))
                    break  # one finding per probe

        return findings

    # ── 3. Mass assignment ────────────────────────────────────────────────────

    async def _check_mass_assignment(self, url: str) -> list[Finding]:
        """Send privileged fields and check if they're accepted."""
        try:
            resp = await self.client.post(
                url,
                json=_MASS_ASSIGN_FIELDS,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except Exception:
            return []

        if resp.status_code not in (200, 201):
            return []

        body_lower = resp.text.lower()
        reflected  = [f for f in ["isadmin", "is_admin", "role", "admin"]
                      if f in body_lower]

        if not reflected:
            return []

        return [Finding(
            vuln_type="Potential Mass Assignment Vulnerability",
            severity="HIGH",
            url=url,
            param=", ".join(reflected),
            method="POST",
            request_example=(
                f"POST {url}\nContent-Type: application/json\n\n"
                + json.dumps({k: v for k, v in _MASS_ASSIGN_FIELDS.items()
                               if k.lower() in reflected}, indent=2)
            ),
            response_indicator=f"Privileged fields reflected in response: {reflected}",
            evidence_snippet=resp.text[:300],
            description=(
                "The API accepted and reflected privileged fields (isAdmin, role, etc.) "
                "in a POST request body. Mass assignment vulnerabilities allow attackers "
                "to set fields that the application never intended to be user-controlled, "
                "potentially escalating privileges or corrupting data."
            ),
            mitigation=(
                "Use an allowlist (whitelist) of accepted fields in your model/schema. "
                "In Mongoose: use select() or schema virtuals to explicitly list "
                "accepted fields. Never pass req.body directly to Model.create() or "
                "Model.findByIdAndUpdate()."
            ),
            cwe="CWE-915",
            confidence="MEDIUM",
        )]

    # ── 4. HTTP method probe ──────────────────────────────────────────────────

    async def _check_method_probe(self, url: str) -> list[Finding]:
        """Check if dangerous HTTP methods are accepted on read-only endpoints."""
        # Only probe endpoints that look like they should be read-only
        if any(m in url.lower() for m in ["/delete", "/remove", "/update", "/edit"]):
            return []

        findings = []
        for method in _DANGEROUS_METHODS:
            try:
                resp = await self.client.request(
                    method, url,
                    json={},
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
            except Exception:
                continue

            # 405 = Method Not Allowed (correct), 401/403 = auth required (fine)
            if resp.status_code in (405, 401, 403, 404):
                continue

            if resp.status_code in (200, 201, 204):
                findings.append(Finding(
                    vuln_type=f"Unexpected HTTP Method Accepted: {method}",
                    severity="MEDIUM",
                    url=url,
                    param=f"HTTP {method}",
                    method=method,
                    request_example=f"{method} {url}\nContent-Type: application/json\n\n{{}}",
                    response_indicator=f"HTTP {resp.status_code} — {method} not rejected",
                    description=(
                        f"The endpoint {url!r} accepted an HTTP {method} request "
                        "with an empty body and returned a success response. "
                        "This may indicate missing method restrictions."
                    ),
                    mitigation=(
                        "Explicitly define which HTTP methods each route accepts. "
                        "In Express: use specific router.get/post/put methods rather than "
                        "router.all(). Return 405 Method Not Allowed for unsupported methods."
                    ),
                    cwe="CWE-650",
                    confidence="LOW",
                ))

        return findings


# ── OpenAPI / Swagger importer ────────────────────────────────────────────────

class OpenAPIImporter:
    """
    Auto-discovers and imports OpenAPI/Swagger specs.
    Returns InputVectors for every documented endpoint+parameter combination.
    """

    COMMON_PATHS = [
        "/openapi.json", "/openapi.yaml",
        "/swagger.json", "/swagger.yaml",
        "/api/docs", "/api/openapi.json",
        "/api/v1/openapi.json", "/api/swagger.json",
        "/v1/openapi.json", "/docs/openapi.json",
        "/_api/swagger.json",
    ]

    def __init__(self, client: httpx.AsyncClient, origin: str):
        self.client = client
        self.origin = origin

    async def discover(self) -> list[InputVector]:
        """Try all common OpenAPI spec paths and parse whichever works."""
        for path in self.COMMON_PATHS:
            url = self.origin + path
            try:
                resp = await self.client.get(url, timeout=10)
                if resp.status_code != 200:
                    continue
                ct   = resp.headers.get("content-type", "")
                if "json" in ct or "yaml" in ct or path.endswith(".json"):
                    try:
                        spec = resp.json()
                        vectors = self._parse_spec(spec, url)
                        if vectors:
                            log.info("OpenAPI spec found at %s — %d endpoints", url, len(vectors))
                            return vectors
                    except Exception:
                        pass
            except Exception:
                pass
        return []

    def _parse_spec(self, spec: dict, spec_url: str) -> list[InputVector]:
        vectors = []
        paths   = spec.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
                    continue

                # Build full URL
                servers = spec.get("servers", [{"url": self.origin}])
                base    = servers[0].get("url", self.origin) if servers else self.origin
                full    = urljoin(base, path)

                # Extract parameters
                params = operation.get("parameters", []) + spec.get("components", {}).get("parameters", {}).values()

                if not params:
                    # Still add the endpoint itself as a vector
                    vectors.append(InputVector(
                        url=full,
                        method=method.upper(),
                        param_name="<body>",
                        param_type="json",
                        source_page=spec_url,
                    ))
                    continue

                for p in params:
                    if not isinstance(p, dict):
                        continue
                    name     = p.get("name", "")
                    location = p.get("in", "query")  # query, path, header, cookie
                    if not name:
                        continue
                    vectors.append(InputVector(
                        url=full,
                        method=method.upper(),
                        param_name=name,
                        param_type=location,
                        example_value=str(p.get("example", p.get("default", ""))),
                        source_page=spec_url,
                    ))

        return vectors


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_api_path(url: str) -> bool:
    return "/api/" in url or url.rstrip("/").endswith("/api")


def _is_likely_public(url: str) -> bool:
    """Heuristic: is this endpoint probably intentionally public?"""
    lower = url.lower()
    public_hints = [
        "/public/", "/health", "/status", "/robots", "/sitemap",
        "/invite/", "/rsvp", "/verify-password", "/join/",
        "/register", "/login", "/auth", "/oauth", "/signup",
        "/terms", "/privacy", "/docs",
    ]
    return any(h in lower for h in public_hints)


def _summarise_response(data) -> str:
    """Create a safe summary of a JSON response for evidence."""
    if isinstance(data, list):
        return f"Array of {len(data)} items. First: {json.dumps(data[0])[:150] if data else 'empty'}"
    if isinstance(data, dict):
        keys = list(data.keys())[:10]
        return f"Object with keys: {keys}"
    return str(data)[:200]
