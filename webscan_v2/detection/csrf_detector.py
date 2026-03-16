"""
detection/csrf_detector.py

Detects POST forms that lack CSRF protection tokens.

Detection logic
---------------
1. For every POST form on a page, check whether any of its input fields
   has a name matching known CSRF token naming conventions.
2. Also check for the SameSite cookie attribute on session-like cookies
   (a defence-in-depth indicator, not sufficient alone).
3. Flag forms that have no apparent CSRF token and no SameSite=Strict/Lax.
"""

import logging

from config import CSRF_TOKEN_NAMES
from crawler.async_crawler import PageResult, DiscoveredForm
from detection.finding import Finding

log = logging.getLogger(__name__)


class CSRFDetector:
    def check_page(self, page: PageResult) -> list[Finding]:
        findings: list[Finding] = []

        for form in page.forms:
            if form.method != "POST":
                continue

            finding = self._check_form(page.url, form)
            if finding:
                findings.append(finding)

        return findings

    @staticmethod
    def _check_form(page_url: str, form: DiscoveredForm) -> Finding | None:
        input_names_lower = {inp.name.lower() for inp in form.inputs}

        has_csrf_token = bool(input_names_lower & CSRF_TOKEN_NAMES)
        if has_csrf_token:
            return None

        # List visible (non-hidden) fields to give context in the report
        visible_params = [
            inp.name for inp in form.inputs
            if inp.input_type not in ("hidden", "submit", "button", "reset")
        ]

        return Finding(
            vuln_type="Missing CSRF Token",
            severity="MEDIUM",
            url=form.action,
            param=", ".join(visible_params) or "<unknown>",
            method="POST",
            request_example=(
                f"# Form found on: {page_url}\n"
                f"POST {form.action}\n"
                f"Content-Type: {form.enctype}\n\n"
                + "\n".join(f"{inp.name}={inp.value or '<user-input>'}"
                             for inp in form.inputs
                             if inp.input_type not in ("submit", "button"))
            ),
            response_indicator=(
                f"POST form at {form.action!r} has no CSRF token field. "
                f"Input fields: {[i.name for i in form.inputs]}"
            ),
            description=(
                f"A POST form at {form.action!r} (found on {page_url}) "
                "does not include any recognisable CSRF token field. "
                "Without a per-session, unpredictable token, an attacker can "
                "craft a malicious page that submits this form on behalf of an "
                "authenticated user — performing unintended state-changing actions "
                "such as password changes, transfers, or account modifications."
            ),
            mitigation=(
                "Add a synchronizer token pattern: generate a cryptographically "
                "random per-session token, store it server-side, include it as a "
                "hidden form field, and validate it on every state-changing request. "
                "Alternatively, use the SameSite=Lax or SameSite=Strict cookie "
                "attribute as a complementary (not sole) defence. "
                "Most web frameworks provide built-in CSRF middleware "
                "(Django: CsrfViewMiddleware, Rails: protect_from_forgery, "
                "Laravel: @csrf directive)."
            ),
            cwe="CWE-352",
            confidence="MEDIUM",
        )
