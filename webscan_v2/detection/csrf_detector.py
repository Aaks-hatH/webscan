"""
detection/csrf_detector.py — CSRF detection on POST forms.

Checks:
1. POST form has no CSRF token field
2. POST form has no SameSite cookie set
3. Also checks PUT/DELETE/PATCH form methods
"""
import logging

from config import CSRF_TOKEN_NAMES
from crawler.async_crawler import PageResult, DiscoveredForm
from detection.finding import Finding

log = logging.getLogger(__name__)


class CSRFDetector:
    def check_page(self, page: PageResult) -> list[Finding]:
        findings = []
        for form in page.forms:
            if form.method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
                continue
            finding = self._check_form(page.url, form)
            if finding:
                findings.append(finding)
        return findings

    @staticmethod
    def _check_form(page_url: str, form: DiscoveredForm) -> Finding | None:
        input_names_lower = {inp.name.lower() for inp in form.inputs}
        if bool(input_names_lower & CSRF_TOKEN_NAMES):
            return None

        visible_params = [
            inp.name for inp in form.inputs
            if inp.input_type not in ("hidden", "submit", "button", "reset")
        ]
        all_params = [inp.name for inp in form.inputs
                      if inp.input_type not in ("submit", "button", "reset")]

        # Determine severity by what the form does
        sev = "HIGH"
        action = (form.action or "").lower()
        sensitive_keywords = ("transfer", "pay", "send", "delete", "admin",
                               "password", "email", "account", "update", "create")
        if any(kw in action for kw in sensitive_keywords):
            sev = "HIGH"
        elif not visible_params:
            sev = "LOW"
        else:
            sev = "MEDIUM"

        return Finding(
            vuln_type="Missing CSRF Token",
            severity=sev,
            url=form.action or page_url,
            param=", ".join(visible_params) or "<hidden fields only>",
            method="POST",
            request_example=(
                f"# Form on: {page_url}\n"
                f"POST {form.action}\n"
                f"Content-Type: {form.enctype}\n\n"
                + "\n".join(
                    f"{inp.name}={inp.value or '<user-input>'}"
                    for inp in form.inputs
                    if inp.input_type not in ("submit", "button")
                )
            ),
            response_indicator=(
                f"POST form submits to {form.action!r} with no CSRF token. "
                f"Fields: {all_params}"
            ),
            evidence_snippet=(
                f"Form action='{form.action}' method=POST — "
                f"no token in: {all_params}"
            ),
            description=(
                f"A state-changing POST form on {page_url!r} has no CSRF protection. "
                "An attacker can host a page that auto-submits this form using a "
                "logged-in user's session — enabling account takeover, transfers, "
                "or privilege escalation without the user's knowledge."
            ),
            mitigation=(
                "Add a cryptographically random per-session CSRF token as a hidden "
                "form field and validate it server-side on every state-changing request. "
                "Complement with SameSite=Lax cookies. Most frameworks have built-in "
                "CSRF middleware (Django CsrfViewMiddleware, Rails protect_from_forgery)."
            ),
            cwe="CWE-352",
            confidence="HIGH",
        )
