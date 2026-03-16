"""detection/header_checker.py"""
from config import REQUIRED_HEADERS, DANGEROUS_HEADERS
from crawler.async_crawler import PageResult
from detection.finding import Finding


class HeaderChecker:
    def check_page(self, page: PageResult) -> list[Finding]:
        findings: list[Finding] = []
        hl = {k.lower(): v for k, v in page.headers.items()}

        for name, meta in REQUIRED_HEADERS.items():
            if name.lower() not in hl:
                findings.append(Finding(
                    vuln_type=f"Missing Security Header: {name}",
                    severity=meta["severity"],
                    url=page.url, param=name, method="GET",
                    request_example=f"GET {page.url}",
                    response_indicator=f"Header {name!r} absent",
                    description=meta["description"],
                    mitigation=meta["mitigation"],
                    cwe="CWE-693", confidence="HIGH",
                ))

        for name, meta in DANGEROUS_HEADERS.items():
            if name.lower() in hl:
                findings.append(Finding(
                    vuln_type=f"Information Disclosure Header: {name}",
                    severity=meta["severity"],
                    url=page.url, param=name, method="GET",
                    request_example=f"GET {page.url}",
                    response_indicator=f"{name}: {hl[name.lower()]}",
                    description=meta["description"],
                    mitigation=meta["mitigation"],
                    cwe="CWE-200", confidence="HIGH",
                ))

        for cookie_line in page.headers.get("set-cookie", "").split("\n"):
            cookie_line = cookie_line.strip()
            if not cookie_line:
                continue
            lower = cookie_line.lower()
            name  = cookie_line.split("=")[0].strip()
            if "secure" not in lower:
                findings.append(Finding(
                    vuln_type="Cookie Missing Secure Flag",
                    severity="MEDIUM",
                    url=page.url, param=f"Set-Cookie: {name}", method="GET",
                    response_indicator=cookie_line[:120],
                    description=f"Cookie {name!r} transmitted over plain HTTP.",
                    mitigation="Add Secure attribute to all cookies.",
                    cwe="CWE-614", confidence="HIGH",
                ))
            if "httponly" not in lower:
                findings.append(Finding(
                    vuln_type="Cookie Missing HttpOnly Flag",
                    severity="MEDIUM",
                    url=page.url, param=f"Set-Cookie: {name}", method="GET",
                    response_indicator=cookie_line[:120],
                    description=f"Cookie {name!r} readable via JavaScript.",
                    mitigation="Add HttpOnly attribute to session cookies.",
                    cwe="CWE-1004", confidence="HIGH",
                ))
        return findings
