"""
webscan_v2/config.py — All probes, patterns, and scan profile definitions.
"""

# ── Request settings ──────────────────────────────────────────────────────────
DEFAULT_TIMEOUT   = 10
DEFAULT_DELAY     = 0.3
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 100
# ── Rotating realistic browser User-Agent pool ───────────────────────────────
import random as _random

_USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.81 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.81 Mobile Safari/537.36",
    # Safari on iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
]

# Default UA for single-UA references
USER_AGENT = _USER_AGENTS[0]


def get_user_agent() -> str:
    """Return a random realistic browser User-Agent string."""
    return _random.choice(_USER_AGENTS)


def get_browser_headers(url: str = "") -> dict:
    """Full browser-like headers for a request to the given URL."""
    ua         = get_user_agent()
    is_firefox = "Firefox" in ua
    is_safari  = "Safari" in ua and "Chrome" not in ua
    accept = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        if is_firefox or is_safari
        else "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    )
    headers = {
        "User-Agent":                ua,
        "Accept":                    accept,
        "Accept-Language":           _random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8"]),
        "Accept-Encoding":           "gzip, deflate, br",
        "Connection":                "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":            "document",
        "Sec-Fetch-Mode":            "navigate",
        "Sec-Fetch-Site":            "none",
        "Sec-Fetch-User":            "?1",
    }
    if url:
        from urllib.parse import urlparse as _up
        p = _up(url)
        if p.path and p.path != "/":
            headers["Referer"] = f"{p.scheme}://{p.netloc}/"
    return headers

# ── XSS probes ────────────────────────────────────────────────────────────────
XSS_PROBES = [
    'wsxss1<wbr id="wsxss1">',
    "wsxss2'wsxss2",
    'wsxss3"wsxss3',
    "<wsxss4>",
    "<script>wsxss5</script>",
    "wsxss6<img src=x onerror=wsxss6>",
]
STORED_XSS_PROBE_TEMPLATE = 'wscan-stored-{uid}'   # uid = 8-char hex

# ── SQLi ──────────────────────────────────────────────────────────────────────
SQLI_PROBES = ["'", "1 AND 1=1", "1 OR 1=1"]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "sqlite3::operationalerror",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "ora-01756",
    "db2 sql error",
]

# ── Blind SQLi time-based payloads ────────────────────────────────────────────
# Each payload targets a different DB backend. Delay = 3 seconds.
BLIND_SQLI_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:3'--",              "MSSQL"),
    ("'; SELECT SLEEP(3)--",                    "MySQL"),
    ("'; SELECT pg_sleep(3)--",                 "PostgreSQL"),
    ("1'; WAITFOR DELAY '0:0:3'--",             "MSSQL (numeric)"),
    ("1 AND SLEEP(3)",                          "MySQL (no quote)"),
    ("1) OR SLEEP(3)--",                        "MySQL (bracket)"),
]
BLIND_SQLI_DELAY_THRESHOLD = 2.5   # seconds above baseline

# ── Security headers ──────────────────────────────────────────────────────────
REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Absent CSP allows inline script execution, increasing XSS impact.",
        "mitigation": "Add Content-Security-Policy: default-src 'self' and expand as needed.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Missing X-Frame-Options enables clickjacking.",
        "mitigation": "Set X-Frame-Options: DENY or SAMEORIGIN.",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Absent header allows MIME-type sniffing.",
        "mitigation": "Set X-Content-Type-Options: nosniff.",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS absent; plain-HTTP connections may be accepted.",
        "mitigation": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "No Referrer-Policy; URLs may leak in Referer header.",
        "mitigation": "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "No Permissions-Policy restricts browser API access.",
        "mitigation": "Add Permissions-Policy to disable unused APIs.",
    },
}

DANGEROUS_HEADERS = {
    "Server":           {"severity": "INFO", "description": "Server version disclosed.", "mitigation": "Suppress or genericise the Server header."},
    "X-Powered-By":     {"severity": "INFO", "description": "Technology stack disclosed.", "mitigation": "Remove X-Powered-By header."},
    "X-AspNet-Version": {"severity": "LOW",  "description": "ASP.NET version disclosed.", "mitigation": "Remove X-AspNet-Version in IIS config."},
}

# ── Open redirect ─────────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = ["https://evil.example.com", "//evil.example.com", "https://evil.example.com/", "/\\evil.example.com", "https:evil.example.com"]
REDIRECT_PARAMS   = [
    "redirect", "redirect_to", "redirect_url", "url", "next",
    "return", "return_url", "goto", "dest", "destination",
    "redir", "r", "out", "jump", "link", "target",
    "callback", "cb", "continue", "forward", "location",
    "to", "page", "view", "path", "from", "back",
]

# ── Sensitive paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.htaccess", "/.htpasswd", "/wp-config.php", "/config.php",
    "/config.yml", "/config.yaml", "/config.json", "/settings.py",
    "/local_settings.py", "/database.yml", "/package.json",
    "/web.config", "/phpinfo.php", "/info.php", "/test.php",
    "/backup.sql", "/dump.sql", "/db.sql", "/backup.sql.gz",
    "/server-status", "/.DS_Store", "/.svn/entries",
    "/.bash_history", "/id_rsa", "/id_dsa",
    # API endpoints
    "/api/config", "/api/v1/config", "/api/health", "/api/v1/health",
    "/api/admin/users", "/api/v1/admin/users", "/api/users", "/api/v1/users",
    # Common debug/admin
    "/debug", "/trace", "/console", "/actuator", "/actuator/env",
    "/actuator/health", "/metrics", "/admin", "/admin/", "/status",
    # Common secrets
    "/secrets.json", "/credentials.json", "/.aws/credentials",
    "/swagger.json", "/openapi.json", "/api/openapi.json",
]

# ── Info leak patterns ────────────────────────────────────────────────────────
LEAK_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Generic API Key":   r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{16,}",
    "Private Key":       r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Password in HTML":  r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
    "JWT Token":         r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Basic Auth in URL": r"https?://[^:@/\n]+:[^@/\n]+@",
    "Internal IP":       r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "Stack Trace (Python)": r"Traceback \(most recent call last\)",
    "Stack Trace (PHP)": r"(Fatal error|Warning):\s+.+\sin\s+.+\.php\s+on\s+line\s+\d+",
    "Stack Trace (Java)": r"at [a-zA-Z_$][a-zA-Z0-9_$.]*\([A-Za-z0-9_.]+:\d+\)",
}

# ── CSRF token field names ────────────────────────────────────────────────────
CSRF_TOKEN_NAMES = {
    "csrf", "_csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "authenticity_token", "__requestverificationtoken", "xsrf",
    "_xsrf", "xsrf_token", "_token", "token",
}

# ── Scan profiles ─────────────────────────────────────────────────────────────
PROFILES: dict[str, dict] = {
    "quick": {
        "description": "Headers and file exposure only — fast, no input fuzzing",
        "run_xss":        False,
        "run_sqli":       False,
        "run_blind_sqli": False,
        "run_stored_xss": False,
        "run_csrf":       True,
        "run_idor":       False,
        "run_headers":    True,
        "run_redirects":  False,
        "run_exposure":   True,
        "run_info_leak":  True,
        "run_api_fuzz":   False,
    },
    "standard": {
        "description": "Full input testing excluding slow blind SQLi and IDOR",
        "run_xss":        True,
        "run_sqli":       True,
        "run_blind_sqli": False,
        "run_stored_xss": True,
        "run_csrf":       True,
        "run_idor":       True,
        "run_headers":    True,
        "run_redirects":  True,
        "run_exposure":   True,
        "run_info_leak":  True,
        "run_api_fuzz":   True,
    },
    "full": {
        "description": "Everything — slowest but most thorough",
        "run_xss":        True,
        "run_sqli":       True,
        "run_blind_sqli": True,
        "run_stored_xss": True,
        "run_csrf":       True,
        "run_idor":       True,
        "run_headers":    True,
        "run_redirects":  True,
        "run_exposure":   True,
        "run_info_leak":  True,
        "run_api_fuzz":   True,
    },
    "api": {
        "description": "API-focused: JSON endpoints, headers, no HTML form tests",
        "run_xss":             True,
        "run_sqli":            True,
        "run_blind_sqli":      False,
        "run_stored_xss":      False,
        "run_csrf":            False,
        "run_idor":            True,
        "run_headers":         True,
        "run_redirects":       True,
        "run_exposure":        True,
        "run_info_leak":       True,
        "run_api_fuzz":        True,
        "run_path_bruteforce": True,
        "run_jwt_analysis":    True,
        "run_tech_fingerprint":True,
        "run_js_secrets":      True,
        "run_admin_probe":     True,
    },
    "pentest": {
        "description": "Full pentest mode — admin bypass, JWT attacks, secret extraction, all checks",
        "run_xss":             True,
        "run_sqli":            True,
        "run_blind_sqli":      True,
        "run_stored_xss":      True,
        "run_csrf":            True,
        "run_idor":            True,
        "run_headers":         True,
        "run_redirects":       True,
        "run_exposure":        True,
        "run_info_leak":       True,
        "run_api_fuzz":        True,
        "run_path_bruteforce": True,
        "run_jwt_analysis":    True,
        "run_tech_fingerprint":True,
        "run_js_secrets":      True,
        "run_admin_probe":     True,
    },
}

# ── Backfill new flags into existing profiles ─────────────────────────────────
_NEW_FLAG_DEFAULTS = {
    "run_path_bruteforce":  False,
    "run_jwt_analysis":     False,
    "run_tech_fingerprint": False,
    "run_js_secrets":       False,
    "run_admin_probe":      False,
}
for _pname, _pdata in PROFILES.items():
    for _flag, _default in _NEW_FLAG_DEFAULTS.items():
        _pdata.setdefault(_flag, _default)
# Enable passive new checks on standard + full
for _pname in ("standard", "full"):
    PROFILES[_pname].update({
        "run_path_bruteforce":  True,
        "run_jwt_analysis":     True,
        "run_tech_fingerprint": True,
        "run_js_secrets":       True,
        "run_admin_probe":      False,  # Opt-in only via pentest profile
    })

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
