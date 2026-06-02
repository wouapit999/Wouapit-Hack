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
    "extended": [],
}

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1; SELECT SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated",
    "syntax error", "ora-", "pg_query", "sqlite_", "microsoft ole db",
    "odbc sql", "jdbc", "sqlstate",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
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
            if r.status_code not in (404, 403, 400):
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
        base_len = len(base_r.text)
    except Exception as e:
        return {"error": str(e)}

    params_in_url = re.findall(r'[?&]([^=&]+)=([^&]*)', url)

    for payload in SQLI_PAYLOADS[:6]:
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
                        "severity": "HIGH",
                    })
                    break
        except Exception:
            pass

    if not result["vulnerabilities"]:
        result["info"].append("No obvious SQL injection errors detected with basic payloads.")
        result["info"].append("Manual testing and advanced techniques recommended.")

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
                    "severity": "MEDIUM",
                })
        except Exception:
            pass

    if not result["vulnerabilities"]:
        result["info"].append("No reflected XSS detected with basic payloads.")
        result["info"].append("DOM-based and stored XSS require manual testing.")

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
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()

                result["valid"] = True
                result["protocol"] = proto
                result["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
                result["subject"] = dict(x[0] for x in cert.get("subject", []))
                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")
                result["san"] = [v for t, v in cert.get("subjectAltName", [])]

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
        content = r.text
        headers_str = str(r.headers).lower()
        all_text = content + headers_str

        for tech, sigs in TECH_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in all_text.lower():
                    if tech not in result["technologies"]:
                        result["technologies"].append(tech)
                    break

        result["server"] = r.headers.get("Server", "Unknown")
        result["powered_by"] = r.headers.get("X-Powered-By", "Not disclosed")
        result["status_code"] = r.status_code
        result["content_type"] = r.headers.get("Content-Type", "Unknown")
    except Exception as e:
        result["error"] = str(e)

    return result
