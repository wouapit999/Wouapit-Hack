import socket
import subprocess
import platform
import concurrent.futures
import re
from datetime import datetime

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def dns_lookup(target: str) -> dict:
    results = {"target": target, "timestamp": datetime.utcnow().isoformat(), "records": {}}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    if DNS_AVAILABLE:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                results["records"][rtype] = [str(r) for r in answers]
            except Exception:
                pass
    else:
        try:
            ip = socket.gethostbyname(target)
            results["records"]["A"] = [ip]
        except Exception as e:
            results["error"] = str(e)

    try:
        results["ip"] = socket.gethostbyname(target)
    except Exception:
        pass

    try:
        info = socket.gethostbyaddr(results.get("ip", target))
        results["reverse_dns"] = info[0]
    except Exception:
        pass

    return results


def whois_lookup(target: str) -> dict:
    result = {"target": target, "timestamp": datetime.utcnow().isoformat()}
    if WHOIS_AVAILABLE:
        try:
            w = whois_lib.whois(target)
            result["data"] = {
                "domain_name": str(w.domain_name),
                "registrar": str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": str(w.name_servers),
                "status": str(w.status),
                "emails": str(w.emails),
                "org": str(w.org),
                "country": str(w.country),
            }
        except Exception as e:
            result["error"] = str(e)
    else:
        system = platform.system()
        cmd = ["whois", target] if system != "Windows" else ["whois", target]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=15).decode(errors="ignore")
            result["data"] = {"raw": out[:3000]}
        except Exception as e:
            result["error"] = f"whois module not installed. pip install python-whois. ({e})"
    return result


def _scan_port(host: str, port: int, timeout: float = 1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = "unknown"
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    pass
                return {"port": port, "state": "open", "service": service}
    except Exception:
        pass
    return None


def port_scan(target: str, ports: str = "1-1024") -> dict:
    result = {"target": target, "timestamp": datetime.utcnow().isoformat(), "open_ports": []}
    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
    except Exception as e:
        return {"error": str(e)}

    port_list = []
    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            port_list.extend(range(int(start), int(end) + 1))
        else:
            try:
                port_list.append(int(part))
            except ValueError:
                pass

    port_list = list(set(port_list))[:2000]

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        futures = {ex.submit(_scan_port, ip, p): p for p in port_list}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                result["open_ports"].append(r)

    result["open_ports"].sort(key=lambda x: x["port"])
    result["total_scanned"] = len(port_list)
    return result


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "dev", "staging",
    "test", "api", "admin", "portal", "remote", "secure", "shop", "blog",
    "cdn", "ns1", "ns2", "mx", "webmail", "support", "help", "app", "mobile",
    "m", "beta", "alpha", "new", "old", "static", "media", "img", "images",
    "video", "docs", "wiki", "git", "gitlab", "github", "jira", "confluence",
    "jenkins", "ci", "monitor", "status", "metrics", "grafana", "prometheus",
    "db", "database", "mysql", "postgres", "redis", "elastic", "kibana",
    "auth", "login", "sso", "oauth", "id", "accounts", "user", "users",
]


def _check_subdomain(domain: str, sub: str):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip, "status": "resolved"}
    except Exception:
        return None


def subdomain_enum(domain: str) -> dict:
    result = {"domain": domain, "timestamp": datetime.utcnow().isoformat(), "found": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_check_subdomain, domain, s): s for s in COMMON_SUBDOMAINS}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                result["found"].append(r)
    result["found"].sort(key=lambda x: x["subdomain"])
    result["count"] = len(result["found"])
    return result


def get_headers(url: str) -> dict:
    result = {"url": url, "timestamp": datetime.utcnow().isoformat()}
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed. pip install requests"}
    try:
        import requests
        r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        result["status_code"] = r.status_code
        result["headers"] = dict(r.headers)

        # Bot-challenge / WAF detection — the target's real headers cannot be
        # observed through an interstitial. Report accurately instead of
        # falsely flagging every header as missing.
        challenge_signals = [
            r.headers.get("X-Vercel-Mitigated", "").lower() == "challenge",
            "X-Vercel-Challenge-Token" in r.headers,
            "cf-mitigated" in {k.lower() for k in r.headers},
            r.headers.get("Server", "").lower() == "cloudflare" and r.status_code == 403,
            r.status_code == 403 and "checking your browser" in r.text.lower()[:2000],
        ]
        if any(challenge_signals):
            result["bot_challenged"] = True
            result["security_headers"] = {}
            result["info"] = (
                "Target returned a bot-challenge / WAF interstitial (Vercel Challenge, "
                "Cloudflare, or similar). Real security headers cannot be assessed "
                "through the challenge page — this is NOT a finding against the target. "
                "Re-run from a whitelisted IP or with an authenticated session, or "
                "inspect headers manually with curl."
            )
            result["cookies"] = []
            return result

        security_headers = [
            "Strict-Transport-Security", "X-Content-Type-Options",
            "X-Frame-Options", "Content-Security-Policy",
            "Referrer-Policy", "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            # X-XSS-Protection is DEPRECATED (MDN, OWASP recommend against setting it)
            # so it is tracked separately as informational, not as a missing control.
        ]
        result["security_headers"] = {}
        for h in security_headers:
            result["security_headers"][h] = r.headers.get(h, "MISSING")
        result["deprecated_headers"] = {
            "X-XSS-Protection": r.headers.get("X-XSS-Protection", "NOT SET (correct — deprecated)"),
        }
        result["cookies"] = [
            {"name": c.name, "secure": c.secure, "httponly": c.has_nonstandard_attr("HttpOnly"),
             "samesite": c._rest.get("SameSite", "Not set")}
            for c in r.cookies
        ]
    except Exception as e:
        result["error"] = str(e)
    return result
