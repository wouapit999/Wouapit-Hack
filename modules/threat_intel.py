"""Threat Intelligence module — IP/domain reputation, IOC lookup, feed aggregator."""
import re, socket
from datetime import datetime

try:
    import requests as req
    REQ_OK = True
except ImportError:
    REQ_OK = False


def _req_get(url, **kw):
    return req.get(url, timeout=10, **kw)


# ── IP Reputation ─────────────────────────────────────────────────────────────
def ip_reputation(ip: str, keys: dict = None) -> dict:
    keys = keys or {}
    result = {"ip": ip, "timestamp": datetime.utcnow().isoformat(),
              "sources": {}, "verdict": "UNKNOWN", "risk_score": 0}
    if not REQ_OK:
        return {"error": "requests not installed"}
    if not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
        return {"error": "Invalid IP address"}

    # AbuseIPDB
    if keys.get("abuseipdb"):
        try:
            r = _req_get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                         headers={"Key": keys["abuseipdb"], "Accept": "application/json"})
            if r.status_code == 200:
                d = r.json().get("data",{})
                result["sources"]["abuseipdb"] = {
                    "score":       d.get("abuseConfidenceScore"),
                    "country":     d.get("countryCode"),
                    "isp":         d.get("isp"),
                    "reports":     d.get("totalReports"),
                    "last_report": d.get("lastReportedAt"),
                    "is_tor":      d.get("isTor"),
                    "usage_type":  d.get("usageType"),
                }
        except Exception as e:
            result["sources"]["abuseipdb"] = {"error": str(e)}

    # VirusTotal
    if keys.get("virustotal"):
        try:
            r = _req_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": keys["virustotal"]})
            if r.status_code == 200:
                d = r.json().get("data",{}).get("attributes",{})
                stats = d.get("last_analysis_stats",{})
                result["sources"]["virustotal"] = {
                    "malicious":  stats.get("malicious",0),
                    "suspicious": stats.get("suspicious",0),
                    "country":    d.get("country"),
                    "asn":        d.get("asn"),
                    "as_owner":   d.get("as_owner"),
                    "reputation": d.get("reputation"),
                }
        except Exception as e:
            result["sources"]["virustotal"] = {"error": str(e)}

    # Shodan (no key needed for basic info)
    try:
        r = _req_get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code == 200:
            d = r.json()
            result["sources"]["shodan"] = {
                "open_ports":  d.get("ports",[]),
                "cpes":        d.get("cpes",[]),
                "hostnames":   d.get("hostnames",[]),
                "vulns":       d.get("vulns",[]),
                "tags":        d.get("tags",[]),
            }
    except Exception as e:
        result["sources"]["shodan"] = {"error": str(e)}

    # IPInfo (free tier)
    try:
        r = _req_get(f"https://ipinfo.io/{ip}/json")
        if r.status_code == 200:
            d = r.json()
            result["geo"] = {
                "city":    d.get("city"),
                "region":  d.get("region"),
                "country": d.get("country"),
                "org":     d.get("org"),
                "timezone":d.get("timezone"),
            }
    except Exception:
        pass

    # Calculate verdict
    risk = 0
    shodan = result["sources"].get("shodan",{})
    if shodan.get("vulns"): risk += len(shodan["vulns"]) * 10
    if shodan.get("tags") and any(t in ["malware","botnet","scanner"] for t in shodan.get("tags",[])):
        risk += 40
    abuse = result["sources"].get("abuseipdb",{})
    if abuse.get("score"): risk += int(abuse["score"] * 0.6)
    vt = result["sources"].get("virustotal",{})
    if vt.get("malicious"): risk += vt["malicious"] * 8
    result["risk_score"] = min(100, risk)
    result["verdict"] = (
        "MALICIOUS"  if result["risk_score"] >= 70 else
        "SUSPICIOUS" if result["risk_score"] >= 30 else
        "CLEAN"
    )
    return result


# ── Domain Reputation ─────────────────────────────────────────────────────────
def domain_reputation(domain: str, keys: dict = None) -> dict:
    keys   = keys or {}
    result = {"domain": domain, "timestamp": datetime.utcnow().isoformat(),
              "sources": {}, "verdict": "UNKNOWN", "risk_score": 0}
    if not REQ_OK:
        return {"error": "requests not installed"}

    # VirusTotal
    if keys.get("virustotal"):
        try:
            r = _req_get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                         headers={"x-apikey": keys["virustotal"]})
            if r.status_code == 200:
                d = r.json().get("data",{}).get("attributes",{})
                stats = d.get("last_analysis_stats",{})
                result["sources"]["virustotal"] = {
                    "malicious":     stats.get("malicious",0),
                    "suspicious":    stats.get("suspicious",0),
                    "categories":    d.get("categories",{}),
                    "reputation":    d.get("reputation"),
                    "creation_date": d.get("creation_date"),
                    "whois":         (d.get("whois") or "")[:500],
                }
        except Exception as e:
            result["sources"]["virustotal"] = {"error": str(e)}

    # URLVoid / HackerTarget
    try:
        r = _req_get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if r.status_code == 200:
            result["sources"]["dns"] = {"records": r.text[:800].splitlines()}
    except Exception as e:
        result["sources"]["dns"] = {"error": str(e)}

    # SSL cert check
    try:
        import ssl, socket as sck
        ctx  = ssl.create_default_context()
        with sck.create_connection((domain, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ss:
                cert = ss.getpeercert()
                result["ssl"] = {
                    "valid":      True,
                    "issuer":     dict(x[0] for x in cert.get("issuer",[])),
                    "not_after":  cert.get("notAfter"),
                    "subject":    dict(x[0] for x in cert.get("subject",[])),
                }
    except Exception as e:
        result["ssl"] = {"valid": False, "error": str(e)}

    # Phishing check via OpenPhish
    try:
        r = _req_get("https://openphish.com/feed.txt", timeout=6)
        if r.status_code == 200:
            lines = r.text.lower().splitlines()
            if any(domain.lower() in l for l in lines[:1000]):
                result["sources"]["openphish"] = {"phishing": True}
                result["risk_score"] += 80
    except Exception:
        pass

    # DNSBL check
    result["dnsbl"] = _check_dnsbl(domain)
    if result["dnsbl"].get("listed"):
        result["risk_score"] += 50

    vt = result["sources"].get("virustotal",{})
    if vt.get("malicious"): result["risk_score"] += vt["malicious"] * 8
    result["risk_score"] = min(100, result["risk_score"])
    result["verdict"] = (
        "MALICIOUS"  if result["risk_score"] >= 70 else
        "SUSPICIOUS" if result["risk_score"] >= 30 else
        "CLEAN"
    )
    return result


def _check_dnsbl(domain_or_ip: str) -> dict:
    dnsbls = ["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net","b.barracudacentral.org"]
    result = {"listed": False, "blacklists": []}
    for bl in dnsbls[:3]:
        try:
            query = f"{domain_or_ip}.{bl}"
            socket.gethostbyname(query)
            result["listed"] = True
            result["blacklists"].append(bl)
        except socket.gaierror:
            pass
        except Exception:
            pass
    return result


# ── IOC Lookup ────────────────────────────────────────────────────────────────
def ioc_lookup(ioc: str, ioc_type: str = "auto", keys: dict = None) -> dict:
    keys = keys or {}
    result = {"ioc": ioc, "type": ioc_type, "timestamp": datetime.utcnow().isoformat(),
              "results": [], "verdict": "UNKNOWN"}
    # Auto-detect type
    if ioc_type == "auto":
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ioc):
            ioc_type = "ip"
        elif re.match(r"^[a-f0-9]{32,64}$", ioc, re.I):
            ioc_type = "hash"
        elif re.match(r"https?://", ioc):
            ioc_type = "url"
        elif re.match(r"^[^@]+@[^@]+\.[^@]+$", ioc):
            ioc_type = "email"
        else:
            ioc_type = "domain"
        result["type"] = ioc_type

    if ioc_type == "ip":
        r2 = ip_reputation(ioc, keys)
        result["results"].append({"source": "IP Intelligence", "data": r2})
        result["verdict"] = r2.get("verdict","UNKNOWN")
    elif ioc_type == "domain":
        r2 = domain_reputation(ioc, keys)
        result["results"].append({"source": "Domain Intelligence", "data": r2})
        result["verdict"] = r2.get("verdict","UNKNOWN")
    elif ioc_type == "hash" and REQ_OK:
        if keys.get("virustotal"):
            try:
                from modules.malware_analysis import virustotal_lookup
                r2 = virustotal_lookup(ioc, keys["virustotal"])
                result["results"].append({"source": "VirusTotal", "data": r2})
                result["verdict"] = r2.get("verdict","UNKNOWN")
            except Exception as e:
                result["results"].append({"source":"VirusTotal","error":str(e)})
    elif ioc_type == "url":
        dom = re.sub(r"https?://([^/]+).*","\\1", ioc)
        r2  = domain_reputation(dom, keys)
        result["results"].append({"source":"Domain Check","data":r2})
        result["verdict"] = r2.get("verdict","UNKNOWN")
    elif ioc_type == "email":
        from modules.osint import email_breach_check
        r2 = email_breach_check(ioc, keys.get("hibp",""))
        result["results"].append({"source":"HIBP Breach Check","data":r2})
        result["verdict"] = "COMPROMISED" if r2.get("breach_count",0)>0 else "CLEAN"

    return result


# ── Threat Feed Aggregator ────────────────────────────────────────────────────
def threat_feed_check(indicator: str) -> dict:
    result = {"indicator": indicator, "timestamp": datetime.utcnow().isoformat(),
              "feeds": [], "overall_malicious": False}
    if not REQ_OK:
        return {"error": "requests not installed"}
    # URLhaus (malware URLs — no key needed)
    try:
        r = req.post("https://urlhaus-api.abuse.ch/v1/host/",
                     data={"host": indicator}, timeout=8)
        if r.status_code == 200:
            d = r.json()
            result["feeds"].append({
                "source": "URLhaus (abuse.ch)",
                "query_status": d.get("query_status"),
                "urls_found": len(d.get("urls",[])),
                "malware_urls": [u.get("url","") for u in d.get("urls",[])[:5]],
            })
            if d.get("query_status") == "is_host":
                result["overall_malicious"] = True
    except Exception as e:
        result["feeds"].append({"source":"URLhaus","error":str(e)})
    # ThreatFox (IOC DB — no key needed)
    try:
        r = req.post("https://threatfox-api.abuse.ch/api/v1/",
                     json={"query":"search_ioc","search_term":indicator}, timeout=8)
        if r.status_code == 200:
            d = r.json()
            iocs = d.get("data",[]) or []
            result["feeds"].append({
                "source": "ThreatFox (abuse.ch)",
                "found": len(iocs) > 0,
                "iocs": [{
                    "ioc_type":    i.get("ioc_type"),
                    "threat_type": i.get("threat_type"),
                    "malware":     i.get("malware"),
                    "confidence":  i.get("confidence_level"),
                } for i in iocs[:5]],
            })
            if iocs:
                result["overall_malicious"] = True
    except Exception as e:
        result["feeds"].append({"source":"ThreatFox","error":str(e)})
    # MalwareBazaar (hash check)
    if re.match(r"^[a-f0-9]{32,64}$", indicator, re.I):
        try:
            r = req.post("https://mb-api.abuse.ch/api/v1/",
                         data={"query":"get_info","hash":indicator}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                result["feeds"].append({
                    "source": "MalwareBazaar (abuse.ch)",
                    "found":  d.get("query_status") == "ok",
                    "data":   d.get("data",{}),
                })
                if d.get("query_status") == "ok":
                    result["overall_malicious"] = True
        except Exception as e:
            result["feeds"].append({"source":"MalwareBazaar","error":str(e)})
    result["verdict"] = "MALICIOUS" if result["overall_malicious"] else "NOT_FOUND"
    return result
