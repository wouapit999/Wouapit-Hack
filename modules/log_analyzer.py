"""Log & SIEM Analysis module — parse Apache/Nginx/Syslog, detect anomalies."""
import re, collections
from datetime import datetime

# ── Log format regexes ────────────────────────────────────────────────────────
APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?(?:\s+"(?P<ua>[^"]*)")?'
)
NGINX_RE  = APACHE_RE   # Same CLF format
SYSLOG_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+'
    r'(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)'
)
SSH_FAIL_RE    = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")
SSH_SUCCESS_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")
SUDO_RE        = re.compile(r"(\S+)\s*:\s*.*COMMAND=(.+)")


def detect_log_format(sample: str) -> str:
    if APACHE_RE.search(sample[:500]):
        return "apache/nginx"
    if SYSLOG_RE.search(sample[:500]):
        return "syslog"
    return "unknown"


def parse_apache_log(text: str) -> dict:
    entries, errors = [], 0
    for line in text.splitlines()[:5000]:
        m = APACHE_RE.match(line.strip())
        if m:
            entries.append({
                "ip":     m.group("ip"),
                "time":   m.group("time"),
                "method": m.group("method"),
                "path":   m.group("path"),
                "status": int(m.group("status")),
                "size":   m.group("size"),
                "ua":     (m.group("ua") or "")[:120],
            })
        else:
            errors += 1
    return {"entries": entries, "parse_errors": errors,
            "total_lines": len(text.splitlines()),
            "timestamp": datetime.utcnow().isoformat()}


def parse_syslog(text: str) -> dict:
    entries = []
    for line in text.splitlines()[:5000]:
        m = SYSLOG_RE.match(line.strip())
        if m:
            entries.append({
                "host":    m.group("host"),
                "process": m.group("process").strip(),
                "pid":     m.group("pid"),
                "message": m.group("message")[:300],
                "time":    f"{m.group('month')} {m.group('day')} {m.group('time')}",
            })
    return {"entries": entries, "total": len(entries),
            "timestamp": datetime.utcnow().isoformat()}


# ── Anomaly detection ─────────────────────────────────────────────────────────
def detect_anomalies(log_text: str, log_type: str = "auto") -> dict:
    result = {
        "anomalies":    [],
        "statistics":   {},
        "top_ips":      [],
        "top_paths":    [],
        "error_codes":  {},
        "timestamp":    datetime.utcnow().isoformat(),
    }
    if log_type == "auto":
        log_type = detect_log_format(log_text)

    if log_type in ("apache/nginx","auto"):
        parsed = parse_apache_log(log_text)
        entries = parsed["entries"]
        _analyze_web_logs(entries, result)
    else:
        parsed = parse_syslog(log_text)
        entries = parsed["entries"]
        _analyze_syslog(entries, result)
    return result


def _analyze_web_logs(entries: list, result: dict):
    ip_counts     = collections.Counter(e["ip"] for e in entries)
    path_counts   = collections.Counter(e["path"] for e in entries)
    status_counts = collections.Counter(str(e["status"]) for e in entries)
    ua_counts     = collections.Counter(e.get("ua","") for e in entries)

    result["statistics"] = {
        "total_requests":  len(entries),
        "unique_ips":      len(ip_counts),
        "unique_paths":    len(path_counts),
        "4xx_errors":      sum(v for k, v in status_counts.items() if k.startswith("4")),
        "5xx_errors":      sum(v for k, v in status_counts.items() if k.startswith("5")),
    }
    result["top_ips"]   = [{"ip":k,"count":v} for k,v in ip_counts.most_common(10)]
    result["top_paths"] = [{"path":k,"count":v} for k,v in path_counts.most_common(10)]
    result["error_codes"] = dict(status_counts.most_common(10))

    # Anomaly: high request rate per IP
    RATE_THRESHOLD = 100
    for ip, count in ip_counts.most_common(5):
        if count > RATE_THRESHOLD:
            result["anomalies"].append({
                "type": "High Request Rate",
                "severity": "HIGH",
                "ip": ip,
                "count": count,
                "message": f"{ip} made {count} requests — possible DoS/scan",
            })

    # Brute force detection (many 401/403 from same IP)
    ip_auth_fails = collections.Counter(
        e["ip"] for e in entries if e["status"] in (401, 403)
    )
    for ip, count in ip_auth_fails.most_common(5):
        if count > 20:
            result["anomalies"].append({
                "type": "Brute Force Attempt",
                "severity": "CRITICAL",
                "ip": ip,
                "count": count,
                "message": f"{ip} had {count} auth failures (401/403) — brute force suspected",
            })

    # Path traversal attempts
    traversal_ips = set()
    for e in entries:
        if any(p in e["path"] for p in ["../","..%2F","..%5C","%2e%2e"]):
            traversal_ips.add(e["ip"])
    if traversal_ips:
        result["anomalies"].append({
            "type": "Path Traversal Attempt",
            "severity": "HIGH",
            "ips": list(traversal_ips),
            "message": f"Path traversal patterns detected from {len(traversal_ips)} IP(s)",
        })

    # SQL injection in URLs
    sqli_patterns = ["' OR","1=1","UNION SELECT","DROP TABLE","--","xp_cmdshell"]
    sqli_ips = set()
    for e in entries:
        if any(p.lower() in e["path"].lower() for p in sqli_patterns):
            sqli_ips.add(e["ip"])
    if sqli_ips:
        result["anomalies"].append({
            "type": "SQL Injection in URL",
            "severity": "CRITICAL",
            "ips": list(sqli_ips),
            "message": f"SQL injection patterns in URLs from {len(sqli_ips)} IP(s)",
        })

    # Scanner detection via User-Agent
    scanner_uas = ["nikto","sqlmap","nmap","masscan","dirbuster","gobuster",
                   "burpsuite","nessus","openvas","qualys","acunetix","metasploit"]
    scanner_hits = []
    for e in entries:
        ua_lower = e.get("ua","").lower()
        for scanner in scanner_uas:
            if scanner in ua_lower:
                scanner_hits.append({"ip": e["ip"], "scanner": scanner, "ua": e["ua"][:80]})
    if scanner_hits:
        result["anomalies"].append({
            "type": "Security Scanner Detected",
            "severity": "HIGH",
            "scanners": scanner_hits[:10],
            "message": f"Security scanner user-agents detected ({len(scanner_hits)} requests)",
        })

    # Admin path access
    admin_patterns = ["/admin","/wp-admin","/phpmyadmin","/.env","/.git","/config"]
    admin_hits = [e for e in entries if any(p in e["path"].lower() for p in admin_patterns)]
    if admin_hits:
        admin_ips = set(e["ip"] for e in admin_hits)
        result["anomalies"].append({
            "type": "Admin/Sensitive Path Access",
            "severity": "MEDIUM",
            "ips": list(admin_ips),
            "paths": list({e["path"] for e in admin_hits})[:10],
            "message": f"Sensitive paths accessed by {len(admin_ips)} unique IP(s)",
        })

    # 5xx spike
    e5xx = sum(v for k, v in status_counts.items() if k.startswith("5"))
    total = result["statistics"]["total_requests"]
    if total > 0 and e5xx / total > 0.1:
        result["anomalies"].append({
            "type": "High 5xx Error Rate",
            "severity": "MEDIUM",
            "rate": f"{e5xx}/{total} ({e5xx/total*100:.1f}%)",
            "message": "Server error rate >10% — possible misconfiguration or attack",
        })


def _analyze_syslog(entries: list, result: dict):
    # SSH brute force
    ssh_fails = collections.Counter()
    ssh_ok    = []
    sudo_cmds = []
    for e in entries:
        msg = e.get("message","")
        m_fail = SSH_FAIL_RE.search(msg)
        if m_fail:
            ssh_fails[m_fail.group(2)] += 1   # count by source IP
        m_ok = SSH_SUCCESS_RE.search(msg)
        if m_ok:
            ssh_ok.append({"user": m_ok.group(1), "ip": m_ok.group(2)})
        m_sudo = SUDO_RE.search(msg)
        if m_sudo and "COMMAND" in msg:
            sudo_cmds.append({"user": m_sudo.group(1).split()[-1], "cmd": m_sudo.group(2)[:100]})

    result["statistics"] = {
        "total_events":   len(entries),
        "ssh_failures":   sum(ssh_fails.values()),
        "ssh_successes":  len(ssh_ok),
        "sudo_commands":  len(sudo_cmds),
    }
    result["top_ips"] = [{"ip":k,"failures":v} for k,v in ssh_fails.most_common(10)]

    for ip, count in ssh_fails.most_common(5):
        if count > 10:
            result["anomalies"].append({
                "type":     "SSH Brute Force",
                "severity": "CRITICAL",
                "ip":       ip,
                "count":    count,
                "message":  f"{ip} had {count} SSH login failures — brute force suspected",
            })
    if ssh_ok:
        result["anomalies"].append({
            "type":     "Successful SSH Logins",
            "severity": "INFO",
            "logins":   ssh_ok[:10],
            "message":  f"{len(ssh_ok)} successful SSH login(s) recorded",
        })
    # Suspicious sudo commands
    dangerous = ["chmod 777","rm -rf","nc ","bash -i","python -c","wget ","curl ","base64"]
    for sc in sudo_cmds:
        if any(d in sc.get("cmd","") for d in dangerous):
            result["anomalies"].append({
                "type":     "Suspicious sudo Command",
                "severity": "HIGH",
                "user":     sc.get("user"),
                "cmd":      sc.get("cmd"),
                "message":  f"User {sc.get('user')} ran suspicious sudo command",
            })


# ── Threat intel IP enrichment from log ─────────────────────────────────────
def enrich_ips_from_log(log_text: str, top_n: int = 10) -> dict:
    result = {"enriched": [], "timestamp": datetime.utcnow().isoformat()}
    parsed  = parse_apache_log(log_text)
    counter = collections.Counter(e["ip"] for e in parsed["entries"])
    top_ips = [ip for ip, _ in counter.most_common(top_n)]
    try:
        import requests as req
        for ip in top_ips:
            try:
                r = req.get(f"https://ipinfo.io/{ip}/json", timeout=5)
                if r.status_code == 200:
                    d = r.json()
                    result["enriched"].append({
                        "ip":       ip,
                        "count":    counter[ip],
                        "country":  d.get("country"),
                        "city":     d.get("city"),
                        "org":      d.get("org"),
                        "hostname": d.get("hostname"),
                    })
            except Exception:
                result["enriched"].append({"ip": ip, "count": counter[ip], "error": "lookup failed"})
    except ImportError:
        result["error"] = "requests not installed"
    return result
