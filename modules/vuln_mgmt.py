"""Vulnerability Management module — import scanner results, correlate CVEs, suggest exploits."""
import re, json, hashlib, socket
from datetime import datetime

try:
    import defusedxml.ElementTree as ET
    XML_OK = True
except ImportError:
    try:
        import xml.etree.ElementTree as ET
        XML_OK = True
    except Exception:
        XML_OK = False

try:
    import requests as req
    REQ_OK = True
except ImportError:
    REQ_OK = False

CVSS_SEVERITY = {
    (9.0, 10.0): "CRITICAL",
    (7.0, 8.9):  "HIGH",
    (4.0, 6.9):  "MEDIUM",
    (0.1, 3.9):  "LOW",
    (0.0, 0.0):  "INFO",
}

def _cvss_to_severity(score: float) -> str:
    for (lo, hi), sev in CVSS_SEVERITY.items():
        if lo <= score <= hi:
            return sev
    return "INFO"


# ── Nmap XML parser ──────────────────────────────────────────────────────────
def parse_nmap_xml(xml_text: str) -> dict:
    result = {"hosts": [], "total_hosts": 0, "open_ports": 0,
              "services": [], "timestamp": datetime.utcnow().isoformat()}
    if not XML_OK:
        return {"error": "XML parsing library not available"}
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall(".//host"):
            addr_el  = host.find("address")
            ip       = addr_el.get("addr","?") if addr_el is not None else "?"
            status   = host.find("status")
            state    = status.get("state","?") if status is not None else "?"
            host_info = {"ip": ip, "state": state, "ports": [], "os": "", "hostnames": []}

            for hn in host.findall(".//hostname"):
                host_info["hostnames"].append(hn.get("name",""))

            os_el = host.find(".//osmatch")
            if os_el is not None:
                host_info["os"] = os_el.get("name","")

            for port in host.findall(".//port"):
                port_id   = port.get("portid","?")
                protocol  = port.get("protocol","tcp")
                state_el  = port.find("state")
                p_state   = state_el.get("state","?") if state_el is not None else "?"
                svc_el    = port.find("service")
                service   = svc_el.get("name","") if svc_el is not None else ""
                product   = svc_el.get("product","") if svc_el is not None else ""
                version   = svc_el.get("version","") if svc_el is not None else ""
                scripts   = []
                for script in port.findall("script"):
                    scripts.append({"id": script.get("id",""), "output": script.get("output","")[:200]})
                port_entry = {
                    "port": port_id, "protocol": protocol, "state": p_state,
                    "service": service, "product": product, "version": version,
                    "scripts": scripts,
                }
                host_info["ports"].append(port_entry)
                if p_state == "open":
                    result["open_ports"] += 1
                    svc_str = f"{service} {product} {version}".strip()
                    if svc_str and svc_str not in result["services"]:
                        result["services"].append(svc_str)
            result["hosts"].append(host_info)
        result["total_hosts"] = len(result["hosts"])
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Nikto CSV/text parser ────────────────────────────────────────────────────
def parse_nikto_output(text: str) -> dict:
    result = {"findings": [], "target": "", "timestamp": datetime.utcnow().isoformat()}
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("+ Target IP:") or line.startswith("- Target IP:"):
            result["target"] = line.split(":", 1)[-1].strip()
        if line.startswith("+ ") or line.startswith("- "):
            content = line[2:].strip()
            if not content or content.startswith("Target") or content.startswith("Start"):
                continue
            sev = "MEDIUM"
            if any(k in content.lower() for k in ["critical","remote code","rce","sql injection"]):
                sev = "CRITICAL"
            elif any(k in content.lower() for k in ["xss","injection","traversal","disclosure"]):
                sev = "HIGH"
            elif any(k in content.lower() for k in ["header","cookie","info","version"]):
                sev = "LOW"
            result["findings"].append({"description": content, "severity": sev,
                                       "cvss": {"CRITICAL":9.8,"HIGH":7.5,"MEDIUM":5.3,"LOW":2.0}[sev]})
    result["total"] = len(result["findings"])
    return result


# ── OpenVAS / Nessus XML ─────────────────────────────────────────────────────
def parse_openvas_xml(xml_text: str) -> dict:
    result = {"vulnerabilities": [], "hosts": [], "timestamp": datetime.utcnow().isoformat()}
    if not XML_OK:
        return {"error": "XML library not available"}
    try:
        root = ET.fromstring(xml_text)
        # OpenVAS format
        for result_el in root.findall(".//result"):
            host_el = result_el.find("host")
            host    = host_el.text if host_el is not None else "?"
            name_el = result_el.find("name")
            name    = name_el.text if name_el is not None else "Unknown"
            sev_el  = result_el.find("severity")
            try:
                sev_score = float(sev_el.text) if sev_el is not None else 0.0
            except Exception:
                sev_score = 0.0
            desc_el = result_el.find("description")
            desc    = desc_el.text if desc_el is not None else ""
            nvt_el  = result_el.find("nvt")
            cve_list = []
            if nvt_el is not None:
                for ref in nvt_el.findall(".//ref"):
                    if ref.get("type","") == "cve":
                        cve_list.append(ref.get("id",""))
            entry = {
                "host": host, "name": name, "severity_score": sev_score,
                "severity": _cvss_to_severity(sev_score),
                "description": (desc or "")[:500], "cves": cve_list,
            }
            result["vulnerabilities"].append(entry)
            if host not in result["hosts"]:
                result["hosts"].append(host)
    except Exception as e:
        # Try Nessus format
        try:
            root2 = ET.fromstring(xml_text)
            for report_host in root2.findall(".//ReportHost"):
                host = report_host.get("name","?")
                if host not in result["hosts"]:
                    result["hosts"].append(host)
                for item in report_host.findall(".//ReportItem"):
                    score = float(item.get("severity","0"))
                    cvss_str = item.get("cvss3_base_score", item.get("cvss_base_score","0"))
                    try:
                        cvss = float(cvss_str)
                    except Exception:
                        cvss = score * 2.5
                    cve_el = item.find("cve")
                    cve_id = cve_el.text if cve_el is not None else ""
                    result["vulnerabilities"].append({
                        "host": host,
                        "name": item.get("pluginName",""),
                        "severity_score": cvss,
                        "severity": _cvss_to_severity(cvss),
                        "description": (item.findtext("description") or "")[:500],
                        "cves": [cve_id] if cve_id else [],
                        "port": item.get("port",""),
                        "plugin_id": item.get("pluginID",""),
                    })
        except Exception as e2:
            result["error"] = f"Parse error: {e} / {e2}"
    result["total"] = len(result["vulnerabilities"])
    return result


# ── CVE correlation via NVD ──────────────────────────────────────────────────
def correlate_cves(cve_list: list) -> dict:
    result = {"cves": [], "timestamp": datetime.utcnow().isoformat()}
    if not REQ_OK:
        return {"error": "requests not installed"}
    for cve_id in cve_list[:10]:
        cve_id = cve_id.upper().strip()
        if not re.match(r"CVE-\d{4}-\d+", cve_id):
            continue
        try:
            r = req.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=8)
            if r.status_code == 200:
                data = r.json()
                cna  = data.get("containers", {}).get("cna", {})
                desc = cna.get("descriptions", [{}])[0].get("value","")[:400]
                metrics = cna.get("metrics", [])
                score = ""
                for m in metrics:
                    for k, v in m.items():
                        if "cvss" in k.lower():
                            score = str(v.get("baseScore",""))
                            break
                result["cves"].append({
                    "id": cve_id, "description": desc, "cvss_score": score,
                    "severity": _cvss_to_severity(float(score) if score else 0),
                })
        except Exception as e:
            result["cves"].append({"id": cve_id, "error": str(e)})
    return result


# ── Exploit suggestions ──────────────────────────────────────────────────────
def suggest_exploits(query: str) -> dict:
    result = {"query": query, "exploits": [], "timestamp": datetime.utcnow().isoformat()}
    if not REQ_OK:
        return {"error": "requests not installed"}
    try:
        # Search Exploit-DB via their search API
        r = req.get(
            "https://www.exploit-db.com/search",
            params={"q": query, "type": "exploits", "platform": ""},
            headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            for item in (data.get("data") or [])[:10]:
                result["exploits"].append({
                    "id":          item.get("id",""),
                    "title":       item.get("description",""),
                    "type":        item.get("type",""),
                    "platform":    item.get("platform",""),
                    "author":      item.get("author", {}).get("name","") if isinstance(item.get("author"),dict) else "",
                    "date":        item.get("date_published",""),
                    "url":         f"https://www.exploit-db.com/exploits/{item.get('id','')}",
                    "cve":         item.get("codes",""),
                })
    except Exception as e:
        result["note"] = f"Exploit-DB direct search: {e}. Use https://www.exploit-db.com/search?q={query}"
    # Also suggest Metasploit module names (curated common ones)
    msf = _metasploit_suggestions(query)
    if msf:
        result["metasploit_modules"] = msf
    return result


_MSF_MAP = {
    "apache":     ["exploit/multi/http/apache_mod_cgi_bash_env_exec",
                   "exploit/unix/webapp/apache_activemq_upload_jsp"],
    "tomcat":     ["exploit/multi/http/tomcat_mgr_upload",
                   "exploit/multi/http/tomcat_jsp_upload_bypass"],
    "iis":        ["exploit/windows/iis/iis_webdav_upload_asp",
                   "exploit/windows/iis/ms03_007_ntdll_webdav"],
    "samba":      ["exploit/multi/samba/usermap_script",
                   "exploit/linux/samba/is_known_pipename"],
    "ssh":        ["auxiliary/scanner/ssh/ssh_login",
                   "auxiliary/scanner/ssh/ssh_version"],
    "ftp":        ["auxiliary/scanner/ftp/anonymous",
                   "exploit/unix/ftp/vsftpd_234_backdoor"],
    "mysql":      ["auxiliary/scanner/mysql/mysql_login",
                   "exploit/multi/mysql/mysql_udf_payload"],
    "mssql":      ["auxiliary/scanner/mssql/mssql_login",
                   "exploit/windows/mssql/mssql_payload"],
    "rdp":        ["auxiliary/scanner/rdp/rdp_scanner",
                   "exploit/windows/rdp/cve_2019_0708_bluekeep"],
    "smb":        ["exploit/windows/smb/ms17_010_eternalblue",
                   "auxiliary/scanner/smb/smb_ms17_010"],
    "wordpress":  ["exploit/unix/webapp/wp_admin_shell_upload",
                   "auxiliary/scanner/http/wordpress_login_enum"],
    "drupal":     ["exploit/unix/webapp/drupal_drupalgeddon2",
                   "exploit/unix/webapp/drupal_restws_exec"],
    "struts":     ["exploit/multi/http/struts2_content_type_ognl",
                   "exploit/multi/http/struts_code_exec_classloader"],
    "log4j":      ["exploit/multi/http/log4shell_header_injection"],
    "shellshock": ["exploit/multi/http/apache_mod_cgi_bash_env_exec"],
    "heartbleed": ["auxiliary/scanner/ssl/openssl_heartbleed"],
}

def _metasploit_suggestions(query: str) -> list:
    q = query.lower()
    suggestions = []
    for keyword, modules in _MSF_MAP.items():
        if keyword in q:
            suggestions.extend([{"module": m, "source": "Metasploit Framework"} for m in modules])
    return suggestions[:5]


# ── Vulnerability dashboard aggregator ──────────────────────────────────────
def build_vuln_dashboard(vulns: list) -> dict:
    counts   = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    affected = set()
    cves     = set()
    top_vulns = []
    for v in vulns:
        sev = v.get("severity","INFO").upper()
        if sev in counts:
            counts[sev] += 1
        if v.get("host"):
            affected.add(v["host"])
        for cve in v.get("cves",[]):
            cves.add(cve)
        if sev in ("CRITICAL","HIGH"):
            top_vulns.append(v)
    top_vulns.sort(key=lambda x: x.get("severity_score",0), reverse=True)
    return {
        "summary":       counts,
        "total":         sum(counts.values()),
        "affected_hosts":list(affected),
        "unique_cves":   list(cves)[:20],
        "top_critical":  top_vulns[:10],
        "risk_score":    _risk_score(counts),
    }


def _risk_score(counts: dict) -> int:
    weights = {"CRITICAL":10,"HIGH":7,"MEDIUM":4,"LOW":1,"INFO":0}
    raw = sum(weights[s]*c for s, c in counts.items())
    return min(100, raw)
