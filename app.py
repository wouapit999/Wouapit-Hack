from flask import Flask, render_template, request, jsonify, send_file
import os, base64

app = Flask(__name__)
app.secret_key = os.urandom(24)
# Vercel's filesystem is read-only except /tmp
REPORTS_DIR = "/tmp/wouapit-reports" if os.environ.get("VERCEL") else os.path.join(os.path.dirname(__file__), "reports")

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/autoscan")
def autoscan():
    return render_template("autoscan.html")

@app.route("/recon")
def recon():
    return render_template("recon.html")

@app.route("/web-scanner")
def web_scanner():
    return render_template("web_scanner.html")

@app.route("/network")
def network():
    return render_template("network.html")

@app.route("/passwords")
def passwords():
    return render_template("passwords.html")

@app.route("/exploits")
def exploits():
    return render_template("exploits.html")

@app.route("/reports")
def reports():
    files = []
    if os.path.exists(REPORTS_DIR):
        files = [f for f in os.listdir(REPORTS_DIR) if f.endswith((".html", ".pdf", ".txt"))]
    return render_template("reports.html", report_files=files)

# ── API Endpoints ────────────────────────────────────────────────────────────

@app.route("/api/recon/dns", methods=["POST"])
def api_dns():
    from modules.recon import dns_lookup
    data = request.json
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    return jsonify(dns_lookup(target))

@app.route("/api/recon/whois", methods=["POST"])
def api_whois():
    from modules.recon import whois_lookup
    data = request.json
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    return jsonify(whois_lookup(target))

@app.route("/api/recon/portscan", methods=["POST"])
def api_portscan():
    from modules.recon import port_scan
    data = request.json
    target = data.get("target", "").strip()
    ports  = data.get("ports", "1-1024")
    if not target:
        return jsonify({"error": "No target provided"}), 400
    return jsonify(port_scan(target, ports))

@app.route("/api/recon/subdomain", methods=["POST"])
def api_subdomain():
    from modules.recon import subdomain_enum
    data = request.json
    domain = data.get("target", "").strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    return jsonify(subdomain_enum(domain))

@app.route("/api/recon/headers", methods=["POST"])
def api_headers():
    from modules.recon import get_headers
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(get_headers(url))

@app.route("/api/web/dirbrute", methods=["POST"])
def api_dirbrute():
    from modules.web_scanner import dir_bruteforce
    data = request.json
    url  = data.get("target", "").strip()
    wl   = data.get("wordlist", "common")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(dir_bruteforce(url, wl))

@app.route("/api/web/sqli", methods=["POST"])
def api_sqli():
    from modules.web_scanner import sqli_test
    data = request.json
    url  = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(sqli_test(url))

@app.route("/api/web/xss", methods=["POST"])
def api_xss():
    from modules.web_scanner import xss_test
    data = request.json
    url  = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(xss_test(url))

@app.route("/api/web/ssl", methods=["POST"])
def api_ssl():
    from modules.web_scanner import ssl_check
    data = request.json
    host = data.get("target", "").strip()
    if not host:
        return jsonify({"error": "No host provided"}), 400
    return jsonify(ssl_check(host))

@app.route("/api/web/techdetect", methods=["POST"])
def api_techdetect():
    from modules.web_scanner import tech_detect
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(tech_detect(url))

@app.route("/api/web/cors", methods=["POST"])
def api_cors():
    from modules.web_scanner import cors_check
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(cors_check(url))

@app.route("/api/web/redirect", methods=["POST"])
def api_redirect():
    from modules.web_scanner import open_redirect_test
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(open_redirect_test(url))

@app.route("/api/web/clickjacking", methods=["POST"])
def api_clickjacking():
    from modules.web_scanner import clickjacking_test
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(clickjacking_test(url))

@app.route("/api/web/httpmethods", methods=["POST"])
def api_httpmethods():
    from modules.web_scanner import http_methods_test
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(http_methods_test(url))

@app.route("/api/web/lfi", methods=["POST"])
def api_lfi():
    from modules.web_scanner import lfi_test
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(lfi_test(url))

@app.route("/api/web/cmdinject", methods=["POST"])
def api_cmdinject():
    from modules.web_scanner import cmd_injection_test
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(cmd_injection_test(url))

@app.route("/api/web/ssti", methods=["POST"])
def api_ssti():
    from modules.web_scanner import ssti_test
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(ssti_test(url))

@app.route("/api/web/ssrf", methods=["POST"])
def api_ssrf():
    from modules.web_scanner import ssrf_test
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(ssrf_test(url))

@app.route("/api/web/cookies", methods=["POST"])
def api_cookies():
    from modules.web_scanner import cookie_analyzer
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(cookie_analyzer(url))

@app.route("/api/web/csrf", methods=["POST"])
def api_csrf():
    from modules.web_scanner import csrf_check
    data = request.json
    url = data.get("target", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(csrf_check(url))

@app.route("/api/network/ping", methods=["POST"])
def api_ping():
    from modules.network import ping_sweep
    data = request.json
    cidr = data.get("target", "").strip()
    if not cidr:
        return jsonify({"error": "No CIDR/host provided"}), 400
    return jsonify(ping_sweep(cidr))

@app.route("/api/network/traceroute", methods=["POST"])
def api_traceroute():
    from modules.network import traceroute
    data = request.json
    host = data.get("target", "").strip()
    if not host:
        return jsonify({"error": "No host provided"}), 400
    return jsonify(traceroute(host))

@app.route("/api/network/banner", methods=["POST"])
def api_banner():
    from modules.network import banner_grab
    data = request.json
    host = data.get("target", "").strip()
    port = int(data.get("port", 80))
    if not host:
        return jsonify({"error": "No host provided"}), 400
    return jsonify(banner_grab(host, port))

@app.route("/api/passwords/identify", methods=["POST"])
def api_hash_id():
    from modules.password_tools import identify_hash
    data = request.json
    h = data.get("hash", "").strip()
    if not h:
        return jsonify({"error": "No hash provided"}), 400
    return jsonify(identify_hash(h))

@app.route("/api/passwords/crack", methods=["POST"])
def api_hash_crack():
    from modules.password_tools import crack_hash
    data = request.json
    h    = data.get("hash", "").strip()
    mode = data.get("hashtype", "md5")
    if not h:
        return jsonify({"error": "No hash provided"}), 400
    return jsonify(crack_hash(h, mode))

@app.route("/api/passwords/generate", methods=["POST"])
def api_passgen():
    from modules.password_tools import generate_password
    data = request.json
    length  = int(data.get("length", 16))
    options = data.get("options", {})
    return jsonify(generate_password(length, options))

@app.route("/api/passwords/encode", methods=["POST"])
def api_encode():
    from modules.password_tools import encode_decode
    data = request.json
    text   = data.get("text", "")
    method = data.get("method", "base64")
    action = data.get("action", "encode")
    return jsonify(encode_decode(text, method, action))

@app.route("/api/exploits/cve", methods=["POST"])
def api_cve():
    from modules.exploits import cve_lookup
    data = request.json
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"error": "No query provided"}), 400
    return jsonify(cve_lookup(query))

@app.route("/api/exploits/payload", methods=["POST"])
def api_payload():
    from modules.exploits import generate_payload
    data    = request.json
    ptype   = data.get("type", "reverse_shell")
    options = data.get("options", {})
    return jsonify(generate_payload(ptype, options))

@app.route("/api/reports/generate", methods=["POST"])
def api_report_gen():
    from modules.reporter import generate_report
    data = request.json
    return jsonify(generate_report(data, REPORTS_DIR))

@app.route("/api/reports/generate-pdf", methods=["POST"])
def api_report_pdf():
    from modules.pdf_reporter import generate_pdf_report
    data = request.json
    return jsonify(generate_pdf_report(data, REPORTS_DIR))

@app.route("/api/reports/generate-remediation", methods=["POST"])
def api_remediation_pdf():
    from modules.pdf_reporter import generate_remediation_pdf
    data = request.json
    return jsonify(generate_remediation_pdf(data, REPORTS_DIR))

@app.route("/api/reports/generate-docx", methods=["POST"])
def api_report_docx():
    from modules.docx_reporter import generate_docx_report
    data = request.json
    return jsonify(generate_docx_report(data, REPORTS_DIR))

@app.route("/api/reports/generate-remediation-docx", methods=["POST"])
def api_remediation_docx():
    from modules.docx_reporter import generate_remediation_docx
    data = request.json
    return jsonify(generate_remediation_docx(data, REPORTS_DIR))

@app.route("/api/reports/download/<filename>")
def api_report_download(filename):
    path = os.path.join(REPORTS_DIR, os.path.basename(filename))
    if os.path.exists(path):
        ext  = os.path.splitext(filename)[1].lower()
        mime = {"pdf":"application/pdf", ".docx":"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".html":"text/html"}.get(ext, "application/octet-stream")
        return send_file(path, as_attachment=True, mimetype=mime)
    return jsonify({"error": "File not found"}), 404

# ═══════════════════════════════════════════════════════════════════════════════
# NEW MODULE PAGES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/vuln-management")
def vuln_management():
    return render_template("vuln_management.html")

@app.route("/osint")
def osint_page():
    return render_template("osint.html")

@app.route("/malware")
def malware_page():
    return render_template("malware.html")

@app.route("/wireless")
def wireless_page():
    return render_template("wireless.html")

@app.route("/cloud-security")
def cloud_security_page():
    return render_template("cloud_security.html")

@app.route("/api-security")
def api_security_page():
    return render_template("api_security.html")

@app.route("/mobile-security")
def mobile_security_page():
    return render_template("mobile_security.html")

@app.route("/log-analyzer")
def log_analyzer_page():
    return render_template("log_analyzer.html")

@app.route("/threat-intel")
def threat_intel_page():
    return render_template("threat_intel.html")

@app.route("/telecom-security")
def telecom_security_page():
    return render_template("telecom_security.html")

@app.route("/appstore-pentest")
def appstore_pentest_page():
    return render_template("appstore_pentest.html")

# ─── Vulnerability Management APIs ──────────────────────────────────────────

@app.route("/api/vuln/import-nmap", methods=["POST"])
def api_import_nmap():
    from modules.vuln_mgmt import parse_nmap_xml
    xml = request.json.get("xml","")
    return jsonify(parse_nmap_xml(xml))

@app.route("/api/vuln/import-nikto", methods=["POST"])
def api_import_nikto():
    from modules.vuln_mgmt import parse_nikto_output
    text = request.json.get("text","")
    return jsonify(parse_nikto_output(text))

@app.route("/api/vuln/import-openvas", methods=["POST"])
def api_import_openvas():
    from modules.vuln_mgmt import parse_openvas_xml
    xml = request.json.get("xml","")
    return jsonify(parse_openvas_xml(xml))

@app.route("/api/vuln/correlate-cves", methods=["POST"])
def api_correlate_cves():
    from modules.vuln_mgmt import correlate_cves
    cves = request.json.get("cves",[])
    return jsonify(correlate_cves(cves))

@app.route("/api/vuln/suggest-exploits", methods=["POST"])
def api_suggest_exploits():
    from modules.vuln_mgmt import suggest_exploits
    query = request.json.get("query","")
    return jsonify(suggest_exploits(query))

@app.route("/api/vuln/dashboard", methods=["POST"])
def api_vuln_dashboard():
    from modules.vuln_mgmt import build_vuln_dashboard
    vulns = request.json.get("vulnerabilities",[])
    return jsonify(build_vuln_dashboard(vulns))

# ─── OSINT APIs ──────────────────────────────────────────────────────────────

@app.route("/api/osint/email-breach", methods=["POST"])
def api_email_breach():
    from modules.osint import email_breach_check
    data = request.json
    return jsonify(email_breach_check(data.get("email",""), data.get("api_key","")))

@app.route("/api/osint/password-pwned", methods=["POST"])
def api_password_pwned():
    from modules.osint import password_pwned_check
    return jsonify(password_pwned_check(request.json.get("password","")))

@app.route("/api/osint/github", methods=["POST"])
def api_github_footprint():
    from modules.osint import github_footprint
    return jsonify(github_footprint(request.json.get("username","")))

@app.route("/api/osint/dns-history", methods=["POST"])
def api_dns_history():
    from modules.osint import dns_history
    return jsonify(dns_history(request.json.get("domain","")))

@app.route("/api/osint/metadata", methods=["POST"])
def api_metadata():
    from modules.osint import extract_metadata
    data     = request.json
    filename = data.get("filename","file.bin")
    b64_data = data.get("data","")
    try:
        file_bytes = base64.b64decode(b64_data)
    except Exception:
        return jsonify({"error":"Invalid base64 data"}), 400
    return jsonify(extract_metadata(file_bytes, filename))

@app.route("/api/osint/dark-web", methods=["POST"])
def api_dark_web():
    from modules.osint import dark_web_exposure
    return jsonify(dark_web_exposure(request.json.get("query","")))

# ─── Malware Analysis APIs ───────────────────────────────────────────────────

@app.route("/api/malware/analyze", methods=["POST"])
def api_malware_analyze():
    from modules.malware_analysis import hash_file, extract_strings, analyze_pe, yara_scan, sandbox_summary
    data     = request.json
    filename = data.get("filename","sample.bin")
    b64_data = data.get("data","")
    try:
        file_bytes = base64.b64decode(b64_data)
    except Exception:
        return jsonify({"error":"Invalid base64 data"}), 400
    return jsonify({
        "hashes":   hash_file(file_bytes),
        "strings":  extract_strings(file_bytes),
        "pe":       analyze_pe(file_bytes),
        "yara":     yara_scan(file_bytes),
        "sandbox":  sandbox_summary(file_bytes, filename),
    })

@app.route("/api/malware/virustotal", methods=["POST"])
def api_malware_vt():
    from modules.malware_analysis import virustotal_lookup
    data = request.json
    return jsonify(virustotal_lookup(data.get("hash",""), data.get("api_key","")))

# ─── Wireless APIs ───────────────────────────────────────────────────────────

@app.route("/api/wireless/scan", methods=["POST"])
def api_wifi_scan():
    from modules.wireless import wifi_scan_simulation
    iface = request.json.get("interface","wlan0")
    return jsonify(wifi_scan_simulation(iface))

@app.route("/api/wireless/analyze-handshake", methods=["POST"])
def api_handshake():
    from modules.wireless import analyze_handshake_file
    data = request.json
    b64  = data.get("data","")
    try:
        file_bytes = base64.b64decode(b64)
    except Exception:
        return jsonify({"error":"Invalid base64"}), 400
    return jsonify(analyze_handshake_file(file_bytes, data.get("filename","capture.cap")))

@app.route("/api/wireless/crack", methods=["POST"])
def api_wifi_crack():
    from modules.wireless import crack_wpa_hash
    data = request.json
    return jsonify(crack_wpa_hash(data.get("hash",""), data.get("ssid",""), data.get("wordlist","")))

@app.route("/api/wireless/rogue-ap", methods=["POST"])
def api_rogue_ap():
    from modules.wireless import detect_rogue_ap
    data = request.json
    return jsonify(detect_rogue_ap(data.get("known",[]), data.get("scanned",None)))

# ─── Cloud Security APIs ─────────────────────────────────────────────────────

@app.route("/api/cloud/dockerfile", methods=["POST"])
def api_dockerfile():
    from modules.cloud_security import scan_dockerfile
    return jsonify(scan_dockerfile(request.json.get("content","")))

@app.route("/api/cloud/env-file", methods=["POST"])
def api_env_file():
    from modules.cloud_security import scan_env_file
    return jsonify(scan_env_file(request.json.get("content","")))

@app.route("/api/cloud/aws", methods=["POST"])
def api_aws():
    from modules.cloud_security import scan_aws_config
    return jsonify(scan_aws_config(request.json.get("content","")))

@app.route("/api/cloud/azure", methods=["POST"])
def api_azure():
    from modules.cloud_security import scan_azure_config
    return jsonify(scan_azure_config(request.json.get("content","")))

@app.route("/api/cloud/gcp", methods=["POST"])
def api_gcp():
    from modules.cloud_security import scan_gcp_config
    return jsonify(scan_gcp_config(request.json.get("content","")))

# ─── API Security APIs ───────────────────────────────────────────────────────

@app.route("/api/apisec/jwt-analyze", methods=["POST"])
def api_jwt_analyze():
    from modules.api_security import jwt_analyze
    return jsonify(jwt_analyze(request.json.get("token","")))

@app.route("/api/apisec/jwt-forge", methods=["POST"])
def api_jwt_forge():
    from modules.api_security import jwt_forge_none
    return jsonify(jwt_forge_none(request.json.get("token","")))

@app.route("/api/apisec/fuzz", methods=["POST"])
def api_fuzz():
    from modules.api_security import fuzz_endpoint
    data = request.json
    return jsonify(fuzz_endpoint(data.get("url",""), data.get("method","GET"),
                                  data.get("params"), data.get("fuzz_types")))

@app.route("/api/apisec/rate-limit", methods=["POST"])
def api_rate_limit():
    from modules.api_security import rate_limit_test
    data = request.json
    return jsonify(rate_limit_test(data.get("url",""), data.get("count",30),
                                    data.get("method","GET"), data.get("body")))

@app.route("/api/apisec/swagger", methods=["POST"])
def api_swagger():
    from modules.api_security import parse_swagger
    return jsonify(parse_swagger(request.json.get("content","")))

@app.route("/api/apisec/idor", methods=["POST"])
def api_idor():
    from modules.api_security import idor_test
    data = request.json
    return jsonify(idor_test(data.get("url",""), data.get("param","id"),
                              data.get("start",1), data.get("count",10), data.get("token","")))

@app.route("/api/apisec/broken-auth", methods=["POST"])
def api_broken_auth():
    from modules.api_security import broken_auth_test
    data = request.json
    return jsonify(broken_auth_test(data.get("url",""), data.get("username_field","username"),
                                     data.get("password_field","password")))

# ─── Mobile Security APIs ────────────────────────────────────────────────────

@app.route("/api/mobile/apk", methods=["POST"])
def api_apk():
    from modules.mobile_security import analyze_apk
    data = request.json
    b64  = data.get("data","")
    try:
        file_bytes = base64.b64decode(b64)
    except Exception:
        return jsonify({"error":"Invalid base64"}), 400
    return jsonify(analyze_apk(file_bytes, data.get("filename","app.apk")))

@app.route("/api/mobile/ipa", methods=["POST"])
def api_ipa():
    from modules.mobile_security import analyze_ipa
    data = request.json
    b64  = data.get("data","")
    try:
        file_bytes = base64.b64decode(b64)
    except Exception:
        return jsonify({"error":"Invalid base64"}), 400
    return jsonify(analyze_ipa(file_bytes, data.get("filename","app.ipa")))

# ─── Log Analyzer APIs ───────────────────────────────────────────────────────

@app.route("/api/logs/analyze", methods=["POST"])
def api_log_analyze():
    from modules.log_analyzer import detect_anomalies
    data = request.json
    return jsonify(detect_anomalies(data.get("log_text",""), data.get("log_type","auto")))

@app.route("/api/logs/enrich-ips", methods=["POST"])
def api_log_enrich():
    from modules.log_analyzer import enrich_ips_from_log
    return jsonify(enrich_ips_from_log(request.json.get("log_text","")))

# ─── Threat Intelligence APIs ────────────────────────────────────────────────

@app.route("/api/intel/ip", methods=["POST"])
def api_intel_ip():
    from modules.threat_intel import ip_reputation
    data = request.json
    return jsonify(ip_reputation(data.get("ip",""), data.get("keys",{})))

@app.route("/api/intel/domain", methods=["POST"])
def api_intel_domain():
    from modules.threat_intel import domain_reputation
    data = request.json
    return jsonify(domain_reputation(data.get("domain",""), data.get("keys",{})))

@app.route("/api/intel/ioc", methods=["POST"])
def api_intel_ioc():
    from modules.threat_intel import ioc_lookup
    data = request.json
    return jsonify(ioc_lookup(data.get("ioc",""), data.get("type","auto"), data.get("keys",{})))

@app.route("/api/intel/feeds", methods=["POST"])
def api_intel_feeds():
    from modules.threat_intel import threat_feed_check
    return jsonify(threat_feed_check(request.json.get("indicator","")))

# ─── Telecom Security APIs ───────────────────────────────────────────────────

@app.route("/api/telecom/ss7", methods=["POST"])
def api_telecom_ss7():
    from modules.telecom_security import ss7_assess
    return jsonify(ss7_assess(request.json.get("network_type","operator")))

@app.route("/api/telecom/diameter", methods=["POST"])
def api_telecom_diameter():
    from modules.telecom_security import diameter_assess
    return jsonify(diameter_assess())

@app.route("/api/telecom/sip-scan", methods=["POST"])
def api_telecom_sip():
    from modules.telecom_security import sip_scan
    data = request.json
    return jsonify(sip_scan(data.get("host",""), int(data.get("port",5060))))

@app.route("/api/telecom/voip-controls", methods=["POST"])
def api_telecom_voip():
    from modules.telecom_security import voip_recommendations
    return jsonify(voip_recommendations())

@app.route("/api/telecom/imsi-catcher", methods=["POST"])
def api_telecom_imsi():
    from modules.telecom_security import imsi_catcher_indicators
    return jsonify(imsi_catcher_indicators())

@app.route("/api/telecom/oss-bss", methods=["POST"])
def api_telecom_ossbss():
    from modules.telecom_security import oss_bss_assess
    return jsonify(oss_bss_assess())

@app.route("/api/telecom/bgp", methods=["POST"])
def api_telecom_bgp():
    from modules.telecom_security import bgp_route_check
    return jsonify(bgp_route_check(request.json.get("asn","")))

@app.route("/api/telecom/5g-ims", methods=["POST"])
def api_telecom_5g():
    from modules.telecom_security import fivegig_security_checklist
    return jsonify(fivegig_security_checklist())

@app.route("/api/telecom/sim", methods=["POST"])
def api_telecom_sim():
    from modules.telecom_security import sim_security_overview
    return jsonify(sim_security_overview())

# ─── App Store Pentest APIs ──────────────────────────────────────────────────

@app.route("/api/appstore/apple-search", methods=["POST"])
def api_appstore_apple_search():
    from modules.appstore_pentest import apple_store_search
    d = request.json
    return jsonify(apple_store_search(d.get("query",""), d.get("country","us"), int(d.get("limit",10))))

@app.route("/api/appstore/apple-lookup", methods=["POST"])
def api_appstore_apple_lookup():
    from modules.appstore_pentest import apple_store_lookup
    d = request.json
    return jsonify(apple_store_lookup(d.get("app_id",""), d.get("country","us")))

@app.route("/api/appstore/play-search", methods=["POST"])
def api_appstore_play_search():
    from modules.appstore_pentest import play_search
    d = request.json
    return jsonify(play_search(d.get("query",""), d.get("country","us"), d.get("lang","en")))

@app.route("/api/appstore/play-lookup", methods=["POST"])
def api_appstore_play_lookup():
    from modules.appstore_pentest import play_store_lookup
    d = request.json
    return jsonify(play_store_lookup(d.get("package",""), d.get("country","us"), d.get("lang","en")))

@app.route("/api/appstore/verdict", methods=["POST"])
def api_appstore_verdict():
    from modules.appstore_pentest import combine_encryption_verdict
    d = request.json
    return jsonify(combine_encryption_verdict(
        d.get("play_result"), d.get("apple_result"), d.get("apk_analysis")))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
