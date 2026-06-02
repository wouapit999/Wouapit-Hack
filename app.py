from flask import Flask, render_template, request, jsonify, send_file
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

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

@app.route("/api/reports/download/<filename>")
def api_report_download(filename):
    path = os.path.join(REPORTS_DIR, os.path.basename(filename))
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
