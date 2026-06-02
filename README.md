# 💀 Wouapit-Hack

> **Professional Penetration Testing Web Portal**

A full-featured, dark-themed web application for authorized penetration testers — covering recon, scanning, exploitation, and professional report generation.

---

## ⚠️ Legal Disclaimer

This tool is designed **exclusively for authorized penetration testing**, CTF competitions, and security research. Never use it against systems you do not own or lack explicit written permission to test. Unauthorized use is illegal and unethical.

---

## 🚀 Features

| Category | Tools |
|---|---|
| **Reconnaissance** | DNS lookup (A/MX/NS/TXT/CNAME/SOA), WHOIS, TCP port scan (multi-threaded), subdomain enumeration, HTTP header analysis |
| **Web Scanner** | Directory bruteforce, SQL injection detection, XSS (reflected) detection, SSL/TLS analysis, technology fingerprinting |
| **Network Tools** | Ping sweep (CIDR), traceroute, banner grabbing |
| **Password Tools** | Hash identification, dictionary crack, secure password generator, encoder/decoder (Base64/Hex/URL/HTML/ROT13/MD5/SHA) |
| **Exploits & Payloads** | CVE lookup (NVD/MITRE), reverse shells (Bash/NC/Python/PHP/Perl/Ruby/PowerShell), bind shells, web shells (PHP/ASPX/JSP), XSS payloads, SQLi payloads, LFI payloads, XXE payloads |
| **Reports** | Professional HTML pentest reports with findings, severity ratings, remediation guidance, recon data, and statistics |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/wouapit999/Wouapit-Hack.git
cd Wouapit-Hack

# Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

Then open your browser at: **http://localhost:5000**

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+ / Flask
- **Frontend**: Vanilla HTML/CSS/JS (no framework dependencies)
- **Libraries**: dnspython, python-whois, requests
- **Reports**: Pure HTML/CSS — print-ready, no external dependencies

---

## 📋 Tool Details

### Reconnaissance Suite
- **DNS Lookup** — Queries A, AAAA, MX, NS, TXT, CNAME, SOA records + reverse DNS
- **WHOIS** — Domain registration, registrar, expiry, nameservers
- **Port Scanner** — Multi-threaded TCP connect scan, up to 2000 ports, service detection
- **Subdomain Enum** — DNS-based brute force with 50+ common prefixes
- **HTTP Headers** — Full header dump + security header audit (HSTS, CSP, X-Frame-Options, etc.)

### Web Application Scanner
- **Dir Bruteforce** — 50+ common paths including admin panels, config files, backups
- **SQL Injection** — Error-based detection with 12 common payloads
- **XSS** — Reflected XSS detection with 6 payload variants
- **SSL/TLS** — Certificate validity, protocol version, cipher strength, SAN enumeration
- **Tech Detect** — Fingerprints 20+ technologies (WordPress, Django, React, Nginx, Cloudflare, AWS…)

### Password Tools
- **Hash Identifier** — Detects MD5, SHA-1/256/512, NTLM, bcrypt, crypt formats
- **Hash Cracker** — Mini wordlist cracker (extend with rockyou.txt + hashcat for production)
- **Password Generator** — Cryptographically secure, configurable charset, entropy display
- **Encoder/Decoder** — Base64, Base32, Hex, URL, HTML entities, ROT13, MD5/SHA hashing

### Exploit & Payload Generator
- **CVE Lookup** — Live queries to NVD and MITRE CVE APIs
- **Reverse Shells** — 7 languages/tools: Bash, Netcat, Python, PHP, Perl, Ruby, PowerShell
- **Web Shells** — PHP, ASPX, JSP, Python
- **XSS Payloads** — Basic, img, svg, cookie stealer, keylogger, DOM
- **SQLi Payloads** — Union, boolean, time-based, error-based, stacked, out-of-file
- **LFI Payloads** — Path traversal, encoding bypass, null byte, proc/self, PHP filters
- **XXE Payloads** — File read, SSRF callback

### Report Generator
- Full HTML reports with cover page, executive summary, findings table, severity stats
- Per-finding sections: title, severity badge, description, location, CVSS, PoC, remediation
- Recon data tables: open ports, subdomains, technologies, security headers
- Recommendations section auto-populated based on findings
- Print-ready CSS, download as HTML

---

## 🔧 Configuration

The app runs on `0.0.0.0:5000` by default. To change:

```python
# app.py — last line
app.run(debug=False, host="127.0.0.1", port=8080)
```

For production deployment, use **gunicorn** behind nginx:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## 📁 Project Structure

```
Wouapit-Hack/
├── app.py                  # Flask application & routes
├── requirements.txt
├── modules/
│   ├── recon.py            # DNS, WHOIS, port scan, subdomains, headers
│   ├── web_scanner.py      # Dir brute, SQLi, XSS, SSL, tech detect
│   ├── network.py          # Ping sweep, traceroute, banner grab
│   ├── password_tools.py   # Hash ID, crack, password gen, encoder
│   ├── exploits.py         # CVE lookup, payload generator
│   └── reporter.py         # HTML report generator
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── recon.html
│   ├── web_scanner.html
│   ├── network.html
│   ├── passwords.html
│   ├── exploits.html
│   └── reports.html
├── static/
│   ├── css/style.css
│   └── js/main.js
└── reports/                # Generated reports (gitignored)
```

---

## 🤝 Contributing

Pull requests welcome. Please test changes locally and keep the authorized-use-only disclaimer visible.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built by [wouapit999](https://github.com/wouapit999)*
