import os
import json
from datetime import datetime


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Penetration Test Report – {title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f4f4; color: #222; }}
  .cover {{ background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%); color: #fff; padding: 80px 60px; min-height: 260px; }}
  .cover h1 {{ font-size: 2.8em; color: #e94560; letter-spacing: 2px; margin-bottom: 10px; }}
  .cover h2 {{ font-size: 1.4em; color: #a8dadc; font-weight: 300; }}
  .cover .meta {{ margin-top: 30px; font-size: 0.9em; color: #ccc; }}
  .cover .meta span {{ display: inline-block; margin-right: 40px; }}
  .container {{ max-width: 900px; margin: 30px auto; padding: 0 20px 60px; }}
  .section {{ background: #fff; border-radius: 8px; padding: 30px; margin-bottom: 24px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }}
  .section h2 {{ color: #1a1a2e; font-size: 1.4em; border-bottom: 3px solid #e94560; padding-bottom: 10px; margin-bottom: 20px; }}
  .section h3 {{ color: #16213e; font-size: 1.1em; margin: 16px 0 8px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }}
  .badge-critical {{ background: #7d1128; color: #fff; }}
  .badge-high {{ background: #e94560; color: #fff; }}
  .badge-medium {{ background: #f4a261; color: #000; }}
  .badge-low {{ background: #52b788; color: #fff; }}
  .badge-info {{ background: #457b9d; color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.9em; }}
  th {{ background: #1a1a2e; color: #fff; padding: 10px 12px; text-align: left; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #eee; }}
  tr:hover td {{ background: #f9f9f9; }}
  .vuln-box {{ border-left: 4px solid #e94560; padding: 14px 18px; margin: 12px 0; background: #fff9f9; border-radius: 0 4px 4px 0; }}
  .vuln-box.high {{ border-color: #e94560; }}
  .vuln-box.critical {{ border-color: #7d1128; background: #fff0f2; }}
  .vuln-box.medium {{ border-color: #f4a261; background: #fffaf5; }}
  .vuln-box.low {{ border-color: #52b788; background: #f5fff8; }}
  .vuln-box.info {{ border-color: #457b9d; background: #f5f9ff; }}
  pre {{ background: #1a1a2e; color: #a8dadc; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 12px 0; }}
  .stat-box {{ text-align: center; padding: 18px; border-radius: 8px; background: #f8f9fa; border: 1px solid #dee2e6; }}
  .stat-box .number {{ font-size: 2.2em; font-weight: bold; color: #e94560; }}
  .stat-box .label {{ font-size: 0.85em; color: #666; margin-top: 4px; }}
  .toc a {{ color: #e94560; text-decoration: none; line-height: 2; }}
  .toc a:hover {{ text-decoration: underline; }}
  footer {{ text-align: center; color: #999; font-size: 0.85em; padding: 30px; }}
  @media print {{ body {{ background: #fff; }} .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
</style>
</head>
<body>
<div class="cover">
  <h1>&#x1F512; WOUAPIT-HACK</h1>
  <h2>Penetration Testing Report</h2>
  <br><h2 style="color:#e94560;font-size:1.8em">{title}</h2>
  <div class="meta">
    <span><strong>Target:</strong> {target}</span>
    <span><strong>Date:</strong> {date}</span>
    <span><strong>Tester:</strong> {tester}</span>
    <span><strong>Classification:</strong> {classification}</span>
  </div>
</div>

<div class="container">

  <!-- Table of Contents -->
  <div class="section toc">
    <h2>Table of Contents</h2>
    <ol>
      <li><a href="#executive">Executive Summary</a></li>
      <li><a href="#scope">Scope &amp; Methodology</a></li>
      <li><a href="#stats">Findings Overview</a></li>
      <li><a href="#findings">Detailed Findings</a></li>
      <li><a href="#recon">Reconnaissance Results</a></li>
      <li><a href="#recommendations">Recommendations</a></li>
      <li><a href="#appendix">Appendix</a></li>
    </ol>
  </div>

  <!-- Executive Summary -->
  <div class="section" id="executive">
    <h2>1. Executive Summary</h2>
    <p>{executive_summary}</p>
    <div class="stat-grid" style="margin-top:20px">
      <div class="stat-box"><div class="number" style="color:#7d1128">{count_critical}</div><div class="label">Critical</div></div>
      <div class="stat-box"><div class="number" style="color:#e94560">{count_high}</div><div class="label">High</div></div>
      <div class="stat-box"><div class="number" style="color:#f4a261">{count_medium}</div><div class="label">Medium</div></div>
      <div class="stat-box"><div class="number" style="color:#52b788">{count_low}</div><div class="label">Low</div></div>
      <div class="stat-box"><div class="number" style="color:#457b9d">{count_info}</div><div class="label">Informational</div></div>
    </div>
  </div>

  <!-- Scope & Methodology -->
  <div class="section" id="scope">
    <h2>2. Scope &amp; Methodology</h2>
    <h3>Scope</h3>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Engagement Type:</strong> {engagement_type}</p>
    <p><strong>Testing Period:</strong> {testing_period}</p>
    <h3>Methodology</h3>
    <p>{methodology}</p>
    <h3>Tools Used</h3>
    <p>{tools_used}</p>
  </div>

  <!-- Stats -->
  <div class="section" id="stats">
    <h2>3. Findings Overview</h2>
    <table>
      <tr><th>Severity</th><th>Count</th><th>Risk Level</th></tr>
      <tr><td><span class="badge badge-critical">Critical</span></td><td>{count_critical}</td><td>Immediate action required</td></tr>
      <tr><td><span class="badge badge-high">High</span></td><td>{count_high}</td><td>Action required within 24-72h</td></tr>
      <tr><td><span class="badge badge-medium">Medium</span></td><td>{count_medium}</td><td>Action required within 30 days</td></tr>
      <tr><td><span class="badge badge-low">Low</span></td><td>{count_low}</td><td>Action recommended</td></tr>
      <tr><td><span class="badge badge-info">Info</span></td><td>{count_info}</td><td>For awareness</td></tr>
    </table>
  </div>

  <!-- Detailed Findings -->
  <div class="section" id="findings">
    <h2>4. Detailed Findings</h2>
    {findings_html}
  </div>

  <!-- Recon Results -->
  <div class="section" id="recon">
    <h2>5. Reconnaissance Results</h2>
    {recon_html}
  </div>

  <!-- Recommendations -->
  <div class="section" id="recommendations">
    <h2>6. Recommendations</h2>
    {recommendations_html}
  </div>

  <!-- Appendix -->
  <div class="section" id="appendix">
    <h2>7. Appendix</h2>
    <h3>Raw Scan Data</h3>
    <pre>{appendix_json}</pre>
  </div>

</div>
<footer>Generated by <strong>Wouapit-Hack</strong> | {date} | For authorized security testing only</footer>
</body>
</html>
"""


def _severity_badge(sev: str) -> str:
    s = sev.lower()
    return f'<span class="badge badge-{s}">{sev.upper()}</span>'


def _build_findings_html(findings: list) -> str:
    if not findings:
        return "<p>No vulnerabilities reported.</p>"
    html = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").lower()
        html += f"""
<div class="vuln-box {sev}">
  <h3>Finding #{i}: {f.get('title', 'Untitled')} {_severity_badge(f.get('severity','info'))}</h3>
  <p><strong>Description:</strong> {f.get('description','')}</p>
  <p><strong>URL/Location:</strong> {f.get('location','N/A')}</p>
  <p><strong>Evidence:</strong> {f.get('evidence','')}</p>
  <p><strong>CVSS Score:</strong> {f.get('cvss','N/A')}</p>
  <p><strong>Remediation:</strong> {f.get('remediation','')}</p>
  {"<pre>" + f['proof'] + "</pre>" if f.get('proof') else ""}
</div>
"""
    return html


def _build_recon_html(recon: dict) -> str:
    if not recon:
        return "<p>No reconnaissance data provided.</p>"
    html = ""
    if recon.get("open_ports"):
        html += "<h3>Open Ports</h3><table><tr><th>Port</th><th>State</th><th>Service</th></tr>"
        for p in recon["open_ports"]:
            html += f"<tr><td>{p.get('port')}</td><td>{p.get('state')}</td><td>{p.get('service','')}</td></tr>"
        html += "</table>"
    if recon.get("subdomains"):
        html += "<h3>Subdomains</h3><table><tr><th>Subdomain</th><th>IP</th></tr>"
        for s in recon["subdomains"]:
            html += f"<tr><td>{s.get('subdomain')}</td><td>{s.get('ip','')}</td></tr>"
        html += "</table>"
    if recon.get("technologies"):
        html += f"<h3>Detected Technologies</h3><p>{', '.join(recon['technologies'])}</p>"
    if recon.get("headers"):
        html += "<h3>Security Headers</h3><table><tr><th>Header</th><th>Value</th></tr>"
        for k, v in recon["headers"].items():
            color = "#e94560" if v == "MISSING" else "#52b788"
            html += f'<tr><td>{k}</td><td style="color:{color}">{v}</td></tr>'
        html += "</table>"
    if not html:
        html = f"<pre>{json.dumps(recon, indent=2)[:3000]}</pre>"
    return html


def _build_recommendations(findings: list, extra: str) -> str:
    recs = []
    sevs = set(f.get("severity","").upper() for f in findings)
    if "CRITICAL" in sevs or "HIGH" in sevs:
        recs.append("<li><strong>Immediately patch or mitigate all Critical and High severity findings.</strong></li>")
    recs.append("<li>Implement a regular penetration testing schedule (at least annually).</li>")
    recs.append("<li>Enable and monitor security headers (HSTS, CSP, X-Frame-Options).</li>")
    recs.append("<li>Apply the principle of least privilege across all systems and accounts.</li>")
    recs.append("<li>Ensure all software components are kept up-to-date with security patches.</li>")
    recs.append("<li>Implement a Web Application Firewall (WAF) to filter malicious traffic.</li>")
    recs.append("<li>Enable MFA for all privileged accounts.</li>")
    recs.append("<li>Conduct regular security awareness training for all staff.</li>")
    if extra:
        recs.append(f"<li>{extra}</li>")
    return "<ul style='line-height:2'>" + "".join(recs) + "</ul>"


def generate_report(data: dict, output_dir: str) -> dict:
    findings = data.get("findings", [])
    recon    = data.get("recon", {})

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1

    now = datetime.utcnow()
    filename = f"report_{data.get('target','target').replace('.','_').replace('/','_')}_{now.strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    html = REPORT_TEMPLATE.format(
        title=data.get("title", "Penetration Test Report"),
        target=data.get("target", "Unknown"),
        date=now.strftime("%B %d, %Y"),
        tester=data.get("tester", "Security Team"),
        classification=data.get("classification", "CONFIDENTIAL"),
        executive_summary=data.get("executive_summary",
            "A comprehensive penetration test was conducted against the target environment. "
            "The assessment identified several security vulnerabilities of varying severity levels. "
            "Immediate remediation is recommended for all Critical and High severity findings."),
        engagement_type=data.get("engagement_type", "Black Box"),
        testing_period=data.get("testing_period", now.strftime("%B %Y")),
        methodology=data.get("methodology",
            "Testing followed the OWASP Testing Guide and PTES (Penetration Testing Execution Standard). "
            "Phases included: Reconnaissance, Scanning, Exploitation, Post-Exploitation, and Reporting."),
        tools_used=data.get("tools_used",
            "Wouapit-Hack, Nmap, Burp Suite, Metasploit, SQLMap, Nikto, Gobuster"),
        count_critical=counts["CRITICAL"],
        count_high=counts["HIGH"],
        count_medium=counts["MEDIUM"],
        count_low=counts["LOW"],
        count_info=counts["INFO"],
        findings_html=_build_findings_html(findings),
        recon_html=_build_recon_html(recon),
        recommendations_html=_build_recommendations(findings, data.get("extra_recommendations", "")),
        appendix_json=json.dumps(data, indent=2)[:5000],
    )

    os.makedirs(output_dir, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)

    return {
        "success": True,
        "filename": filename,
        "filepath": filepath,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
        },
    }
