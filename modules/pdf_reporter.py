"""
PDF report generator using reportlab.
Produces two report types:
  - Full penetration test report
  - Remediation-focused report
"""

import os
import io
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.platypus.flowables import BalancedColumns
    from reportlab.graphics.shapes import Drawing, Rect, String
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ── Brand colours ────────────────────────────────────────────────────────────
GOLD        = colors.HexColor("#D4A017")
GOLD_LIGHT  = colors.HexColor("#FFD700")
GOLD_DIM    = colors.HexColor("#8B6914")
BLACK       = colors.HexColor("#0A0A08")
DARK        = colors.HexColor("#161610")
DARK2       = colors.HexColor("#1E1E14")
OFF_WHITE   = colors.HexColor("#F0E8D0")
MUTED       = colors.HexColor("#8A7A50")

SEV_COLOURS = {
    "CRITICAL": (colors.HexColor("#8B1A1A"), colors.HexColor("#FFD700")),
    "HIGH":     (colors.HexColor("#7A2020"), colors.HexColor("#FFB3B3")),
    "MEDIUM":   (colors.HexColor("#5A3A00"), colors.HexColor("#E8A030")),
    "LOW":      (colors.HexColor("#1A4A2A"), colors.HexColor("#6DBF8A")),
    "INFO":     (colors.HexColor("#1A3050"), colors.HexColor("#5B9BD5")),
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


def _styles():
    base = getSampleStyleSheet()
    def s(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)
    return {
        "cover_title":   s("ct",  fontName="Helvetica-Bold",   fontSize=28, textColor=GOLD_LIGHT, spaceAfter=6,  alignment=TA_LEFT),
        "cover_sub":     s("cs",  fontName="Helvetica",        fontSize=14, textColor=OFF_WHITE,  spaceAfter=4,  alignment=TA_LEFT),
        "cover_meta":    s("cm",  fontName="Helvetica",        fontSize=9,  textColor=MUTED,      spaceAfter=2,  alignment=TA_LEFT),
        "section":       s("sh",  fontName="Helvetica-Bold",   fontSize=13, textColor=GOLD,       spaceBefore=14,spaceAfter=6),
        "subsection":    s("ssh", fontName="Helvetica-Bold",   fontSize=10, textColor=OFF_WHITE,  spaceBefore=8, spaceAfter=4),
        "body":          s("bd",  fontName="Helvetica",        fontSize=9,  textColor=OFF_WHITE,  spaceAfter=4,  leading=14, alignment=TA_JUSTIFY),
        "body_small":    s("bs",  fontName="Helvetica",        fontSize=8,  textColor=MUTED,      spaceAfter=3,  leading=12),
        "code":          s("cd",  fontName="Courier",          fontSize=8,  textColor=colors.HexColor("#A8DADC"), backColor=BLACK, spaceAfter=4, leftIndent=6, leading=11),
        "finding_title": s("ft",  fontName="Helvetica-Bold",   fontSize=10, textColor=GOLD_LIGHT, spaceAfter=3),
        "label":         s("lb",  fontName="Helvetica-Bold",   fontSize=8,  textColor=MUTED,      spaceAfter=1, spaceBefore=6),
        "toc_item":      s("ti",  fontName="Helvetica",        fontSize=9,  textColor=OFF_WHITE,  spaceAfter=3, leftIndent=10),
        "disclaimer":    s("di",  fontName="Helvetica-Oblique",fontSize=8,  textColor=MUTED,      spaceAfter=3, alignment=TA_CENTER),
    }


def _sev_badge_table(severity):
    bg, fg = SEV_COLOURS.get(severity.upper(), (DARK2, MUTED))
    data = [[Paragraph(f'<font name="Helvetica-Bold" size="8">{severity.upper()}</font>',
                       ParagraphStyle("b", textColor=fg, alignment=TA_CENTER))]]
    t = Table(data, colWidths=[22*mm], rowHeights=[6*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("ROUNDEDCORNERS", [3]),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t


def _hr(width=None):
    return HRFlowable(width=width or (PAGE_W - 2*MARGIN), thickness=0.5, color=GOLD_DIM, spaceAfter=6, spaceBefore=6)


def _cover_page(story, meta, report_type, st):
    """Black/gold cover page."""
    story.append(Spacer(1, 40*mm))
    story.append(Paragraph("💀 WOUAPIT-HACK", st["cover_title"]))
    story.append(Paragraph(report_type, st["cover_sub"]))
    story.append(Spacer(1, 6*mm))
    story.append(_hr())
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f'<font color="#E8D48B">{meta.get("title","Penetration Test Report")}</font>', st["cover_sub"]))
    story.append(Spacer(1, 10*mm))
    for label, key in [("Target", "target"), ("Tester", "tester"), ("Date", "date"),
                       ("Engagement", "engagement_type"), ("Classification", "classification")]:
        story.append(Paragraph(f'<b><font color="#8A7A50">{label}:</font></b>  '
                                f'<font color="#F0E8D0">{meta.get(key,"—")}</font>', st["cover_meta"]))
    story.append(Spacer(1, 20*mm))
    story.append(Paragraph(
        "This document contains confidential security information. "
        "Distribute only to authorised personnel. "
        "For authorised penetration testing use only.",
        st["disclaimer"]))
    story.append(PageBreak())


def _severity_summary_table(findings, st):
    counts = {s: sum(1 for f in findings if f.get("severity","INFO").upper()==s)
              for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
    rows = [
        [Paragraph('<font name="Helvetica-Bold" size="8" color="#8A7A50">SEVERITY</font>', st["body_small"]),
         Paragraph('<font name="Helvetica-Bold" size="8" color="#8A7A50">COUNT</font>',    st["body_small"]),
         Paragraph('<font name="Helvetica-Bold" size="8" color="#8A7A50">REMEDIATION SLA</font>', st["body_small"])],
    ]
    slas = {"CRITICAL":"Immediate (24h)","HIGH":"72 hours","MEDIUM":"30 days","LOW":"Next cycle","INFO":"Advisory"}
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        bg, fg = SEV_COLOURS[sev]
        rows.append([
            Paragraph(f'<font name="Helvetica-Bold" size="8">{sev}</font>',
                      ParagraphStyle("x", textColor=fg, alignment=TA_LEFT)),
            Paragraph(f'<font name="Helvetica-Bold" size="14">{counts[sev]}</font>',
                      ParagraphStyle("x", textColor=fg, alignment=TA_CENTER)),
            Paragraph(f'<font size="8" color="#F0E8D0">{slas[sev]}</font>',
                      ParagraphStyle("x", textColor=OFF_WHITE, alignment=TA_LEFT)),
        ])
    t = Table(rows, colWidths=[40*mm, 28*mm, None])
    style = [
        ("BACKGROUND",  (0,0), (-1,0),  DARK2),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("TOPPADDING",  (0,0), (-1,-1), 6),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.3, GOLD_DIM),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[DARK, DARK2]),
    ]
    for i, sev in enumerate(("CRITICAL","HIGH","MEDIUM","LOW","INFO"), 1):
        bg, _ = SEV_COLOURS[sev]
        style.append(("BACKGROUND", (0,i), (0,i), bg))
    t.setStyle(TableStyle(style))
    return t


def _finding_block(finding, idx, st, remediation_only=False):
    """Returns a list of flowables for one finding."""
    sev      = finding.get("severity","INFO").upper()
    bg, fg   = SEV_COLOURS.get(sev, (DARK2, MUTED))
    elements = []

    # Header row: number + title + badge
    title_para = Paragraph(
        f'<font name="Helvetica-Bold" size="10" color="#FFD700">#{idx}  {finding.get("title","Untitled")}</font>',
        ParagraphStyle("fh", textColor=GOLD_LIGHT, leading=14))
    badge_data = [[Paragraph(f'<font name="Helvetica-Bold" size="8">{sev}</font>',
                              ParagraphStyle("sv", textColor=fg, alignment=TA_CENTER))]]
    badge_t = Table(badge_data, colWidths=[22*mm], rowHeights=[6*mm])
    badge_t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),bg),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))

    header = Table([[title_para, badge_t]],
                   colWidths=[PAGE_W - 2*MARGIN - 26*mm, 26*mm])
    header.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1), DARK2),
        ("LEFTPADDING",(0,0),(-1,-1), 8),
        ("RIGHTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING",(0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("LINEBELOW",(0,0),(-1,-1), 1.5, bg),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    elements.append(header)

    def field(label, value, code=False):
        if not value or value == "N/A":
            return
        elements.append(Paragraph(label, st["label"]))
        style = st["code"] if code else st["body"]
        elements.append(Paragraph(str(value)[:800], style))

    if not remediation_only:
        field("Description", finding.get("description",""))
        field("Location / URL", finding.get("location",""))
        field("CVSS Score", finding.get("cvss",""))
        field("Evidence / Proof of Concept", finding.get("evidence",""), code=True)

    field("Remediation", finding.get("remediation",""))
    elements.append(Spacer(1, 4*mm))
    return elements


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf_report(data: dict, output_dir: str) -> dict:
    """Full penetration test report as PDF."""
    if not REPORTLAB_OK:
        return {"error": "reportlab not installed. Run: pip install reportlab"}

    os.makedirs(output_dir, exist_ok=True)
    now      = datetime.utcnow()
    findings = data.get("findings", [])
    meta     = {
        "title":           data.get("title", "Penetration Test Report"),
        "target":          data.get("target", "Unknown"),
        "tester":          data.get("tester", "Security Team"),
        "date":            now.strftime("%B %d, %Y"),
        "engagement_type": data.get("engagement_type", "Black Box"),
        "classification":  data.get("classification", "CONFIDENTIAL"),
        "testing_period":  data.get("testing_period", now.strftime("%B %Y")),
        "tools_used":      data.get("tools_used", "Wouapit-Hack"),
    }

    slug     = meta["target"].replace(".", "_").replace("/", "_")
    filename = f"pentest_report_{slug}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_dir, filename)

    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=MARGIN, rightMargin=MARGIN,
                             topMargin=MARGIN,  bottomMargin=MARGIN,
                             title=meta["title"])
    st   = _styles()
    story = []

    # Cover
    _cover_page(story, meta, "PENETRATION TEST REPORT", st)

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", st["section"]))
    story.append(_hr())
    story.append(Paragraph(
        data.get("executive_summary",
                 f"A penetration test was conducted against {meta['target']}. "
                 f"The assessment identified {len(findings)} finding(s) across multiple test categories."),
        st["body"]))
    story.append(Spacer(1, 4*mm))
    story.append(_severity_summary_table(findings, st))
    story.append(Spacer(1, 6*mm))

    # Scope & Methodology
    story.append(Paragraph("2. Scope &amp; Methodology", st["section"]))
    story.append(_hr())
    rows = [
        ["Target",          meta["target"]],
        ["Engagement Type", meta["engagement_type"]],
        ["Testing Period",  meta["testing_period"]],
        ["Tester",          meta["tester"]],
        ["Tools Used",      meta["tools_used"]],
        ["Methodology",     "OWASP Testing Guide / PTES"],
    ]
    info_data = [[Paragraph(f'<font name="Helvetica-Bold" size="8" color="#D4A017">{r}</font>',
                             ParagraphStyle("k", textColor=GOLD)),
                  Paragraph(f'<font size="8" color="#F0E8D0">{v}</font>',
                             ParagraphStyle("v", textColor=OFF_WHITE))]
                 for r, v in rows]
    info_t = Table(info_data, colWidths=[38*mm, None])
    info_t.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[DARK, DARK2]),
        ("GRID",(0,0),(-1,-1),0.3,GOLD_DIM),
        ("LEFTPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
    ]))
    story.append(info_t)
    story.append(Spacer(1, 6*mm))

    # Recon Results
    recon = data.get("recon", {})
    if any(recon.get(k) for k in ("open_ports","subdomains","technologies","headers")):
        story.append(Paragraph("3. Reconnaissance Results", st["section"]))
        story.append(_hr())

        if recon.get("technologies"):
            story.append(Paragraph("Technologies Detected", st["subsection"]))
            story.append(Paragraph(", ".join(recon["technologies"]), st["body"]))

        if recon.get("open_ports"):
            story.append(Paragraph("Open Ports", st["subsection"]))
            port_rows = [[
                Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">PORT</font>', st["body_small"]),
                Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">STATE</font>', st["body_small"]),
                Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">SERVICE</font>', st["body_small"]),
            ]]
            for p in recon["open_ports"][:40]:
                port_rows.append([
                    Paragraph(f'<font name="Helvetica-Bold" size="8" color="#FFD700">{p.get("port","")}</font>', st["body_small"]),
                    Paragraph('<font size="8" color="#6DBF8A">OPEN</font>', st["body_small"]),
                    Paragraph(f'<font size="8" color="#F0E8D0">{p.get("service","")}</font>', st["body_small"]),
                ])
            pt = Table(port_rows, colWidths=[22*mm, 22*mm, None])
            pt.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),DARK2),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[DARK,DARK2]),
                ("GRID",(0,0),(-1,-1),0.3,GOLD_DIM),
                ("LEFTPADDING",(0,0),(-1,-1),6),
                ("TOPPADDING",(0,0),(-1,-1),4),
                ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ]))
            story.append(pt)
            story.append(Spacer(1,3*mm))

        if recon.get("subdomains"):
            story.append(Paragraph("Subdomains Found", st["subsection"]))
            sub_rows = [[
                Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">SUBDOMAIN</font>', st["body_small"]),
                Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">IP ADDRESS</font>', st["body_small"]),
            ]] + [[
                Paragraph(f'<font size="8" color="#F0E8D0">{s.get("subdomain","")}</font>', st["body_small"]),
                Paragraph(f'<font size="8" color="#A8DADC">{s.get("ip","")}</font>', st["body_small"]),
            ] for s in recon["subdomains"][:30]]
            st2 = Table(sub_rows, colWidths=[None, 36*mm])
            st2.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),DARK2),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[DARK,DARK2]),
                ("GRID",(0,0),(-1,-1),0.3,GOLD_DIM),
                ("LEFTPADDING",(0,0),(-1,-1),6),
                ("TOPPADDING",(0,0),(-1,-1),4),
                ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ]))
            story.append(st2)
            story.append(Spacer(1,3*mm))

        if recon.get("headers"):
            story.append(Paragraph("Security Headers Audit", st["subsection"]))
            hdr_rows = [[
                Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">HEADER</font>', st["body_small"]),
                Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">STATUS</font>', st["body_small"]),
            ]]
            for k, v in recon["headers"].items():
                col = "#E05252" if v == "MISSING" else "#6DBF8A"
                hdr_rows.append([
                    Paragraph(f'<font size="8" color="#F0E8D0">{k}</font>', st["body_small"]),
                    Paragraph(f'<font size="8" color="{col}">{"✗ MISSING" if v=="MISSING" else "✓ "+str(v)[:60]}</font>', st["body_small"]),
                ])
            ht = Table(hdr_rows, colWidths=[None, 80*mm])
            ht.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),DARK2),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[DARK,DARK2]),
                ("GRID",(0,0),(-1,-1),0.3,GOLD_DIM),
                ("LEFTPADDING",(0,0),(-1,-1),6),
                ("TOPPADDING",(0,0),(-1,-1),4),
                ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ]))
            story.append(ht)
        story.append(Spacer(1,6*mm))

    # Detailed Findings
    story.append(PageBreak())
    story.append(Paragraph("4. Detailed Findings", st["section"]))
    story.append(_hr())
    if not findings:
        story.append(Paragraph("No vulnerabilities were identified during this assessment.", st["body"]))
    else:
        for i, f in enumerate(findings, 1):
            block = _finding_block(f, i, st)
            story.append(KeepTogether(block[:3]))
            for el in block[3:]:
                story.append(el)

    # Recommendations
    story.append(PageBreak())
    story.append(Paragraph("5. Recommendations", st["section"]))
    story.append(_hr())
    recs = [
        "Immediately remediate all CRITICAL and HIGH severity findings.",
        "Apply the principle of least privilege across all systems and accounts.",
        "Implement and enforce a Web Application Firewall (WAF).",
        "Enable MFA on all privileged and externally accessible accounts.",
        "Enforce HTTPS everywhere and configure HSTS with a long max-age.",
        "Add all missing security headers to web server configurations.",
        "Conduct regular penetration tests (at minimum annually).",
        "Maintain a vulnerability management programme with defined SLAs.",
        "Perform security awareness training for all staff quarterly.",
        "Keep all software components, libraries, and OS packages patched.",
    ]
    for r in recs:
        story.append(Paragraph(f"• {r}", st["body"]))
    story.append(Spacer(1,6*mm))

    # Footer disclaimer
    story.append(_hr())
    story.append(Paragraph(
        f"Generated by Wouapit-Hack | {meta['date']} | CONFIDENTIAL — Authorised Security Testing Only",
        st["disclaimer"]))

    doc.build(story)
    with open(filepath, "wb") as fh:
        fh.write(buf.getvalue())

    counts = {s: sum(1 for f in findings if f.get("severity","INFO").upper()==s)
              for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
    return {"success": True, "filename": filename, "filepath": filepath,
            "type": "pentest", "summary": {"total": len(findings), "severity_counts": counts}}


def generate_remediation_pdf(data: dict, output_dir: str) -> dict:
    """Remediation-focused report: roadmap, priority matrix, step-by-step fixes."""
    if not REPORTLAB_OK:
        return {"error": "reportlab not installed. Run: pip install reportlab"}

    os.makedirs(output_dir, exist_ok=True)
    now      = datetime.utcnow()
    findings = data.get("findings", [])
    meta     = {
        "title":          data.get("title", "Remediation Report"),
        "target":         data.get("target", "Unknown"),
        "tester":         data.get("tester", "Security Team"),
        "date":           now.strftime("%B %d, %Y"),
        "engagement_type":data.get("engagement_type", "Black Box"),
        "classification": data.get("classification", "CONFIDENTIAL"),
        "testing_period": data.get("testing_period", now.strftime("%B %Y")),
    }

    slug     = meta["target"].replace(".", "_").replace("/", "_")
    filename = f"remediation_report_{slug}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_dir, filename)

    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=MARGIN, rightMargin=MARGIN,
                             topMargin=MARGIN,  bottomMargin=MARGIN,
                             title=f"Remediation — {meta['title']}")
    st   = _styles()
    story = []

    _cover_page(story, meta, "REMEDIATION REPORT", st)

    # Intro
    story.append(Paragraph("1. Purpose", st["section"]))
    story.append(_hr())
    story.append(Paragraph(
        "This remediation report provides a prioritised, actionable roadmap to address all security "
        "findings identified during the penetration test. Each finding includes a concrete remediation "
        "step, effort estimate, and recommended timeline. Findings are ordered by severity — address "
        "CRITICAL items immediately before moving to lower-priority issues.",
        st["body"]))
    story.append(Spacer(1, 4*mm))

    # Priority matrix table
    story.append(Paragraph("2. Remediation Priority Matrix", st["section"]))
    story.append(_hr())

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    by_sev    = {s: [f for f in findings if f.get("severity","INFO").upper()==s] for s in sev_order}
    slas      = {"CRITICAL":"24 hours","HIGH":"72 hours","MEDIUM":"30 days","LOW":"90 days","INFO":"Advisory"}
    efforts   = {"CRITICAL":"High","HIGH":"High","MEDIUM":"Medium","LOW":"Low","INFO":"Minimal"}

    matrix_rows = [[
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">SEVERITY</font>', st["body_small"]),
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">COUNT</font>',    st["body_small"]),
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">SLA</font>',      st["body_small"]),
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">EFFORT</font>',   st["body_small"]),
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">PRIORITY</font>', st["body_small"]),
    ]]
    for sev in sev_order:
        bg, fg = SEV_COLOURS[sev]
        cnt = len(by_sev[sev])
        matrix_rows.append([
            Paragraph(f'<font name="Helvetica-Bold" size="8">{sev}</font>',
                      ParagraphStyle("x", textColor=fg)),
            Paragraph(f'<font name="Helvetica-Bold" size="12">{cnt}</font>',
                      ParagraphStyle("x", textColor=fg, alignment=TA_CENTER)),
            Paragraph(f'<font size="8" color="#F0E8D0">{slas[sev]}</font>', st["body_small"]),
            Paragraph(f'<font size="8" color="#F0E8D0">{efforts[sev]}</font>', st["body_small"]),
            Paragraph(f'<font size="8" color="#F0E8D0">{"P1" if sev=="CRITICAL" else "P2" if sev=="HIGH" else "P3" if sev=="MEDIUM" else "P4" if sev=="LOW" else "P5"}</font>', st["body_small"]),
        ])
    mt = Table(matrix_rows, colWidths=[30*mm, 18*mm, 30*mm, 24*mm, None])
    mstyle = [
        ("BACKGROUND",(0,0),(-1,0), DARK2),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[DARK,DARK2]),
        ("GRID",(0,0),(-1,-1),0.3,GOLD_DIM),
        ("LEFTPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),6),
    ]
    for i, sev in enumerate(sev_order, 1):
        bg, _ = SEV_COLOURS[sev]
        mstyle.append(("BACKGROUND",(0,i),(0,i), bg))
    mt.setStyle(TableStyle(mstyle))
    story.append(mt)
    story.append(Spacer(1, 6*mm))

    # Remediation Roadmap timeline
    story.append(Paragraph("3. Remediation Roadmap", st["section"]))
    story.append(_hr())
    phases = [
        ("Phase 1 — Immediate (0-24h)",  "CRITICAL", "#8B1A1A", "#FFD700"),
        ("Phase 2 — Short Term (1-3d)",  "HIGH",     "#7A2020", "#FFB3B3"),
        ("Phase 3 — Medium Term (30d)",  "MEDIUM",   "#5A3A00", "#E8A030"),
        ("Phase 4 — Long Term (90d)",    "LOW",      "#1A4A2A", "#6DBF8A"),
        ("Phase 5 — Advisory",           "INFO",     "#1A3050", "#5B9BD5"),
    ]
    for phase_label, sev, bg_hex, fg_hex in phases:
        items = by_sev[sev]
        if not items:
            continue
        bg_col = colors.HexColor(bg_hex)
        fg_col = colors.HexColor(fg_hex)
        phase_para = Paragraph(
            f'<font name="Helvetica-Bold" size="9">{phase_label}  '
            f'({len(items)} item{"s" if len(items)!=1 else ""})</font>',
            ParagraphStyle("ph", textColor=fg_col, leading=14))
        phase_cell = Table([[phase_para]], colWidths=[PAGE_W - 2*MARGIN])
        phase_cell.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),bg_col),
            ("LEFTPADDING",(0,0),(-1,-1),10),
            ("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ]))
        story.append(phase_cell)
        for item in items:
            story.append(Paragraph(
                f'<font name="Helvetica-Bold" size="8" color="#FFD700">→ {item.get("title","")}</font>  '
                f'<font size="8" color="#8A7A50">| CVSS {item.get("cvss","N/A")} | {item.get("location","")[:60]}</font>',
                ParagraphStyle("ri", leftIndent=12, spaceAfter=2, leading=12, textColor=OFF_WHITE)))
        story.append(Spacer(1, 3*mm))

    story.append(Spacer(1, 4*mm))

    # Detailed remediation steps
    story.append(PageBreak())
    story.append(Paragraph("4. Detailed Remediation Steps", st["section"]))
    story.append(_hr())
    story.append(Paragraph(
        "The following section provides step-by-step remediation guidance for each finding, "
        "ordered by severity. Implement fixes in priority order.",
        st["body"]))
    story.append(Spacer(1, 4*mm))

    idx = 1
    for sev in sev_order:
        items = by_sev[sev]
        if not items:
            continue
        bg, fg = SEV_COLOURS[sev]
        story.append(Paragraph(f"{sev} Severity Findings", st["subsection"]))
        for f in items:
            block = _finding_block(f, idx, st, remediation_only=True)
            story.append(KeepTogether(block[:2]))
            for el in block[2:]:
                story.append(el)
            idx += 1

    # Verification checklist
    story.append(PageBreak())
    story.append(Paragraph("5. Post-Remediation Verification Checklist", st["section"]))
    story.append(_hr())
    story.append(Paragraph(
        "After applying fixes, use this checklist to verify each remediation was successful "
        "before requesting a re-test.",
        st["body"]))
    story.append(Spacer(1, 4*mm))

    checks = [
        ("All CRITICAL findings patched or mitigated", "CRITICAL"),
        ("All HIGH findings patched or mitigated", "HIGH"),
        ("Security headers added to web server configuration", "MEDIUM"),
        ("SSL/TLS certificates valid and up to date", "MEDIUM"),
        ("Firewall rules restrict unnecessary open ports", "MEDIUM"),
        ("Default credentials changed on all services", "HIGH"),
        ("Input validation implemented on all user inputs", "CRITICAL"),
        ("Error messages do not expose stack traces or DB details", "MEDIUM"),
        ("Patch management process documented and scheduled", "LOW"),
        ("Security training completed for development team", "LOW"),
        ("Re-test scheduled with security team", "INFO"),
    ]
    check_rows = [[
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">☐</font>', st["body_small"]),
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">TASK</font>', st["body_small"]),
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">SEVERITY</font>', st["body_small"]),
        Paragraph('<font name="Helvetica-Bold" size="8" color="#D4A017">OWNER</font>', st["body_small"]),
    ]]
    for task, sev in checks:
        bg, fg = SEV_COLOURS.get(sev, (DARK2, MUTED))
        check_rows.append([
            Paragraph('<font size="10" color="#6DBF8A">☐</font>', st["body_small"]),
            Paragraph(f'<font size="8" color="#F0E8D0">{task}</font>', st["body_small"]),
            Paragraph(f'<font name="Helvetica-Bold" size="8">{sev}</font>',
                      ParagraphStyle("x", textColor=fg)),
            Paragraph('<font size="8" color="#8A7A50">___________</font>', st["body_small"]),
        ])
    ct = Table(check_rows, colWidths=[8*mm, None, 24*mm, 36*mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),DARK2),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[DARK,DARK2]),
        ("GRID",(0,0),(-1,-1),0.3,GOLD_DIM),
        ("LEFTPADDING",(0,0),(-1,-1),6),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    story.append(ct)
    story.append(Spacer(1,6*mm))

    # Footer
    story.append(_hr())
    story.append(Paragraph(
        f"Generated by Wouapit-Hack | {meta['date']} | CONFIDENTIAL — Authorised Security Testing Only",
        st["disclaimer"]))

    doc.build(story)
    with open(filepath, "wb") as fh:
        fh.write(buf.getvalue())

    return {"success": True, "filename": filename, "filepath": filepath, "type": "remediation",
            "summary": {"total": len(findings), "phases": {s: len(by_sev[s]) for s in sev_order}}}
