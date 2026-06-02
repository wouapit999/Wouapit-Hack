"""
PDF report generator – clean white background, fully readable, Bouquet Innovation logo.
Two report types:
  • generate_pdf_report()      – Full penetration test report
  • generate_remediation_pdf() – Remediation roadmap report
"""

import os, io
from datetime import datetime

# ── Logo path ────────────────────────────────────────────────────────────────
_BASE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGO_PATH = os.path.join(_BASE, "static", "img", "bouquet_logo.png")

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether, Image as RLImage,
    )
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ── Palette (light/readable) ─────────────────────────────────────────────────
GOLD        = colors.HexColor("#B48C14")
GOLD_DARK   = colors.HexColor("#7A5E00")
GOLD_LIGHT  = colors.HexColor("#D4A017")
BLACK       = colors.HexColor("#1A1A1A")
GREY_DARK   = colors.HexColor("#2C2C2C")
GREY_MID    = colors.HexColor("#555555")
GREY_LIGHT  = colors.HexColor("#F5F5F5")
GREY_BORDER = colors.HexColor("#DDDDDD")
WHITE       = colors.white

SEV = {
    "CRITICAL": (colors.HexColor("#7D1128"), colors.HexColor("#FFE4E9"), colors.HexColor("#FFD0DA")),
    "HIGH":     (colors.HexColor("#9B2335"), colors.HexColor("#FFF0F0"), colors.HexColor("#FFD6D6")),
    "MEDIUM":   (colors.HexColor("#7A4F00"), colors.HexColor("#FFF8E6"), colors.HexColor("#FFE8B0")),
    "LOW":      (colors.HexColor("#1A5C2A"), colors.HexColor("#F0FFF4"), colors.HexColor("#C8EDD4")),
    "INFO":     (colors.HexColor("#1A3A5C"), colors.HexColor("#F0F5FF"), colors.HexColor("#C8D9F0")),
}

PAGE_W, PAGE_H = A4
MARGIN  = 18 * mm
CONTENT = PAGE_W - 2 * MARGIN


# ── Styles ───────────────────────────────────────────────────────────────────
def _styles():
    def s(name, **kw):
        return ParagraphStyle(name, **kw)
    return {
        "h1":        s("h1",  fontName="Helvetica-Bold",   fontSize=22, textColor=GOLD,      spaceBefore=0,  spaceAfter=4,  leading=26),
        "h2":        s("h2",  fontName="Helvetica-Bold",   fontSize=14, textColor=GOLD_DARK,  spaceBefore=14, spaceAfter=5,  leading=18),
        "h3":        s("h3",  fontName="Helvetica-Bold",   fontSize=11, textColor=GREY_DARK,  spaceBefore=10, spaceAfter=4,  leading=15),
        "body":      s("bd",  fontName="Helvetica",        fontSize=9,  textColor=GREY_DARK,  spaceAfter=4,   leading=14, alignment=TA_JUSTIFY),
        "body_left": s("bdl", fontName="Helvetica",        fontSize=9,  textColor=GREY_DARK,  spaceAfter=3,   leading=14),
        "small":     s("sm",  fontName="Helvetica",        fontSize=8,  textColor=GREY_MID,   spaceAfter=2,   leading=12),
        "code":      s("cd",  fontName="Courier",          fontSize=8,  textColor=GREY_DARK,  spaceAfter=3,   leading=11,
                                                           backColor=colors.HexColor("#F8F8F8"), leftIndent=6, borderPadding=4),
        "label":     s("lb",  fontName="Helvetica-Bold",   fontSize=8,  textColor=GREY_MID,   spaceAfter=1,   spaceBefore=6, textTransform="uppercase"),
        "cover_co":  s("cco", fontName="Helvetica-Bold",   fontSize=11, textColor=GREY_MID,   spaceAfter=2),
        "cover_tgt": s("ctg", fontName="Helvetica-Bold",   fontSize=28, textColor=GOLD_DARK,  spaceAfter=6,   leading=32),
        "cover_sub": s("csb", fontName="Helvetica",        fontSize=14, textColor=GREY_MID,   spaceAfter=3),
        "cover_meta":s("cmt", fontName="Helvetica",        fontSize=9,  textColor=GREY_MID,   spaceAfter=2),
        "disclaimer":s("dis", fontName="Helvetica-Oblique",fontSize=8,  textColor=GREY_MID,   alignment=TA_CENTER, spaceAfter=2),
        "toc":       s("toc", fontName="Helvetica",        fontSize=9,  textColor=GREY_DARK,  spaceAfter=4,   leftIndent=12),
    }


def _hr():
    return HRFlowable(width=CONTENT, thickness=1, color=GOLD_LIGHT,
                      spaceAfter=6, spaceBefore=2)


def _thin_hr():
    return HRFlowable(width=CONTENT, thickness=0.4, color=GREY_BORDER,
                      spaceAfter=4, spaceBefore=4)


# ── Logo helper ───────────────────────────────────────────────────────────────
def _logo_img(height=18*mm):
    if os.path.exists(LOGO_PATH):
        return RLImage(LOGO_PATH, height=height, width=height * 0.9)
    return Paragraph("<b>BOUQUET INNOVATION Lda</b>",
                     ParagraphStyle("li", fontName="Helvetica-Bold",
                                    fontSize=9, textColor=GOLD))


# ── Page template with header/footer ─────────────────────────────────────────
def _build_doc(filepath, title):
    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=28*mm, bottomMargin=20*mm,
        title=title, author="Bouquet Innovation Lda / Wouapit-Hack",
    )

    def on_page(canvas, doc):
        canvas.saveState()
        # Header line
        canvas.setStrokeColor(GOLD_LIGHT)
        canvas.setLineWidth(1.5)
        canvas.line(MARGIN, PAGE_H - 18*mm, PAGE_W - MARGIN, PAGE_H - 18*mm)
        # Logo left
        if os.path.exists(LOGO_PATH):
            canvas.drawImage(LOGO_PATH, MARGIN, PAGE_H - 17*mm,
                             width=14*mm, height=14*mm,
                             preserveAspectRatio=True, mask="auto")
        # Title right
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(GOLD)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 12*mm, "WOUAPIT-HACK  |  BOUQUET INNOVATION Lda")
        # Footer
        canvas.setStrokeColor(GREY_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 14*mm, PAGE_W - MARGIN, 14*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GREY_MID)
        canvas.drawString(MARGIN, 10*mm, "CONFIDENTIAL – Authorised Security Testing Only")
        canvas.drawRightString(PAGE_W - MARGIN, 10*mm,
                               f"Page {doc.page}  |  {datetime.utcnow().strftime('%d %b %Y')}")
        canvas.restoreState()

    doc._on_page = on_page
    return doc


# ── Severity badge ────────────────────────────────────────────────────────────
def _sev_badge(sev, st):
    text_c, bg_c, _ = SEV.get(sev.upper(), (GREY_MID, GREY_LIGHT, GREY_BORDER))
    p = Paragraph(
        f'<font name="Helvetica-Bold" size="8">{sev.upper()}</font>',
        ParagraphStyle("sv", textColor=text_c, alignment=TA_CENTER))
    t = Table([[p]], colWidths=[22*mm], rowHeights=[6*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), bg_c),
        ("BOX",        (0,0),(-1,-1), 0.5, text_c),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
    ]))
    return t


# ── Severity summary table ────────────────────────────────────────────────────
def _sev_table(findings, st):
    counts = {s: sum(1 for f in findings if f.get("severity","INFO").upper()==s)
              for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
    slas   = {"CRITICAL":"Immediate (24 h)","HIGH":"72 hours","MEDIUM":"30 days",
              "LOW":"90 days","INFO":"Advisory"}
    rows   = [[
        Paragraph('<font name="Helvetica-Bold" size="8">SEVERITY</font>', st["small"]),
        Paragraph('<font name="Helvetica-Bold" size="8">COUNT</font>',    st["small"]),
        Paragraph('<font name="Helvetica-Bold" size="8">REMEDIATION SLA</font>', st["small"]),
        Paragraph('<font name="Helvetica-Bold" size="8">RISK LEVEL</font>', st["small"]),
    ]]
    risk = {"CRITICAL":"Critical – Act immediately","HIGH":"High – Act within 72 h",
            "MEDIUM":"Medium – Act within 30 days","LOW":"Low – Schedule fix","INFO":"Informational"}
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        tc, bg, lt = SEV[sev]
        rows.append([
            Paragraph(f'<font name="Helvetica-Bold" size="9">{sev}</font>',
                      ParagraphStyle("x", textColor=tc)),
            Paragraph(f'<font name="Helvetica-Bold" size="14">{counts[sev]}</font>',
                      ParagraphStyle("x", textColor=tc, alignment=TA_CENTER)),
            Paragraph(f'<font size="8">{slas[sev]}</font>', st["small"]),
            Paragraph(f'<font size="8">{risk[sev]}</font>', st["small"]),
        ])
    t = Table(rows, colWidths=[32*mm, 20*mm, 42*mm, None])
    style = [
        ("BACKGROUND", (0,0),(-1,0), GREY_LIGHT),
        ("LINEBELOW",  (0,0),(-1,0), 1, GOLD_LIGHT),
        ("GRID",       (0,0),(-1,-1),0.4, GREY_BORDER),
        ("LEFTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING", (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
    ]
    for i, sev in enumerate(("CRITICAL","HIGH","MEDIUM","LOW","INFO"), 1):
        _, bg, lt = SEV[sev]
        style += [("BACKGROUND",(0,i),(0,i), bg), ("BACKGROUND",(1,i),(1,i), bg)]
    t.setStyle(TableStyle(style))
    return t


# ── Single finding block ──────────────────────────────────────────────────────
def _finding_block(f, idx, st, remediation_only=False):
    sev = f.get("severity","INFO").upper()
    tc, bg, lt = SEV.get(sev, SEV["INFO"])
    out = []

    # Header bar
    title_p = Paragraph(
        f'<font name="Helvetica-Bold" size="10">#{idx}  {f.get("title","Untitled")}</font>',
        ParagraphStyle("fh", textColor=GREY_DARK, leading=14))
    badge_p = Paragraph(
        f'<font name="Helvetica-Bold" size="8">{sev}</font>',
        ParagraphStyle("bh", textColor=tc, alignment=TA_CENTER))
    badge_t = Table([[badge_p]], colWidths=[22*mm], rowHeights=[6*mm])
    badge_t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1), bg),
        ("BOX",(0,0),(-1,-1), 0.5, tc),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    hdr = Table([[title_p, badge_t]], colWidths=[CONTENT - 26*mm, 26*mm])
    hdr.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1), lt),
        ("LINEBELOW", (0,0),(-1,-1), 2, tc),
        ("LEFTPADDING",(0,0),(-1,-1), 10),
        ("RIGHTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING",(0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    out.append(hdr)

    def field(label, value, code=False):
        if not value or str(value).strip() in ("", "N/A", "None"):
            return
        out.append(Paragraph(label, st["label"]))
        out.append(Paragraph(str(value)[:1000], st["code"] if code else st["body_left"]))

    if not remediation_only:
        field("Description", f.get("description"))
        field("Location / URL", f.get("location"))
        field("CVSS Score", f.get("cvss"))
        field("Evidence / Proof of Concept", f.get("evidence"), code=True)

    field("Remediation", f.get("remediation"))
    out.append(Spacer(1, 4*mm))
    return out


# ── Cover page ────────────────────────────────────────────────────────────────
def _cover(story, meta, report_type, st):
    story.append(Spacer(1, 18*mm))

    # Logo + company name
    logo_row = [[_logo_img(24*mm),
                 Paragraph(
                     '<font name="Helvetica-Bold" size="13" color="#B48C14">BOUQUET INNOVATION Lda</font><br/>'
                     '<font name="Helvetica" size="9" color="#777777">Cybersecurity &amp; Technology Consultancy</font>',
                     ParagraphStyle("cr", leading=16))]]
    lt = Table(logo_row, colWidths=[28*mm, None])
    lt.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),0),
    ]))
    story.append(lt)
    story.append(Spacer(1, 8*mm))

    # Gold divider
    story.append(HRFlowable(width=CONTENT, thickness=3, color=GOLD, spaceAfter=8))

    # Report type label
    story.append(Paragraph(report_type, st["cover_sub"]))
    story.append(Spacer(1, 3*mm))

    # Report title (big)
    story.append(Paragraph(meta.get("title","Penetration Test Report"), st["cover_tgt"]))
    story.append(HRFlowable(width=CONTENT, thickness=0.5, color=GREY_BORDER, spaceAfter=8))

    # Metadata grid
    meta_rows = [
        ["Target",          meta.get("target","—")],
        ["Engagement Type", meta.get("engagement_type","—")],
        ["Testing Period",  meta.get("testing_period","—")],
        ["Tester",          meta.get("tester","—")],
        ["Date",            meta.get("date","—")],
        ["Classification",  meta.get("classification","CONFIDENTIAL")],
    ]
    meta_data = [[
        Paragraph(f'<font name="Helvetica-Bold" size="9" color="#B48C14">{r}</font>',
                  ParagraphStyle("mk", textColor=GOLD)),
        Paragraph(f'<font name="Helvetica" size="9" color="#2C2C2C">{v}</font>',
                  ParagraphStyle("mv", textColor=GREY_DARK)),
    ] for r, v in meta_rows]
    mt = Table(meta_data, colWidths=[40*mm, None])
    mt.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[WHITE, GREY_LIGHT]),
        ("GRID",          (0,0),(-1,-1), 0.3, GREY_BORDER),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
    ]))
    story.append(mt)
    story.append(Spacer(1, 12*mm))
    story.append(Paragraph(
        "This document is CONFIDENTIAL and intended solely for the named recipient. "
        "It contains sensitive security information. Distribution to unauthorised persons is prohibited. "
        "Prepared by Bouquet Innovation Lda using Wouapit-Hack.",
        st["disclaimer"]))
    story.append(PageBreak())


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC: Full pentest report
# ═══════════════════════════════════════════════════════════════════════════════
def generate_pdf_report(data: dict, output_dir: str) -> dict:
    if not REPORTLAB_OK:
        return {"error": "reportlab not installed. pip install reportlab"}

    os.makedirs(output_dir, exist_ok=True)
    now      = datetime.utcnow()
    findings = data.get("findings", [])
    meta = {
        "title":           data.get("title", "Penetration Test Report"),
        "target":          data.get("target", "Unknown"),
        "tester":          data.get("tester", "Bouquet Innovation Lda"),
        "date":            now.strftime("%d %B %Y"),
        "engagement_type": data.get("engagement_type", "Black Box"),
        "classification":  data.get("classification", "CONFIDENTIAL"),
        "testing_period":  data.get("testing_period", now.strftime("%B %Y")),
        "tools_used":      data.get("tools_used", "Wouapit-Hack"),
    }

    slug     = meta["target"].replace(".", "_").replace("/", "_").replace(":", "_")
    filename = f"pentest_{slug}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_dir, filename)

    buf = io.BytesIO()
    doc = _build_doc(buf, meta["title"])
    st  = _styles()
    story = []

    _cover(story, meta, "PENETRATION TEST REPORT", st)

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary", st["h2"]))
    story.append(_hr())
    story.append(Paragraph(
        data.get("executive_summary",
                 f"A penetration test was conducted against {meta['target']}. "
                 f"The assessment identified {len(findings)} finding(s)."),
        st["body"]))
    story.append(Spacer(1, 4*mm))
    story.append(_sev_table(findings, st))
    story.append(Spacer(1, 6*mm))

    # 2. Scope & Methodology
    story.append(Paragraph("2. Scope &amp; Methodology", st["h2"]))
    story.append(_hr())
    rows = [
        ["Target",          meta["target"]],
        ["Engagement Type", meta["engagement_type"]],
        ["Testing Period",  meta["testing_period"]],
        ["Tester",          meta["tester"]],
        ["Tools Used",      meta["tools_used"]],
        ["Methodology",     "OWASP Testing Guide v4, PTES, OWASP Top 10"],
    ]
    tbl = Table(
        [[Paragraph(f'<b><font size="8" color="#B48C14">{r}</font></b>',
                    ParagraphStyle("k")),
          Paragraph(f'<font size="8">{v}</font>',
                    ParagraphStyle("v", textColor=GREY_DARK))]
         for r, v in rows],
        colWidths=[42*mm, None])
    tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[WHITE, GREY_LIGHT]),
        ("GRID",          (0,0),(-1,-1), 0.3, GREY_BORDER),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 6*mm))

    # 3. Reconnaissance Results
    recon = data.get("recon", {})
    if any(recon.get(k) for k in ("open_ports","subdomains","technologies","headers")):
        story.append(Paragraph("3. Reconnaissance Results", st["h2"]))
        story.append(_hr())

        if recon.get("technologies"):
            story.append(Paragraph("Technologies Detected", st["h3"]))
            story.append(Paragraph(", ".join(recon["technologies"]), st["body"]))

        if recon.get("open_ports"):
            story.append(Paragraph("Open Ports", st["h3"]))
            port_rows = [[
                Paragraph('<b><font size="8">PORT</font></b>', st["small"]),
                Paragraph('<b><font size="8">STATE</font></b>', st["small"]),
                Paragraph('<b><font size="8">SERVICE</font></b>', st["small"]),
            ]] + [[
                Paragraph(f'<b><font size="8">{p.get("port","")}</font></b>', st["small"]),
                Paragraph('<font size="8" color="#1A5C2A">OPEN</font>', st["small"]),
                Paragraph(f'<font size="8">{p.get("service","")}</font>', st["small"]),
            ] for p in recon["open_ports"][:50]]
            pt = Table(port_rows, colWidths=[24*mm, 22*mm, None])
            pt.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0), GREY_LIGHT),
                ("LINEBELOW", (0,0),(-1,0), 1, GOLD_LIGHT),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, colors.HexColor("#FAFAFA")]),
                ("GRID",     (0,0),(-1,-1), 0.3, GREY_BORDER),
                ("LEFTPADDING",(0,0),(-1,-1), 6),
                ("TOPPADDING",(0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ]))
            story.append(pt)
            story.append(Spacer(1, 3*mm))

        if recon.get("subdomains"):
            story.append(Paragraph("Subdomains Found", st["h3"]))
            sub_rows = [[
                Paragraph('<b><font size="8">SUBDOMAIN</font></b>', st["small"]),
                Paragraph('<b><font size="8">IP ADDRESS</font></b>', st["small"]),
            ]] + [[
                Paragraph(f'<font size="8">{s.get("subdomain","")}</font>', st["small"]),
                Paragraph(f'<font size="8">{s.get("ip","")}</font>', st["small"]),
            ] for s in recon["subdomains"][:30]]
            st2 = Table(sub_rows, colWidths=[None, 40*mm])
            st2.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0), GREY_LIGHT),
                ("LINEBELOW",(0,0),(-1,0), 1, GOLD_LIGHT),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, colors.HexColor("#FAFAFA")]),
                ("GRID",(0,0),(-1,-1), 0.3, GREY_BORDER),
                ("LEFTPADDING",(0,0),(-1,-1), 6),
                ("TOPPADDING",(0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ]))
            story.append(st2)
            story.append(Spacer(1, 3*mm))

        if recon.get("headers"):
            story.append(Paragraph("Security Headers Audit", st["h3"]))
            hdr_rows = [[
                Paragraph('<b><font size="8">HEADER</font></b>', st["small"]),
                Paragraph('<b><font size="8">STATUS</font></b>', st["small"]),
            ]] + [[
                Paragraph(f'<font size="8">{k}</font>', st["small"]),
                Paragraph(
                    f'<font size="8" color="{"#7D1128" if v=="MISSING" else "#1A5C2A"}">{"✗ MISSING" if v=="MISSING" else "✓ "+str(v)[:60]}</font>',
                    st["small"]),
            ] for k, v in recon["headers"].items()]
            ht = Table(hdr_rows, colWidths=[None, 90*mm])
            ht.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0), GREY_LIGHT),
                ("LINEBELOW",(0,0),(-1,0), 1, GOLD_LIGHT),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, colors.HexColor("#FAFAFA")]),
                ("GRID",(0,0),(-1,-1), 0.3, GREY_BORDER),
                ("LEFTPADDING",(0,0),(-1,-1), 6),
                ("TOPPADDING",(0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ]))
            story.append(ht)
        story.append(Spacer(1, 6*mm))

    # 4. Detailed Findings
    story.append(PageBreak())
    story.append(Paragraph("4. Detailed Findings", st["h2"]))
    story.append(_hr())
    if not findings:
        story.append(Paragraph("No vulnerabilities were identified.", st["body"]))
    else:
        for i, f in enumerate(findings, 1):
            block = _finding_block(f, i, st)
            story.append(KeepTogether(block[:3]))
            for el in block[3:]:
                story.append(el)

    # 5. Recommendations
    story.append(PageBreak())
    story.append(Paragraph("5. Recommendations", st["h2"]))
    story.append(_hr())
    for rec in [
        "Immediately remediate all Critical and High severity findings.",
        "Apply the principle of least privilege across all systems and accounts.",
        "Implement and enforce a Web Application Firewall (WAF).",
        "Enable Multi-Factor Authentication on all externally accessible accounts.",
        "Enforce HTTPS everywhere and configure HSTS with a long max-age.",
        "Add all missing security headers to web server configurations.",
        "Conduct regular penetration tests (minimum annually).",
        "Maintain a vulnerability management programme with defined SLAs.",
        "Perform security awareness training for all staff quarterly.",
        "Keep all software components, libraries and OS packages patched.",
    ]:
        story.append(Paragraph(f"• {rec}", st["body"]))
    story.append(Spacer(1, 6*mm))

    # Footer disclaimer
    story.append(_thin_hr())
    story.append(Paragraph(
        f"Prepared by Bouquet Innovation Lda using Wouapit-Hack  |  {meta['date']}  |  CONFIDENTIAL",
        st["disclaimer"]))

    doc.build(story, onFirstPage=doc._on_page, onLaterPages=doc._on_page)
    with open(filepath, "wb") as fh:
        fh.write(buf.getvalue())

    counts = {s: sum(1 for f in findings if f.get("severity","INFO").upper()==s)
              for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
    return {"success": True, "filename": filename, "filepath": filepath, "type": "pentest",
            "summary": {"total_findings": len(findings), "severity_counts": counts}}


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC: Remediation report
# ═══════════════════════════════════════════════════════════════════════════════
def generate_remediation_pdf(data: dict, output_dir: str) -> dict:
    if not REPORTLAB_OK:
        return {"error": "reportlab not installed. pip install reportlab"}

    os.makedirs(output_dir, exist_ok=True)
    now      = datetime.utcnow()
    findings = data.get("findings", [])
    meta = {
        "title":           data.get("title", "Remediation Report"),
        "target":          data.get("target", "Unknown"),
        "tester":          data.get("tester", "Bouquet Innovation Lda"),
        "date":            now.strftime("%d %B %Y"),
        "engagement_type": data.get("engagement_type", "Black Box"),
        "classification":  data.get("classification", "CONFIDENTIAL"),
        "testing_period":  data.get("testing_period", now.strftime("%B %Y")),
    }

    slug     = meta["target"].replace(".", "_").replace("/", "_").replace(":", "_")
    filename = f"remediation_{slug}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_dir, filename)

    buf = io.BytesIO()
    doc = _build_doc(buf, f"Remediation – {meta['title']}")
    st  = _styles()
    story = []

    _cover(story, meta, "REMEDIATION REPORT", st)

    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    by_sev    = {s: [f for f in findings if f.get("severity","INFO").upper()==s]
                 for s in sev_order}
    slas  = {"CRITICAL":"24 hours","HIGH":"72 hours","MEDIUM":"30 days","LOW":"90 days","INFO":"Advisory"}
    effort= {"CRITICAL":"High","HIGH":"High","MEDIUM":"Medium","LOW":"Low","INFO":"Minimal"}

    # 1. Purpose
    story.append(Paragraph("1. Purpose", st["h2"]))
    story.append(_hr())
    story.append(Paragraph(
        "This remediation report provides a prioritised, actionable roadmap to address all security "
        "findings identified during the penetration test. Findings are ordered by severity — address "
        "Critical items before moving to lower-priority issues. Each finding includes concrete "
        "remediation steps, estimated effort, and a recommended timeline.",
        st["body"]))
    story.append(Spacer(1, 4*mm))

    # 2. Priority Matrix
    story.append(Paragraph("2. Remediation Priority Matrix", st["h2"]))
    story.append(_hr())
    m_rows = [[
        Paragraph('<b><font size="8">SEVERITY</font></b>', st["small"]),
        Paragraph('<b><font size="8">COUNT</font></b>',    st["small"]),
        Paragraph('<b><font size="8">SLA</font></b>',      st["small"]),
        Paragraph('<b><font size="8">EFFORT</font></b>',   st["small"]),
        Paragraph('<b><font size="8">PRIORITY</font></b>', st["small"]),
    ]]
    p_labels = {"CRITICAL":"P1","HIGH":"P2","MEDIUM":"P3","LOW":"P4","INFO":"P5"}
    for sev in sev_order:
        tc, bg, lt = SEV[sev]
        m_rows.append([
            Paragraph(f'<b><font size="9">{sev}</font></b>',
                      ParagraphStyle("x", textColor=tc)),
            Paragraph(f'<b><font size="14">{len(by_sev[sev])}</font></b>',
                      ParagraphStyle("x", textColor=tc, alignment=TA_CENTER)),
            Paragraph(f'<font size="8">{slas[sev]}</font>', st["small"]),
            Paragraph(f'<font size="8">{effort[sev]}</font>', st["small"]),
            Paragraph(f'<b><font size="9">{p_labels[sev]}</font></b>',
                      ParagraphStyle("x", textColor=tc, alignment=TA_CENTER)),
        ])
    mt = Table(m_rows, colWidths=[32*mm, 18*mm, 34*mm, 26*mm, 20*mm])
    mstyle = [
        ("BACKGROUND",(0,0),(-1,0), GREY_LIGHT),
        ("LINEBELOW",  (0,0),(-1,0), 1, GOLD_LIGHT),
        ("GRID",       (0,0),(-1,-1),0.3, GREY_BORDER),
        ("LEFTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING", (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("VALIGN",     (0,0),(-1,-1),"MIDDLE"),
    ]
    for i, sev in enumerate(sev_order, 1):
        _, bg, _ = SEV[sev]
        mstyle += [("BACKGROUND",(0,i),(1,i), bg)]
    mt.setStyle(TableStyle(mstyle))
    story.append(mt)
    story.append(Spacer(1, 6*mm))

    # 3. Roadmap
    story.append(Paragraph("3. Remediation Roadmap", st["h2"]))
    story.append(_hr())
    phases = [
        ("Phase 1 — Immediate (0–24 h)",   "CRITICAL"),
        ("Phase 2 — Short Term (1–3 days)", "HIGH"),
        ("Phase 3 — Medium Term (30 days)", "MEDIUM"),
        ("Phase 4 — Long Term (90 days)",   "LOW"),
        ("Phase 5 — Advisory",              "INFO"),
    ]
    for label, sev in phases:
        items = by_sev[sev]
        if not items:
            continue
        tc, bg, lt = SEV[sev]
        phase_p = Paragraph(
            f'<font name="Helvetica-Bold" size="9">{label}  ({len(items)} item{"s" if len(items)!=1 else ""})</font>',
            ParagraphStyle("ph", textColor=tc, leading=14))
        phase_t = Table([[phase_p]], colWidths=[CONTENT])
        phase_t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1), bg),
            ("LINEBELOW",  (0,0),(-1,-1), 2, tc),
            ("LEFTPADDING",(0,0),(-1,-1), 10),
            ("TOPPADDING", (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ]))
        story.append(phase_t)
        for item in items:
            story.append(Paragraph(
                f'<font name="Helvetica-Bold" size="8" color="#B48C14">→ {item.get("title","")}</font>  '
                f'<font size="8" color="#888888">CVSS {item.get("cvss","N/A")} | {str(item.get("location",""))[:60]}</font>',
                ParagraphStyle("ri", leftIndent=12, spaceAfter=2, leading=12, textColor=GREY_DARK)))
        story.append(Spacer(1, 3*mm))
    story.append(Spacer(1, 4*mm))

    # 4. Detailed Remediation Steps
    story.append(PageBreak())
    story.append(Paragraph("4. Detailed Remediation Steps", st["h2"]))
    story.append(_hr())
    story.append(Paragraph(
        "Step-by-step remediation guidance for each finding, ordered by severity.",
        st["body"]))
    story.append(Spacer(1, 4*mm))
    idx = 1
    for sev in sev_order:
        items = by_sev[sev]
        if not items:
            continue
        story.append(Paragraph(f"{sev} Severity Findings", st["h3"]))
        for f in items:
            block = _finding_block(f, idx, st, remediation_only=True)
            story.append(KeepTogether(block[:2]))
            for el in block[2:]:
                story.append(el)
            idx += 1

    # 5. Verification Checklist
    story.append(PageBreak())
    story.append(Paragraph("5. Post-Remediation Verification Checklist", st["h2"]))
    story.append(_hr())
    story.append(Paragraph(
        "Use this checklist to verify each remediation before requesting a re-test.",
        st["body"]))
    story.append(Spacer(1, 4*mm))
    checks = [
        ("All Critical findings patched or mitigated", "CRITICAL"),
        ("All High findings patched or mitigated", "HIGH"),
        ("Security headers configured on web server", "MEDIUM"),
        ("SSL/TLS certificates valid and up to date", "MEDIUM"),
        ("Unnecessary ports firewalled", "MEDIUM"),
        ("Default credentials changed on all services", "HIGH"),
        ("Input validation on all user-supplied inputs", "CRITICAL"),
        ("Error messages do not expose stack traces", "MEDIUM"),
        ("Patch management process documented", "LOW"),
        ("Security training completed for dev team", "LOW"),
        ("Re-test scheduled with security team", "INFO"),
    ]
    c_rows = [[
        Paragraph('<b><font size="8">☐</font></b>', st["small"]),
        Paragraph('<b><font size="8">TASK</font></b>', st["small"]),
        Paragraph('<b><font size="8">SEV</font></b>', st["small"]),
        Paragraph('<b><font size="8">OWNER</font></b>', st["small"]),
        Paragraph('<b><font size="8">DATE DONE</font></b>', st["small"]),
    ]]
    for task, sev in checks:
        tc, bg, _ = SEV.get(sev, (GREY_MID, GREY_LIGHT, GREY_BORDER))
        c_rows.append([
            Paragraph('<font size="10">☐</font>', st["small"]),
            Paragraph(f'<font size="8">{task}</font>', st["small"]),
            Paragraph(f'<font name="Helvetica-Bold" size="7">{sev}</font>',
                      ParagraphStyle("sv", textColor=tc)),
            Paragraph('', st["small"]),
            Paragraph('', st["small"]),
        ])
    ct = Table(c_rows, colWidths=[8*mm, None, 24*mm, 34*mm, 30*mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,0), GREY_LIGHT),
        ("LINEBELOW",    (0,0),(-1,0), 1, GOLD_LIGHT),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, colors.HexColor("#FAFAFA")]),
        ("GRID",         (0,0),(-1,-1), 0.3, GREY_BORDER),
        ("LEFTPADDING",  (0,0),(-1,-1), 6),
        ("TOPPADDING",   (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("VALIGN",       (0,0),(-1,-1),"MIDDLE"),
    ]))
    story.append(ct)
    story.append(Spacer(1, 6*mm))
    story.append(_thin_hr())
    story.append(Paragraph(
        f"Prepared by Bouquet Innovation Lda using Wouapit-Hack  |  {meta['date']}  |  CONFIDENTIAL",
        st["disclaimer"]))

    doc.build(story, onFirstPage=doc._on_page, onLaterPages=doc._on_page)
    with open(filepath, "wb") as fh:
        fh.write(buf.getvalue())

    return {"success": True, "filename": filename, "filepath": filepath, "type": "remediation",
            "summary": {"total": len(findings),
                        "phases": {s: len(by_sev[s]) for s in sev_order}}}
