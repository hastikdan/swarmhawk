"""
report_pdf.py
=============
Generates a branded SwarmHawk security report PDF using ReportLab.
Called by report_email.py — returns PDF as bytes.

Install: pip3 install reportlab --break-system-packages
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
import io

# ── Brand colours ─────────────────────────────────────────────────────────────
BLACK  = colors.HexColor("#0E0D12")
LIME   = colors.HexColor("#CBFF00")
NAVY   = colors.HexColor("#0D1B3E")
WHITE  = colors.white
GREY   = colors.HexColor("#6B7280")
LGREY  = colors.HexColor("#F2F5F9")
PALE   = colors.HexColor("#F0F7E6")
ACCENT = colors.HexColor("#3A6200")
RED    = colors.HexColor("#C0392B")
AMBER  = colors.HexColor("#D4850A")

STATUS_COLORS = {
    "critical": "#C0392B",
    "warning":  "#D4850A",
    "ok":       "#1A7A4A",
    "error":    "#6B7280",
}

STATUS_ICONS = {
    "critical": "CRITICAL",
    "warning":  "WARNING",
    "ok":       "OK",
    "error":    "ERROR",
}

# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    s = getSampleStyleSheet()
    base = {"fontName": "Helvetica", "fontSize": 10, "leading": 14, "textColor": NAVY}

    styles = {
        "domain":    ParagraphStyle("domain",    fontName="Helvetica-Bold", fontSize=28, textColor=WHITE,    leading=34),
        "subtitle":  ParagraphStyle("subtitle",  fontName="Helvetica",      fontSize=13, textColor=LIME,     leading=18),
        "section":   ParagraphStyle("section",   fontName="Helvetica-Bold", fontSize=11, textColor=LIME,     leading=16, spaceAfter=4),
        "body":      ParagraphStyle("body",      fontName="Helvetica",      fontSize=9,  textColor=NAVY,     leading=13, spaceAfter=6),
        "body_bold": ParagraphStyle("body_bold", fontName="Helvetica-Bold", fontSize=9,  textColor=NAVY,     leading=13, spaceAfter=4),
        "small":     ParagraphStyle("small",     fontName="Helvetica",      fontSize=8,  textColor=GREY,     leading=11),
        "ai":        ParagraphStyle("ai",        fontName="Helvetica",      fontSize=8.5,textColor=NAVY,     leading=13, spaceAfter=4),
        "footer":    ParagraphStyle("footer",    fontName="Helvetica",      fontSize=7.5,textColor=GREY,     leading=10, alignment=TA_CENTER),
        "risk_num":  ParagraphStyle("risk_num",  fontName="Helvetica-Bold", fontSize=36, textColor=LIME,     leading=40, alignment=TA_CENTER),
        "risk_lbl":  ParagraphStyle("risk_lbl",  fontName="Helvetica",      fontSize=8,  textColor=LIME,     leading=10, alignment=TA_CENTER),
    }
    return styles

# ── Header / Footer ───────────────────────────────────────────────────────────
def make_header_footer(canvas, doc, domain, scan_date, risk_score):
    canvas.saveState()
    W, H = A4

    # Top black bar
    canvas.setFillColor(BLACK)
    canvas.rect(0, H - 18*mm, W, 18*mm, fill=1, stroke=0)
    canvas.setFillColor(LIME)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(12*mm, H - 11*mm, "SWARMHAWK")
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(W - 12*mm, H - 11*mm, f"Security Report  |  {domain}  |  {scan_date}")

    # Bottom bar
    canvas.setFillColor(BLACK)
    canvas.rect(0, 0, W, 10*mm, fill=1, stroke=0)
    canvas.setFillColor(GREY)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(12*mm, 3.5*mm, "CONFIDENTIAL — For authorised recipients only")
    canvas.drawRightString(W - 12*mm, 3.5*mm, f"Page {doc.page}")

    canvas.restoreState()

# ── Risk score gauge ──────────────────────────────────────────────────────────
def risk_color(score):
    if score >= 60: return RED
    if score >= 30: return AMBER
    return colors.HexColor("#1A7A4A")

def risk_label(score):
    if score >= 60: return "HIGH RISK"
    if score >= 30: return "MEDIUM RISK"
    return "LOW RISK"

# ── Main PDF builder ──────────────────────────────────────────────────────────
def build_report_pdf(scan_data: dict) -> bytes:
    """
    scan_data = {
        "domain": "csob.cz",
        "country": "CZ",
        "scanned_at": "2026-03-04T...",
        "risk_score": 30,
        "critical": 1,
        "warnings": 1,
        "checks": [...],   # list of check result dicts
    }
    Returns PDF as bytes.
    """
    buffer = io.BytesIO()
    domain     = scan_data.get("domain", "unknown")
    risk_score = scan_data.get("risk_score", 0)
    critical   = scan_data.get("critical", 0)
    warnings   = scan_data.get("warnings", 0)
    checks     = scan_data.get("checks", [])
    country    = scan_data.get("country", "")
    scan_dt    = scan_data.get("scanned_at", datetime.utcnow().isoformat())
    try:
        scan_date = datetime.fromisoformat(scan_dt[:19]).strftime("%d %b %Y")
    except:
        scan_date = scan_dt[:10]

    styles = make_styles()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=22*mm, bottomMargin=14*mm,
        leftMargin=12*mm, rightMargin=12*mm,
        title=f"SwarmHawk Security Report — {domain}",
        author="SwarmHawk",
    )

    story = []
    W = A4[0] - 24*mm  # content width

    # ── Cover block ──────────────────────────────────────────────────────────
    cover_data = [[
        # Left: domain + meta
        [
            Paragraph(domain, styles["domain"]),
            Spacer(1, 2*mm),
            Paragraph(f"Monthly Security Report  ·  {scan_date}  ·  {country}", styles["subtitle"]),
        ],
        # Right: risk score
        [
            Paragraph(str(risk_score), styles["risk_num"]),
            Paragraph("RISK SCORE", styles["risk_lbl"]),
            Paragraph(risk_label(risk_score), ParagraphStyle("rl2",
                fontName="Helvetica-Bold", fontSize=9,
                textColor=risk_color(risk_score), alignment=TA_CENTER)),
        ],
    ]]
    cover_tbl = Table(cover_data, colWidths=[W*0.65, W*0.35])
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), BLACK),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",(0,0),(0,-1), 6*mm),
        ("RIGHTPADDING",(-1,0),(-1,-1), 4*mm),
        ("TOPPADDING", (0,0),(-1,-1), 6*mm),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6*mm),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 4*mm))

    # Summary stats row
    stats = [["CRITICAL FINDINGS", "WARNINGS", "CHECKS PASSED", "RISK LEVEL"]]
    passed = sum(1 for c in checks if c.get("status") == "ok")
    stats.append([
        str(critical), str(warnings), str(passed), risk_label(risk_score)
    ])
    stats_tbl = Table(stats, colWidths=[W/4]*4)
    stats_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), NAVY),
        ("TEXTCOLOR",   (0,0), (-1,0), LIME),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0), (-1,-1), 3*mm),
        ("BOTTOMPADDING",(0,0),(-1,-1), 3*mm),
        ("BACKGROUND",  (0,1), (0,1), colors.HexColor("#FDECEA") if critical else PALE),
        ("TEXTCOLOR",   (0,1), (0,1), RED if critical else ACCENT),
        ("FONTNAME",    (0,1), (0,1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,1), (0,1), 18 if critical else 14),
        ("BACKGROUND",  (1,1), (1,1), colors.HexColor("#FFF8E6") if warnings else PALE),
        ("TEXTCOLOR",   (1,1), (1,1), AMBER if warnings else ACCENT),
        ("FONTNAME",    (1,1), (1,1), "Helvetica-Bold"),
        ("FONTSIZE",    (1,1), (1,1), 18 if warnings else 14),
        ("BACKGROUND",  (2,1), (2,1), PALE),
        ("TEXTCOLOR",   (2,1), (2,1), ACCENT),
        ("FONTNAME",    (2,1), (2,1), "Helvetica-Bold"),
        ("FONTSIZE",    (2,1), (2,1), 14),
        ("BACKGROUND",  (3,1), (3,1), BLACK),
        ("TEXTCOLOR",   (3,1), (3,1), risk_color(risk_score)),
        ("FONTNAME",    (3,1), (3,1), "Helvetica-Bold"),
        ("FONTSIZE",    (3,1), (3,1), 9),
        ("GRID",        (0,0), (-1,-1), 0.5, WHITE),
    ]))
    story.append(stats_tbl)
    story.append(Spacer(1, 5*mm))

    # ── Check results table ───────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIME))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("SECURITY CHECK RESULTS", styles["section"]))
    story.append(Spacer(1, 1*mm))

    check_rows = [["STATUS", "CHECK", "FINDING"]]
    for c in checks:
        if c.get("check") == "ai_summary":
            continue
        status = c.get("status", "ok")
        col    = STATUS_COLORS.get(status, GREY)
        label  = STATUS_ICONS.get(status, status.upper())
        check_rows.append([
            Paragraph(f'<font color="{col}">{label}</font>', styles["small"]),
            Paragraph(c.get("check","").replace("_"," ").upper(), styles["small"]),
            Paragraph((c.get("title","") or "")[:120], styles["small"]),
        ])

    checks_tbl = Table(check_rows, colWidths=[18*mm, 28*mm, W-46*mm])
    style_cmds = [
        ("BACKGROUND",    (0,0), (-1,0), NAVY),
        ("TEXTCOLOR",     (0,0), (-1,0), LIME),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("ALIGN",         (0,0), (1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 2.5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2.5),
        ("LEFTPADDING",   (0,0), (-1,-1), 3),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LGREY]),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#D1D5DB")),
    ]
    # Colour status cells
    for i, c in enumerate(checks, start=1):
        if c.get("check") == "ai_summary": continue
        status = c.get("status","ok")
        if status == "critical":
            style_cmds.append(("BACKGROUND", (0,i),(0,i), colors.HexColor("#FDECEA")))
            style_cmds.append(("TEXTCOLOR",  (0,i),(0,i), RED))
        elif status == "warning":
            style_cmds.append(("BACKGROUND", (0,i),(0,i), colors.HexColor("#FFF8E6")))
            style_cmds.append(("TEXTCOLOR",  (0,i),(0,i), AMBER))
        elif status == "ok":
            style_cmds.append(("TEXTCOLOR",  (0,i),(0,i), ACCENT))

    checks_tbl.setStyle(TableStyle(style_cmds))
    story.append(checks_tbl)
    story.append(Spacer(1, 5*mm))

    # ── AI Analysis section ───────────────────────────────────────────────────
    ai_check = next((c for c in checks if c.get("check") == "ai_summary"), None)
    if ai_check and ai_check.get("detail"):
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIME))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("AI THREAT ANALYSIS & RECOMMENDATIONS", styles["section"]))
        story.append(Spacer(1, 1*mm))

        # Render AI text in a shaded box
        ai_text = ai_check["detail"]
        # Split into sections by numbered headers
        lines = ai_text.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                story.append(Spacer(1, 1.5*mm))
                continue
            # Section headers (1. EXECUTIVE SUMMARY etc)
            if line and line[0].isdigit() and ". " in line[:4]:
                story.append(Spacer(1, 2*mm))
                story.append(Paragraph(line.upper(), styles["body_bold"]))
            else:
                story.append(Paragraph(line, styles["ai"]))

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=0.3, color=GREY))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        f"This report was automatically generated by SwarmHawk on {scan_date}. "
        "Next report will be sent in 30 days. "
        "To manage your subscription visit hastikdan.github.io/cee-scanner",
        styles["footer"]
    ))

    doc.build(
        story,
        onFirstPage =lambda c,d: make_header_footer(c, d, domain, scan_date, risk_score),
        onLaterPages=lambda c,d: make_header_footer(c, d, domain, scan_date, risk_score),
    )
    return buffer.getvalue()
