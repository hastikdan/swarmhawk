"""
report_email.py
===============
Sends monthly SwarmHawk security reports via Resend.
Includes branded HTML email + PDF attachment.

Install: pip3 install resend --break-system-packages
         pip3 install reportlab --break-system-packages

Usage:
    from report_email import send_report
    send_report(user_email="user@example.com", scan_data={...})

Env vars needed:
    RESEND_API_KEY=re_...
"""

import os
import base64
from datetime import datetime

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL = "SwarmHawk <onboarding@resend.dev>"


def _status_badge(status: str) -> str:
    styles = {
        "critical": "background:#FDECEA;color:#C0392B;border:1px solid #C0392B",
        "warning":  "background:#FFF8E6;color:#D4850A;border:1px solid #D4850A",
        "ok":       "background:#E8F5EE;color:#1A7A4A;border:1px solid #1A7A4A",
        "error":    "background:#F3F4F6;color:#6B7280;border:1px solid #D1D5DB",
    }
    labels = {"critical":"CRITICAL","warning":"WARNING","ok":"OK","error":"ERROR"}
    style = styles.get(status, styles["error"])
    label = labels.get(status, status.upper())
    return f'<span style="font-size:10px;font-weight:bold;padding:2px 7px;border-radius:3px;{style}">{label}</span>'


def _risk_color(score: int) -> str:
    if score >= 60: return "#C0392B"
    if score >= 30: return "#D4850A"
    return "#1A7A4A"


def _risk_label(score: int) -> str:
    if score >= 60: return "HIGH RISK"
    if score >= 30: return "MEDIUM RISK"
    return "LOW RISK"


def build_html_email(scan_data: dict) -> str:
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

    risk_col   = _risk_color(risk_score)
    risk_lbl   = _risk_label(risk_score)
    passed     = sum(1 for c in checks if c.get("status") == "ok")

    # Build check rows (skip ai_summary — shown separately)
    check_rows = ""
    for c in checks:
        if c.get("check") == "ai_summary":
            continue
        badge  = _status_badge(c.get("status","ok"))
        check  = c.get("check","").replace("_"," ").title()
        title  = (c.get("title","") or "")[:100]
        detail = (c.get("detail","") or "")[:150]
        bg     = "#FDECEA" if c.get("status")=="critical" else "#FFF8E6" if c.get("status")=="warning" else "#ffffff"
        check_rows += f"""
        <tr style="background:{bg}">
          <td style="padding:8px 10px;border-bottom:1px solid #eee">{badge}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #eee;font-weight:bold;font-size:12px;color:#0D1B3E">{check}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #eee;font-size:12px;color:#374151">{title}</td>
        </tr>"""

    # AI analysis
    ai_check  = next((c for c in checks if c.get("check") == "ai_summary"), None)
    ai_section = ""
    if ai_check and ai_check.get("detail"):
        ai_html = ai_check["detail"].replace("\n", "<br>")
        ai_section = f"""
      <div style="margin-top:24px;background:#F5FFCC;border-left:4px solid #CBFF00;padding:16px 20px;border-radius:4px">
        <div style="font-size:11px;font-weight:bold;color:#3A6200;text-transform:uppercase;margin-bottom:10px">
          AI Threat Analysis &amp; Recommendations
        </div>
        <div style="font-size:12px;color:#1A1A2E;line-height:1.6">{ai_html}</div>
      </div>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F2F5F9;font-family:Arial,Helvetica,sans-serif">
  <div style="max-width:640px;margin:0 auto;background:#ffffff">

    <!-- Header -->
    <div style="background:#0E0D12;padding:20px 24px;display:flex;align-items:center">
      <span style="color:#CBFF00;font-size:20px;font-weight:bold;letter-spacing:2px">● SWARMHAWK</span>
      <span style="color:#6B7280;font-size:11px;margin-left:auto">Monthly Security Report</span>
    </div>

    <!-- Domain hero -->
    <div style="background:#0D1B3E;padding:28px 24px">
      <div style="font-size:26px;font-weight:bold;color:#ffffff">{domain}</div>
      <div style="font-size:13px;color:#CBFF00;margin-top:4px">{country}  ·  Scanned {scan_date}</div>
    </div>

    <!-- Risk score bar -->
    <div style="display:flex;background:#0E0D12">
      <div style="flex:1;padding:16px;text-align:center;border-right:1px solid #1A1A2E">
        <div style="font-size:32px;font-weight:bold;color:{risk_col}">{risk_score}</div>
        <div style="font-size:10px;color:#6B7280;text-transform:uppercase;margin-top:2px">Risk Score</div>
        <div style="font-size:11px;font-weight:bold;color:{risk_col};margin-top:2px">{risk_lbl}</div>
      </div>
      <div style="flex:1;padding:16px;text-align:center;border-right:1px solid #1A1A2E">
        <div style="font-size:32px;font-weight:bold;color:{'#C0392B' if critical else '#CBFF00'}">{critical}</div>
        <div style="font-size:10px;color:#6B7280;text-transform:uppercase;margin-top:2px">Critical</div>
      </div>
      <div style="flex:1;padding:16px;text-align:center;border-right:1px solid #1A1A2E">
        <div style="font-size:32px;font-weight:bold;color:{'#D4850A' if warnings else '#CBFF00'}">{warnings}</div>
        <div style="font-size:10px;color:#6B7280;text-transform:uppercase;margin-top:2px">Warnings</div>
      </div>
      <div style="flex:1;padding:16px;text-align:center">
        <div style="font-size:32px;font-weight:bold;color:#1A7A4A">{passed}</div>
        <div style="font-size:10px;color:#6B7280;text-transform:uppercase;margin-top:2px">Passed</div>
      </div>
    </div>

    <!-- Body -->
    <div style="padding:24px">

      <!-- Check results -->
      <div style="font-size:11px;font-weight:bold;color:#0D1B3E;text-transform:uppercase;
                  border-bottom:2px solid #CBFF00;padding-bottom:6px;margin-bottom:12px">
        Security Check Results
      </div>
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr style="background:#0D1B3E">
            <th style="padding:8px 10px;color:#CBFF00;font-size:10px;text-align:left;width:80px">Status</th>
            <th style="padding:8px 10px;color:#CBFF00;font-size:10px;text-align:left;width:140px">Check</th>
            <th style="padding:8px 10px;color:#CBFF00;font-size:10px;text-align:left">Finding</th>
          </tr>
        </thead>
        <tbody>{check_rows}</tbody>
      </table>

      {ai_section}

      <!-- CTA -->
      <div style="margin-top:28px;text-align:center">
        <a href="https://hastikdan.github.io/cee-scanner"
           style="background:#CBFF00;color:#0E0D12;font-weight:bold;font-size:13px;
                  padding:12px 28px;border-radius:4px;text-decoration:none;display:inline-block">
          View Full Report Online →
        </a>
      </div>

      <!-- Next scan note -->
      <div style="margin-top:20px;padding:12px 16px;background:#F2F5F9;border-radius:4px;
                  font-size:11px;color:#6B7280;text-align:center">
        Next monthly scan scheduled in 30 days.
        Your PDF report is attached to this email.
      </div>
    </div>

    <!-- Footer -->
    <div style="background:#0E0D12;padding:16px 24px;text-align:center">
      <div style="color:#6B7280;font-size:10px">
        SwarmHawk Security Intelligence  ·  hastikdan.github.io/cee-scanner<br>
        You are receiving this because you have an active SwarmHawk subscription for {domain}.<br>
        <a href="#" style="color:#CBFF00">Manage subscription</a>
      </div>
    </div>

  </div>
</body>
</html>"""


def send_report(user_email: str, scan_data: dict) -> dict:
    """
    Send monthly security report email with PDF attachment.

    Args:
        user_email: recipient email address
        scan_data:  dict from run_checks() — domain, risk_score, checks etc

    Returns:
        {"success": True, "id": "..."} or {"success": False, "error": "..."}
    """
    if not RESEND_API_KEY:
        return {"success": False, "error": "RESEND_API_KEY not set"}

    domain     = scan_data.get("domain", "unknown")
    risk_score = scan_data.get("risk_score", 0)
    risk_lbl   = _risk_label(risk_score)
    scan_dt    = scan_data.get("scanned_at", datetime.utcnow().isoformat())
    try:
        scan_date = datetime.fromisoformat(scan_dt[:19]).strftime("%b %Y")
    except:
        scan_date = "Monthly"

    try:
        import resend
        resend.api_key = RESEND_API_KEY

        # Generate PDF
        from report_pdf import build_report_pdf
        pdf_bytes  = build_report_pdf(scan_data)
        pdf_b64    = base64.b64encode(pdf_bytes).decode()
        pdf_name   = f"SwarmHawk_{domain}_{scan_date.replace(' ','_')}.pdf"

        # Build email
        html_body  = build_html_email(scan_data)
        subject    = f"[{risk_lbl}] SwarmHawk Monthly Report — {domain} — {scan_date}"

        response = resend.Emails.send({
            "from":    FROM_EMAIL,
            "to":      [user_email],
            "subject": subject,
            "html":    html_body,
            "attachments": [{
                "filename":    pdf_name,
                "content":     pdf_b64,
                "contentType": "application/pdf",
            }],
        })

        return {"success": True, "id": response.get("id",""), "pdf_size": len(pdf_bytes)}

    except ImportError:
        return {"success": False, "error": "pip3 install resend reportlab --break-system-packages"}
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    test_email = sys.argv[1] if len(sys.argv) > 1 else "test@example.com"

    # Simulate a scan result
    test_scan = {
        "domain": "csob.cz", "country": "CZ",
        "scanned_at": datetime.utcnow().isoformat(),
        "risk_score": 30, "critical": 1, "warnings": 1,
        "checks": [
            {"check":"ssl",       "status":"ok",       "title":"SSL valid — 336 days remaining",    "detail":"","score_impact":0},
            {"check":"headers",   "status":"ok",       "title":"Security headers present",           "detail":"","score_impact":0},
            {"check":"dns",       "status":"ok",       "title":"DNS resolves to 2.21.33.34",         "detail":"","score_impact":0},
            {"check":"breach",    "status":"ok",       "title":"No known breaches found",            "detail":"","score_impact":0},
            {"check":"typosquat", "status":"critical", "title":"8 typosquat domains registered",     "detail":"csob-cz.com, csobcz.net and 6 more","score_impact":25},
            {"check":"spamhaus",  "status":"warning",  "title":"Spamhaus DBL listed",                "detail":"127.255.255.254","score_impact":5},
            {"check":"ai_summary","status":"warning",  "title":"AI Analysis: MEDIUM RISK",
             "detail":"1. EXECUTIVE SUMMARY\nMEDIUM RISK. Domain csob.cz has 8 typosquat lookalikes registered that could be used for phishing.\n\n2. CRITICAL FINDINGS\nTyposquat domains registered — attackers could clone the site and redirect users.\n\n3. THREAT SCENARIOS\n- Phishing emails from csob-cz.com impersonating CSOB bank\n- Credential harvesting via fake login page on typosquat domain\n\n4. PRIORITISED RECOMMENDATIONS\n1. Register top typosquat variants immediately (Easy, 30 min, ~€10/domain/yr)\n2. Enable DMARC policy to block spoofed emails (Medium, 2hrs)\n3. Monitor typosquat domains monthly for content changes (automated via SwarmHawk)\n\n5. INTELLIGENCE NOTES\nHosted on Akamai CDN. No dark web signals detected.",
             "score_impact":0},
        ],
    }

    # Test PDF generation only
    print("Generating test PDF...")
    from report_pdf import build_report_pdf
    pdf = build_report_pdf(test_scan)
    with open("/tmp/test_report.pdf", "wb") as f:
        f.write(pdf)
    print(f"PDF generated: {len(pdf):,} bytes → /tmp/test_report.pdf")

    # Test email send
    if RESEND_API_KEY and RESEND_API_KEY != "re_...":
        print(f"\nSending test email to {test_email}...")
        result = send_report(test_email, test_scan)
        print(f"Result: {result}")
    else:
        print("\nSkipping email send — set RESEND_API_KEY env var to test")
