"""
monthly_scheduler.py
====================
Runs monthly re-scans and sends reports to all paying subscribers.
Can be triggered:
  1. Manually: python3 monthly_scheduler.py
  2. Render cron job: set up in Render dashboard → Cron Jobs
  3. GitHub Actions: schedule: cron: '0 8 1 * *'  (8am on 1st of each month)

Env vars needed:
    SUPABASE_URL, SUPABASE_KEY
    ANTHROPIC_API_KEY
    RESEND_API_KEY
"""

import os
import sys
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def get_paying_subscribers():
    """
    Fetch all domains with active paid subscriptions from Supabase.
    Returns list of {domain, country, user_email, domain_id, user_id}
    """
    try:
        from supabase import create_client
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")
        if not url or not key:
            logger.error("SUPABASE_URL or SUPABASE_KEY not set")
            return []

        sb = create_client(url, key)

        # Get all paid domains with user email
        result = sb.table("purchases").select(
            "domain_id, domains(id, domain, country, user_id), users(email, name)"
        ).execute()

        subscribers = []
        for row in result.data or []:
            domain_info = row.get("domains", {})
            user_info   = row.get("users", {})
            if domain_info and user_info:
                subscribers.append({
                    "domain_id":   domain_info.get("id"),
                    "domain":      domain_info.get("domain"),
                    "country":     domain_info.get("country", ""),
                    "user_id":     domain_info.get("user_id"),
                    "user_email":  user_info.get("email"),
                    "user_name":   user_info.get("name", ""),
                })

        logger.info(f"Found {len(subscribers)} paying subscribers")
        return subscribers

    except Exception as e:
        logger.error(f"Failed to fetch subscribers: {e}")
        return []


def save_scan_to_db(domain_id: str, scan_result: dict):
    """Save scan result to Supabase scans table."""
    try:
        from supabase import create_client
        import json
        sb = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
        sb.table("scans").insert({
            "domain_id":   domain_id,
            "risk_score":  scan_result.get("risk_score", 0),
            "critical":    scan_result.get("critical", 0),
            "warnings":    scan_result.get("warnings", 0),
            "checks":      scan_result.get("checks", []),
            "scanned_at":  scan_result.get("scanned_at"),
        }).execute()
        logger.info(f"Scan saved to DB for domain_id {domain_id}")
    except Exception as e:
        logger.error(f"Failed to save scan: {e}")


def run_monthly_reports(dry_run: bool = False, domain_filter: str = None):
    """
    Main function — scans all paying subscribers and sends reports.

    Args:
        dry_run:       If True, generate PDF but don't send emails
        domain_filter: If set, only process this specific domain
    """
    logger.info("=" * 60)
    logger.info(f"SwarmHawk Monthly Report Run — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    logger.info(f"Dry run: {dry_run}")
    logger.info("=" * 60)

    # Import scanner and email modules
    sys.path.insert(0, os.path.expanduser("~/cee_scanner"))
    from cee_scanner.checks import run_checks
    from report_email import send_report

    subscribers = get_paying_subscribers()

    if domain_filter:
        subscribers = [s for s in subscribers if s["domain"] == domain_filter]
        logger.info(f"Filtered to domain: {domain_filter}")

    if not subscribers:
        logger.warning("No paying subscribers found — nothing to do")
        return

    results = {"sent": 0, "failed": 0, "skipped": 0}

    for i, sub in enumerate(subscribers, 1):
        domain = sub["domain"]
        email  = sub["user_email"]
        logger.info(f"[{i}/{len(subscribers)}] Processing {domain} → {email}")

        try:
            # Run all 17 checks
            logger.info(f"  Scanning {domain}...")
            scan = run_checks(domain)
            scan["country"] = sub.get("country", "")

            logger.info(f"  Scan complete — Risk: {scan['risk_score']} | "
                       f"Critical: {scan['critical']} | Warnings: {scan['warnings']}")

            # Save to Supabase
            if sub.get("domain_id"):
                save_scan_to_db(sub["domain_id"], scan)

            # Send report
            if dry_run:
                logger.info(f"  DRY RUN — would send to {email}")
                results["skipped"] += 1
            else:
                logger.info(f"  Sending report to {email}...")
                result = send_report(email, scan)
                if result.get("success"):
                    logger.info(f"  Sent — email ID: {result.get('id')} | "
                               f"PDF: {result.get('pdf_size',0):,} bytes")
                    results["sent"] += 1
                else:
                    logger.error(f"  Send failed: {result.get('error')}")
                    results["failed"] += 1

        except Exception as e:
            logger.error(f"  ERROR processing {domain}: {e}")
            results["failed"] += 1

    logger.info("=" * 60)
    logger.info(f"Run complete — Sent: {results['sent']} | "
               f"Failed: {results['failed']} | Skipped: {results['skipped']}")
    logger.info("=" * 60)
    return results


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SwarmHawk Monthly Report Scheduler")
    parser.add_argument("--dry-run",  action="store_true", help="Scan but don't send emails")
    parser.add_argument("--domain",   type=str, help="Process only this domain")
    parser.add_argument("--test",     type=str, help="Send test report to this email (uses csob.cz mock data)")
    args = parser.parse_args()

    if args.test:
        # Quick test with mock data
        logger.info(f"Sending test report to {args.test}")
        from report_email import send_report
        from report_pdf import build_report_pdf
        mock_scan = {
            "domain":"csob.cz","country":"CZ",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "risk_score":30,"critical":1,"warnings":1,
            "checks":[
                {"check":"ssl","status":"ok","title":"SSL valid — 336 days","detail":"","score_impact":0},
                {"check":"typosquat","status":"critical","title":"8 typosquat domains registered","detail":"csob-cz.com and 7 more","score_impact":25},
                {"check":"spamhaus","status":"warning","title":"Spamhaus DBL listed","detail":"127.255.255.254","score_impact":5},
                {"check":"ai_summary","status":"warning","title":"AI Analysis: MEDIUM RISK",
                 "detail":"1. EXECUTIVE SUMMARY\nMEDIUM RISK — typosquat exposure and Spamhaus listing require attention.\n\n4. PRIORITISED RECOMMENDATIONS\n1. Register key typosquat variants (Easy, 30min)\n2. Request Spamhaus delisting (Medium, 1hr)","score_impact":0},
            ],
        }
        result = send_report(args.test, mock_scan)
        print(f"Result: {result}")
    else:
        run_monthly_reports(dry_run=args.dry_run, domain_filter=args.domain)
