"""
cee_scanner — Main CLI + daily scheduler

Usage:
  python run.py scan              # run scan now
  python run.py dashboard         # generate dashboard from latest results
  python run.py scan --dashboard  # scan + generate dashboard
  python run.py schedule          # run daily at 06:00 UTC forever
  python run.py demo              # generate demo dashboard (no real scan)
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(name)s  %(levelname)s  %(message)s"
)

from cee_scanner.scanner import Scanner
from cee_scanner.dashboard import generate_dashboard
from cee_scanner.targets import TARGETS


COUNTRIES = ["Czech Republic", "Poland", "Hungary", "Slovakia", "Romania"]
DATA_DIR = "./data"
REPORT_DIR = "./reports"


def cmd_scan(args):
    print(f"\n  ✦ SwarmHawk CEE Scanner")
    print(f"  {'─'*50}")
    print(f"  Countries: {', '.join(COUNTRIES)}")
    print(f"  Domains: {sum(len(v) for v in TARGETS.values())} total")
    print(f"  Mode: Passive OSINT only")
    print(f"  {'─'*50}")

    scanner = Scanner(output_dir=DATA_DIR, max_workers=50)
    data = scanner.run_all(countries=COUNTRIES)

    if args.dashboard or True:   # always generate dashboard
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
        dashboard_path = f"{REPORT_DIR}/cee_dashboard_{ts}.html"
        latest_path = f"{REPORT_DIR}/cee_dashboard_latest.html"

        generate_dashboard(data, dashboard_path)
        generate_dashboard(data, latest_path)

        print(f"\n  ✓ Dashboard saved:")
        print(f"    → {dashboard_path}")
        print(f"    → {latest_path}  (always latest)")
        print(f"\n  Open in browser to view and share!")

    # Print quick summary
    print(f"\n  {'─'*50}")
    print(f"  QUICK SUMMARY")
    print(f"  {'─'*50}")
    summaries = data.get("country_summaries", {})
    for country, s in sorted(summaries.items(), key=lambda x: x[1]["avg_risk_score"], reverse=True):
        score = s["avg_risk_score"]
        color = "\033[91m" if score >= 60 else "\033[93m" if score >= 30 else "\033[92m"
        reset = "\033[0m"
        print(
            f"  {color}{score:5.1f}{reset}  {country:<20}  "
            f"crit={s['total_critical']:3d}  warn={s['total_warnings']:3d}  "
            f"worst: {s['highest_risk_domain']}"
        )
    print()


def cmd_dashboard(args):
    latest = Path(DATA_DIR) / "latest.json"
    if not latest.exists():
        print(f"\n  No scan data found. Run: python run.py scan\n")
        sys.exit(1)

    data = json.loads(latest.read_text())
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
    path = f"{REPORT_DIR}/cee_dashboard_{ts}.html"
    latest_path = f"{REPORT_DIR}/cee_dashboard_latest.html"

    generate_dashboard(data, path)
    generate_dashboard(data, latest_path)
    print(f"\n  ✓ Dashboard: {path}\n")


def cmd_demo(args):
    """Generate a demo dashboard with realistic mock data."""
    print("\n  Generating demo dashboard with mock data...")

    import random
    random.seed(42)

    mock_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": "passive_osint",
        "countries": COUNTRIES,
        "total_domains": 100,
        "global_avg_risk": 34.2,
        "country_summaries": {},
    }

    # Config checks — SSL, headers, DNS etc
    config_checks = {
        "ssl": {
            "critical": ("SSL expires in 5 days", "Certificate expires Mar 6 2026. Issuer: Let's Encrypt"),
            "warning":  (lambda: f"SSL expires in {random.randint(10,28)} days", "Renew soon to avoid browser warnings"),
            "ok":       (lambda: f"SSL valid — {random.randint(60,300)} days remaining", ""),
        },
        "headers": {
            "critical": ("HSTS + CSP + X-Frame-Options missing", "3 critical security headers absent — XSS and clickjacking risk"),
            "warning":  ("X-Frame-Options missing", "Clickjacking protection not set"),
            "ok":       ("All security headers present", "HSTS, CSP, X-Frame-Options all configured"),
        },
        "dns": {
            "critical": ("Domain resolution failed", "DNS lookup returned NXDOMAIN"),
            "warning":  ("No SPF record found", "Email spoofing possible — add v=spf1 record"),
            "ok":       ("DNS resolves correctly", ""),
        },
        "https_redirect": {
            "critical": ("HTTP served without HTTPS redirect", "Plain HTTP accessible — no encryption enforcement"),
            "warning":  ("HTTP redirect not enforced consistently", "Some paths skip HTTPS upgrade"),
            "ok":       ("HTTP → HTTPS redirect working", "All traffic upgraded to HTTPS"),
        },
        "typosquat": {
            "critical": (lambda: f"{random.randint(4,8)} typosquat domains registered", "Lookalike domains active — phishing risk"),
            "warning":  ("2 potential typosquat domains", "Suspicious lookalike domains found"),
            "ok":       ("No typosquat domains detected", ""),
        },
        "performance": {
            "critical": ("Request timed out", "No response within 15s — site may be down"),
            "warning":  (lambda: f"Slow response: {random.uniform(4,8):.1f}s", "Performance degraded"),
            "ok":       (lambda: f"Fast response: {random.uniform(0.2,1.8):.1f}s", "HTTP 200 OK"),
        },
    }

    # Threat intel checks — realistic mock data
    threat_checks = {
        "urlhaus": {
            "critical": ("ACTIVE MALWARE — 2 live malicious URL(s)",
                         "Threats: trojan, backdoor | Tags: malware, abuse"),
            "warning":  ("Historical malware — 1 past URL flagged",
                         "All offline now. Threats: phishing"),
            "ok":       ("No malware URLs found in URLhaus", ""),
        },
        "safebrowsing": {
            "critical": ("GOOGLE FLAGGED — SOCIAL_ENGINEERING",
                         "Chrome shows security warning for this domain. 2 threat match(es) confirmed."),
            "warning":  ("GOOGLE FLAGGED — UNWANTED_SOFTWARE",
                         "Chrome warns users about unwanted software downloads."),
            "ok":       ("Google Safe Browsing: clean", ""),
        },
        "virustotal": {
            "critical": (lambda: f"VIRUSTOTAL — {random.randint(6,18)}/89 engines: MALICIOUS",
                         "Reputation: -85 | Categories: malware, phishing"),
            "warning":  ("VirusTotal — 2 malicious, 4 suspicious",
                         "Reputation: -12 | Categories: suspicious"),
            "ok":       ("VirusTotal: clean (89 engines checked)",
                         lambda: f"Reputation: {random.randint(0,95)} | Categories: news, finance"),
        },
        "spamhaus": {
            "critical": ("SPAMHAUS BLOCKLIST — Phishing domain",
                         "Domain is on Spamhaus DBL (127.0.1.4). Mail and web traffic likely blocked globally."),
            "warning":  ("Spamhaus DBL — Abused legit spam",
                         "Domain flagged (127.0.1.102)"),
            "ok":       ("Spamhaus DBL: not listed — clean", ""),
        },
        "breach": {
            "critical": (lambda: f"Domain in {random.randint(2,5)} breach(es)",
                         lambda: f"Found in: Collection #1, LinkedIn 2021 +{random.randint(1,3)} more"),
            "warning":  ("Domain in 1 breach",
                         "Found in: Adobe 2013"),
            "ok":       ("No known breaches found", ""),
        },
    }

    def get_val(v):
        return v() if callable(v) else v

    for country, domains in TARGETS.items():
        domain_results = []
        for domain in domains:
            checks = []
            total_impact = 0

            # Config checks — ~15% critical, ~30% warning
            for check, outcomes in config_checks.items():
                r = random.random()
                if r < 0.10:
                    status, impact = "critical", random.randint(10, 18)
                    title, detail = outcomes["critical"]
                elif r < 0.35:
                    status, impact = "warning", random.randint(3, 8)
                    title, detail = outcomes["warning"]
                else:
                    status, impact = "ok", 0
                    title, detail = outcomes["ok"]
                checks.append({
                    "check": check, "status": status,
                    "title": get_val(title), "detail": get_val(detail),
                    "score_impact": impact,
                })
                total_impact += impact

            # Threat intel checks — rare but realistic hit rates
            threat_rates = {
                "urlhaus":      0.03,   # 3% of major sites have malware URLs
                "safebrowsing": 0.02,   # 2% flagged by Google
                "virustotal":   0.05,   # 5% flagged by at least some AV
                "spamhaus":     0.04,   # 4% on spam/malware blocklist
                "breach":       0.25,   # 25% of major sites have had breaches
            }
            warning_rates = {
                "urlhaus": 0.06, "safebrowsing": 0.03,
                "virustotal": 0.08, "spamhaus": 0.06, "breach": 0.15,
            }

            for check, outcomes in threat_checks.items():
                r = random.random()
                if r < threat_rates[check]:
                    status, impact = "critical", random.randint(15, 25)
                    title, detail = outcomes["critical"]
                elif r < threat_rates[check] + warning_rates[check]:
                    status, impact = "warning", random.randint(6, 12)
                    title, detail = outcomes["warning"]
                else:
                    status, impact = "ok", 0
                    title, detail = outcomes["ok"]
                checks.append({
                    "check": check, "status": status,
                    "title": get_val(title), "detail": get_val(detail),
                    "score_impact": impact,
                })
                total_impact += impact

            risk_score = min(100, total_impact)
            domain_results.append({
                "domain": domain,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "risk_score": risk_score,
                "critical": sum(1 for c in checks if c["status"] == "critical"),
                "warnings": sum(1 for c in checks if c["status"] == "warning"),
                "checks": checks,
            })

        domain_results.sort(key=lambda x: x["risk_score"], reverse=True)
        avg = sum(d["risk_score"] for d in domain_results) / len(domain_results)

        mock_data["country_summaries"][country] = {
            "domain_count": len(domain_results),
            "avg_risk_score": round(avg, 1),
            "total_critical": sum(d["critical"] for d in domain_results),
            "total_warnings": sum(d["warnings"] for d in domain_results),
            "highest_risk_domain": domain_results[0]["domain"],
            "highest_risk_score": domain_results[0]["risk_score"],
            "domains": domain_results,
        }

    mock_data["global_avg_risk"] = round(
        sum(s["avg_risk_score"] for s in mock_data["country_summaries"].values()) /
        len(mock_data["country_summaries"]), 1
    )

    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    path = f"{REPORT_DIR}/cee_dashboard_demo.html"
    Path(f"{DATA_DIR}/latest.json").write_text(json.dumps(mock_data, indent=2))

    generate_dashboard(mock_data, path)
    print(f"\n  ✓ Demo dashboard: {path}")
    print(f"  Copy to your Downloads folder and open in Chrome!\n")


def cmd_schedule(args):
    """Run daily scan at 06:00 UTC."""
    print(f"\n  ✦ SwarmHawk CEE — Daily scheduler started")
    print(f"  Scans at 06:00 UTC every day")
    print(f"  Press Ctrl+C to stop\n")

    while True:
        now = datetime.now(timezone.utc)
        # Next 06:00 UTC
        next_run = now.replace(hour=6, minute=0, second=0, microsecond=0)
        if next_run <= now:
            from datetime import timedelta
            next_run += timedelta(days=1)

        wait_secs = (next_run - now).total_seconds()
        print(f"  Next scan: {next_run.strftime('%Y-%m-%d %H:%M UTC')} "
              f"(in {int(wait_secs//3600)}h {int((wait_secs%3600)//60)}m)")

        time.sleep(wait_secs)

        print(f"\n  [{datetime.now(timezone.utc).isoformat()}] Starting scheduled scan...")
        try:
            args.dashboard = True
            cmd_scan(args)
        except Exception as e:
            print(f"  Scan failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        prog="cee-scanner",
        description="SwarmHawk CEE Cyber Risk Scanner — Passive OSINT",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run scan now")
    scan_p.add_argument("--dashboard", action="store_true", help="Generate dashboard after scan")
    scan_p.add_argument("--workers", type=int, default=8, help="Parallel workers")

    sub.add_parser("dashboard", help="Generate dashboard from latest results")
    sub.add_parser("demo", help="Generate demo dashboard (no real scan)")
    sub.add_parser("schedule", help="Run daily at 06:00 UTC")

    args = parser.parse_args()

    if args.command == "scan":        cmd_scan(args)
    elif args.command == "dashboard": cmd_dashboard(args)
    elif args.command == "demo":      cmd_demo(args)
    elif args.command == "schedule":  cmd_schedule(args)


if __name__ == "__main__":
    main()
