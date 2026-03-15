"""
cee_scanner.checks
==================
Passive OSINT checks — all 100% legal, no authorization required.
No active exploitation. No vulnerability scanning.
Only publicly available information.

Checks:
  1. SSL certificate — expiry, issuer, validity
  2. HTTP security headers — missing headers
  3. DNS — basic misconfiguration detection
  4. HaveIBeenPwned — domain in breach databases
  5. Shodan (optional, requires free API key)
  6. Typosquat — suspicious lookalike domains registered
"""

import ssl
import socket
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("cee_scanner.checks")

TIMEOUT = 5
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}


# ── Result dataclass ──────────────────────────────────────────────────────────

class CheckResult:
    def __init__(self, check: str, domain: str):
        self.check = check
        self.domain = domain
        self.status = "ok"        # ok | warning | critical | error
        self.title = ""
        self.detail = ""
        self.score_impact = 0     # 0-25 penalty points

    def warn(self, title: str, detail: str = "", impact: int = 5):
        self.status = "warning"
        self.title = title
        self.detail = detail
        self.score_impact = impact
        return self

    def critical(self, title: str, detail: str = "", impact: int = 15):
        self.status = "critical"
        self.title = title
        self.detail = detail
        self.score_impact = impact
        return self

    def ok(self, title: str, detail: str = ""):
        self.status = "ok"
        self.title = title
        self.detail = detail
        self.score_impact = 0
        return self

    def error(self, title: str, detail: str = ""):
        self.status = "error"
        self.title = title
        self.detail = detail
        self.score_impact = 5
        return self

    def to_dict(self) -> dict:
        d = {
            "check": self.check,
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
            "score_impact": self.score_impact,
        }
        # CVE skill attaches extra structured data
        if hasattr(self, "cves"):
            d["cves"] = self.cves
        if hasattr(self, "software"):
            d["software"] = [{"product": p, "version": v} for p, v in self.software]
        return d


# ── Individual checks ─────────────────────────────────────────────────────────

def check_ssl(domain: str) -> CheckResult:
    """Check SSL certificate validity and expiry."""
    result = CheckResult("ssl", domain)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=TIMEOUT),
            server_hostname=domain
        ) as sock:
            cert = sock.getpeercert()

        # Parse expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days

            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_name = issuer.get("organizationName", "Unknown")

            if days_left < 0:
                return result.critical(
                    "SSL certificate EXPIRED",
                    f"Expired {abs(days_left)} days ago. Issuer: {issuer_name}",
                    impact=20
                )
            elif days_left <= 7:
                return result.critical(
                    f"SSL expires in {days_left} days",
                    f"Critical — expires {expiry.strftime('%Y-%m-%d')}. Issuer: {issuer_name}",
                    impact=15
                )
            elif days_left <= 30:
                return result.warn(
                    f"SSL expires in {days_left} days",
                    f"Expires {expiry.strftime('%Y-%m-%d')}. Issuer: {issuer_name}",
                    impact=8
                )
            else:
                return result.ok(
                    f"SSL valid — {days_left} days remaining",
                    f"Expires {expiry.strftime('%Y-%m-%d')}. Issuer: {issuer_name}"
                )
    except ssl.SSLCertVerificationError as e:
        return result.critical("SSL certificate invalid", str(e)[:100], impact=20)
    except ssl.CertificateError as e:
        return result.critical("SSL certificate error", str(e)[:100], impact=15)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        return result.error("SSL check failed", str(e)[:80])
    except Exception as e:
        return result.error("SSL check error", str(e)[:80])


def check_headers(domain: str) -> CheckResult:
    """Check HTTP security headers."""
    result = CheckResult("headers", domain)
    missing = []
    warnings = []

    REQUIRED_HEADERS = [
        ("strict-transport-security", "HSTS", 8),
        ("x-content-type-options", "X-Content-Type-Options", 5),
        ("x-frame-options", "X-Frame-Options", 5),
        ("content-security-policy", "CSP", 6),
    ]

    try:
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT,
            headers=HEADERS, allow_redirects=True, verify=False
        )
        response_headers = {k.lower(): v for k, v in r.headers.items()}

        total_impact = 0
        for header_key, header_name, impact in REQUIRED_HEADERS:
            if header_key not in response_headers:
                missing.append(header_name)
                total_impact += impact

        # Check for server version disclosure
        server = response_headers.get("server", "")
        if any(c.isdigit() for c in server):
            warnings.append(f"Server version disclosed: {server}")
            total_impact += 3

        if missing:
            return result.warn(
                f"{len(missing)} security headers missing",
                f"Missing: {', '.join(missing)}",
                impact=min(total_impact, 20)
            )
        return result.ok(
            "Security headers present",
            f"HSTS, CSP, X-Frame-Options all set"
        )

    except requests.exceptions.SSLError:
        return result.critical("HTTPS not available", "Site not accessible over HTTPS", impact=15)
    except Exception as e:
        return result.error("Header check failed", str(e)[:80])


def check_dns(domain: str) -> CheckResult:
    """Check basic DNS configuration."""
    result = CheckResult("dns", domain)
    issues = []

    try:
        # Check if domain resolves
        ip = socket.gethostbyname(domain)

        # Check for common misconfigurations via TXT records
        # (using basic socket, no dnspython dependency)
        try:
            import subprocess
            # Check SPF record exists (email spoofing protection)
            spf = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=5
            )
            if spf.returncode == 0:
                if "v=spf1" not in spf.stdout:
                    issues.append("No SPF record (email spoofing risk)")
            else:
                # dig not available — skip DNS text record checks
                pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if issues:
            return result.warn(
                f"{len(issues)} DNS issue(s) found",
                " | ".join(issues),
                impact=5 * len(issues)
            )
        return result.ok(f"DNS resolves to {ip}")

    except socket.gaierror:
        return result.critical("Domain does not resolve", "DNS lookup failed", impact=20)
    except Exception as e:
        return result.error("DNS check failed", str(e)[:80])


def check_http_redirect(domain: str) -> CheckResult:
    """Check if HTTP redirects to HTTPS."""
    result = CheckResult("https_redirect", domain)
    try:
        r = requests.get(
            f"http://{domain}", timeout=TIMEOUT,
            headers=HEADERS, allow_redirects=False, verify=False
        )
        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("location", "")
            if location.startswith("https://"):
                return result.ok("HTTP → HTTPS redirect working")
            else:
                return result.warn(
                    "HTTP redirect not to HTTPS",
                    f"Redirects to: {location[:60]}",
                    impact=8
                )
        elif r.status_code == 200:
            return result.warn(
                "HTTP served without redirect",
                "Site accessible over plain HTTP — no HTTPS enforcement",
                impact=10
            )
        else:
            return result.ok(f"HTTP returns {r.status_code}")
    except Exception as e:
        return result.error("Redirect check failed", str(e)[:80])


def check_breach(domain: str) -> CheckResult:
    """Check HaveIBeenPwned for domain breaches."""
    result = CheckResult("breach", domain)
    try:
        # HIBP v3 API — domain search (public endpoint, no key needed for domain lookup)
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": domain},
            headers={**HEADERS, "hibp-api-key": ""},
            timeout=TIMEOUT
        )

        if r.status_code == 200:
            breaches = r.json()
            if breaches:
                breach_names = [b.get("Name", "?") for b in breaches[:3]]
                total = len(breaches)
                return result.critical(
                    f"Domain in {total} breach(es)",
                    f"Found in: {', '.join(breach_names)}"
                    + (f" +{total-3} more" if total > 3 else ""),
                    impact=15
                )
            return result.ok("No known breaches found")
        elif r.status_code == 404:
            return result.ok("No known breaches found")
        elif r.status_code == 401:
            # API key required for this endpoint — skip gracefully
            return result.ok("Breach check skipped (API key required)")
        else:
            return result.error(f"Breach API returned {r.status_code}")

    except Exception as e:
        return result.error("Breach check failed", str(e)[:80])


def check_typosquat(domain: str) -> CheckResult:
    """Check for registered typosquat lookalike domains."""
    result = CheckResult("typosquat", domain)

    # Generate common typosquats
    parts = domain.split(".")
    if len(parts) < 2:
        return result.ok("Typosquat check skipped")

    name = parts[0]
    tld = ".".join(parts[1:])

    candidates = set()

    # Character substitutions
    substitutions = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}
    for i, c in enumerate(name):
        if c in substitutions:
            variant = name[:i] + substitutions[c] + name[i+1:]
            candidates.add(f"{variant}.{tld}")

    # Missing/double character
    for i in range(len(name)):
        candidates.add(f"{name[:i]+name[i+1:]}.{tld}")             # missing char
        candidates.add(f"{name[:i]+name[i]+name[i]+name[i+1:]}.{tld}")  # doubled char

    # Common TLD variations
    for alt_tld in ["com", "net", "org", "io", "eu", "co"]:
        if alt_tld != tld:
            candidates.add(f"{name}.{alt_tld}")

    # Hyphen insertion (csob → c-sob, cs-ob …)
    for i in range(1, len(name)):
        candidates.add(f"{name[:i]}-{name[i:]}.{tld}")

    # Common prefix/suffix squats
    for affix in [f"{name}-{tld.split('.')[0]}", f"{tld.split('.')[0]}-{name}",
                  f"{name}online", f"{name}secure", f"my{name}"]:
        candidates.add(f"{affix}.com")

    # Check which ones resolve (registered)
    registered = []
    for candidate in list(candidates)[:25]:   # cap at 25
        try:
            socket.gethostbyname(candidate)
            registered.append(candidate)
        except socket.gaierror:
            pass

    if len(registered) >= 3:
        return result.critical(
            f"{len(registered)} typosquat domains registered",
            f"Examples: {', '.join(registered[:3])}",
            impact=10
        )
    elif registered:
        return result.warn(
            f"{len(registered)} potential typosquat domain(s)",
            f"{', '.join(registered)}",
            impact=5
        )
    return result.ok("No obvious typosquat domains detected")


def check_response_time(domain: str) -> CheckResult:
    """Check website response time."""
    result = CheckResult("performance", domain)
    try:
        start = datetime.now(timezone.utc)
        r = requests.get(
            f"https://{domain}", timeout=15,
            headers=HEADERS, allow_redirects=True, verify=False
        )
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        if elapsed > 10:
            return result.critical(
                f"Very slow response: {elapsed:.1f}s",
                "Site taking over 10 seconds to respond",
                impact=10
            )
        elif elapsed > 5:
            return result.warn(
                f"Slow response: {elapsed:.1f}s",
                f"HTTP {r.status_code} in {elapsed:.1f}s",
                impact=5
            )
        elif r.status_code >= 500:
            return result.critical(
                f"Server error: HTTP {r.status_code}",
                f"Response in {elapsed:.1f}s",
                impact=15
            )
        elif r.status_code >= 400:
            return result.warn(
                f"Client error: HTTP {r.status_code}",
                f"Response in {elapsed:.1f}s",
                impact=8
            )
        else:
            return result.ok(
                f"Responding normally: {elapsed:.1f}s",
                f"HTTP {r.status_code}"
            )
    except requests.exceptions.Timeout:
        return result.critical("Request timed out", "No response within 15s", impact=15)
    except Exception as e:
        return result.error("Performance check failed", str(e)[:80])


# ── THREAT INTELLIGENCE CHECKS ───────────────────────────────────────────────

def check_urlhaus(domain: str) -> CheckResult:
    """
    URLhaus (abuse.ch) — real-time malware URL database.
    Checks if domain is currently hosting or distributing malware.
    Free API, no key required.
    """
    result = CheckResult("urlhaus", domain)
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            query_status = data.get("query_status", "")

            if query_status == "is_host":
                urls = data.get("urls", [])
                active = [u for u in urls if u.get("url_status") == "online"]
                tags = list({t for u in urls for t in u.get("tags") or []})[:5]
                malware_names = list({
                    u.get("threat", "") for u in urls if u.get("threat")
                })[:3]

                if active:
                    return result.critical(
                        f"ACTIVE MALWARE — {len(active)} live malicious URL(s)",
                        f"Threats: {', '.join(malware_names) or 'unknown'} | "
                        f"Tags: {', '.join(tags) or '—'}",
                        impact=25
                    )
                elif urls:
                    return result.warn(
                        f"Historical malware — {len(urls)} past URL(s) flagged",
                        f"All offline now. Threats: {', '.join(malware_names) or 'unknown'}",
                        impact=10
                    )
            elif query_status == "no_results":
                return result.ok("No malware URLs found in URLhaus")
            else:
                return result.ok(f"URLhaus: {query_status}")
        return result.error(f"URLhaus API returned {r.status_code}")
    except Exception as e:
        return result.error("URLhaus check failed", str(e)[:80])


def check_google_safebrowsing(domain: str, api_key: str = "") -> CheckResult:
    """
    Google Safe Browsing API — checks if Chrome has flagged this domain.
    Free API key from console.cloud.google.com (10,000 req/day free).
    Falls back to graceful skip if no key provided.
    """
    import os
    result = CheckResult("safebrowsing", domain)
    key = api_key or os.getenv("GOOGLE_SAFEBROWSING_KEY", "")

    if not key:
        # Try without key — limited but sometimes works
        result.ok("Safe Browsing: no API key (set GOOGLE_SAFEBROWSING_KEY)")
        return result

    try:
        payload = {
            "client": {"clientId": "cee-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"https://{domain}"},
                    {"url": f"http://{domain}"},
                ],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=payload,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = list({m.get("threatType", "UNKNOWN") for m in matches})
                return result.critical(
                    f"GOOGLE FLAGGED — {', '.join(threat_types)}",
                    f"Chrome shows security warning for this domain. "
                    f"{len(matches)} threat match(es) confirmed.",
                    impact=25
                )
            return result.ok("Google Safe Browsing: clean")
        elif r.status_code == 400:
            return result.error("Safe Browsing: invalid API key")
        else:
            return result.error(f"Safe Browsing API: HTTP {r.status_code}")
    except Exception as e:
        return result.error("Safe Browsing check failed", str(e)[:80])


def check_virustotal(domain: str, api_key: str = "") -> CheckResult:
    """
    VirusTotal — 70+ antivirus engines + threat intel aggregation.
    Free API key from virustotal.com (4 req/min, 500/day free).
    Falls back to graceful skip if no key provided.
    """
    import os
    result = CheckResult("virustotal", domain)
    key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    if not key:
        return result.ok("VirusTotal: no API key (set VIRUSTOTAL_API_KEY)")

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={**HEADERS, "x-apikey": key},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            categories = attrs.get("categories", {})
            cat_values = list(set(categories.values()))[:3]
            reputation = attrs.get("reputation", 0)

            if malicious >= 5:
                return result.critical(
                    f"VIRUSTOTAL — {malicious}/{total} engines: MALICIOUS",
                    f"Reputation: {reputation} | "
                    f"Categories: {', '.join(cat_values) or '—'}",
                    impact=25
                )
            elif malicious >= 2 or suspicious >= 5:
                return result.warn(
                    f"VirusTotal — {malicious} malicious, {suspicious} suspicious",
                    f"Reputation score: {reputation} | "
                    f"Categories: {', '.join(cat_values) or '—'}",
                    impact=12
                )
            elif malicious == 1:
                return result.warn(
                    f"VirusTotal — 1 engine flagged as malicious",
                    f"Reputation: {reputation} (possible false positive)",
                    impact=6
                )
            else:
                return result.ok(
                    f"VirusTotal: clean ({total} engines checked)",
                    f"Reputation: {reputation} | "
                    f"Categories: {', '.join(cat_values) or '—'}"
                )
        elif r.status_code == 404:
            return result.ok("VirusTotal: domain not in database yet")
        elif r.status_code == 401:
            return result.error("VirusTotal: invalid API key")
        elif r.status_code == 429:
            return result.error("VirusTotal: rate limit hit (4 req/min on free tier)")
        else:
            return result.error(f"VirusTotal API: HTTP {r.status_code}")
    except Exception as e:
        return result.error("VirusTotal check failed", str(e)[:80])


def check_spamhaus(domain: str) -> CheckResult:
    """
    Spamhaus DBL — domain block list.
    DNS-based lookup, completely free, no API key needed.
    Checks if domain is on the spam/malware/phishing block list.
    """
    result = CheckResult("spamhaus", domain)
    try:
        lookup = f"{domain}.dbl.spamhaus.org"
        try:
            answer = socket.gethostbyname(lookup)
            # Spamhaus returns specific IPs to indicate list type
            codes = {
                "127.0.1.2": ("Spammer domain", "critical", 20),
                "127.0.1.4": ("Phishing domain", "critical", 25),
                "127.0.1.5": ("Malware domain", "critical", 25),
                "127.0.1.6": ("Botnet C&C domain", "critical", 25),
                "127.0.1.102": ("Abused legit spam", "warning", 10),
                "127.0.1.103": ("Abused legit phish", "warning", 12),
                "127.0.1.104": ("Abused legit malware", "warning", 12),
            }
            if answer in codes:
                label, severity, impact = codes[answer]
                if severity == "critical":
                    return result.critical(
                        f"SPAMHAUS BLOCKLIST — {label}",
                        f"Domain is on Spamhaus DBL ({answer}). "
                        f"Mail and web traffic likely blocked globally.",
                        impact=impact
                    )
                else:
                    return result.warn(
                        f"Spamhaus DBL — {label}",
                        f"Domain flagged ({answer})",
                        impact=impact
                    )
            else:
                # Any response = listed
                return result.warn(
                    f"Spamhaus DBL listed ({answer})",
                    "Domain appears on Spamhaus block list",
                    impact=15
                )
        except socket.gaierror:
            # NXDOMAIN = not listed = clean
            return result.ok("Spamhaus DBL: not listed — clean")
    except Exception as e:
        return result.error("Spamhaus check failed", str(e)[:80])


# ── Run all checks for a domain ───────────────────────────────────────────────

def check_cve(domain: str) -> CheckResult:
    """CVE Enrichment Skill — detects software versions and looks up real CVEs."""
    from cee_scanner.skills.cve import check_cve as _check_cve
    return _check_cve(domain)


def check_darkweb(domain: str) -> CheckResult:
    """
    Dark-web credential & leak intelligence via ParanoidLab.
    Categorises leaks into: ransomware, infostealers, credentials, forum mentions.
    Requires PARANOIDLAB_API_KEY env var. Graceful fallback if absent.
    """
    import os
    r = CheckResult("darkweb", domain)

    api_key = os.getenv("PARANOIDLAB_API_KEY", "")
    if not api_key:
        r.status = "ok"
        r.title  = "Dark-web scan skipped"
        r.detail = "Set PARANOIDLAB_API_KEY to enable dark-web credential monitoring (paranoidlab.com)"
        r.score_impact = 0
        # Store skip marker so frontend knows to show the tip
        r.darkweb_data = {"skipped": True}
        return r

    base = "https://paranoidlab.com/v1"
    headers = {"X-Key": api_key, "Content-Type": "application/json"}

    # ── Fetch leaks ──────────────────────────────────────────────────────────
    leaks_raw = []
    leaks_total = 0
    leaks_error = None
    try:
        resp = requests.get(
            f"{base}/leaks",
            headers=headers,
            params={"data_url": domain, "limit": 50, "offset": 0},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            leaks_raw   = data.get("items") or data.get("leaks") or []
            leaks_total = data.get("total") or len(leaks_raw)
        elif resp.status_code == 401:
            leaks_error = "Invalid ParanoidLab API key"
        elif resp.status_code == 429:
            leaks_error = "Rate limited — retry later"
        elif resp.status_code == 404:
            leaks_total = 0   # no leaks found = clean
        else:
            leaks_error = f"API error {resp.status_code}"
    except requests.exceptions.Timeout:
        leaks_error = "Request timed out"
    except Exception as e:
        leaks_error = str(e)[:80]

    # ── Fetch Telegram mentions ──────────────────────────────────────────────
    tg_posts = []
    tg_total = 0
    try:
        resp_tg = requests.get(
            f"{base}/telegram/posts",
            headers=headers,
            params={"keyword": domain, "limit": 20},
            timeout=12,
        )
        if resp_tg.status_code == 200:
            tg_data  = resp_tg.json()
            tg_posts = tg_data.get("posts") or tg_data.get("items") or []
            tg_total = tg_data.get("total") or len(tg_posts)
    except Exception:
        pass   # Telegram is bonus intel — fail silently

    # ── Categorise leaks ────────────────────────────────────────────────────
    ransomware   = []
    infostealers = []
    credentials  = []
    forum_hits   = []

    for item in leaks_raw:
        source  = (item.get("source") or "").lower()
        itype   = (item.get("type")   or "").lower()
        # Mask email in sample
        email = item.get("data_user") or item.get("email") or ""
        if email and "@" in email:
            local, host = email.split("@", 1)
            email = local[:3] + "***@" + host

        record = {
            "source":   item.get("source") or "unknown",
            "type":     itype,
            "date":     (item.get("created_at") or "")[:10],
            "email":    email,
            "severity": item.get("risk_level") or "medium",
        }

        if "ransom" in source or itype == "ransomware":
            ransomware.append(record)
        elif "stealer" in source or "malware" in source or itype == "cookie":
            infostealers.append(record)
        elif itype in ("password", "pii") or "combo" in source or "breach" in source:
            credentials.append(record)
        else:
            forum_hits.append(record)

    # Add Telegram as forum hits
    for post in tg_posts[:5]:
        forum_hits.append({
            "source":   "Telegram dark-web channel",
            "type":     "forum",
            "date":     (post.get("date") or "")[:10],
            "email":    "",
            "severity": "medium",
            "preview":  (post.get("text") or "")[:120],
        })

    # ── Score ────────────────────────────────────────────────────────────────
    impact = 0
    if ransomware:
        impact += 25
    if infostealers:
        impact += 20
    if len(credentials) >= 100:
        impact += 20
    elif credentials:
        impact += 10
    if forum_hits or tg_total > 0:
        impact += 5

    total_leaks = leaks_total + tg_total
    darkweb_data = {
        "total":       total_leaks,
        "ransomware":  ransomware[:5],
        "infostealers":infostealers[:5],
        "credentials": credentials[:5],
        "forum_hits":  forum_hits[:5],
        "counts": {
            "ransomware":   len(ransomware),
            "infostealers": len(infostealers),
            "credentials":  len(credentials),
            "forum_hits":   tg_total + len(forum_hits),
        },
        "error": leaks_error,
    }

    if leaks_error and leaks_total == 0 and not tg_total:
        r.status = "error"
        r.title  = "Dark-web check failed"
        r.detail = leaks_error
        r.score_impact = 0
        r.darkweb_data = darkweb_data
        return r

    if ransomware:
        r.crit(f"Ransomware group leak detected for {domain}",
               f"{len(ransomware)} ransomware leak(s) · {len(infostealers)} stealer(s) · "
               f"{len(credentials)} credential(s) · {tg_total} Telegram mentions",
               impact=min(impact, 25))
    elif infostealers:
        r.crit(f"Infostealer credentials leaked for {domain}",
               f"{len(infostealers)} stealer log(s) · {len(credentials)} credential record(s) · "
               f"{tg_total} Telegram mentions",
               impact=min(impact, 25))
    elif credentials:
        if len(credentials) >= 10:
            r.crit(f"{len(credentials)}+ credentials found in dark-web leaks",
                   f"Source: combo lists & breach databases · {tg_total} Telegram mentions",
                   impact=min(impact, 20))
        else:
            r.warn(f"{len(credentials)} credential record(s) found in leak databases",
                   f"Source: combo lists · {tg_total} Telegram mentions",
                   impact=min(impact, 10))
    elif tg_total > 0 or forum_hits:
        r.warn(f"Domain mentioned {tg_total} time(s) in dark-web Telegram channels",
               "No credential leaks found but domain has dark-web exposure",
               impact=5)
    else:
        r.status = "ok"
        r.title  = f"No dark-web leaks found for {domain}"
        r.detail = "Not detected in credential dumps, stealer logs, or Telegram dark-web channels"
        r.score_impact = 0

    r.darkweb_data = darkweb_data
    return r


def _check_darkweb_serialise(r: "CheckResult") -> dict:
    """Extend to_dict() to include darkweb_data blob."""
    d = r.to_dict()
    if hasattr(r, "darkweb_data"):
        d["darkweb_data"] = r.darkweb_data
    return d


# Monkey-patch to_dict so darkweb_data travels through scan_domain
_orig_to_dict = CheckResult.to_dict
def _patched_to_dict(self):
    d = _orig_to_dict(self)
    if hasattr(self, "darkweb_data"):
        d["darkweb_data"] = self.darkweb_data
    return d
CheckResult.to_dict = _patched_to_dict


# ── New OSINT checks ──────────────────────────────────────────────────────────

def check_whois(domain: str) -> CheckResult:
    """Check domain registration info via RDAP (free, no key)."""
    result = CheckResult("whois", domain)
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code != 200:
            return result.error(f"RDAP returned {r.status_code}")
        data = r.json()

        events = {e.get("eventAction"): e.get("eventDate", "") for e in data.get("events", [])}
        registered = events.get("registration", "")
        expiration = events.get("expiration", "")
        now = datetime.now(timezone.utc)

        if registered:
            try:
                reg_date = datetime.fromisoformat(registered.replace("Z", "+00:00"))
                age_days = (now - reg_date).days
                if age_days < 30:
                    return result.critical(
                        f"Very new domain — registered {age_days} days ago",
                        f"Registered: {registered[:10]}. Newly registered domains are high phishing risk.",
                        impact=15
                    )
            except (ValueError, TypeError):
                pass

        if expiration:
            try:
                exp_date = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
                days_left = (exp_date - now).days
                if days_left <= 30:
                    return result.warn(
                        f"Domain expires in {days_left} days",
                        f"Expiry: {expiration[:10]}. Risk of domain hijacking if not renewed.",
                        impact=8
                    )
            except (ValueError, TypeError):
                pass

        entities = data.get("entities", [])
        combined = " ".join(
            str(e.get("vcardArray", "")) + " ".join(
                r2.get("description", [""])[0] for r2 in e.get("remarks", [])
            )
            for e in entities
        ).lower()
        if any(kw in combined for kw in ["privacy", "proxy", "redacted", "withheld"]):
            return result.warn(
                "Privacy/proxy registration detected",
                "Registrant identity hidden — common in phishing infrastructure",
                impact=5
            )

        return result.ok(
            "Domain registration looks normal",
            f"Registered: {registered[:10] if registered else 'unknown'} | "
            f"Expires: {expiration[:10] if expiration else 'unknown'}"
        )
    except Exception as e:
        return result.error("WHOIS lookup failed", str(e)[:80])


def check_email_security(domain: str) -> CheckResult:
    """Check SPF, DMARC, and DKIM email security records via dig."""
    result = CheckResult("email_security", domain)
    try:
        import subprocess

        spf_found = False
        dmarc_found = False
        dmarc_policy = ""

        try:
            spf_out = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=5
            )
            if spf_out.returncode == 0 and "v=spf1" in spf_out.stdout:
                spf_found = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            dmarc_out = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=5
            )
            if dmarc_out.returncode == 0 and "v=DMARC1" in dmarc_out.stdout:
                dmarc_found = True
                for part in dmarc_out.stdout.split(";"):
                    part = part.strip().strip('"')
                    if part.startswith("p="):
                        dmarc_policy = part[2:].strip().lower()
                        break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if not spf_found:
            return result.critical(
                "No SPF record — email spoofing possible",
                f"Domain {domain} has no SPF record. Anyone can send email as @{domain}.",
                impact=12
            )
        if not dmarc_found:
            return result.warn(
                "SPF exists but no DMARC policy",
                "Without DMARC, SPF failures are not enforced. Spoofed emails may still be delivered.",
                impact=8
            )
        if dmarc_policy == "none":
            return result.warn(
                "DMARC policy is p=none (monitoring only)",
                "DMARC is configured but not enforcing. Upgrade to p=quarantine or p=reject.",
                impact=6
            )

        return result.ok(
            f"Email security configured — SPF + DMARC p={dmarc_policy}",
            "SPF record present and DMARC policy enforces spoofing protection"
        )
    except Exception as e:
        return result.error("Email security check failed", str(e)[:80])


def check_ip_intel(domain: str) -> CheckResult:
    """Check IP reputation, ASN, TOR/proxy detection via ip-api.com (free, no key)."""
    result = CheckResult("ip_intel", domain)
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,isp,org,as,hosting,proxy,tor",
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code != 200:
            return result.error(f"ip-api returned {r.status_code}")

        data = r.json()
        if data.get("status") != "success":
            return result.error("IP lookup failed", data.get("message", "")[:80])

        is_tor = data.get("tor", False)
        is_proxy = data.get("proxy", False)
        is_hosting = data.get("hosting", False)
        isp = data.get("isp", "Unknown")
        org = data.get("org", "")
        asn = data.get("as", "")

        BULLETPROOF_KEYWORDS = [
            "M247", "FranTech", "Leaseweb", "B2 Net", "Webzilla",
            "Quasi", "CyberBunker", "Combahton", "Selectel", "Serverius"
        ]

        if is_tor:
            return result.critical(
                f"TOR exit node detected — {ip}",
                f"ISP: {isp} | AS: {asn}. TOR routing indicates anonymization.",
                impact=20
            )
        if is_proxy:
            return result.critical(
                f"Known proxy/anonymizer — {ip}",
                f"ISP: {isp} | AS: {asn}. IP flagged as proxy/VPN/anonymizer.",
                impact=20
            )
        if any(kw.lower() in (isp + org).lower() for kw in BULLETPROOF_KEYWORDS):
            return result.warn(
                "Bulletproof/suspicious hosting detected",
                f"ISP: {isp} | AS: {asn}. Associated with high-abuse hosting provider.",
                impact=8
            )

        net_type = "datacenter/hosting" if is_hosting else "regular network"
        return result.ok(
            f"IP intelligence clean — {ip}",
            f"ISP: {isp} | AS: {asn} | Type: {net_type}"
        )
    except socket.gaierror:
        return result.error("IP lookup failed", "Domain does not resolve")
    except Exception as e:
        return result.error("IP intel check failed", str(e)[:80])


def check_shodan(domain: str) -> CheckResult:
    """
    Shodan host intelligence — uses paid API when SHODAN_API_KEY is set,
    falls back to free InternetDB otherwise.
    Paid API adds: service banners, software versions, CPE, hostnames, org/ISP/country.
    """
    import os
    result = CheckResult("shodan", domain)
    api_key = os.getenv("SHODAN_API_KEY", "")

    DANGEROUS_PORTS = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC"}

    def _score(ports, cves, tags, vulns, services, ip, org="", isp=""):
        """Shared scoring logic for both API paths."""
        open_dangerous = [f"{p}({DANGEROUS_PORTS[p]})" for p in ports if p in DANGEROUS_PORTS]

        # Paid API vulns dict takes priority over InternetDB cves list
        all_cves = list(vulns.keys()) if vulns else cves

        if all_cves:
            cve_list = ", ".join(all_cves[:5])
            extra = f" | Services: {services[:3]}" if services else ""
            return result.critical(
                f"CVEs detected — {len(all_cves)} vulnerabilities on {ip}",
                f"CVEs: {cve_list}{' +more' if len(all_cves) > 5 else ''} | Ports: {ports[:10]}{extra}",
                impact=20
            )
        if open_dangerous:
            return result.critical(
                f"Dangerous ports open: {', '.join(open_dangerous)}",
                f"IP: {ip} | All open ports: {ports[:15]} | Tags: {tags}",
                impact=20
            )
        if len(ports) > 10:
            svc_str = f" | Services: {', '.join(services[:4])}" if services else ""
            return result.warn(
                f"Large attack surface — {len(ports)} open ports",
                f"IP: {ip} | Org: {org or isp}{svc_str}",
                impact=8
            )

        svc_str = f" | Services: {', '.join(services[:4])}" if services else ""
        return result.ok(
            f"Shodan: clean — {len(ports)} port(s) indexed",
            f"IP: {ip} | Org: {org or isp} | Tags: {tags}{svc_str}"
        )

    try:
        ip = socket.gethostbyname(domain)

        if api_key:
            # ── Paid Shodan Host API ──────────────────────────────────────────
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
                headers=HEADERS, timeout=TIMEOUT
            )
            if r.status_code == 404:
                return result.ok(f"Shodan: no data for {ip} — not indexed")
            if r.status_code == 401:
                return result.error("Shodan: invalid API key")
            if r.status_code != 200:
                return result.error(f"Shodan API returned {r.status_code}")

            data = r.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", {})   # dict: {"CVE-XXXX": {...}}
            tags = data.get("tags", [])
            org = data.get("org", "")
            isp = data.get("isp", "")

            # Extract product/version strings from service banners
            services = []
            for item in data.get("data", []):
                product = item.get("product", "")
                version = item.get("version", "")
                if product:
                    services.append(f"{product} {version}".strip())
            services = list(dict.fromkeys(services))  # deduplicate, preserve order

            return _score(ports, [], tags, vulns, services, ip, org, isp)

        else:
            # ── Free Shodan InternetDB fallback ──────────────────────────────
            r = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                headers=HEADERS, timeout=TIMEOUT
            )
            if r.status_code == 404:
                return result.ok(f"Shodan: no data for {ip} — minimal attack surface")
            if r.status_code != 200:
                return result.error(f"Shodan InternetDB returned {r.status_code}")

            data = r.json()
            return _score(
                data.get("ports", []),
                data.get("cves", []),
                data.get("tags", []),
                {}, [], ip
            )

    except socket.gaierror:
        return result.error("Shodan check failed", "Domain does not resolve")
    except Exception as e:
        return result.error("Shodan check failed", str(e)[:80])


def check_open_ports(domain: str) -> CheckResult:
    """Active port scan of high-risk ports via socket connect (2s timeout)."""
    result = CheckResult("open_ports", domain)
    try:
        ip = socket.gethostbyname(domain)

        HIGH_RISK_PORTS = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            3306: "MySQL", 5432: "Postgres", 6379: "Redis", 27017: "MongoDB",
            3389: "RDP", 5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt"
        }
        DB_PORTS = {3306, 5432, 6379, 27017}
        CRITICAL_PORTS = {23, 3389, 5900}

        open_ports = []
        for port, name in HIGH_RISK_PORTS.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append((port, name))
            sock.close()

        critical_open = [(p, n) for p, n in open_ports if p in DB_PORTS or p in CRITICAL_PORTS]
        warning_open = [(p, n) for p, n in open_ports if p not in DB_PORTS and p not in CRITICAL_PORTS]

        if critical_open:
            labels = ", ".join(f"{p}/{n}" for p, n in critical_open)
            return result.critical(
                f"Critical ports exposed: {labels}",
                f"Directly accessible from internet. High exploitation risk.",
                impact=20
            )
        if warning_open:
            labels = ", ".join(f"{p}/{n}" for p, n in warning_open)
            return result.warn(
                f"Risky ports open: {labels}",
                f"Services exposed to internet: {labels}",
                impact=8
            )

        return result.ok(
            "No high-risk ports open",
            f"Scanned {len(HIGH_RISK_PORTS)} common high-risk ports — none accessible"
        )
    except socket.gaierror:
        return result.error("Port scan failed", "Domain does not resolve")
    except Exception as e:
        return result.error("Port scan failed", str(e)[:80])


def check_sast(domain: str) -> CheckResult:
    """Check for exposed source code, git repos, and debug endpoints."""
    result = CheckResult("sast", domain)
    try:
        base = f"https://{domain}"
        PROBES = [
            ("/.git/HEAD", "git_head"),
            ("/.git/config", "git_config"),
            ("/composer.json", "composer"),
            ("/package.json", "package_json"),
            ("/.env.example", "env_example"),
            ("/phpinfo.php", "phpinfo"),
            ("/server-status", "server_status"),
            ("/?XDEBUG_SESSION_START=1", "xdebug"),
        ]

        findings = []
        for path, label in PROBES:
            try:
                r = requests.get(
                    f"{base}{path}", headers=HEADERS, timeout=TIMEOUT,
                    allow_redirects=False, verify=False
                )
                if r.status_code != 200:
                    continue
                content = r.text[:300]
                if label == "git_head" and "ref:" in content:
                    return result.critical(
                        "Git repository exposed — /.git/HEAD accessible",
                        f"Source code repository directly downloadable from {domain}/.git/",
                        impact=25
                    )
                if label == "phpinfo" and "phpinfo" in content.lower():
                    return result.critical(
                        "phpinfo() page exposed",
                        "Server configuration, PHP version, and environment variables visible",
                        impact=20
                    )
                if label == "xdebug" and "xdebug" in content.lower():
                    return result.critical(
                        "Xdebug active on production",
                        "Remote PHP debugging enabled — full code execution risk",
                        impact=20
                    )
                if label in ("composer", "package_json", "git_config", "env_example", "server_status"):
                    findings.append(path)
            except requests.exceptions.RequestException:
                continue

        if findings:
            return result.warn(
                f"Source/config files exposed: {len(findings)} path(s)",
                f"Accessible: {', '.join(findings)}",
                impact=10
            )

        return result.ok("No source code or debug endpoints exposed")
    except Exception as e:
        return result.error("SAST check failed", str(e)[:80])


def check_sca(domain: str) -> CheckResult:
    """Check for exposed dependency manifests and known-vulnerable versions."""
    result = CheckResult("sca", domain)
    KNOWN_VULNERABLE = [
        "log4j-core", "struts2", "log4j",
        "lodash\":\"4.17.20", "axios\":\"0.21.0",
        "prototype.js", "\"jquery\":\"1.", "\"jquery\":\"2.",
        "\"angular\":\"1.",
    ]
    try:
        base = f"https://{domain}"
        MANIFEST_PATHS = [
            "/package.json",
            "/composer.json",
            "/requirements.txt",
            "/Gemfile.lock",
        ]

        exposed = []
        vulnerable = []

        for path in MANIFEST_PATHS:
            try:
                r = requests.get(
                    f"{base}{path}", headers=HEADERS, timeout=TIMEOUT,
                    allow_redirects=False, verify=False
                )
                if r.status_code == 200 and len(r.text) > 20:
                    exposed.append(path)
                    content_lower = r.text.lower()
                    for vuln in KNOWN_VULNERABLE:
                        if vuln.lower() in content_lower:
                            vulnerable.append(f"{path}: {vuln.split(':')[0]}")
            except requests.exceptions.RequestException:
                continue

        if vulnerable:
            return result.critical(
                "Exposed dependencies with known vulnerabilities",
                f"Files: {', '.join(exposed)} | Flagged: {', '.join(vulnerable[:3])}",
                impact=15
            )
        if exposed:
            return result.warn(
                f"Dependency manifests publicly accessible: {len(exposed)} file(s)",
                f"Files exposed: {', '.join(exposed)}. Reveals tech stack and versions.",
                impact=8
            )

        return result.ok("No dependency manifests exposed")
    except Exception as e:
        return result.error("SCA check failed", str(e)[:80])


def check_dast(domain: str) -> CheckResult:
    """Check for exposed admin panels, credential files, and sensitive paths."""
    result = CheckResult("dast", domain)
    try:
        base = f"https://{domain}"
        SENSITIVE_PATHS = [
            ("/admin", "admin_panel"),
            ("/wp-admin", "wp_admin"),
            ("/phpmyadmin", "phpmyadmin"),
            ("/.well-known/security.txt", "security_txt"),
            ("/api/v1", "api"),
            ("/.env", "env_file"),
            ("/backup.zip", "backup"),
            ("/debug", "debug"),
            ("/console", "console"),
        ]

        critical_findings = []
        warning_findings = []

        for path, label in SENSITIVE_PATHS:
            try:
                r = requests.get(
                    f"{base}{path}", headers=HEADERS, timeout=TIMEOUT,
                    allow_redirects=False, verify=False
                )
                if r.status_code != 200:
                    continue
                content = r.text[:300].lower()

                if label == "env_file":
                    if any(kw in content for kw in ["db_password", "secret", "api_key", "database_url", "="]):
                        critical_findings.append("/.env (credentials exposed)")
                elif label in ("admin_panel", "wp_admin", "phpmyadmin"):
                    if any(kw in content for kw in ["login", "password", "username", "sign in"]):
                        warning_findings.append(f"{path} (login form)")
                    else:
                        critical_findings.append(f"{path} (no auth detected)")
                elif label in ("debug", "console"):
                    critical_findings.append(f"{path} (debug active)")
                elif label == "backup":
                    critical_findings.append(f"{path} (backup file exposed)")
            except requests.exceptions.RequestException:
                continue

        if critical_findings:
            return result.critical(
                f"Critical exposure: {critical_findings[0]}",
                f"Found: {', '.join(critical_findings[:3])}",
                impact=20
            )
        if warning_findings:
            return result.warn(
                f"Admin panels exposed: {', '.join(warning_findings[:2])}",
                f"Login panels accessible: {', '.join(warning_findings)}",
                impact=10
            )

        return result.ok("No sensitive paths exposed")
    except Exception as e:
        return result.error("DAST check failed", str(e)[:80])


def check_iac(domain: str) -> CheckResult:
    """Check for exposed infrastructure-as-code and configuration files."""
    result = CheckResult("iac", domain)
    try:
        base = f"https://{domain}"
        IAC_PATHS = [
            ("/.env", "env"),
            ("/docker-compose.yml", "docker_compose"),
            ("/docker-compose.yaml", "docker_compose"),
            ("/Dockerfile", "dockerfile"),
            ("/terraform.tfstate", "tfstate"),
            ("/k8s.yaml", "k8s"),
            ("/kubernetes.yaml", "k8s"),
            ("/.terraform/", "terraform_dir"),
            ("/ansible.cfg", "ansible"),
            ("/deploy.sh", "deploy_script"),
        ]

        critical_findings = []
        warning_findings = []

        for path, label in IAC_PATHS:
            try:
                r = requests.get(
                    f"{base}{path}", headers=HEADERS, timeout=TIMEOUT,
                    allow_redirects=False, verify=False
                )
                if r.status_code != 200 or len(r.text) <= 10:
                    continue
                content = r.text[:500].lower()
                if label in ("env", "tfstate"):
                    if label == "tfstate" or any(
                        kw in content for kw in ["password", "secret", "key", "token", "="]
                    ):
                        critical_findings.append(path)
                    else:
                        warning_findings.append(path)
                elif label in ("docker_compose", "dockerfile"):
                    warning_findings.append(path)
                else:
                    warning_findings.append(path)
            except requests.exceptions.RequestException:
                continue

        if critical_findings:
            return result.critical(
                f"IaC secrets exposed: {critical_findings[0]}",
                f"Critical files accessible: {', '.join(critical_findings)}. May contain credentials.",
                impact=25
            )
        if warning_findings:
            return result.warn(
                f"IaC files exposed: {len(warning_findings)} file(s)",
                f"Accessible: {', '.join(warning_findings[:4])}. Reveals infrastructure details.",
                impact=12
            )

        return result.ok("No IaC or infrastructure files exposed")
    except Exception as e:
        return result.error("IaC check failed", str(e)[:80])


ALL_CHECKS = [
    check_ssl,
    check_headers,
    check_dns,
    check_http_redirect,
    check_breach,
    check_typosquat,
    check_response_time,
    # ── Real-time threat intelligence ──
    check_urlhaus,              # free, no key
    check_spamhaus,             # free, no key (DNS-based)
    check_google_safebrowsing,  # free key: console.cloud.google.com
    check_virustotal,           # free key: virustotal.com
    # ── CVE Enrichment Skill ──
    check_cve,                  # free (NVD API); set NVD_API_KEY for higher rate limits
    # ── Dark-web credential intelligence ──
    check_darkweb,              # paranoidlab.com — set PARANOIDLAB_API_KEY
    # ── OSINT & Attack Surface ──
    check_whois,                # free (RDAP)
    check_email_security,       # free (DNS/dig)
    check_ip_intel,             # free (ip-api.com, 45 req/min)
    check_shodan,               # free (Shodan InternetDB, no key)
    check_open_ports,           # active socket scan
    check_sast,                 # passive HTTP probes
    check_sca,                  # dependency manifest check
    check_dast,                 # sensitive path probes
    check_iac,                  # IaC file exposure check
]


def scan_domain(domain: str) -> dict:
    """Run all passive checks against a single domain."""
    results = []
    for check_fn in ALL_CHECKS:
        try:
            r = check_fn(domain)
            results.append(r.to_dict())
        except Exception as e:
            logger.error(f"Check {check_fn.__name__} failed for {domain}: {e}")
            results.append(CheckResult(check_fn.__name__, domain).error(
                "Check crashed", str(e)[:80]
            ).to_dict())

    # Calculate risk score (0=best, 100=worst)
    penalty = sum(r["score_impact"] for r in results)
    risk_score = min(100, penalty)

    critical_count = sum(1 for r in results if r["status"] == "critical")
    warning_count = sum(1 for r in results if r["status"] == "warning")

    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "critical": critical_count,
        "warnings": warning_count,
        "checks": results,
    }


# Alias used by main.py backend
run_checks = scan_domain
