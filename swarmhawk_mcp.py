import os, sys, json, hashlib
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastmcp import FastMCP

SERVER_API_KEY = os.getenv("SWARMHAWK_SERVER_KEY", "")
CLIENT_API_KEY = os.getenv("SWARMHAWK_API_KEY", "")
USAGE_FILE = Path("/tmp/swarmhawk_usage.json")
FREE_LIMIT = 10

def load_usage():
    try: return json.loads(USAGE_FILE.read_text())
    except: return {}

def check_auth(api_key=""):
    if not SERVER_API_KEY: return True, "ok"
    key = api_key or CLIENT_API_KEY
    if not key: return False, "API key required. Get one free at hastikdan.github.io/swarmhawk"
    if key.startswith("swh_pro_") or key.startswith("swh_biz_"): return True, "ok"
    if key.startswith("swh_free_"):
        usage = load_usage()
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        k = hashlib.sha256(key.encode()).hexdigest()[:16] + ":" + month
        count = usage.get(k, 0)
        if count >= FREE_LIMIT: return False, f"Free limit reached ({FREE_LIMIT}/month). Upgrade at hastikdan.github.io/swarmhawk"
        usage[k] = count + 1
        USAGE_FILE.write_text(json.dumps(usage))
        return True, f"ok ({FREE_LIMIT - usage[k]} free scans left this month)"
    return False, "Invalid API key"

def rlabel(s): return "HIGH RISK" if s>=60 else "MEDIUM RISK" if s>=30 else "LOW RISK"

mcp = FastMCP("SwarmHawk Security Intelligence", instructions="Scan domains for security threats across 25 European countries. Run scan_domain for full analysis, quick_risk_score for fast checks, batch_risk_scores for portfolios.")

@mcp.tool
def scan_domain(domain: str, api_key: str = "") -> dict:
    """Full 17-check security scan with AI threat analysis. Use for due diligence, pre-deployment checks, vendor assessment. Args: domain: e.g. 'example.com'"""
    ok, msg = check_auth(api_key)
    if not ok: return {"error": msg, "domain": domain}
    try:
        from cee_scanner.checks import run_checks
        r = run_checks(domain)
        checks = [{"check":c.get("check"),"status":c.get("status"),"finding":c.get("title",""),"detail":c.get("detail",""),"impact":c.get("score_impact",0)} for c in r.get("checks",[]) if c.get("check")!="ai_summary"]
        ai = next((c for c in r.get("checks",[]) if c.get("check")=="ai_summary"), None)
        return {"domain":domain,"risk_score":r["risk_score"],"risk_level":rlabel(r["risk_score"]),"critical":r["critical"],"warnings":r["warnings"],"scanned_at":r["scanned_at"],"checks":checks,"ai_analysis":ai.get("detail","") if ai else "","quota":msg}
    except Exception as e: return {"error":str(e),"domain":domain}

@mcp.tool
def quick_risk_score(domain: str, api_key: str = "") -> dict:
    """Fast 4-check risk score in ~3 seconds. Checks SSL, DNS, HTTPS, headers. Args: domain: e.g. 'example.com'"""
    ok, msg = check_auth(api_key)
    if not ok: return {"error": msg, "domain": domain}
    try:
        from cee_scanner.checks import check_ssl, check_headers, check_dns, check_https_redirect
        risk=0; crit=0; warn=0; res=[]
        for fn in [check_ssl, check_headers, check_dns, check_https_redirect]:
            r=fn(domain); risk+=r.score_impact or 0
            if r.status=="critical": crit+=1
            if r.status=="warning": warn+=1
            res.append({"check":r.check,"status":r.status,"finding":r.title})
        return {"domain":domain,"risk_score":min(risk,100),"risk_level":rlabel(risk),"critical":crit,"warnings":warn,"checks":res,"quota":msg}
    except Exception as e: return {"error":str(e),"domain":domain}

@mcp.tool
def check_typosquats(domain: str, api_key: str = "") -> dict:
    """Check for registered typosquat lookalike domains. Essential for phishing risk and brand protection. Args: domain: e.g. 'mybank.com'"""
    ok, msg = check_auth(api_key)
    if not ok: return {"error": msg, "domain": domain}
    try:
        from cee_scanner.checks import check_typosquat
        r=check_typosquat(domain)
        return {"domain":domain,"status":r.status,"finding":r.title,"detail":r.detail,"risk_impact":r.score_impact,"recommendation":"Register key variants (~€10/yr) and enable DMARC." if r.status in ("critical","warning") else "No significant exposure.","quota":msg}
    except Exception as e: return {"error":str(e),"domain":domain}

@mcp.tool
def check_reputation(domain: str, api_key: str = "") -> dict:
    """Check Spamhaus + VirusTotal (70+ engines) + Google Safe Browsing + URLhaus. Args: domain: domain to check"""
    ok, msg = check_auth(api_key)
    if not ok: return {"error": msg, "domain": domain}
    try:
        from cee_scanner.checks import check_spamhaus, check_virustotal, check_google_safebrowsing, check_urlhaus
        results={}; overall="ok"
        for name,fn in [("spamhaus",check_spamhaus),("virustotal",check_virustotal),("safebrowsing",check_google_safebrowsing),("urlhaus",check_urlhaus)]:
            try:
                r=fn(domain); results[name]={"status":r.status,"finding":r.title,"detail":r.detail}
                if r.status=="critical": overall="critical"
                elif r.status=="warning" and overall=="ok": overall="warning"
            except Exception as e: results[name]={"status":"error","finding":str(e)[:80]}
        return {"domain":domain,"overall_status":overall,"sources":results,"quota":msg}
    except Exception as e: return {"error":str(e),"domain":domain}

@mcp.tool
def batch_risk_scores(domains: list[str], api_key: str = "") -> dict:
    """Quick risk scores for up to 10 domains at once, sorted by risk. Perfect for M&A due diligence and portfolio reviews. Args: domains: list of domains"""
    ok, msg = check_auth(api_key)
    if not ok: return {"error": msg}
    if len(domains)>10: return {"error":"Max 10 domains per batch"}
    results=[]
    for domain in domains:
        try:
            from cee_scanner.checks import check_ssl, check_dns, check_headers
            risk=0; crit=0
            for fn in [check_ssl,check_dns,check_headers]:
                r=fn(domain); risk+=r.score_impact or 0
                if r.status=="critical": crit+=1
            results.append({"domain":domain,"risk_score":min(risk,100),"risk_level":rlabel(risk),"critical":crit})
        except Exception as e: results.append({"domain":domain,"error":str(e)[:60]})
    results.sort(key=lambda x:x.get("risk_score",0),reverse=True)
    high=[r for r in results if r.get("risk_score",0)>=60]
    return {"total":len(results),"high_risk":len(high),"results":results,"priority":"Investigate: "+", ".join(r["domain"] for r in high) if high else "No high-risk domains.","quota":msg}

@mcp.tool
def get_quota(api_key: str = "") -> dict:
    """Check remaining scan quota for this month. Args: api_key: your SwarmHawk API key"""
    key = api_key or CLIENT_API_KEY
    if not key: return {"plan":"none","message":"Get a free API key at hastikdan.github.io/swarmhawk"}
    if key.startswith("swh_pro_"): return {"plan":"Pro","scans_per_month":500}
    if key.startswith("swh_biz_"): return {"plan":"Business","scans_per_month":"unlimited"}
    if key.startswith("swh_free_"):
        usage=load_usage(); month=datetime.now(timezone.utc).strftime("%Y-%m")
        k=hashlib.sha256(key.encode()).hexdigest()[:16]+":"+month
        count=usage.get(k,0)
        return {"plan":"Free","limit":FREE_LIMIT,"used":count,"remaining":max(0,FREE_LIMIT-count),"upgrade":"hastikdan.github.io/swarmhawk"}
    return {"error":"Invalid key format"}

@mcp.resource("swarmhawk://info")
def get_info() -> str:
    """SwarmHawk coverage and pricing."""
    return json.dumps({"name":"SwarmHawk","version":"1.0.0","countries":25,"checks":17,"free_tier":"10 scans/month","pricing":"€50/domain/yr or €29/mo Pro","get_key":"hastikdan.github.io/swarmhawk"},indent=2)

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--http",action="store_true")
    p.add_argument("--port",type=int,default=8001)
    args=p.parse_args()
    if args.http:
        print(f"SwarmHawk MCP running at http://0.0.0.0:{args.port}/mcp")
        mcp.run(transport="streamable-http",host="0.0.0.0",port=args.port,path="/mcp")
    else:
        mcp.run()
