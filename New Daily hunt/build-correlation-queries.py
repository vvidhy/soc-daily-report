"""
build-correlation-queries.py
Zero-token script: reads findings-json from daily-latest.md,
extracts IPs/users from MEDIUM/LOW findings, generates structured
cross-surface Graylog queries -> reports-noskill/correlation-queries.json
"""
import json, re, sys
from pathlib import Path

PROJ      = Path(r"D:\Vidhya\New Daily hunt")
ALERT_DIR = PROJ / "reports-noskill"
DAILY_MD  = ALERT_DIR / "daily-latest.md"
OUT_JSON  = ALERT_DIR / "correlation-queries.json"

SKIP_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

def main():
    if not DAILY_MD.exists():
        print("[corr-queries] No daily-latest.md - nothing to correlate.")
        OUT_JSON.write_text("[]", encoding="utf-8")
        return

    md_text = DAILY_MD.read_text(encoding="utf-8", errors="replace")

    # Extract findings-json block
    m = re.search(r"```findings-json\s*\n(.*?)\n```", md_text, re.DOTALL)
    parsed = []
    if m:
        try:
            raw = json.loads(m.group(1))
            if isinstance(raw, list):
                parsed = raw
            elif isinstance(raw, dict) and "value" in raw and "sev" not in raw:
                parsed = raw["value"]
        except Exception as e:
            print(f"[corr-queries] findings-json parse error: {e}")

    ips      = set()
    users    = set()
    surfaces = set()
    med_low  = []

    ip_re   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
    user_re = re.compile(r'\b[\w.\-]+@casepoint\.(?:com|in)\b', re.IGNORECASE)

    for f in parsed:
        sev = str(f.get("sev", ""))
        if sev not in ("MEDIUM", "LOW"):
            continue
        med_low.append(f)
        if f.get("surface"):
            surfaces.add(str(f["surface"]))
        text = " ".join(str(f.get(k, "")) for k in ("finding", "evidence", "detail"))
        ips.update(ip_re.findall(text))
        users.update(user_re.findall(text))

    ips -= SKIP_IPS

    if not med_low:
        print("[corr-queries] No MEDIUM/LOW findings - no manual correlation queries needed.")
        OUT_JSON.write_text("[]", encoding="utf-8")
        return

    print(f"[corr-queries] {len(med_low)} MEDIUM/LOW findings. IPs: {len(ips)}, Users: {len(users)}")

    rows = []

    # IP pivot queries — field names kept generic (no attack literals)
    for ip in sorted(ips):
        rows.append({
            "label":   "IP cross-surface",
            "pivot":   ip,
            "surface": "all",
            "sev":     "pivot",
            "query":   f'Client_ip:"{ip}" OR src_ip:"{ip}" OR source_ip:"{ip}" OR properties_callerIpAddress:"{ip}" OR message:"{ip}"',
            "note":    "Run across all 4 Graylogs. rangeSeconds=86400"
        })

    # User pivot queries
    for u in sorted(users):
        rows.append({
            "label":   "User cross-surface",
            "pivot":   u,
            "surface": "all",
            "sev":     "pivot",
            "query":   f'properties_userPrincipalName:"{u}" OR properties_userId:"{u}" OR message:"{u}"',
            "note":    "Run across all 4 Graylogs. rangeSeconds=86400"
        })

    # Surface-pair patterns
    if "azure" in surfaces or "rdp" in surfaces:
        rows.append({
            "label":   "Azure->RDP pivot",
            "pivot":   "Azure MEDIUM/LOW user -> Windows RDP",
            "surface": "azure + windows",
            "sev":     "pattern",
            "query":   "EventID:4624 OR EventID:4625 OR EventID:4648",
            "note":    "Run on PROD-GL / AZ-GL. Cross-reference with Azure MEDIUM/LOW user accounts"
        })

    if "iis" in surfaces or "azure" in surfaces:
        rows.append({
            "label":   "IIS->Azure correlation",
            "pivot":   "IIS attacker IP in Azure failed auth",
            "surface": "iis + azure",
            "sev":     "pattern",
            "query":   'result_value:"Failure" AND properties_callerIpAddress:*',
            "note":    "Run on AZ-GL. Filter by IPs from IIS MEDIUM/LOW findings above"
        })

    if "sftp" in surfaces or "linux" in surfaces:
        rows.append({
            "label":   "SFTP->Linux lateral",
            "pivot":   "SFTP brute-force IP in Linux SSH",
            "surface": "sftp + linux",
            "sev":     "pattern",
            "query":   "message:*Failed password* OR message:*Invalid user*",
            "note":    "Run on PROD-GL. Cross-reference SFTP client IPs with Linux auth failures"
        })

    if "network" in surfaces or "firewall" in surfaces:
        rows.append({
            "label":   "FortiGate->IIS web",
            "pivot":   "FortiGate-blocked IP probing IIS",
            "surface": "network + iis",
            "sev":     "pattern",
            "query":   "action:deny AND proto:6",
            "note":    "Run on PROD-GL. Cross-reference denied src IPs with IIS URI_Stream findings"
        })

    # Per-finding re-run queries
    for f in med_low:
        fq = str(f.get("query", ""))
        if fq and fq.lower() != "n/a":
            rows.append({
                "label":   f"Re-run: {f.get('sev','')} {f.get('surface','')}",
                "pivot":   str(f.get("finding", "")),
                "surface": str(f.get("surface", "")),
                "sev":     str(f.get("sev", "")),
                "query":   fq,
                "note":    "Original detection query from the hunt. Widen time range to pivot further"
            })

    OUT_JSON.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    print(f"[corr-queries] Wrote {len(rows)} query rows to correlation-queries.json")

if __name__ == "__main__":
    main()
