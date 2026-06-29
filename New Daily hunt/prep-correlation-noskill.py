"""
prep-correlation-noskill.py
Reads daily-latest.md, extracts the findings-json block, filters non-CLEAN findings,
and writes reports-noskill\_merged-findings.json.
Writes logs-noskill\run-correlation.flag only when >=1 HIGH or CRITICAL finding exists.
Ported from prep-correlation-noskill.ps1 (XDR-safe: no attack literals in script body).
"""
import sys, re, json, pathlib, datetime

BASE = pathlib.Path(r"D:\Vidhya\New Daily hunt")
DAILY  = BASE / "reports-noskill" / "daily-latest.md"
OUT    = BASE / "reports-noskill" / "_merged-findings.json"
FLAG   = BASE / "logs-noskill" / "run-correlation.flag"

def log(msg):
    print(msg, flush=True)

FLAG.unlink(missing_ok=True)

if not DAILY.exists():
    log("prep-correlation: no daily-latest.md - skip")
    sys.exit(0)

raw = DAILY.read_text(encoding="utf-8", errors="replace")
raw = "".join(c for c in raw if 0x20 <= ord(c) <= 0x7E or c in "\r\n")

m = re.search(r"```findings-json\s*[\r\n]+(.*?)[\r\n]+```", raw, re.DOTALL)
if not m:
    log("prep-correlation: no findings-json block - skip")
    sys.exit(0)

try:
    parsed = json.loads(m.group(1))
except Exception as e:
    log(f"prep-correlation: JSON parse error - skip ({e})")
    sys.exit(0)

# Flatten wrapper objects {value:[...], Count:N} that lack a 'sev' key
flat = []
for item in (parsed if isinstance(parsed, list) else [parsed]):
    if isinstance(item, dict) and "value" in item and "sev" not in item:
        for sub in (item["value"] if isinstance(item["value"], list) else []):
            if sub is not None:
                flat.append(sub)
    else:
        flat.append(item)

HIGH_SEVS = {"HIGH", "CRITICAL"}
CLEAN_SEV = "CLEAN"

nonclean  = [f for f in flat if isinstance(f, dict) and str(f.get("sev","")).upper() != CLEAN_SEV]
high_crit = [f for f in nonclean if str(f.get("sev","")).upper() in HIGH_SEVS]

if not high_crit:
    log(f"prep-correlation: no HIGH/CRITICAL findings ({len(nonclean)} non-clean total) - skipping Opus correlation. MEDIUM/LOW queries will be generated.")
    sys.exit(0)

KEEP = ["sev","env","surface","finding","evidence","mitre","tactic","killchain","action"]
slim = [{k: str(f.get(k,"")) for k in KEEP} for f in nonclean]

OUT.write_text(json.dumps(slim, ensure_ascii=True), encoding="utf-8")
FLAG.write_text(datetime.datetime.now().isoformat(), encoding="utf-8")
log(f"prep-correlation: wrote _merged-findings.json ({len(nonclean)} findings, {len(high_crit)} HIGH/CRITICAL) - Opus correlation will run.")
