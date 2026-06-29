"""
merge-correlation-noskill.py
Merges correlation-latest.md findings-json block into daily-latest.md.
Ported from merge-correlation-noskill.ps1 (XDR-safe: no attack literals in script body).
"""
import sys, re, json, pathlib

BASE  = pathlib.Path(r"D:\Vidhya\New Daily hunt")
MAIN  = BASE / "reports-noskill" / "daily-latest.md"
CORR  = BASE / "reports-noskill" / "correlation-latest.md"

def log(msg):
    print(msg, flush=True)

def clean(text):
    return "".join(c for c in text if 0x20 <= ord(c) <= 0x7E or c in "\r\n")

def extract_findings(text):
    m = re.search(r"```findings-json\s*[\r\n]+(.*?)[\r\n]+```", text, re.DOTALL)
    if not m:
        return []
    try:
        parsed = json.loads(m.group(1))
        return parsed if isinstance(parsed, list) else [parsed]
    except Exception as e:
        log(f"merge-correlation: JSON parse error: {e}")
        return []

if not CORR.exists():
    log("merge-correlation: no correlation-latest.md - nothing to merge.")
    sys.exit(0)
if not MAIN.exists():
    log("merge-correlation: no daily-latest.md - cannot merge.")
    sys.exit(0)

main_raw = clean(MAIN.read_text(encoding="utf-8", errors="replace"))
corr_raw = clean(CORR.read_text(encoding="utf-8", errors="replace"))

main_findings = extract_findings(main_raw)
corr_findings = [f for f in extract_findings(corr_raw) if isinstance(f, dict) and str(f.get("sev","")).upper() != "CLEAN"]

if not corr_findings:
    log("merge-correlation: no non-clean correlation findings - nothing to add.")
    sys.exit(0)

merged = main_findings + corr_findings
new_json = json.dumps(merged, ensure_ascii=True, separators=(",", ":"))
new_block = "```findings-json\n" + new_json + "\n```"

new_main = re.sub(r"```findings-json[\r\n]+.*?[\r\n]+```", new_block, main_raw, flags=re.DOTALL)
MAIN.write_text(new_main, encoding="utf-8")
log(f"merge-correlation: added {len(corr_findings)} correlation finding(s) to daily-latest.md ({len(merged)} total).")
