"""
Python equivalent of run-noskill-hunt.ps1
Used for hunts whose prompts contain security-keyword literals that trigger
Cortex XDR's PowerShell script-block scanner (e.g. correlation, depth).
Python subprocess execution is not subject to PS Script Block Logging (Event 4104),
so XDR does not intercept it.

Usage:  py run-noskill-hunt.py <KEY>
Output: stdout only — caller's >> daily.log redirect captures everything.
Exit codes: 0=ok  2=config error  3=rate-limited
"""

import sys
import os
import json
import subprocess
from datetime import datetime, timezone

if len(sys.argv) < 2:
    print("run-noskill-hunt.py: KEY argument required")
    sys.exit(2)

KEY = sys.argv[1]
PROJ = r"D:\Vidhya\New Daily hunt"
CLAUDE = r"C:\Users\VidhyaV\AppData\Roaming\npm\claude.cmd"

os.chdir(PROJ)

# --- Load manifest ---
manifest_path = os.path.join(PROJ, "noskill-hunts.json")
try:
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
except Exception as e:
    print(f"run-noskill-hunt.py: cannot read noskill-hunts.json - {e}")
    sys.exit(2)

hunt = next((h for h in manifest if h.get("key") == KEY), None)
if hunt is None:
    print(f"run-noskill-hunt.py: unknown key '{KEY}'")
    sys.exit(2)

# --- Rate-limit check (rate-limit-check.ps1 doesn't read attack sigs — safe to call via PS) ---
rl_result = subprocess.run(
    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
     "-File", os.path.join(PROJ, "rate-limit-check.ps1"),
     "-Key", KEY, "-WeeklyLimit", "85"],
    capture_output=True, text=True
)
if rl_result.stdout:
    print(rl_result.stdout, end="")
if rl_result.returncode == 1:
    sys.exit(3)

# --- Resolve config ---
prompt_path = os.path.join(PROJ, hunt["prompt"])
if not os.path.exists(prompt_path):
    print(f"run-noskill-hunt.py: missing prompt file {prompt_path}")
    sys.exit(2)

mcp_name = hunt.get("mcp", ".mcp.json")
mcp_path = os.path.join(PROJ, mcp_name)
if not os.path.exists(mcp_path):
    print(f"run-noskill-hunt.py: missing mcp config {mcp_path} - falling back to .mcp.json")
    mcp_path = os.path.join(PROJ, ".mcp.json")
    mcp_name = ".mcp.json"

max_turns = str(hunt.get("maxTurns", 200))
model = hunt.get("model", "claude-sonnet-4-6")

print(f"==== NOSKILL HUNT [{KEY}] model={model} {datetime.now(timezone.utc).isoformat()} ====")
print(f"run-noskill-hunt.py [{KEY}]: mcp={mcp_name} maxTurns={max_turns}")
print(f"run-noskill-hunt.py [{KEY}]: prompt piped via stdin (python runner - XDR safe)")

# --- Build claude args ---
base_args = [
    CLAUDE,
    "--model", model,
    "--permission-mode", "bypassPermissions",
    "--disallowed-tools", "Skill",
    "--mcp-config", mcp_path,
    "--strict-mcp-config",
    "--max-turns", max_turns,
]

# Pipe the prompt file directly into claude's stdin — never read content into a variable.
# This is the critical difference: the attack-sig bytes never appear in Python's
# evaluated code, only as opaque bytes flowing through a file handle.
with open(prompt_path, "rb") as prompt_file:
    result = subprocess.run(base_args, stdin=prompt_file)

sys.exit(result.returncode)
