@echo off
cd /d "D:\Vidhya\New Daily hunt"
echo ==== TICK %DATE% %TIME% ==== >> "logs\sweep.log"

rem === TIER 1 SWEEP - Sonnet, loads sweep.txt via run-noskill-hunt.ps1 ===
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-noskill-hunt.ps1" -Key sweep > "logs\last-tick.txt" 2>&1
type "logs\last-tick.txt" >> "logs\sweep.log"
echo. >> "logs\sweep.log"

powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\send-alert.ps1" >> "logs\sweep.log" 2>&1

findstr /c:"ESCALATE:" "logs\last-tick.txt" > "logs\escalations.txt"
if errorlevel 1 goto :done

echo ==== ESCALATION %DATE% %TIME% ==== >> "logs\sweep.log"
call "C:\Users\VidhyaV\AppData\Roaming\npm\claude.cmd" -p "You are an Opus SOC incident investigator. The monitoring tick just raised one or more escalations. Read the file D:\Vidhya\New Daily hunt\logs\escalations.txt - each line is an ESCALATE marker in the format: ESCALATE: env / host-or-user / reason / anchor. For EACH escalation, perform a full deep investigation DIRECTLY in this session - do NOT spawn a subagent (subagents cannot access the Graylog MCP tools in headless mode); call your own mcp__AZ-GL__/mcp__PROD-GL__/mcp__DEV-GL__/mcp__OP-GL__ tools yourself. Anchor the event and pull surrounding logs, recover source IPs, determine whether any authentication succeeded, correlate across streams and envs for lateral movement, enrich IOCs via WebSearch, and give a verdict (confirmed-incident / needs-human / false-positive) with confidence, MITRE ATT&CK IDs, blast radius, and concrete containment + remediation. Cite evidence (log _id and timestamp) on every claim. For each escalation write a write-up to D:\Vidhya\New Daily hunt\logs\incident-HOST-UTCDATE.md (substitute the host and UTC date), then print a concise summary. Be rigorous." --model opus --permission-mode bypassPermissions --mcp-config "D:\Vidhya\New Daily hunt\.mcp.json" --strict-mcp-config --add-dir "C:\Users\VidhyaV\.claude\state" < NUL >> "logs\sweep.log" 2>&1
echo. >> "logs\sweep.log"

:done
