@echo off
rem ============================================================
rem  SOC-Depth-Test : isolated, on-demand test of the DEPTH layer.
rem  Runs ONLY the opus depth pass + merge-depth against the CURRENT
rem  breadth leads (reports-noskill\daily-latest.md + alert-*.json).
rem  NO breadth re-run, NO PDF, NO Teams, NO email.
rem  The live daily-latest.md is backed up and RESTORED so this test
rem  never alters the delivered report; the merged result is saved to
rem  daily-latest.depthtest-merged.md for inspection.
rem ============================================================
cd /d "D:\Vidhya\New Daily hunt"
set "LOG=logs-noskill\depth-test.log"
del /q "logs-noskill\depth-test.done" 2>nul
echo ==== DEPTH LAYER ISOLATED TEST %DATE% %TIME% ==== > "%LOG%"

rem back up the live report so this test cannot alter it
copy /y "reports-noskill\daily-latest.md" "reports-noskill\daily-latest.md.depthtest-bak" >nul 2>&1

rem clear stale depth output
del /q "reports-noskill\depth-findings.json" 2>nul

echo [%TIME%] Running opus DEPTH pass (-Key depth, maxTurns from manifest) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-noskill-hunt.ps1" -Key depth >> "%LOG%" 2>&1

echo [%TIME%] Running merge-depth-noskill.ps1 >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\merge-depth-noskill.ps1" >> "%LOG%" 2>&1

rem save merged result for inspection, then restore the pristine live file
copy /y "reports-noskill\daily-latest.md" "reports-noskill\daily-latest.depthtest-merged.md" >nul 2>&1
copy /y "reports-noskill\daily-latest.md.depthtest-bak" "reports-noskill\daily-latest.md" >nul 2>&1
del /q "reports-noskill\daily-latest.md.depthtest-bak" 2>nul

echo [%TIME%] DEPTH TEST COMPLETE >> "%LOG%"
echo done> "logs-noskill\depth-test.done"
