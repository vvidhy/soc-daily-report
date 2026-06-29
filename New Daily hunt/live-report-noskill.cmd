@echo off
rem ============================================================
rem  LIVE HOURLY HUNT - near-real-time MITRE + UEBA sweep of the
rem  last ~65 min across all 4 Graylogs, delivered to the IIS-OPGL
rem  Teams channel. No multi-pass stale retry - the next hourly
rem  run covers any gap. Fully separate from the daily pipeline
rem  (its own reports-live\ + live.log + .webhook-live), so the
rem  daily report flow is untouched.
rem  Flow: hunt -> PDF (Edge headless) -> upload to SharePoint ->
rem        Teams cards with PDF link in summary card button.
rem ============================================================
cd /d "D:\Vidhya\New Daily hunt"
if not exist "reports-live"  mkdir "reports-live"
if not exist "logs-noskill"  mkdir "logs-noskill"
echo ==== LIVE %DATE% %TIME% ==== >> "logs-noskill\live.log"

rem fresh window: clear prior live outputs (daily reports-noskill\ untouched)
del /q "reports-live\live-latest.md" 2>nul
del /q "reports-live\alert-*.json" 2>nul

rem === RUN the live hunt (sonnet, key=live, 65-min window) ===
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-noskill-hunt.ps1" -Key live >> "logs-noskill\live.log" 2>&1

rem === token / rate-limit guard: skip delivery this hour, next hour retries ===
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=(Get-Content 'logs-noskill\live.log' -Tail 80 -EA SilentlyContinue) -join ' '; if($t -match 'rate_limit_error|insufficient_quota|overloaded_error|too many requests|context window|credit'){ exit 1 }" 2>> "logs-noskill\live.log"
if errorlevel 1 (
  echo [%TIME%] LIVE token/rate-limit hit - skipping delivery this hour ^(next hour retries^) >> "logs-noskill\live.log"
  goto :checkpoint
)

rem === PDF: render live-latest.md -> live-SOC-YYYY-MM-DD-HHmm.pdf + OneDrive copy ===
if exist "reports-live\live-latest.md" (
  echo [%TIME%] Generating live PDF >> "logs-noskill\live.log"
  powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\generate-live-pdf.ps1" >> "logs-noskill\live.log" 2>&1
) else (
  echo [%TIME%] no reports-live\live-latest.md - skipping PDF >> "logs-noskill\live.log"
)

rem === DELIVER to IIS-OPGL channel (only if the hunt wrote findings) ===
if exist "reports-live\live-latest.md" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\send-live-noskill.ps1" >> "logs-noskill\live.log" 2>&1
) else (
  echo [%TIME%] no reports-live\live-latest.md - hunt wrote nothing this window >> "logs-noskill\live.log"
)

:checkpoint
powershell -NoProfile -ExecutionPolicy Bypass -Command "[IO.File]::WriteAllText('logs-noskill\live-last-run.json', (@{ run_time=(Get-Date -Format o) } | ConvertTo-Json))" >> "logs-noskill\live.log" 2>&1
echo. >> "logs-noskill\live.log"
goto :eof
