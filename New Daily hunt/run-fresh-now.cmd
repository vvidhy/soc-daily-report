@echo off
rem On-demand FRESH full-depth no-skill scan + delivery (channel-only), TODAY.
rem Calls the RAW daily-report cmd directly (bypasses the guarded wrapper).
rem SOC_BYPASS_DEADLINE=1 skips the stale-retry/correlation/depth deadline guards.
rem SOC_SKIP_EMAIL=1 posts to Teams channel only (no email). Currently ENABLED (email on).
cd /d "D:\Vidhya\New Daily hunt"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=Get-Date -Format yyyyMMdd; del \"logs-noskill\hunt-complete-$d.txt\" -EA SilentlyContinue; del \"logs-noskill\delivered-$d.txt\" -EA SilentlyContinue" 2>nul
del /q "logs-noskill\token-exhausted.flag" 2>nul
del /q "logs-noskill\gaps-rerun.flag" 2>nul
del /q "logs-noskill\skip-hunt.flag" 2>nul
del /q "logs-noskill\run-start.flag" 2>nul
del /q "reports-noskill\coverage-gaps.json" 2>nul
rem set SOC_SKIP_EMAIL=1
set SOC_BYPASS_DEADLINE=1
echo ==== FRESH-NOW full-scan (forced, email+Teams) %DATE% %TIME% ==== >> "logs-noskill\daily.log"
call "D:\Vidhya\New Daily hunt\daily-report-noskill.cmd"
echo ==== FRESH-NOW full-scan done %DATE% %TIME% ==== >> "logs-noskill\daily.log"
