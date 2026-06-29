@echo off
setlocal
set PROJ=D:\Vidhya\New Daily hunt

echo [%TIME%] === DEPTH CATCHUP (6 skipped modules) ===

rem --- run the 6 skipped modules ---
del /q "%PROJ%\reports-noskill\depth-catchup.json" 2>nul
echo [%TIME%] Running depth-catchup hunt...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJ%\run-noskill-hunt.ps1" -Key depth-catchup
if not exist "%PROJ%\reports-noskill\depth-catchup.json" (
  echo [%TIME%] depth-catchup.json not written - agent may have written text only. Aborting.
  exit /b 1
)

rem --- TI enrich catchup findings before merge ---
echo [%TIME%] TI enriching catchup findings...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJ%\enrich-findings-ti.ps1" -FindingsFile "%PROJ%\reports-noskill\depth-catchup.json"

rem --- merge catchup findings into daily-latest.md ---
echo [%TIME%] Merging catchup findings...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJ%\merge-depth-noskill.ps1" -DepthFile "%PROJ%\reports-noskill\depth-catchup.json"

rem --- regenerate PDF ---
echo [%TIME%] Regenerating PDF...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJ%\generate-pdf-noskill.ps1"

rem --- send email ---
echo [%TIME%] Sending updated report...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJ%\send-csv-noskill.ps1"

echo [%TIME%] === DEPTH CATCHUP DONE ===
