@echo off
rem ============================================================
rem  NOSKILL DAILY REPORT - single-prompt hunt with stale retry.
rem
rem  Flow:
rem   1. FRESH START (no token-exhausted.flag, no gaps-rerun.flag):
rem      - Clear prior run files
rem      - Run main hunt (all surfaces, one sonnet session)
rem      - If no output -> mark ALL surfaces stale + Teams alert
rem      - If partial coverage -> Teams alert, stale retry continues
rem      - Detect token/API exhaustion -> Teams alert + write flag, exit 1
rem   2. STALE RETRY (up to 2 passes via retry-stale-noskill.ps1):
rem      - For each surface in coverage-gaps.json, run a focused session
rem      - If token exhaustion -> Teams alert + write flag, exit 1
rem      - If gaps remain after all passes -> Teams partial-coverage alert
rem   3. DELIVER: generate PDF + send Teams cards
rem      - If PDF missing -> Teams alert (delivery continues without PDF link)
rem
rem  Token exhaustion resume (token-exhausted.flag present):
rem   - Jumps straight to :stale_only, preserving daily-latest.md and all
rem     prior hunt output. The flag is cleared just before delivery (line ~99).
rem   - guarded.cmd does NOT clear the flag -- it stays until we reach :stale_only.
rem
rem  Post-delivery gap retry (gaps-rerun.flag present):
rem   - Delivery already ran; jumps to :gaps_only which runs stale retry
rem     without re-posting all finding cards (avoids duplicates in Teams).
rem ============================================================
cd /d "D:\Vidhya\New Daily hunt"
echo ==== NOSKILL DAILY %DATE% %TIME% ==== >> "logs-noskill\daily.log"
type nul > "logs-noskill\run-start.flag"

rem === GAPS-RERUN: delivery already done, gaps remain - stale retry only ===
if exist "logs-noskill\gaps-rerun.flag" (
  del /q "logs-noskill\gaps-rerun.flag" 2>nul
  echo [%TIME%] GAPS-RERUN: delivery already done - running stale-only retry, no re-delivery >> "logs-noskill\daily.log"
  goto :gaps_only
)

rem === TOKEN RESUME: prior run hit token budget - resume from where it stopped ===
rem NOTE: do NOT delete the flag here. It is deleted at the delivery section
rem (~line 99) so that if stale retry also exhausts tokens it can write a
rem new flag and the hourly retry fires again correctly.
if exist "logs-noskill\token-exhausted.flag" (
  echo [%TIME%] RESUME: token-exhausted flag present - skipping main hunt, resuming stale retry with prior daily-latest.md output preserved >> "logs-noskill\daily.log"
  goto :stale_only
)

rem === HUNT-COMPLETE GUARD: hunt already ran today - skip straight to delivery ===
del /q "logs-noskill\skip-hunt.flag" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=Get-Date -Format yyyyMMdd; $m='logs-noskill\hunt-complete-'+$d+'.txt'; if(Test-Path $m){ Write-Output 'HUNT-COMPLETE guard: hunt already ran today - skipping to delivery'; [IO.File]::WriteAllText('logs-noskill\skip-hunt.flag',$d) }" >> "logs-noskill\daily.log" 2>&1
if exist "logs-noskill\skip-hunt.flag" (
  del /q "logs-noskill\skip-hunt.flag" 2>nul
  echo [%TIME%] Hunt-complete guard fired - skipping to PDF+delivery >> "logs-noskill\daily.log"
  goto :stale_only
)

rem === FRESH START: clear prior run outputs ===
rem Keep today's *-latest.md files so a restart resumes from where it left off.
rem Only delete files from previous days (stale from yesterday or earlier).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem 'reports-noskill\*-latest.md' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime.Date -lt (Get-Date).Date } | Remove-Item -Force -ErrorAction SilentlyContinue; Write-Output 'fresh-start: prior-day *-latest.md cleared (today''s kept for resume)'" >> "logs-noskill\daily.log" 2>&1
del /q "reports-noskill\coverage-gaps.json" 2>nul
del /q "reports-noskill\alert-*.json" 2>nul
del /q "reports-noskill\correlation-queries.json" 2>nul
del /q "logs-noskill\sent-alerts\*.sent" 2>nul
rem === COMMON PRE-PARSE: REST pre-aggregations for ALL surfaces (0 Claude tokens) ===
echo [%TIME%] Common pre-parse: RDP + Linux + Azure + SFTP + IIS via REST (0 tokens) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\common-preparse.ps1" >> "logs-noskill\daily.log" 2>&1

rem === SUB-HUNTS: 9 focused sessions, one per surface ===
rem Each uses an MCP-scoped config (8-24 tools) vs 32 for the old monolithic daily.
rem Token exhaustion on one surface marks a gap and continues - never aborts the pipeline.
echo [%TIME%] SUB-HUNT 1/9: IIS web-attacks + user-behavior (OP+PROD+AZ, 30t, mcp-3gl) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key iis -Surfaces "iis" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 2/9: Windows + RDP (AZ+PROD+OP, 20t, mcp-3gl) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key rdp -Surfaces "rdp" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 3/9: Azure / Entra ID (AZ+PROD, 18t, mcp-azprod) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key azure -Surfaces "azure" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 4/9: Linux + SSH (AZ+PROD+OP, 18t, mcp-3gl) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key linux -Surfaces "linux" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 5/9: SFTP + DTC Rebex (AZ+PROD+OP, 18t, mcp-3gl) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key sftp -Surfaces "sftp,dtc" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 6/9: Network / Firewall (AZ+PROD+OP, 20t, mcp-3gl) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key network -Surfaces "firewall,switch,lb" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 7/9: Database (all 4 GLs, 15t) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key db -Surfaces "db" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 8/9: ESET + Securenvoy + Virt + HW (all 4 GLs, 16t) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key infra -Surfaces "edr,mfa,virt,hw" >> "logs-noskill\daily.log" 2>&1

echo [%TIME%] SUB-HUNT 9/9: DEV-GL all surfaces incl Azure Event Hub (DEV, 12t, mcp-dev) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\run-sub-hunt.ps1" -Key dev -Surfaces "linux,rdp,iis,sftp,azure,firewall,app" >> "logs-noskill\daily.log" 2>&1

rem === MERGE: assemble daily-latest.md from all surface *-latest.md outputs ===
echo [%TIME%] Merging surface reports into daily-latest.md >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\merge-all-noskill.ps1" >> "logs-noskill\daily.log" 2>&1

rem === Write hunt-complete marker ===
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=Get-Date -Format yyyyMMdd; [IO.File]::WriteAllText('logs-noskill\hunt-complete-'+$d+'.txt',(Get-Date -Format o)); Write-Output 'Hunt-complete marker written.'" >> "logs-noskill\daily.log" 2>&1

rem === CHECK: Alert if any surfaces are in coverage-gaps (token-exhausted during sub-hunts) ===
del /q "logs-noskill\skip-hunt.flag" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; if(-not (Test-Path $gf)){ exit 0 }; $parsed=Get-Content $gf -Raw | ConvertFrom-Json; $gaps=@($parsed | ForEach-Object {[string]$_} | Where-Object {$_ -ne ''}); if($gaps.Count -gt 0){ Write-Output \"PARTIAL: $($gaps.Count) surfaces to retry: $($gaps -join ', ')\"; [IO.File]::WriteAllText('logs-noskill\skip-hunt.flag','partial') }" >> "logs-noskill\daily.log" 2>&1
if exist "logs-noskill\skip-hunt.flag" (
  del /q "logs-noskill\skip-hunt.flag" 2>nul
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; $gaps=(Get-Content $gf -Raw | ConvertFrom-Json) -join ','; & 'D:\Vidhya\New Daily hunt\alert-hunt-status-noskill.ps1' -Stage 'main-hunt' -Status 'partial' -Detail 'Some surfaces token-exhausted during focused sub-hunts. Targeted surface retry running now.' -Gaps $gaps" >> "logs-noskill\daily.log" 2>&1
)

:after_hunt_checks
rem === STALE RETRY: cover missed surfaces (max 2 passes, 60 turns each) ===
rem DEADLINE CHECK: skip if >= 05:45 to guarantee delivery by 06:00
if "%SOC_BYPASS_DEADLINE%"=="1" ( echo [%TIME%] DEADLINE: bypassed by SOC_BYPASS_DEADLINE=1 >> "logs-noskill\daily.log" ) else (
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h=[int](Get-Date -Format HH); $m=[int](Get-Date -Format mm); if(($h -gt 5) -or ($h -eq 5 -and $m -ge 45)){ Write-Output 'DEADLINE: past 05:45 - skipping stale retry to deliver by 06:00'; [IO.File]::WriteAllText('logs-noskill\deadline-skip.flag','stale') } else { Write-Output 'DEADLINE: OK' }" >> "logs-noskill\daily.log" 2>&1
)
if exist "logs-noskill\deadline-skip.flag" (
  del /q "logs-noskill\deadline-skip.flag" 2>nul
  echo [%TIME%] DEADLINE: stale retry skipped - proceeding to delivery >> "logs-noskill\daily.log"
  goto :after_stale
)
echo [%TIME%] Running stale-surface retry pass >> "logs-noskill\daily.log"

:stale_only
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\retry-targeted-noskill.ps1" >> "logs-noskill\daily.log" 2>&1
if errorlevel 1 (
  echo [%TIME%] TOKEN EXHAUSTION in stale retry >> "logs-noskill\daily.log"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; $parsed=if(Test-Path $gf){Get-Content $gf -Raw | ConvertFrom-Json}else{@()}; $gl=(@($parsed | ForEach-Object{[string]$_} | Where-Object{$_}) -join ','); if(-not $gl){$gl='unknown'}; & 'D:\Vidhya\New Daily hunt\alert-hunt-status-noskill.ps1' -Stage 'stale-retry' -Status 'token-exhausted' -Detail 'Token exhausted during stale retry. Remaining surfaces retried next 1h window.' -Gaps $gl" >> "logs-noskill\daily.log" 2>&1
  exit /b 1
)

rem === CHECK 5: Alert if gaps remain after all retry passes ===
del /q "logs-noskill\skip-hunt.flag" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; if(-not (Test-Path $gf)){ exit 0 }; $parsed=Get-Content $gf -Raw | ConvertFrom-Json; $gaps=@($parsed | ForEach-Object {[string]$_} | Where-Object {$_ -ne ''}); if($gaps.Count -gt 0){ Write-Output \"FINAL-GAPS: still uncovered: $($gaps -join ', ')\"; [IO.File]::WriteAllText('logs-noskill\skip-hunt.flag','final-gaps') }" >> "logs-noskill\daily.log" 2>&1
if exist "logs-noskill\skip-hunt.flag" (
  del /q "logs-noskill\skip-hunt.flag" 2>nul
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; $gaps=(Get-Content $gf -Raw | ConvertFrom-Json) -join ','; & 'D:\Vidhya\New Daily hunt\alert-hunt-status-noskill.ps1' -Stage 'stale-retry' -Status 'partial' -Detail 'Stale retry exhausted all passes. These surfaces have no findings for today and are prioritized for tomorrows run.' -Gaps $gaps" >> "logs-noskill\daily.log" 2>&1
)

:after_stale
rem IIS is now sub-hunt 1/11 (50-turn dedicated session) - no separate deep IIS pass needed.

:after_iis
rem === AZURE FLOOR: deterministic failed-auth check (sagar-class) - 0 tokens, always runs ===
echo [%TIME%] Running deterministic Azure failed-auth floor >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\azure-floor.ps1" >> "logs-noskill\daily.log" 2>&1

rem === CORRELATION: Opus cross-surface + kill-chain for HIGH/CRITICAL findings only ===
rem prep-correlation-noskill.ps1 sets run-correlation.flag ONLY when >=1 HIGH/CRITICAL finding exists.
rem MEDIUM/LOW findings get paste-ready Graylog queries via build-correlation-queries.ps1 (0 tokens).
rem DEADLINE CHECK: skip if >= 05:40
if "%SOC_BYPASS_DEADLINE%"=="1" ( echo [%TIME%] DEADLINE: bypassed by SOC_BYPASS_DEADLINE=1 >> "logs-noskill\daily.log" ) else (
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h=[int](Get-Date -Format HH); $m=[int](Get-Date -Format mm); if(($h -gt 5) -or ($h -eq 5 -and $m -ge 40)){ Write-Output 'DEADLINE: past 05:40 - skipping correlation'; [IO.File]::WriteAllText('logs-noskill\deadline-skip.flag','corr') } else { Write-Output 'DEADLINE: OK' }" >> "logs-noskill\daily.log" 2>&1
)
if exist "logs-noskill\deadline-skip.flag" (
  del /q "logs-noskill\deadline-skip.flag" 2>nul
  echo [%TIME%] DEADLINE: Opus correlation skipped - MEDIUM/LOW queries still generated >> "logs-noskill\daily.log"
  goto :after_opus_correlation
)
py "D:\Vidhya\New Daily hunt\prep-correlation-noskill.py" >> "logs-noskill\daily.log" 2>&1
if exist "logs-noskill\run-correlation.flag" (
  del /q "logs-noskill\run-correlation.flag" 2>nul
  del /q "reports-noskill\correlation-latest.md" 2>nul
  echo [%TIME%] Running Opus correlation (HIGH/CRITICAL cross-surface kill-chain) >> "logs-noskill\daily.log"
  py "D:\Vidhya\New Daily hunt\run-noskill-hunt.py" correlation >> "logs-noskill\daily.log" 2>&1
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=(Get-Content 'logs-noskill\daily.log' -Tail 80 -EA SilentlyContinue) -join ' '; if($t -match 'rate_limit_error|insufficient_quota|overloaded_error|too many requests|context window|credit'){ exit 1 }" 2>> "logs-noskill\daily.log"
  if errorlevel 1 (
    echo [%TIME%] CORRELATION token-exhausted - delivering with in-session correlation only >> "logs-noskill\daily.log"
  ) else (
    py "D:\Vidhya\New Daily hunt\merge-correlation-noskill.py" >> "logs-noskill\daily.log" 2>&1
  )
) else (
  echo [%TIME%] No HIGH/CRITICAL findings - Opus correlation skipped (MEDIUM/LOW queries coming) >> "logs-noskill\daily.log"
)

:after_opus_correlation
rem === MEDIUM/LOW CORRELATION QUERIES: 0 tokens, paste-ready Graylog pivots ===
echo [%TIME%] Building MEDIUM/LOW manual correlation queries (0 tokens) >> "logs-noskill\daily.log"
python "D:\Vidhya\New Daily hunt\build-correlation-queries.py" >> "logs-noskill\daily.log" 2>&1

:after_correlation
rem === DEPTH PASS: opus per-technique deep-dive (13 modules) on breadth+correlation leads ===
rem DEADLINE CHECK: skip if >= 05:45
if "%SOC_BYPASS_DEADLINE%"=="1" ( echo [%TIME%] DEADLINE: bypassed by SOC_BYPASS_DEADLINE=1 >> "logs-noskill\daily.log" ) else (
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h=[int](Get-Date -Format HH); $m=[int](Get-Date -Format mm); if(($h -gt 5) -or ($h -eq 5 -and $m -ge 45)){ Write-Output 'DEADLINE: past 05:45 - skipping depth pass'; [IO.File]::WriteAllText('logs-noskill\deadline-skip.flag','depth') } else { Write-Output 'DEADLINE: OK' }" >> "logs-noskill\daily.log" 2>&1
)
if exist "logs-noskill\deadline-skip.flag" (
  del /q "logs-noskill\deadline-skip.flag" 2>nul
  echo [%TIME%] DEADLINE: depth pass skipped - delivering breadth report >> "logs-noskill\daily.log"
  goto :after_depth
)
rem === DEPTH PASS: opus per-technique deep-dive (13 modules) on breadth+correlation leads ===
rem  ADD-ON / MONOTONIC. Reads daily-latest.md + alert-*.json leads, runs depth-modules\*.json,
rem  writes reports-noskill\depth-findings.json; merge-depth then folds it into daily-latest.md.
rem  NON-FATAL: if depth errors or runs out of tokens, merge-depth no-ops and the breadth
rem  report ships exactly as it would have. Depth can only ADD or raise a finding, never remove.
del /q "reports-noskill\depth-findings.json" 2>nul
echo [%TIME%] Running opus DEPTH pass (per-technique deep-dive on breadth leads) >> "logs-noskill\daily.log"
py "D:\Vidhya\New Daily hunt\run-noskill-hunt.py" depth >> "logs-noskill\daily.log" 2>&1
if exist "reports-noskill\depth-findings.json" powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\enrich-findings-ti.ps1" >> "logs-noskill\daily.log" 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\merge-depth-noskill.ps1" >> "logs-noskill\daily.log" 2>&1

rem === DEPTH CATCHUP (REST, 0 tokens): covers modules depth did not reach due to turn limit ===
rem  Reads depth-coverage.json for status "budget" modules, runs each module's primary
rem  detection query via REST, writes depth-catchup.json (REVIEW if count>0, CLEAN if 0).
rem  Analyst can paste the query field directly into Graylog to complete the triage.
del /q "reports-noskill\depth-catchup.json" 2>nul
echo [%TIME%] Running depth-catchup-rest (0 tokens, REST count for budget-skipped modules) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\depth-catchup-rest.ps1" >> "logs-noskill\daily.log" 2>&1
if exist "reports-noskill\depth-catchup.json" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\merge-depth-noskill.ps1" -DepthFile "reports-noskill\depth-catchup.json" >> "logs-noskill\daily.log" 2>&1
)

:after_depth
rem Clear token flag before delivery (flag stays through stale retry so new
rem exhaustion during stale retry can write a fresh flag; clear it only now)
del /q "logs-noskill\token-exhausted.flag" 2>nul

rem === DELIVER ===
echo [%TIME%] Generating PDF >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\generate-pdf-noskill.ps1" >> "logs-noskill\daily.log" 2>&1

rem === CHECK 6: PDF must exist before sending ===
del /q "logs-noskill\skip-hunt.flag" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=Get-Date -Format 'yyyy-MM-dd'; $p=Get-ChildItem ('reports-noskill\daily-SOC-noskill-'+$d+'.pdf') -EA SilentlyContinue; if(-not $p){ Write-Output 'PDF-CHECK: not found'; [IO.File]::WriteAllText('logs-noskill\skip-hunt.flag','pdf-missing') } else { Write-Output ('PDF-CHECK: '+$p.Name) }" >> "logs-noskill\daily.log" 2>&1
if exist "logs-noskill\skip-hunt.flag" (
  del /q "logs-noskill\skip-hunt.flag" 2>nul
  echo [%TIME%] PDF not generated - posting alert >> "logs-noskill\daily.log"
  powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\alert-hunt-status-noskill.ps1" -Stage "pdf" -Status "pdf-missing" -Detail "PDF generation failed. Teams summary card posting without PDF link. Check generate-pdf-noskill.ps1 output." >> "logs-noskill\daily.log" 2>&1
)

echo [%TIME%] Sending Teams report >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\send-report-noskill.ps1" >> "logs-noskill\daily.log" 2>&1
echo [%TIME%] Sending CSV email >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\send-csv-noskill.ps1" >> "logs-noskill\daily.log" 2>&1

rem === QUERY CACHE: extract every Graylog query that ran into query-cache.json ===
echo [%TIME%] Caching hunt queries >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\extract-queries-noskill.ps1" >> "logs-noskill\daily.log" 2>&1

echo. >> "logs-noskill\daily.log"
goto :eof

rem ============================================================
rem  :gaps_only  -  Post-delivery gap retry path
rem
rem  Delivery already happened (send-report-noskill.ps1 ran and wrote the
rem  delivered-YYYYMMDD.txt marker). guarded.cmd detected remaining gaps and
rem  set gaps-rerun.flag so we land here instead of the full fresh-start path.
rem
rem  Behaviour:
rem  - Run stale retry for the listed gaps (same retry-stale-noskill.ps1)
rem  - New findings are merged into daily-latest.md by the retry script
rem  - Do NOT call send-report-noskill.ps1 again (avoids duplicate finding
rem    cards in Teams for surfaces already delivered)
rem  - Post a status-only Teams card indicating outcome
rem ============================================================
:gaps_only
echo [%TIME%] GAPS-RERUN: running targeted surface retry (delivery already done, no re-post of all cards) >> "logs-noskill\daily.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\retry-targeted-noskill.ps1" >> "logs-noskill\daily.log" 2>&1
if errorlevel 1 (
  echo [%TIME%] TOKEN EXHAUSTION in gaps-rerun retry >> "logs-noskill\daily.log"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; $parsed=if(Test-Path $gf){Get-Content $gf -Raw | ConvertFrom-Json}else{@()}; $gl=(@($parsed | ForEach-Object{[string]$_} | Where-Object{$_}) -join ','); if(-not $gl){$gl='unknown'}; & 'D:\Vidhya\New Daily hunt\alert-hunt-status-noskill.ps1' -Stage 'stale-retry' -Status 'token-exhausted' -Detail 'Token exhausted during gaps-rerun retry (post-delivery). Remaining surfaces retried next 1h window.' -Gaps $gl" >> "logs-noskill\daily.log" 2>&1
  exit /b 1
)

rem Post status card only (no re-delivery)
del /q "logs-noskill\skip-hunt.flag" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; $parsed=if(Test-Path $gf){Get-Content $gf -Raw | ConvertFrom-Json}else{@()}; $gaps=@($parsed | ForEach-Object{[string]$_} | Where-Object{$_}); if($gaps.Count -gt 0){ Write-Output \"GAPS-RERUN: $($gaps.Count) gap(s) still remain: $($gaps -join ', ')\"; [IO.File]::WriteAllText('logs-noskill\skip-hunt.flag','gaps-remain') } else { Write-Output 'GAPS-RERUN: all surfaces covered' }" >> "logs-noskill\daily.log" 2>&1
if exist "logs-noskill\skip-hunt.flag" (
  del /q "logs-noskill\skip-hunt.flag" 2>nul
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $gf='reports-noskill\coverage-gaps.json'; $gaps=(Get-Content $gf -Raw | ConvertFrom-Json) -join ','; & 'D:\Vidhya\New Daily hunt\alert-hunt-status-noskill.ps1' -Stage 'stale-retry' -Status 'partial' -Detail 'Gaps-rerun complete. Some surfaces still uncovered after all retry passes. Will attempt again in next window.' -Gaps $gaps" >> "logs-noskill\daily.log" 2>&1
) else (
  echo [%TIME%] GAPS-RERUN: all surfaces now covered >> "logs-noskill\daily.log"
  rem === Re-send email if it failed during the 4 AM delivery (daily-latest.md was missing then) ===
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=Get-Date -Format yyyy-MM-dd; $f='logs-noskill\email-sent-'+$d+'.txt'; if(Test-Path $f){ Write-Output 'GAPS-RERUN: email already delivered - skipping re-send' } else { Write-Output 'GAPS-RERUN: email not yet delivered - re-sending now'; [IO.File]::WriteAllText('logs-noskill\resend-email.flag','1') }" >> "logs-noskill\daily.log" 2>&1
  if exist "logs-noskill\resend-email.flag" (
    del /q "logs-noskill\resend-email.flag" 2>nul
    echo [%TIME%] Re-generating PDF with full findings before email re-send >> "logs-noskill\daily.log"
    powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\generate-pdf-noskill.ps1" >> "logs-noskill\daily.log" 2>&1
    echo [%TIME%] Re-sending CSV email (initial send failed - daily-latest.md was not ready) >> "logs-noskill\daily.log"
    powershell -NoProfile -ExecutionPolicy Bypass -File "D:\Vidhya\New Daily hunt\send-csv-noskill.ps1" >> "logs-noskill\daily.log" 2>&1
  )
)

echo [%TIME%] GAPS-RERUN done >> "logs-noskill\daily.log"
goto :eof
