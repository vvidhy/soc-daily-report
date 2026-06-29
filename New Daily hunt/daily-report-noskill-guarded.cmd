@echo off
rem ============================================================
rem  Guard wrapper for SOC-DailyReport-NoSkill.
rem
rem  Idempotency rules (checked on every PT1H Task Scheduler retry):
rem
rem  Guard 1 - Token exhaustion:
rem    If logs-noskill\token-exhausted.flag is < 60 min old -> skip.
rem    If >= 60 min old -> leave the flag in place (daily-report-noskill.cmd
rem    reads it, clears it, and jumps to stale-only to resume from where the
rem    hunt left off without re-running already-completed surfaces).
rem
rem  Guard 2a - Already delivered AND no remaining gaps -> skip (done today).
rem    If delivered but gaps remain -> set gaps-rerun.flag and proceed
rem    (daily-report-noskill.cmd will run only the stale retry + a status
rem    card, NOT a full re-delivery that would duplicate all finding cards).
rem
rem  Guard 2b - PDF exists and no stale surfaces -> skip.
rem
rem  Otherwise: call daily-report-noskill.cmd.
rem ============================================================
cd /d "D:\Vidhya\New Daily hunt"

rem === NEW-DAY RESET: clear token-exhausted flag if it is from a previous calendar day ===
powershell -NoProfile -ExecutionPolicy Bypass -Command "if(Test-Path 'logs-noskill\token-exhausted.flag'){ $flagDate=(Get-Item 'logs-noskill\token-exhausted.flag').LastWriteTime.Date; $today=(Get-Date).Date; if($flagDate -lt $today){ Remove-Item 'logs-noskill\token-exhausted.flag' -Force; Write-Output ('NEW-DAY RESET: cleared stale token-exhausted.flag from ' + $flagDate.ToString('yyyy-MM-dd') + ' - starting fresh hunt') } else { Write-Output ('NEW-DAY RESET: flag is from today (' + $flagDate.ToString('yyyy-MM-dd') + ') - leaving in place') } }" >> "logs-noskill\daily.log" 2>&1

rem === DEADLINE GUARD: do not run if past 06:55 (hunt window is 03:00-06:55) ===
powershell -NoProfile -ExecutionPolicy Bypass -Command "$now=Get-Date; $deadline=$now.Date.AddHours(6).AddMinutes(55); if($now -gt $deadline){ Write-Output ('DEADLINE: ' + $now.ToString('HH:mm') + ' is past 06:55 - skipping run'); exit 1 }" >> "logs-noskill\daily.log" 2>&1
if errorlevel 1 (
  echo ==== SKIP %DATE% %TIME% past 06:55 deadline - no more retries today ==== >> "logs-noskill\daily.log"
  goto :eof
)

rem === Guard 1: token exhaustion flag age check ===
rem NOTE: do NOT clear the flag here. daily-report-noskill.cmd clears it
rem when it jumps to :stale_only so prior hunt output is preserved.
if not exist "logs-noskill\token-exhausted.flag" goto :done_check
powershell -NoProfile -ExecutionPolicy Bypass -Command "$age=(New-TimeSpan -Start (Get-Item 'logs-noskill\token-exhausted.flag').LastWriteTime -End (Get-Date)).TotalMinutes; if($age -lt 60){ Write-Output \"TOKEN-GUARD: flag is ${age}m old (<60m) - waiting for next hourly retry\"; exit 1 } else { Write-Output \"TOKEN-GUARD: flag is ${age}m old - passing through to resume hunt\" }" >> "logs-noskill\daily.log" 2>&1
if errorlevel 1 (
  echo ==== SKIP %DATE% %TIME% token exhaustion guard active ==== >> "logs-noskill\daily.log"
  goto :eof
)
rem Flag is old enough - fall through to daily-report-noskill.cmd which
rem will clear it and resume from :stale_only
goto :call_cmd

:done_check
rem === Guard 2a: delivered today? ===
rem If delivered AND gaps are empty -> done for today, skip.
rem If delivered AND gaps remain -> set gaps-rerun.flag so the cmd does
rem  a stale-only retry without re-posting all finding cards.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Continue'; $d=Get-Date -Format yyyyMMdd; $marker='logs-noskill\delivered-'+$d+'.txt'; if(-not (Test-Path $marker)){ exit 0 }; $gf='reports-noskill\coverage-gaps.json'; $gaps=@(); if(Test-Path $gf){ $parsed=Get-Content $gf -Raw | ConvertFrom-Json; $gaps=@($parsed | ForEach-Object{[string]$_} | Where-Object{$_}) }; if($gaps.Count -eq 0){ Write-Output 'Delivered + no gaps - done for today'; exit 9 }; Write-Output \"Delivered but $($gaps.Count) gap(s) remain ($($gaps -join ',')); setting gaps-rerun.flag\"; [IO.File]::WriteAllText('logs-noskill\gaps-rerun.flag',$gaps -join ','); exit 0" >> "logs-noskill\daily.log" 2>&1
if errorlevel 9 (
  echo ==== SKIP %DATE% %TIME% delivered + no gaps ==== >> "logs-noskill\daily.log"
  goto :eof
)

rem === Guard 2b: PDF exists and no stale surfaces ===
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=Get-Date -Format yyyy-MM-dd; $pdf=Get-ChildItem 'reports-noskill' -Filter ('daily-SOC-noskill-'+$d+'.pdf') -EA SilentlyContinue; if(-not $pdf){ Write-Output 'No PDF yet - proceeding'; exit 0 }; $g=if(Test-Path 'reports-noskill\coverage-gaps.json'){ @(Get-Content 'reports-noskill\coverage-gaps.json' -Raw | ConvertFrom-Json).Count } else { 0 }; if($g -gt 0){ Write-Output \"PDF exists but $g stale surface(s) remain - proceeding\"; exit 0 }; Write-Output 'Done for today - PDF complete, no stale surfaces'; exit 9" >> "logs-noskill\daily.log" 2>&1
if errorlevel 9 (
  echo ==== SKIP %DATE% %TIME% report complete no stale surfaces ==== >> "logs-noskill\daily.log"
  goto :eof
)

:call_cmd
call "D:\Vidhya\New Daily hunt\daily-report-noskill.cmd"
