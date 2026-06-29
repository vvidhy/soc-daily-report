@echo off
rem One-time TEST @ 19:00 - force a FRESH full-depth no-skill scan + delivery.
rem Validates against today's edits: token usage, ZERO stale (coverage-gaps empty),
rem full-depth Azure Event Hub, content-first + deep IIS, correlation + kill chain.
rem Clears today's skip-markers + stale coverage-gaps so the hunt starts clean and
rem does a FRESH hunt instead of skip-to-delivery. Runs the RAW cmd (not the guarded
rem wrapper) so the "delivered today" guard does not short-circuit it.
cd /d "D:\Vidhya\New Daily hunt"
del /q "logs-noskill\hunt-complete-20260614.txt" 2>nul
del /q "logs-noskill\delivered-20260614.txt" 2>nul
del /q "logs-noskill\token-exhausted.flag" 2>nul
del /q "logs-noskill\gaps-rerun.flag" 2>nul
del /q "logs-noskill\skip-hunt.flag" 2>nul
del /q "reports-noskill\coverage-gaps.json" 2>nul
rem Channel-only tonight: build CSV/workbook but SKIP the email send (relay blocks our
rem egress IP; O365 needs an app-password). The Teams channel post is unaffected.
set SOC_SKIP_EMAIL=1
echo ==== TEST FULL-SCAN 1900 (forced, channel-only) %DATE% %TIME% ==== >> "logs-noskill\daily.log"
call "D:\Vidhya\New Daily hunt\daily-report-noskill.cmd"
echo ==== TEST FULL-SCAN 1900 done %DATE% %TIME% ==== >> "logs-noskill\daily.log"
