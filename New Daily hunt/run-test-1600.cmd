@echo off
rem One-time TEST: force a fresh full no-skill scan + delivery (PDF + CSV/workbook email + Teams).
rem Clears today's skip-markers so daily-report-noskill.cmd does a FRESH hunt instead of skip-to-delivery.
rem Runs the RAW cmd (not the guarded wrapper) so the "delivered today" guard does not short-circuit it.
cd /d "D:\Vidhya\New Daily hunt"
del /q "logs-noskill\hunt-complete-20260614.txt" 2>nul
del /q "logs-noskill\delivered-20260614.txt" 2>nul
del /q "logs-noskill\token-exhausted.flag" 2>nul
del /q "logs-noskill\gaps-rerun.flag" 2>nul
echo ==== TEST FULL-SCAN (forced) %DATE% %TIME% ==== >> "logs-noskill\daily.log"
call "D:\Vidhya\New Daily hunt\daily-report-noskill.cmd"
echo ==== TEST FULL-SCAN done %DATE% %TIME% ==== >> "logs-noskill\daily.log"
