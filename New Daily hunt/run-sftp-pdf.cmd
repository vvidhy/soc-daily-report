@echo off
REM SFTP Hunt PDF Generator — 2026-06-24
REM Run this from the New Daily hunt directory

python "C:\Users\VidhyaV\.claude\skills\sftp-graylog-hunt\scripts\generate_pdf_report.py" ^
  "D:\Vidhya\New Daily hunt\reports-noskill\sftp-findings-2026-06-24.json" ^
  "D:\Vidhya\New Daily hunt\reports-noskill\sftp-hunt-report-2026-06-24.pdf" ^
  --logo "D:\Vidhya\New Daily hunt\assets\casepoint-logo.png"

if %ERRORLEVEL% EQU 0 (
    echo PDF generated successfully.
    echo Output: reports-noskill\sftp-hunt-report-2026-06-24.pdf
) else (
    echo PDF generation failed. Check Python/reportlab installation.
    echo Try: pip install reportlab
)
pause
