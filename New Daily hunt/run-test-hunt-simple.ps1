# Test Hunt Runner - Simple Version
# Runs from: D:\Vidhya\New Daily Hunt
# Sends: CSV to email

param(
    [string]$EmailTo = "vidhya.v@casepoint.in"
)

$ErrorActionPreference = 'Continue'
$proj = 'D:\Vidhya\New Daily Hunt'
$runDate = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = "$proj\logs-noskill\test-run-$runDate.log"

# Ensure directories exist
if (-not (Test-Path "$proj\logs-noskill")) {
    New-Item -ItemType Directory -Path "$proj\logs-noskill" -Force | Out-Null
}

Set-Location $proj

Write-Output "TEST HUNT STARTED: $runDate" | Tee-Object -FilePath $logFile -Append
Write-Output "Location: $proj" | Tee-Object -FilePath $logFile -Append
Write-Output "" | Tee-Object -FilePath $logFile -Append

# Run the daily hunt orchestrator
Write-Output "Running daily hunts..." | Tee-Object -FilePath $logFile -Append
try {
    # Execute daily report command
    cmd /c "D:\Vidhya\New Daily Hunt\daily-report-noskill.cmd" 2>&1 | Tee-Object -FilePath $logFile -Append
    Write-Output "Hunt execution completed" | Tee-Object -FilePath $logFile -Append
} catch {
    Write-Output "Hunt execution error: $_" | Tee-Object -FilePath $logFile -Append
}

Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "Collecting findings..." | Tee-Object -FilePath $logFile -Append

# Create CSV from findings
$csvOutput = "$proj\reports-noskill\Test-Hunt-Findings-$runDate.csv"
$findingsArray = @()

# Parse all markdown reports for findings-json blocks
$reportFiles = @(
    "$proj\reports-noskill\iis-latest.md",
    "$proj\reports-noskill\rdp-latest.md",
    "$proj\reports-noskill\azure-latest.md",
    "$proj\reports-noskill\linux-latest.md",
    "$proj\reports-noskill\sftp-latest.md"
)

foreach ($reportFile in $reportFiles) {
    if (Test-Path $reportFile) {
        $content = Get-Content $reportFile -Raw
        if ($content -match '```findings-json\s*\[(.*?)\]\s*```') {
            try {
                $jsonStr = "[$($matches[1])]"
                $findings = $jsonStr | ConvertFrom-Json
                foreach ($f in $findings) {
                    $findingsArray += [PSCustomObject]@{
                        Severity = $f.sev
                        Environment = $f.env
                        Surface = $f.surface
                        Finding = $f.finding
                        Evidence = $f.evidence
                        MITRE = $f.mitre -join ','
                        Action = $f.action
                    }
                }
            } catch {
                Write-Output "Error parsing $reportFile : $_" | Tee-Object -FilePath $logFile -Append
            }
        }
    }
}

# Export CSV
if ($findingsArray.Count -gt 0) {
    $findingsArray | Export-Csv -Path $csvOutput -NoTypeInformation -Encoding UTF8
    Write-Output "CSV created: $csvOutput" | Tee-Object -FilePath $logFile -Append
    Write-Output "Findings exported: $($findingsArray.Count) records" | Tee-Object -FilePath $logFile -Append
} else {
    Write-Output "No findings to export" | Tee-Object -FilePath $logFile -Append
}

# Send email
Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "Sending email..." | Tee-Object -FilePath $logFile -Append

$emailSubject = "Test Hunt Report - Optimized Hunts - $runDate"
$emailBody = "Test Hunt Execution Report - $runDate"

if (Test-Path $csvOutput) {
    try {
        $emailParams = @{
            To = "vidhya.v@casepoint.in"
            Subject = $emailSubject
            Body = $emailBody
            Attachments = @($csvOutput)
            SmtpServer = "smtp.casepoint.com"
            Port = 25
            UseSsl = $false
        }
        Send-MailMessage @emailParams -ErrorAction Stop
        Write-Output "Email sent successfully to $EmailTo" | Tee-Object -FilePath $logFile -Append
    } catch {
        Write-Output "Email error: $_" | Tee-Object -FilePath $logFile -Append
    }
}

Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "TEST RUN COMPLETED" | Tee-Object -FilePath $logFile -Append
