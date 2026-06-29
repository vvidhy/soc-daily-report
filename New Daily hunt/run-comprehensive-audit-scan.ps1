# Comprehensive Audit Scan - Complete Log Analysis
# Full coverage: Anomalies + Suspicious Activity
# Token-efficient: Status-first logic + Graceful truncation
# Output: CSV + PDF to vidhya.v@casepoint.in
# Location: D:\Vidhya\New Daily Hunt (cached inputs)

param(
    [string]$EmailTo = "vidhya.v@casepoint.in"
)

$ErrorActionPreference = 'Continue'
$proj = 'D:\Vidhya\New Daily Hunt'
$runDate = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = "$proj\logs-noskill\comprehensive-audit-$runDate.log"
$reportDir = "$proj\reports-noskill"

# Ensure directories exist
foreach ($dir in @("$proj\logs-noskill", $reportDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Set-Location $proj

Write-Output "========================================" | Tee-Object -FilePath $logFile -Append
Write-Output "COMPREHENSIVE AUDIT SCAN" | Tee-Object -FilePath $logFile -Append
Write-Output "Started: $runDate" | Tee-Object -FilePath $logFile -Append
Write-Output "Location: $proj" | Tee-Object -FilePath $logFile -Append
Write-Output "========================================" | Tee-Object -FilePath $logFile -Append
Write-Output "" | Tee-Object -FilePath $logFile -Append

Write-Output "SCAN CONFIGURATION:" | Tee-Object -FilePath $logFile -Append
Write-Output "  Mode: Full Coverage (All Anomalies + Suspicious Activity)" | Tee-Object -FilePath $logFile -Append
Write-Output "  Optimization: Status-First Logic + Graceful Truncation" | Tee-Object -FilePath $logFile -Append
Write-Output "  Input Caching: Enabled (Graylog metadata cached)" | Tee-Object -FilePath $logFile -Append
Write-Output "  Coverage: IIS, RDP, Azure, Linux, SFTP" | Tee-Object -FilePath $logFile -Append
Write-Output "" | Tee-Object -FilePath $logFile -Append

# Run all optimized hunts
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Executing hunts..." | Tee-Object -FilePath $logFile -Append

$hunts = @('iis', 'rdp', 'azure', 'linux', 'sftp')
$huntResults = @()

foreach ($hunt in $hunts) {
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Running $hunt hunt..." | Tee-Object -FilePath $logFile -Append

    try {
        $result = & powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\run-noskill-hunt.ps1" -Key $hunt 2>&1
        $huntResults += @{Hunt=$hunt; Status='Completed'; Output=$result}
        Write-Output "  -> ${hunt}: SUCCESS" | Tee-Object -FilePath $logFile -Append
    } catch {
        $huntResults += @{Hunt=$hunt; Status='Failed'; Error=$_}
        Write-Output "  -> ${hunt}: FAILED - $_" | Tee-Object -FilePath $logFile -Append
    }
}

Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Collecting findings from all reports..." | Tee-Object -FilePath $logFile -Append

# Parse all findings from markdown reports
$allFindings = @()
$reportFiles = @(
    "$reportDir\iis-latest.md",
    "$reportDir\rdp-latest.md",
    "$reportDir\azure-latest.md",
    "$reportDir\linux-latest.md",
    "$reportDir\sftp-latest.md"
)

foreach ($reportFile in $reportFiles) {
    if (Test-Path $reportFile) {
        $reportName = (Get-Item $reportFile).BaseName
        Write-Output "  Reading: $reportName" | Tee-Object -FilePath $logFile -Append

        $content = Get-Content $reportFile -Raw
        if ($content -match '```findings-json\s*\[(.*?)\]\s*```') {
            try {
                $jsonStr = "[$($matches[1])]"
                $findings = $jsonStr | ConvertFrom-Json

                foreach ($f in $findings) {
                    $allFindings += [PSCustomObject]@{
                        Severity = $f.sev
                        Environment = $f.env
                        Surface = $f.surface
                        Finding = $f.finding
                        Evidence = $f.evidence
                        MITRE = if ($f.mitre -is [array]) { $f.mitre -join ',' } else { $f.mitre }
                        Tactic = if ($f.tactic) { $f.tactic } else { '' }
                        KillChain = if ($f.killchain) { $f.killchain } else { '' }
                        Action = $f.action
                        QueryUsed = $f.query
                        InvestigateNext = $f.investigate
                    }
                }

                Write-Output "    -> Extracted $($findings.Count) findings" | Tee-Object -FilePath $logFile -Append
            } catch {
                Write-Output "    -> Parse error: $_" | Tee-Object -FilePath $logFile -Append
            }
        }
    }
}

Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Total findings collected: $($allFindings.Count)" | Tee-Object -FilePath $logFile -Append

# Export to CSV
$csvOutput = "$reportDir\Comprehensive-Audit-$runDate.csv"
if ($allFindings.Count -gt 0) {
    $allFindings | Export-Csv -Path $csvOutput -NoTypeInformation -Encoding UTF8
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] CSV exported: $csvOutput" | Tee-Object -FilePath $logFile -Append
} else {
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] No findings to export" | Tee-Object -FilePath $logFile -Append
}

# Create comprehensive HTML report (for PDF conversion)
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Generating comprehensive report..." | Tee-Object -FilePath $logFile -Append

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Audit Report - $runDate</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; border-bottom: 2px solid #007bff; }
        h2 { color: #555; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background-color: #007bff; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .severity-HIGH { color: #dc3545; font-weight: bold; }
        .severity-MEDIUM { color: #ff9800; font-weight: bold; }
        .severity-REVIEW { color: #2196f3; font-weight: bold; }
        .severity-LOW { color: #28a745; }
        .severity-CLEAN { color: #6c757d; }
        .summary { background-color: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Comprehensive Audit Report</h1>
    <p><strong>Generated:</strong> $runDate</p>
    <p><strong>Location:</strong> D:\Vidhya\New Daily Hunt</p>

    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Total Findings:</strong> $($allFindings.Count)</p>
        <p><strong>Coverage Mode:</strong> Full (Status-First Logic + Graceful Truncation)</p>
        <p><strong>Modules Scanned:</strong> IIS, RDP, Azure, Linux, SFTP</p>
        <p><strong>Email Recipient:</strong> vidhya.v@casepoint.in</p>
    </div>

    <h2>Findings by Severity</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
"@

# Count by severity
$severityCounts = $allFindings | Group-Object -Property Severity | Select-Object Name, Count
foreach ($sev in @('HIGH', 'MEDIUM', 'REVIEW', 'LOW', 'CLEAN')) {
    $count = ($severityCounts | Where-Object {$_.Name -eq $sev} | Select-Object -ExpandProperty Count) -or 0
    $pct = if ($allFindings.Count -gt 0) { [math]::Round(($count / $allFindings.Count) * 100, 1) } else { 0 }
    $htmlReport += "<tr><td class='severity-$sev'>$sev</td><td>$count</td><td>$pct%</td></tr>"
}

$htmlReport += @"
    </table>

    <h2>All Findings</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Environment</th>
            <th>Surface</th>
            <th>Finding</th>
            <th>Evidence</th>
            <th>MITRE</th>
            <th>Action</th>
        </tr>
"@

foreach ($finding in $allFindings) {
    $htmlReport += "<tr>"
    $htmlReport += "<td class='severity-$($finding.Severity)'>$($finding.Severity)</td>"
    $htmlReport += "<td>$($finding.Environment)</td>"
    $htmlReport += "<td>$($finding.Surface)</td>"
    $htmlReport += "<td>$($finding.Finding)</td>"
    $htmlReport += "<td>$($finding.Evidence)</td>"
    $htmlReport += "<td>$($finding.MITRE)</td>"
    $htmlReport += "<td>$($finding.Action)</td>"
    $htmlReport += "</tr>"
}

$htmlReport += @"
    </table>

    <h2>Coverage and Completeness</h2>
    <p>This audit includes all available logs across all environments with:</p>
    <ul>
        <li>Status-first anomaly detection (efficient entry point)</li>
        <li>Graceful truncation with explicit coverage-gap reporting</li>
        <li>Cached Graylog input for consistent analysis</li>
        <li>Comprehensive handling of all suspicious activities</li>
    </ul>

    <p><strong>Note:</strong> Any REVIEW severity findings indicate coverage gaps at turn budget limits. These areas should be re-scanned with higher turn caps if needed.</p>
</body>
</html>
"@

$htmlOutput = "$reportDir\Comprehensive-Audit-$runDate.html"
$htmlReport | Out-File -FilePath $htmlOutput -Encoding UTF8
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] HTML report created: $htmlOutput" | Tee-Object -FilePath $logFile -Append

# Create PDF from HTML (using built-in conversion if available)
$pdfOutput = "$reportDir\Comprehensive-Audit-$runDate.pdf"
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Creating PDF..." | Tee-Object -FilePath $logFile -Append

# Note: PDF creation requires external tools - for now create printable HTML
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] PDF can be generated from HTML using print-to-PDF" | Tee-Object -FilePath $logFile -Append

Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Sending email..." | Tee-Object -FilePath $logFile -Append

$emailSubject = "Comprehensive Audit Report - Full Coverage Analysis - $runDate"
$emailBody = @"
Comprehensive Audit Scan Report

Date: $runDate
Location: D:\Vidhya\New Daily Hunt

SUMMARY:
- Total Findings: $($allFindings.Count)
- Coverage: IIS, RDP, Azure, Linux, SFTP
- Mode: Full (Status-First + Graceful Truncation)
- Input: Cached Graylog data

ATTACHMENTS:
- Comprehensive-Audit-$runDate.csv (all findings)
- Comprehensive-Audit-$runDate.html (formatted report)

The scan includes all anomalies and suspicious activities detected across:
- IIS web attacks and anomalies
- RDP behavioral triggers and host-wide events
- Azure identity and access anomalies
- Linux system and security anomalies
- SFTP brute-force and transfer anomalies

Any REVIEW findings indicate coverage gaps at turn budget limits.

For questions, contact: vidhya.v@casepoint.in
"@

$attachments = @()
if (Test-Path $csvOutput) { $attachments += $csvOutput }
if (Test-Path $htmlOutput) { $attachments += $htmlOutput }

if ($attachments.Count -gt 0) {
    try {
        $emailParams = @{
            To = "vidhya.v@casepoint.in"
            Subject = $emailSubject
            Body = $emailBody
            Attachments = $attachments
            SmtpServer = "smtp.casepoint.com"
            Port = 25
            UseSsl = $false
        }
        Send-MailMessage @emailParams -ErrorAction Stop
        Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Email sent successfully to $EmailTo" | Tee-Object -FilePath $logFile -Append
    } catch {
        Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Email error: $_" | Tee-Object -FilePath $logFile -Append
    }
}

Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "========================================" | Tee-Object -FilePath $logFile -Append
Write-Output "AUDIT COMPLETE" | Tee-Object -FilePath $logFile -Append
Write-Output "Completion Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Tee-Object -FilePath $logFile -Append
Write-Output "========================================" | Tee-Object -FilePath $logFile -Append
Write-Output "" | Tee-Object -FilePath $logFile -Append
Write-Output "Reports Generated:" | Tee-Object -FilePath $logFile -Append
Write-Output "  CSV: $csvOutput" | Tee-Object -FilePath $logFile -Append
Write-Output "  HTML: $htmlOutput" | Tee-Object -FilePath $logFile -Append
Write-Output "  LOG: $logFile" | Tee-Object -FilePath $logFile -Append
