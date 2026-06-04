# Probes the Power Automate webhook with a representative SOC payload.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/test-webhook.ps1

. "$PSScriptRoot\..\config\secrets.local.ps1"

if (-not $env:SOC_TEAMS_WEBHOOK) {
    Write-Error "SOC_TEAMS_WEBHOOK not set. Check config/secrets.local.ps1"
    exit 1
}

$payload = [ordered]@{
    severity     = 'INFO'
    title        = 'SOC Monitor: connectivity test'
    environment  = 'PROD-GL'
    technique    = 'N/A - test ping'
    summary      = 'If you see this card in Teams, the webhook works. No action required.'
    anchor_user  = 'soc-monitor@casepoint.local'
    anchor_host  = 'D-VIDHYA'
    anchor_ip    = '127.0.0.1'
    anchor_time  = (Get-Date).ToString('o')
    graylog_link = 'https://example.invalid/'
    finding_id   = [guid]::NewGuid().ToString()
} | ConvertTo-Json -Depth 5

Write-Host "POSTing test payload to webhook..." -ForegroundColor Cyan
Write-Host $payload

# Force UTF-8 on the wire — PS 5.1's default body encoding mangles non-ASCII.
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)

try {
    $resp = Invoke-RestMethod `
        -Uri $env:SOC_TEAMS_WEBHOOK `
        -Method Post `
        -ContentType 'application/json; charset=utf-8' `
        -Body $bodyBytes `
        -TimeoutSec 30
    Write-Host "`nSUCCESS. Response:" -ForegroundColor Green
    $resp | ConvertTo-Json -Depth 5
} catch {
    Write-Host "`nFAILED." -ForegroundColor Red
    Write-Host "Status:   $($_.Exception.Response.StatusCode.value__)"
    Write-Host "Reason:   $($_.Exception.Response.StatusDescription)"
    Write-Host "Message:  $($_.Exception.Message)"
    if ($_.ErrorDetails.Message) {
        Write-Host "Body:`n$($_.ErrorDetails.Message)"
    }
    exit 1
}
