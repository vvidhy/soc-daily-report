# Posts a concise hunt-status Adaptive Card to the SOC Teams channel.
# Called by daily-report-noskill.cmd on failure / partial coverage.
# Does NOT post on clean success (summary card from send-report-noskill.ps1 covers that).
#
# Usage:
#   alert-hunt-status-noskill.ps1 -Stage <str> -Status <str> -Detail <str> [-Gaps <str>]
#
# Stage  : main-hunt | stale-retry | pdf | delivery
# Status : token-exhausted | no-output | partial | failed | pdf-missing
# Detail : free-form explanation (<= 200 chars)
# Gaps   : comma-separated surface names still uncovered (optional)

param(
    [Parameter(Mandatory)][string]$Stage,
    [Parameter(Mandatory)][string]$Status,
    [Parameter(Mandatory)][string]$Detail,
    [string]$Gaps = ''
)
$ErrorActionPreference = 'Continue'
$webhookFile = 'D:\Vidhya\New Daily hunt\.webhook-noskill'
if (-not (Test-Path $webhookFile)) { Write-Output 'ALERT: webhook file missing'; exit 1 }
$webhookUrl = (Get-Content $webhookFile -Raw -Encoding utf8).Trim()

$colorMap = @{
    'token-exhausted' = 'Warning'
    'no-output'       = 'Attention'
    'partial'         = 'Warning'
    'failed'          = 'Attention'
    'pdf-missing'     = 'Warning'
}
$color = if ($colorMap.ContainsKey($Status)) { $colorMap[$Status] } else { 'Accent' }

$titleMap = @{
    'token-exhausted' = 'TOKEN BUDGET HIT'
    'no-output'       = 'HUNT PRODUCED NO OUTPUT'
    'partial'         = 'PARTIAL COVERAGE'
    'failed'          = 'HUNT STOPPED UNEXPECTEDLY'
    'pdf-missing'     = 'PDF NOT GENERATED'
}
$title = if ($titleMap.ContainsKey($Status)) { $titleMap[$Status] } else { $Status.ToUpper() }

$facts = [System.Collections.Generic.List[hashtable]]::new()
$facts.Add(@{ title='Stage';    value=$Stage })
$facts.Add(@{ title='Status';   value=$Status })
$facts.Add(@{ title='Time';     value=(Get-Date -Format 'yyyy-MM-dd HH:mm UTC') })
$facts.Add(@{ title='Detail';   value=$Detail })
if ($Gaps) {
    $facts.Add(@{ title='Uncovered'; value=$Gaps })
    $facts.Add(@{ title='Next step'; value='Hourly retry (if token guard cleared) or next 02:30 run' })
}

$body = @(
    @{
        type   = 'TextBlock'
        text   = "SOC Hunt Alert -- $title"
        color  = $color
        weight = 'Bolder'
        size   = 'Medium'
        wrap   = $true
    }
    @{ type = 'FactSet'; facts = $facts.ToArray() }
)

$card = [ordered]@{
    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
    type       = 'AdaptiveCard'
    version    = '1.4'
    body       = $body
}
$envelope = @{
    type        = 'message'
    attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
}

try {
    $json  = $envelope | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $webhookUrl -Method Post `
        -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 30 | Out-Null
    Write-Output "Hunt status card posted [$Stage/$Status]"
} catch {
    Write-Output "Hunt status card POST FAILED: $($_.Exception.Message)"
}
