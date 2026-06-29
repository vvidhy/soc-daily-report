# noskill-live-watcher.ps1
# Monitors reports-noskill\alert-*.json files written by the hunt and sends
# a rich Adaptive Card to Teams immediately for each HIGH/CRITICAL/MEDIUM finding.
# Run as a background job before the hunt starts; self-terminates after $LifetimeMin.
#
# Alert file protocol:
#   The hunt writes reports-noskill\alert-{surface}-{stamp}.json (one JSON object,
#   all finding keys) for each HIGH or CRITICAL finding as soon as it is identified.
#   This watcher picks them up within 15 seconds and posts the card.
[CmdletBinding()]
param([int]$LifetimeMin = 420)   # default 7 h (covers the full 5-6 h hunt + buffer)

$ErrorActionPreference = 'Continue'
$alertDir    = 'D:\Vidhya\New Daily hunt\reports-noskill'
$webhookFile = 'D:\Vidhya\New Daily hunt\.webhook-noskill'
$logFile     = 'D:\Vidhya\New Daily hunt\logs-noskill\live-watcher.log'
$sentDir     = 'D:\Vidhya\New Daily hunt\logs-noskill\sent-alerts'

function Write-WLog {
  param([string]$Level, [string]$Msg)
  "$([datetime]::UtcNow.ToString('o')) [$Level] watcher: $Msg" | Add-Content $logFile -Encoding utf8
}

if (-not (Test-Path $webhookFile)) { Write-WLog ERROR 'webhook file missing'; exit 1 }
$webhookUrl = (Get-Content $webhookFile -Raw -Encoding utf8).Trim()
$null = New-Item -ItemType Directory -Force -Path $sentDir

. (Join-Path 'D:\Vidhya\New Daily hunt' 'noskill-alert-card.ps1')

function Send-AlertCard {
  param([psobject]$Finding)
  $envelope = Build-NoskillFindingCard -Finding $Finding
  $json     = $envelope | ConvertTo-Json -Depth 20 -Compress
  $bytes    = [System.Text.Encoding]::UTF8.GetBytes($json)
  try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $webhookUrl -Method Post `
      -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 30 | Out-Null
    return $true
  } catch {
    Write-WLog WARN "POST failed: $($_.Exception.Message)"
    return $false
  }
}

$start = Get-Date
$seen  = @{}

# Restore already-sent set so a watcher restart won't re-send
foreach ($f in (Get-ChildItem $sentDir -Filter '*.sent' -EA SilentlyContinue)) {
  $seen[$f.BaseName] = $true
}

Write-WLog INFO "started (lifetime=$LifetimeMin min)"

while (((Get-Date) - $start).TotalMinutes -lt $LifetimeMin) {

  $newFiles = Get-ChildItem $alertDir -Filter 'alert-*.json' -EA SilentlyContinue |
              Where-Object { -not $seen.ContainsKey($_.Name) } |
              Sort-Object CreationTime

  foreach ($af in $newFiles) {
    $seen[$af.Name] = $true          # mark before attempt to avoid retry loops
    Start-Sleep -Seconds 2           # let Claude finish writing the file

    try {
      $raw = Get-Content $af.FullName -Raw -Encoding utf8 -EA Stop
      $finding = $raw | ConvertFrom-Json
      $sev = [string]$finding.sev

      if ($sev -notin 'CRITICAL','HIGH','MEDIUM') {
        Write-WLog INFO "skipped ($sev) $($af.Name)"
        continue
      }

      if (Send-AlertCard -Finding $finding) {
        Write-WLog INFO "sent $sev $([string]$finding.env)/$([string]$finding.surface) ($($af.Name))"
        Set-Content (Join-Path $sentDir "$($af.Name).sent") (Get-Date -Format o) -Encoding utf8
      }
    } catch {
      Write-WLog WARN "error processing $($af.Name): $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 1
  }

  Start-Sleep -Seconds 15
}

Write-WLog INFO 'stopping (lifetime reached)'
