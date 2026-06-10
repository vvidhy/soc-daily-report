<#
  iis-opgl-daily-sweep.ps1 - Tier 3: once-daily opus completeness sweep.

  Closes the one gap the free hourly engine can't: a NOVEL attack from an
  already-known entity that trips no signature rule. Gathers a bounded set of the
  most unusual IIS requests (via the free REST layer) and asks opus to surface
  anything subtle. ADVISORY ONLY - writes a dated report for analyst review and
  logs a summary; it does NOT post HIGH alerts (preserves "alerts fire only at
  HIGH" + data integrity; AI hunches never auto-escalate). Runs 1x/day = bounded
  token cost.

  Param -WindowHours (default 24).
#>
[CmdletBinding()]
param([int] $WindowHours = 24)

$ErrorActionPreference = 'Stop'
$here        = $PSScriptRoot
$repoRoot    = Split-Path -Parent (Split-Path -Parent $here)
$secretsPath = Join-Path $repoRoot 'soc-monitor\config\secrets.local.ps1'
$logDir      = Join-Path $here 'logs'
$null = New-Item -ItemType Directory -Force -Path $logDir
$logFile = Join-Path $logDir 'iis-opgl-monitor.log'

function Write-SweepLog { param([string]$Level,[string]$Msg)
    "$([datetime]::UtcNow.ToString('o')) [$Level] sweep: $Msg" | Add-Content $logFile -Encoding utf8
}

if (Test-Path $secretsPath) { . $secretsPath }
. (Join-Path $here 'graylog-api.ps1')
. (Join-Path $here 'opus-investigate.ps1')

$config = Get-Content (Join-Path $here 'config.json') -Raw -Encoding utf8 | ConvertFrom-Json
Write-SweepLog INFO "starting daily completeness sweep (window=${WindowHours}h)"

$analysis = $null
try { $analysis = Invoke-OpusDailySweep -Config $config -WindowHours $WindowHours }
catch { Write-SweepLog ERROR "Invoke-OpusDailySweep threw: $($_.Exception.Message)" }

$stamp  = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$report = Join-Path $logDir "daily-sweep-$stamp.md"
$body   = if ($analysis) { $analysis } else { '(opus unavailable or returned no output)' }
$doc = "# IIS OP-GL daily completeness sweep`r`n`r`nGenerated (UTC): $([datetime]::UtcNow.ToString('o'))`r`nLook-back: ${WindowHours}h`r`nNote: ADVISORY ONLY - analyst review; not auto-alerted.`r`n`r`n$body`r`n"
[System.IO.File]::WriteAllText($report, $doc, [System.Text.UTF8Encoding]::new($false))
Write-SweepLog INFO "report written: $report"
Write-Host "Daily sweep report: $report"
Write-Host "----"
Write-Host $body
