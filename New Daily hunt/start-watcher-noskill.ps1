# Starts noskill-live-watcher.ps1 as a background process if not already running.
# Writes the PID to logs-noskill\watcher.pid so stop-watcher-noskill.ps1 can clean up.
param([int]$LifetimeMin = 420)

$root    = 'D:\Vidhya\New Daily hunt'
$wpf     = Join-Path $root 'logs-noskill\watcher.pid'
$wScript = Join-Path $root 'noskill-live-watcher.ps1'
$logFile = Join-Path $root 'logs-noskill\daily.log'

function Log([string]$m){ "$([datetime]::Now.ToString('HH:mm:ss')) [watcher-start] $m" | Add-Content $logFile -Encoding utf8 }

$running = $false
if (Test-Path $wpf) {
  try {
    $existing = [int](Get-Content $wpf -Raw -EA Stop).Trim()
    if ($existing -gt 0 -and (Get-Process -Id $existing -EA SilentlyContinue)) {
      Log "already running pid=$existing"; $running = $true
    }
  } catch {}
}

if (-not $running) {
  $proc = Start-Process powershell `
    -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$wScript`" -LifetimeMin $LifetimeMin" `
    -WindowStyle Hidden -PassThru
  $proc.Id | Set-Content $wpf -Encoding utf8
  Log "started pid=$($proc.Id)"
  Write-Output "Live watcher started (pid $($proc.Id))"
}
