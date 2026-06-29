# Stops the background live watcher by PID recorded in watcher.pid.
$root    = 'D:\Vidhya\New Daily hunt'
$wpf     = Join-Path $root 'logs-noskill\watcher.pid'
$logFile = Join-Path $root 'logs-noskill\daily.log'

function Log([string]$m){ "$([datetime]::Now.ToString('HH:mm:ss')) [watcher-stop] $m" | Add-Content $logFile -Encoding utf8 }

if (Test-Path $wpf) {
  try {
    $wpid = [int](Get-Content $wpf -Raw -EA Stop).Trim()
    Stop-Process -Id $wpid -Force -EA SilentlyContinue
    Remove-Item $wpf -EA SilentlyContinue
    Log "stopped pid=$wpid"
    Write-Output "Live watcher stopped (pid $wpid)"
  } catch { Log "stop error: $($_.Exception.Message)" }
} else {
  Log 'no watcher.pid found - nothing to stop'
}
