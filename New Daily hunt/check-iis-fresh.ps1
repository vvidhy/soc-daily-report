# check-iis-fresh.ps1
# Checks whether iis-latest.md was written THIS run (newer than run-start.flag)
# and contains a findings-json block.
# Exit 1 = FRESH (no retry needed)
# Exit 0 = STALE/MISSING (caller should retry)
# Called by daily-report-noskill.cmd immediately after call :hunt iis.
# LOGGING: writes ONLY to stdout - caller owns the log via >> daily.log 2>&1.
$proj = 'D:\Vidhya\New Daily hunt'
$flag = (Get-Item "$proj\logs-noskill\run-start.flag" -ErrorAction SilentlyContinue)
if(-not $flag){ Write-Output "check-iis-fresh: no run-start.flag - skipping freshness check"; exit 1 }
$f = "$proj\reports-noskill\iis-latest.md"
$fresh = (Test-Path $f) -and
         (Get-Item $f).LastWriteTime -ge $flag.LastWriteTime -and
         (Select-String -Path $f -Pattern 'findings-json' -Quiet)
if($fresh){
  Write-Output "IIS: FRESH - no inline retry needed"
  exit 1
} else {
  Write-Output "IIS CRITICAL: stale/missing after first pass - triggering inline retry now"
  exit 0
}
