# Background watchdog for the daily SOC pipeline.
# A hunt that hangs (stalled MCP call, stuck model) would otherwise block the whole
# pipeline indefinitely and/or keep burning time. This watchdog kills any *pipeline hunt*
# that has run longer than $maxMin - well past the ~15 min a legit hunt takes, so a
# survivor is almost certainly stuck. When the hunt process is killed, its `call` in
# daily-report.cmd returns and the pipeline proceeds to the next step; the freshness
# cross-check in generate-pdf.ps1 then flags the killed hunt's report as STALE.
#
# SAFETY: it matches ONLY processes whose command line contains a pipeline hunt prompt
# ("Run a daily ..." or "Run a CROSS-MODULE ...") - that text sits right after -p, before
# the WMI command-line truncation limit - so it can NEVER kill an interactive claude session.
# Self-terminates after $lifetimeMin as a backstop.

$maxMin=25
$lifetimeMin=150
$log='D:\Vidhya\New Daily hunt\logs\daily.log'
$start=Get-Date
while(((Get-Date)-$start).TotalMinutes -lt $lifetimeMin){
  try {
    $procs=Get-CimInstance Win32_Process -Filter "Name='claude.exe' OR Name='node.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and ($_.CommandLine -match 'Run a (daily|CROSS-MODULE)') }
    foreach($p in $procs){
      $ct=$p.CreationDate
      if($ct -and (((Get-Date)-$ct).TotalMinutes -gt $maxMin)){
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        ("WATCHDOG "+(Get-Date).ToString('u')+": killed stuck hunt PID "+$p.ProcessId+" (ran > "+$maxMin+" min) - pipeline continues, report will be flagged STALE") | Add-Content $log
      }
    }
  } catch {}
  Start-Sleep -Seconds 60
}
