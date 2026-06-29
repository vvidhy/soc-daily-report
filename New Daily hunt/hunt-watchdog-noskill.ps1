# NO-SKILL pipeline copy of hunt-watchdog.ps1.
# Kills any *no-skill pipeline hunt* that has run longer than $maxMin (stuck). It matches ONLY
# processes whose command line contains "Run a NOSKILL" - the distinct prefix used by every
# no-skill hunt prompt - so it can NEVER kill an interactive claude session NOR the 08:00
# skill pipeline (whose prompts start "Run a daily"/"Run a CROSS-MODULE"). Self-terminates
# after $lifetimeMin as a backstop.

$maxMin=25
$lifetimeMin=150
$log='D:\Vidhya\New Daily hunt\logs-noskill\daily.log'
$start=Get-Date
while(((Get-Date)-$start).TotalMinutes -lt $lifetimeMin){
  try {
    $procs=Get-CimInstance Win32_Process -Filter "Name='claude.exe' OR Name='node.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and ($_.CommandLine -match 'Run a NOSKILL') }
    foreach($p in $procs){
      $ct=$p.CreationDate
      if($ct -and (((Get-Date)-$ct).TotalMinutes -gt $maxMin)){
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        ("WATCHDOG "+(Get-Date).ToString('u')+": killed stuck noskill hunt PID "+$p.ProcessId+" (ran > "+$maxMin+" min) - pipeline continues, report will be flagged STALE") | Add-Content $log
      }
    }
  } catch {}
  Start-Sleep -Seconds 60
}
