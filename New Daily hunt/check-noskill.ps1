# Quick health/staleness check for the 05:00 NO-SKILL pipeline.
# Run anytime after the 05:00 task to see whether any surface shipped STALE.
$proj='D:\Vidhya\New Daily hunt'
$dir="$proj\reports-noskill"
$log="$proj\logs-noskill\daily.log"
$flagP="$proj\logs-noskill\run-start.flag"
$expected='iis','rdp','azure','linux','sftp','app','app-pt','infra','db','network','dev','correlation'

Write-Output "===== SOC No-Skill pipeline health ====="
if(Test-Path $flagP){ $flag=(Get-Item $flagP).LastWriteTime; Write-Output ("Last run started : {0}" -f $flag.ToString('u')) }
else { Write-Output "Last run started : (never - run-start.flag missing)"; $flag=[datetime]::MinValue }

# 1) Per-report freshness vs the run-start flag
Write-Output "`n-- Report freshness (must be newer than run start AND carry findings-json) --"
$stale=@()
foreach($s in $expected){
  $fp="$dir\$s-latest.md"
  if(-not(Test-Path $fp)){ Write-Output ("  {0,-12} MISSING" -f $s); $stale+=$s; continue }
  $it=Get-Item $fp
  $hasJson=[bool](Select-String -Path $fp -Pattern 'findings-json' -Quiet)
  $status= if($it.LastWriteTime -lt $flag){'STALE'} elseif(-not $hasJson){'NO-JSON'} else {'FRESH'}
  if($status -ne 'FRESH'){ $stale+=$s }
  Write-Output ("  {0,-12} {1,-8} ({2})" -f $s,$status,$it.LastWriteTime.ToString('MM-dd HH:mm'))
}
Write-Output ("`nVERDICT: " + $(if($stale.Count){"STALE/MISSING -> $($stale -join ', ')"}else{'ALL FRESH'}))

# 2) Session-limit / watchdog kills in this run's log tail
if(Test-Path $log){
  $tail=Get-Content $log -Tail 400
  $hits=$tail | Select-String -Pattern 'session limit|usage limit|WATCHDOG|FRESHNESS|render FAILED|FALLBACK|retry-stale'
  Write-Output "`n-- Notable log lines (session limit / watchdog / freshness / render) --"
  if($hits){ $hits | ForEach-Object { Write-Output ("  "+$_.Line.Trim()) } } else { Write-Output "  (none)" }
}

# 3) Delivery + PDF
$marker="$proj\logs-noskill\delivered-$((Get-Date).ToString('yyyyMMdd')).txt"
Write-Output ("`nDelivered to channel today : " + $(if(Test-Path $marker){'YES ('+(Get-Content $marker -Raw).Trim()+')'}else{'no marker yet'}))
$pdf=Get-ChildItem "$dir\daily-SOC-noskill-*.pdf" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Output ("Latest PDF                 : " + $(if($pdf){$pdf.Name+' ('+$pdf.LastWriteTime.ToString('MM-dd HH:mm')+')'}else{'none yet'}))
