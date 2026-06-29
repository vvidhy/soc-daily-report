$ErrorActionPreference='Continue'
$webhookFile='D:\Vidhya\New Daily hunt\.webhook-reports'
$dir='D:\Vidhya\New Daily hunt\reports'
$now=Get-Date
if(-not (Test-Path $webhookFile)){ Write-Output 'ERROR: webhook file missing'; exit 1 }
$url=(Get-Content $webhookFile -Raw).Trim()
$cutoff=$now.AddHours(-20)
$files=Get-ChildItem $dir -File -Filter '*-latest.md' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cutoff } | Sort-Object Name

$script:posted=$false
function Clean([string]$s){ ($s -replace '[^\x20-\x7E\r\n]', '') }
function Send-Card([string]$title,[string]$text){
  $title=Clean $title; $text=Clean $text
  $p=@{ type='message'; attachments=@(@{
    contentType='application/vnd.microsoft.card.adaptive'
    content=@{ type='AdaptiveCard'; '$schema'='http://adaptivecards.io/schemas/adaptive-card.json'; version='1.4'
      body=@(@{type='TextBlock';text=$title;weight='Bolder';size='Medium';wrap=$true}
             @{type='TextBlock';text=$text;wrap=$true}) }
  }) } | ConvertTo-Json -Depth 12 -Compress
  try { Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' -Body $p -ErrorAction Stop | Out-Null; Write-Output "Posted: $title"; $script:posted=$true }
  catch { Write-Output "FAILED $title : $($_.Exception.Message)" }
}
function Send-Chunked([string]$titleBase,[string]$text){
  $cs=2500; $text=$text.Trim(); if(-not $text){ $text='(no content)' }
  if($text.Length -le $cs){ Send-Card $titleBase $text; Start-Sleep -Seconds 2 }
  else { $n=[int][Math]::Ceiling($text.Length/$cs)
    for($i=0;$i -lt $n;$i++){
      $start=$i*$cs; $len=[Math]::Min($cs,$text.Length-$start)
      Send-Card "$titleBase (part $($i+1)/$n)" $text.Substring($start,$len)
      Start-Sleep -Seconds 2 } }
}

$findings=@()
foreach($f in $files){
  $txt=Clean (Get-Content $f.FullName -Raw)
  $m=[regex]::Match($txt,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){
    try { $arr=$m.Groups[1].Value | ConvertFrom-Json; foreach($x in $arr){ $findings += $x } }
    catch { Write-Output "Findings parse failed for $($f.Name): $($_.Exception.Message)" }
  } else { Write-Output "No findings-json block in $($f.Name)" }
}

$cnts=@{HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}
foreach($r in $findings){ $s=[string]$r.sev; if($cnts.ContainsKey($s)){ $cnts[$s]++ } }
$ord=@{HIGH=1;MEDIUM=2;REVIEW=3;LOW=4;CLEAN=5}
$sorted = $findings | Sort-Object @{Expression={ $s=[string]$_.sev; if($ord.ContainsKey($s)){ $ord[$s] } else { 99 } }}, env, surface

$dateStr=$now.ToString('yyyy-MM-dd HH:mm')
$exec="Hunt completed: $($now.ToString('u'))`nHost: $env:COMPUTERNAME`n`nCounts: HIGH=$($cnts.HIGH)  MEDIUM=$($cnts.MEDIUM)  REVIEW=$($cnts.REVIEW)  LOW=$($cnts.LOW)  CLEAN=$($cnts.CLEAN)`n"
$top = $sorted | Where-Object { ([string]$_.sev) -in 'HIGH','MEDIUM' } | Select-Object -First 5
if($top){ $exec += "`nTop actionable items:`n"; foreach($t in $top){ $exec += "- [$([string]$t.sev)] $([string]$t.env)/$([string]$t.surface): $([string]$t.action)`n" } }
else { $exec += "`nNo HIGH or MEDIUM findings - clean day.`n" }
$pdf=Get-ChildItem "$dir\daily-SOC-*.pdf" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$shareUrl=$null
# Upload the PDF to the SOC team SharePoint library via the Power Automate flow (SOC-Report-Upload),
# if configured. Pure HTTP from PowerShell - zero Claude tokens. Any failure falls back silently below.
$uploadFlowFile='D:\Vidhya\New Daily hunt\.upload-flow-url'
if($pdf -and (Test-Path $uploadFlowFile)){
  try {
    $upUrl=(Get-Content $uploadFlowFile -Raw).Trim()
    $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($pdf.FullName))
    $upBody=@{ fileName=$pdf.Name; contentBase64=$b64 } | ConvertTo-Json -Compress
    $upResp=Invoke-RestMethod -Uri $upUrl -Method Post -ContentType 'application/json' -Body $upBody -ErrorAction Stop
    if($upResp.webUrl){ $shareUrl=([string]$upResp.webUrl).Trim(); Write-Output "Uploaded PDF to SharePoint: $shareUrl" }
    else { Write-Output "Upload flow returned no webUrl" }
  } catch { Write-Output "SharePoint upload failed: $($_.Exception.Message)" }
}
# Fallback: OneDrive folder link, if the SharePoint upload did not yield a URL.
if(-not $shareUrl -and (Test-Path 'D:\Vidhya\New Daily hunt\.onedrive-folder-url')){ $shareUrl=(Get-Content 'D:\Vidhya\New Daily hunt\.onedrive-folder-url' -Raw).Trim() }
if($pdf){ if($shareUrl){ $exec += "`n`nDaily PDF report (shared folder - all of casepoint can view):`n$shareUrl`nFile: $($pdf.Name)" } else { $exec += "`n`nPDF on laptop:`n$($pdf.FullName)`n(save an org-wide view link for the SOC-Reports folder to .onedrive-folder-url to get a clickable team link here)" } }
Send-Card "SOC Daily Report - Executive Summary ($dateStr)" $exec

function Esc([string]$s){ ($s -replace '\|','/') -replace "`r?`n",' ' }
$tbl = "| Sev | Env | Surface | Finding | Action |`n|---|---|---|---|---|`n"
foreach($r in $sorted){
  $env=([string]$r.env) -replace '-GL',''
  $tbl += "| $([string]$r.sev) | $env | $([string]$r.surface) | $(Esc ([string]$r.finding)) | $(Esc ([string]$r.action)) |`n"
}
Send-Chunked "SOC Daily Report - Findings Table" $tbl

foreach($r in ($sorted | Where-Object { ([string]$_.sev) -in 'HIGH','MEDIUM' })){
  $body=@("Severity: $([string]$r.sev)","Environment: $([string]$r.env)","Surface: $([string]$r.surface)","MITRE: $([string]$r.mitre)","Evidence: $([string]$r.evidence)","Action: $([string]$r.action)","","Finding: $([string]$r.finding)") -join "`n"
  Send-Chunked "$([string]$r.sev) - $([string]$r.env)/$([string]$r.surface)" $body
}

# Delivery marker: written only when at least one card posted OK. The safety-net
# task reads this to decide whether the channel post already succeeded today.
if($script:posted){
  $marker="D:\Vidhya\New Daily hunt\logs\delivered-$($now.ToString('yyyyMMdd')).txt"
  Set-Content -Path $marker -Value (Get-Date -Format o) -Encoding utf8
  Write-Output "Delivery marker written: $marker"
} else {
  Write-Output "No cards posted - delivery marker NOT written"
}