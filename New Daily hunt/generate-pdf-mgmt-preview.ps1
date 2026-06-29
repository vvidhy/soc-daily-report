# ============================================================================
#  MANAGEMENT-EDITION PREVIEW renderer  (standalone, non-destructive)
#  Reads the SAME reports\*-latest.md findings the analyst PDF uses, and emits
#  an executive summary PDF to a PREVIEW filename. Does NOT touch the live
#  pipeline: no OneDrive copy, no Teams delivery, no changes to generate-pdf.ps1.
#  Output: reports\daily-SOC-mgmt-preview-<HHmmss>.pdf
# ============================================================================
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$dir="$proj\reports"
$now=Get-Date
$dateStr=$now.ToString('yyyy-MM-dd')
$stamp=$now.ToString('HHmmss')
$htmlPath="$dir\daily-SOC-mgmt-preview-$stamp.html"
$pdfPath ="$dir\daily-SOC-mgmt-preview-$stamp.pdf"

$flag="$proj\logs\run-start.flag"
$runStart=if(Test-Path $flag){ (Get-Item $flag).LastWriteTime } else { $now.Date }

$logoTag=''
$logoPath="$proj\assets\casepoint-logo.png"
if(Test-Path $logoPath){ $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($logoPath)); $logoTag="<img class=`"logo`" src=`"data:image/png;base64,$b64`" />" }

$edge=$null
foreach($p in @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")){ if(Test-Path $p){ $edge=$p; break } }
if(-not $edge){ Write-Output 'ERROR: msedge.exe not found, cannot render PDF'; exit 1 }

function EncHtml([string]$s){ if(-not $s){ return '' }; ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }

# --- Load findings from the same per-surface reports ---
$files=Get-ChildItem $dir -File -Filter '*-latest.md' -ErrorAction SilentlyContinue | Sort-Object Name
$findings=@()
foreach($f in $files){
  $txt=(Get-Content $f.FullName -Raw) -replace '[^\x20-\x7E\r\n]', ''
  $m=[regex]::Match($txt,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){ try { $arr=$m.Groups[1].Value | ConvertFrom-Json; foreach($x in $arr){ $findings += $x } } catch {} }
}

# --- Freshness (management should be told if data is incomplete) ---
$expected='iis','rdp','azure','linux','sftp','infra','db','network','correlation'
$stale=@()
foreach($s in $expected){
  $fp="$dir\$s-latest.md"
  if(-not (Test-Path $fp)){ $stale+=$s; continue }
  $it=Get-Item $fp
  $hasJson=[bool](Select-String -Path $fp -Pattern 'findings-json' -Quiet)
  if($it.LastWriteTime -lt $runStart){ $stale+=$s } elseif(-not $hasJson){ $stale+=$s }
}
$freshBanner=if($stale.Count -gt 0){ "<div class=`"freshwarn`">DATA GAP: $($stale.Count) monitoring surface(s) did not refresh in the latest run (<strong>$($stale -join ', ')</strong>). This summary may be incomplete.</div>" } else { '' }

# --- Counts ---
$cnts=@{CRITICAL=0;HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}
foreach($r in $findings){ $s=[string]$r.sev; if($cnts.ContainsKey($s)){ $cnts[$s]++ } }

# --- Posture verdict (computed one-liner) ---
if($cnts.CRITICAL -gt 0){ $verdict='CRITICAL'; $vclass='v-crit'; $vtext="Immediate action required - $($cnts.CRITICAL) critical and $($cnts.HIGH) high-severity finding(s) need owner attention now." }
elseif($cnts.HIGH -gt 0){ $verdict='ELEVATED'; $vclass='v-high'; $vtext="$($cnts.HIGH) high-severity finding(s) require action. No critical incidents." }
elseif($cnts.MEDIUM -gt 0){ $verdict='GUARDED'; $vclass='v-med'; $vtext="$($cnts.MEDIUM) medium finding(s) to review. No high-severity activity." }
elseif($cnts.REVIEW -gt 0){ $verdict='NOMINAL'; $vclass='v-rev'; $vtext="$($cnts.REVIEW) item(s) flagged for analyst review; none high-severity." }
else{ $verdict='NORMAL'; $vclass='v-ok'; $vtext="No notable security findings across the monitored estate in the latest run." }
if($stale.Count -gt 0){ $vtext += " (Note: $($stale.Count) surface(s) had a data gap - see banner.)" }

# --- Priority actions: CRITICAL/HIGH only, plain language (no MITRE, no queries) ---
$priOrder=@{CRITICAL=1;HIGH=2}
$pri=$findings | Where-Object { [string]$_.sev -in 'CRITICAL','HIGH' } | Sort-Object @{Expression={ $s=[string]$_.sev; if($priOrder.ContainsKey($s)){$priOrder[$s]}else{9} }}, env, surface
$priHtml=''
if($pri){
  $priHtml="<table><tr><th>Severity</th><th>Environment</th><th>Area</th><th>What it is</th><th>Action needed</th></tr>"
  foreach($r in $pri){ $sev=[string]$r.sev; $priHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span></td><td>$(([string]$r.env) -replace '-GL','')</td><td>$(EncHtml ([string]$r.surface))</td><td>$(EncHtml ([string]$r.finding))</td><td>$(EncHtml ([string]$r.action))</td></tr>" }
  $priHtml+="</table>"
} else { $priHtml="<p class=`"good`">&#10004; No high or critical findings this run - no priority actions for management.</p>" }

# --- Coverage by environment: compact severity rollup (shows monitoring breadth) ---
$envOrder='DEV-GL','PROD-GL','AZ-GL','OP-GL'
$covHtml="<table><tr><th>Environment</th><th>High</th><th>Medium</th><th>Review</th><th>Low</th><th>Clean</th></tr>"
foreach($e in $envOrder){
  $ef=$findings | Where-Object { ([string]$_.env) -eq $e }
  $ec=@{HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}
  foreach($r in $ef){ $s=[string]$r.sev; if($ec.ContainsKey($s)){ $ec[$s]++ } }
  $covHtml+="<tr><td><strong>$($e -replace '-GL','')</strong></td><td>$($ec.HIGH)</td><td>$($ec.MEDIUM)</td><td>$($ec.REVIEW)</td><td>$($ec.LOW)</td><td>$($ec.CLEAN)</td></tr>"
}
$covHtml+="</table>"

# --- Correlated incidents (kill chains) as plain-English narrative ---
$corr = if(Test-Path "$dir\correlation-latest.md"){ Get-Content "$dir\correlation-latest.md" -Raw } else { '' }
$blocks = if($corr){ [regex]::Split($corr,'(?m)^### ') | Where-Object { $_ -match '^KC-' } } else { @() }
$kcHtml=''
foreach($b in $blocks){
  $hdr=($b -split "`n")[0]; $parts=$hdr -split '\|'
  $id=$parts[0].Trim(); $ksev=if($parts.Count-gt1){$parts[1].Trim()}else{''}
  $titleM=[regex]::Match($b,'(?m)^\*\*(.+?)\*\*\s*$'); $title=if($titleM.Success){$titleM.Groups[1].Value}else{''}
  $whyM=[regex]::Match($b,'(?ms)\*\*Why this is .+?\*\*\s*(.+?)(?:\r?\n\r?\n|\*\*Contributing|\*\*Confidence|\*\*Parallel)'); $why=if($whyM.Success){($whyM.Groups[1].Value -replace '\s+',' ').Trim()}else{''}
  $confM=[regex]::Match($b,'(?m)^\*\*Confidence:\*\*\s*(.+)$'); $conf=if($confM.Success){($confM.Groups[1].Value -replace '[`*]','').Trim()}else{''}
  $actM=[regex]::Match($b,'(?m)^\*\*Action:\*\*\s*(.+)$'); $action=if($actM.Success){$actM.Groups[1].Value.Trim()}else{''}
  $kcHtml+="<div class=`"kc`"><p><span class=`"badge $ksev`">$ksev</span> <strong>$(EncHtml $id) - $(EncHtml $title)</strong></p>"
  if($why){ $kcHtml+="<p>$(EncHtml $why)</p>" }
  if($conf){ $kcHtml+="<p class=`"meta`">Confidence: $(EncHtml $conf)</p>" }
  if($action){ $kcHtml+="<p><strong>Recommended action:</strong> $(EncHtml $action)</p>" }
  $kcHtml+="</div>"
}
if(-not $kcHtml){ $kcHtml="<p class=`"good`">&#10004; No multi-stage / cross-environment incidents correlated this run.</p>" }

$html=@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOC Management Summary</title>
<style>
@page { margin: 30mm 16mm 16mm 16mm; }
body { font-family: 'Segoe UI', Calibri, Arial, sans-serif; font-size: 11pt; color: #222; padding-top: 10px; }
.pagehdr { position: fixed; top: 0; left: 0; right: 0; height: 30px; display: flex; align-items: center; justify-content: space-between; padding: 4pt 0; border-bottom: 2px solid #111; background: #fff; }
.pagehdr img { height: 22px; }
.pagehdr .pht { color: #111; font-weight: 600; font-size: 10.5pt; }
h1 { color: #1a3a5c; font-size: 22pt; margin-bottom: 2pt; }
h2 { color: #1a3a5c; border-bottom: 2px solid #1a3a5c; padding-bottom: 3pt; margin-top: 18pt; }
.hdr { display:flex; flex-direction:column; align-items:flex-start; gap:6pt; border-bottom:3px solid #1a3a5c; padding-bottom:8pt; margin-top:14pt; margin-bottom:8pt; }
.meta { color: #555; font-size: 10pt; }
.verdict { padding:12pt 16pt; border-radius:5pt; margin:10pt 0; font-size:12pt; }
.verdict .vlabel { font-size:16pt; font-weight:bold; display:block; margin-bottom:4pt; }
.v-crit { background:#fde7e7; border-left:8px solid #c00; } .v-crit .vlabel{ color:#c00; }
.v-high { background:#fff0e6; border-left:8px solid #c87000; } .v-high .vlabel{ color:#c87000; }
.v-med  { background:#fff8e6; border-left:8px solid #c8a800; } .v-med .vlabel{ color:#9a7b00; }
.v-rev  { background:#f5fbff; border-left:8px solid #5080a0; } .v-rev .vlabel{ color:#3a6080; }
.v-ok   { background:#e8f5e9; border-left:8px solid #2e7d32; } .v-ok .vlabel{ color:#1b5e20; }
.counts { display: inline-block; padding: 6pt 12pt; margin-right: 6pt; border-radius: 4pt; font-weight: bold; color: white; font-size:11pt; }
.counts.CRITICAL { background:#900; } .counts.HIGH { background: #c00; } .counts.MEDIUM { background: #c87000; }
.counts.REVIEW { background: #c8a800; } .counts.LOW { background: #5080a0; } .counts.CLEAN { background: #2e7d32; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0; font-size: 10pt; }
th { background: #1a3a5c; color: white; padding: 6pt; text-align: left; }
td { border: 1px solid #ccc; padding: 5pt; vertical-align: top; }
tr.sev-CRITICAL td { background:#fdd; } tr.sev-HIGH td { background: #fee; }
.badge { display:inline-block; padding:1pt 6pt; border-radius:3pt; color:#fff; font-size:8pt; font-weight:bold; }
.badge.CRITICAL{background:#900}.badge.HIGH{background:#c00}.badge.MEDIUM{background:#c87000}.badge.REVIEW{background:#c8a800}.badge.LOW{background:#5080a0}.badge.CLEAN{background:#2e7d32}
.freshwarn { background:#fde7e7; border:2px solid #c00; color:#a00; padding:8pt 12pt; margin:8pt 0; font-weight:bold; border-radius:3pt; }
.good { color:#1b5e20; font-weight:600; }
.kc { border-left:4px solid #1a3a5c; background:#f7f9fc; padding:6pt 12pt; margin:8pt 0; }
.kc p { margin:3pt 0; }
.foot { color:#777; font-size:8.5pt; margin-top:18pt; border-top:1px solid #ccc; padding-top:6pt; }
</style></head><body>
<div class="pagehdr">$logoTag<span class="pht">Security Posture - Management Summary</span></div>
<div class="hdr"><h1>Security Posture</h1><span class="meta">Management Summary &mdash; PREVIEW</span></div>
<p class="meta">Date: $dateStr | Estate: DEV / PROD / AZ / OP | Generated: $($now.ToString('u'))</p>
$freshBanner
<div class="verdict $vclass"><span class="vlabel">$verdict</span>$vtext</div>
<h2>At a Glance</h2>
<p>
<span class="counts CRITICAL">CRITICAL: $($cnts.CRITICAL)</span>
<span class="counts HIGH">HIGH: $($cnts.HIGH)</span>
<span class="counts MEDIUM">MEDIUM: $($cnts.MEDIUM)</span>
<span class="counts REVIEW">REVIEW: $($cnts.REVIEW)</span>
<span class="counts CLEAN">CLEAN: $($cnts.CLEAN)</span>
</p>
<h2>Priority Actions</h2>
$priHtml
<h2>Correlated Incidents</h2>
$kcHtml
<h2>Coverage by Environment</h2>
<p class="meta">Findings monitored across all four environments in the latest run.</p>
$covHtml
<p class="foot">This is a management summary. Full technical detail - Graylog queries, evidence, MITRE mapping, kill-chain reconstruction and the recurring-noise tracker - is in the analyst investigation report. Casepoint SOC, automated daily run.</p>
</body></html>
"@
[System.IO.File]::WriteAllText($htmlPath,$html,(New-Object System.Text.UTF8Encoding($false)))
$urlPath = 'file:///' + ($htmlPath -replace '\\','/')
$tmpPdf="$env:TEMP\soc-mgmt-render-$dateStr-$stamp.pdf"
if(Test-Path $tmpPdf){ Remove-Item $tmpPdf -Force -ErrorAction SilentlyContinue }
& $edge --headless=new --disable-gpu --user-data-dir="$env:TEMP\edge-soc-pdf-mgmt" --no-pdf-header-footer --print-to-pdf="$tmpPdf" $urlPath 2>$null
$pdfReady=$false
for($w=0; $w -lt 60; $w++){
  Start-Sleep -Seconds 1
  if(Test-Path $tmpPdf){ $sz1=(Get-Item $tmpPdf).Length; Start-Sleep -Seconds 1; $sz2=(Get-Item $tmpPdf).Length; if($sz1 -gt 0 -and $sz1 -eq $sz2){ $pdfReady=$true; break } }
}
if($pdfReady){
  try { Copy-Item $tmpPdf $pdfPath -Force -ErrorAction Stop } catch { Write-Output "WARN: $pdfPath locked - fresh render kept at $tmpPdf" }
  Write-Output "PREVIEW PDF: $pdfPath"
} else { Write-Output "PDF render FAILED. HTML at: $htmlPath" }
