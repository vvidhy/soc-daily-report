$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$dir="$proj\reports"
$now=Get-Date
$dateStr=$now.ToString('yyyy-MM-dd')
$htmlPath="$dir\daily-SOC-$dateStr.html"
$pdfPath ="$dir\daily-SOC-$dateStr.pdf"

# --- Run-start reference for the freshness cross-check ---
# daily-report.cmd writes logs\run-start.flag at the top of each run; any
# report file older than that flag was NOT refreshed this run = STALE.
# Fallback (manual PDF-only run / first run): midnight today.
$flag="$proj\logs\run-start.flag"
$runStart=if(Test-Path $flag){ (Get-Item $flag).LastWriteTime } else { $now.Date }

# Casepoint logo - embedded as base64 so the headless render needs no external file
$logoTag=''
$logoPath="$proj\assets\casepoint-logo.png"
if(Test-Path $logoPath){ $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($logoPath)); $logoTag="<img class=`"logo`" src=`"data:image/png;base64,$b64`" />" }

$edge=$null
foreach($p in @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")){ if(Test-Path $p){ $edge=$p; break } }
if(-not $edge){ Write-Output 'ERROR: msedge.exe not found, cannot render PDF'; exit 1 }

$files=Get-ChildItem $dir -File -Filter '*-latest.md' -ErrorAction SilentlyContinue | Sort-Object Name
$findings=@(); $reportTexts=@{}
foreach($f in $files){
  $txt=(Get-Content $f.FullName -Raw) -replace '[^\x20-\x7E\r\n]', ''
  $reportTexts[$f.BaseName]=$txt
  $m=[regex]::Match($txt,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){ try { $arr=$m.Groups[1].Value | ConvertFrom-Json; foreach($x in $arr){ $findings += $x } } catch {} }
}
# --- Freshness cross-check: every expected report must be (re)written THIS run AND carry a findings-json block ---
$expected='iis','rdp','azure','linux','sftp','infra','db','network','correlation'
$freshSpans=''; $stale=@()
foreach($s in $expected){
  $fp="$dir\$s-latest.md"
  if(-not (Test-Path $fp)){ $status='MISSING'; $when='-'; $stale+=$s }
  else{
    $it=Get-Item $fp; $when=$it.LastWriteTime.ToString('MM-dd HH:mm')
    $hasJson=[bool](Select-String -Path $fp -Pattern 'findings-json' -Quiet)
    if($it.LastWriteTime -lt $runStart){ $status='STALE'; $stale+=$s }
    elseif(-not $hasJson){ $status='NO-JSON'; $stale+=$s }
    else{ $status='FRESH' }
  }
  $cls=if($status -eq 'FRESH'){'fresh-ok'}else{'fresh-bad'}
  $freshSpans+="<span class=`"$cls`">$s : $status ($when)</span> "
}
if($stale.Count -gt 0){ Write-Output ("REPORT FRESHNESS WARNING: stale/missing -> " + ($stale -join ', ')) }
else{ Write-Output "REPORT FRESHNESS: all $($expected.Count) reports fresh this run and carry findings-json." }
$freshBanner=if($stale.Count -gt 0){ "<div class=`"freshwarn`">DATA FRESHNESS WARNING - these surfaces were NOT refreshed this run (report may contain stale or missing data): <strong>$($stale -join ', ')</strong>. Investigate before relying on this report.</div>" } else { '' }

$cnts=@{CRITICAL=0;HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}
foreach($r in $findings){ $s=[string]$r.sev; if($cnts.ContainsKey($s)){ $cnts[$s]++ } }
$ord=@{CRITICAL=0;HIGH=1;MEDIUM=2;REVIEW=3;LOW=4;CLEAN=5}
$sorted=$findings | Sort-Object @{Expression={ $s=[string]$_.sev; if($ord.ContainsKey($s)){ $ord[$s] } else { 99 } }}, env, surface

function EncHtml([string]$s){ if(-not $s){ return '' }; ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }

# ====================== Kill-chain parsing (cross-module / cross-environment correlation) ======================
$corr = if(Test-Path "$dir\correlation-latest.md"){ Get-Content "$dir\correlation-latest.md" -Raw } else { '' }
$blocks = if($corr){ [regex]::Split($corr,'(?m)^### ') | Where-Object { $_ -match '^KC-' } } else { @() }
$KCs=@()
foreach($b in $blocks){
  $hdr=($b -split "`n")[0]; $parts=$hdr -split '\|'
  $id=$parts[0].Trim(); $ksev=if($parts.Count-gt1){$parts[1].Trim()}else{''}
  $envs=if($parts.Count-gt2){$parts[2].Trim()}else{''}; $surf=if($parts.Count-gt3){$parts[3].Trim()}else{''}
  $titleM=[regex]::Match($b,'(?m)^\*\*(.+?)\*\*\s*$'); $title=if($titleM.Success){$titleM.Groups[1].Value}else{''}
  $entM=[regex]::Match($b,'(?m)^\*\*Shared entity:\*\*\s*(.+)$'); $entity=if($entM.Success){($entM.Groups[1].Value -replace '[`*]','').Trim()}else{''}
  $whyM=[regex]::Match($b,'(?ms)\*\*Why this is .+?\*\*\s*(.+?)(?:\r?\n\r?\n|\*\*Contributing|\*\*Confidence|\*\*Parallel)'); $why=if($whyM.Success){($whyM.Groups[1].Value -replace '\s+',' ').Trim()}else{''}
  $confM=[regex]::Match($b,'(?m)^\*\*Confidence:\*\*\s*(.+)$'); $conf=if($confM.Success){($confM.Groups[1].Value -replace '[`*]','').Trim()}else{''}
  $actM=[regex]::Match($b,'(?m)^\*\*Action:\*\*\s*(.+)$'); $action=if($actM.Success){$actM.Groups[1].Value.Trim()}else{''}
  $parM=[regex]::Match($b,'(?ms)\*\*Parallel entity.+?\*\*\s*(.+?)(?:\r?\n\r?\n|\*\*Confidence)'); $parallel=if($parM.Success){($parM.Groups[1].Value -replace '\s+',' ').Trim()}else{''}
  $parLbl=if($parM.Success){([regex]::Match($b,'(?m)^\*\*(Parallel entity[^*]*)\*\*')).Groups[1].Value}else{''}
  $rows=@(); $tbl=$false
  foreach($ln in ($b -split "`n")){
    if($ln -match '^\|\s*#\s*\|'){ $tbl=$true; continue }
    if($tbl -and $ln -match '^\|\s*-'){ continue }
    if($tbl -and $ln -match '^\|'){ $rows+=$ln; continue }
    if($tbl -and $ln -notmatch '^\|'){ $tbl=$false }
  }
  $chainHtml=''
  if($rows.Count -gt 0){
    $chainHtml="<table class=`"kc`"><tr><th>#</th><th>Tactic</th><th>Technique</th><th>Evidence</th></tr>"
    foreach($rw in $rows){ $c=($rw.Trim('|') -split '\|')|ForEach-Object{$_.Trim()}; $chainHtml+="<tr><td>$(EncHtml $c[0])</td><td>$(EncHtml $c[1])</td><td>$(EncHtml $c[2])</td><td>$(EncHtml $c[3])</td></tr>" }
    $chainHtml+="</table>"
  }
  $contrib=@()
  $cM=[regex]::Match($b,'(?ms)\*\*Contributing findings.+?\*\*\s*(.+?)(?:\r?\n\r?\n|\*\*Why|\*\*Parallel|\*\*Confidence)')
  if($cM.Success){ foreach($ln in ($cM.Groups[1].Value -split "`n")){ if($ln.Trim() -match '^- '){ $contrib += ($ln.Trim() -replace '^- ','' -replace '[`]','') } } }
  $KCs += [pscustomobject]@{ id=$id;sev=$ksev;envs=$envs;surf=$surf;title=$title;entity=$entity;why=$why;conf=$conf;action=$action;parallel=$parallel;parLbl=$parLbl;chain=$chainHtml;contrib=$contrib }
}
function EntityTokens([string]$s){
  $t=@()
  $t+=[regex]::Matches($s,'\b(?:\d{1,3}\.){2}\d{1,3}\.0/24\b')|ForEach-Object{$_.Value}
  $t+=[regex]::Matches($s,'\b(?:\d{1,3}\.){3}\d{1,3}\b')|ForEach-Object{$_.Value}
  $t+=[regex]::Matches($s,'\b[A-Z]{2,}[A-Z0-9]{3,}\b')|ForEach-Object{$_.Value}
  $t+=[regex]::Matches($s,'\b[a-z]{2,}user\b|\bssadmin\b')|ForEach-Object{$_.Value}
  return ($t|Select-Object -Unique)
}
function LinkKC($r){
  $hay=(([string]$r.finding)+' '+([string]$r.evidence))
  foreach($kc in $KCs){ $ents=EntityTokens $kc.entity; if(-not $ents){continue}; foreach($t in $ents){ if($t -and $hay -match [regex]::Escape($t)){ return $kc } } }
  return $null
}
function DeepCorr($r){
  $kc=LinkKC $r
  if(-not $kc){ return "<div class=`"corr nocorr`"><div class=`"corrhd nocorrhd`">&#128279; No cross-module / cross-environment kill chain matched this $([string]$r.sev) &mdash; standalone. Pivot via the query above.</div></div>" }
  $contribHtml=''
  if($kc.contrib.Count -gt 0){ $contribHtml="<p><strong>Contributing findings (cross-module):</strong></p><ul>"; foreach($c in $kc.contrib){ $contribHtml+="<li>$(EncHtml $c)</li>" }; $contribHtml+="</ul>" }
  $parHtml=if($kc.parallel){ "<p><strong>$(EncHtml $kc.parLbl) (cross-environment):</strong> $(EncHtml $kc.parallel)</p>" }else{''}
  return "<div class=`"corr`"><div class=`"corrhd`">&#128279; Cross-correlation kill chain <strong>$($kc.id)</strong> <span class=`"badge $($kc.sev)`">$($kc.sev)</span> &nbsp;[modules/env: $(EncHtml $kc.envs) / $(EncHtml $kc.surf)]</div>" +
         "<p class=`"corrtitle`">$(EncHtml $kc.title)</p>" +
         "<p><strong>Shared entity:</strong> $(EncHtml $kc.entity)</p>" +
         "<p><strong>Reconstructed kill chain (ordered):</strong></p>$($kc.chain)" +
         $contribHtml + $parHtml +
         $(if($kc.why){"<p><strong>Why this is $($kc.sev):</strong> $(EncHtml $kc.why)</p>"}) +
         $(if($kc.conf){"<p><strong>Confidence:</strong> $(EncHtml $kc.conf)</p>"}) +
         $(if($kc.action){"<p><strong>Correlated action:</strong> $(EncHtml $kc.action)</p>"}) + "</div>"
}
# ====================== Priority table: HIGH / CRITICAL at a glance ======================
$priOrder=@{CRITICAL=1;HIGH=2}
$pri=$sorted | Where-Object { [string]$_.sev -in 'CRITICAL','HIGH' } | Sort-Object @{Expression={ $s=[string]$_.sev; if($priOrder.ContainsKey($s)){$priOrder[$s]}else{9} }}, env, surface
$priHtml=''
if($pri){
  $priHtml="<table><tr><th>Sev</th><th>Env</th><th>Surface</th><th>Finding</th><th>MITRE</th><th>Action needed</th></tr>"
  foreach($r in $pri){ $sev=[string]$r.sev; $priHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span></td><td>$(([string]$r.env) -replace '-GL','')</td><td>$([string]$r.surface)</td><td>$(EncHtml ([string]$r.finding))</td><td>$(EncHtml ([string]$r.mitre))</td><td>$(EncHtml ([string]$r.action))</td></tr>" }
  $priHtml+="</table>"
} else { $priHtml="<p class=`"meta`">No HIGH or Critical findings this run.</p>" }
# --- Per-environment grouping (read order: DEV-GL, PROD-GL, AZ-GL, OP-GL) ---
$envOrder='DEV-GL','PROD-GL','AZ-GL','OP-GL'
$envHtml=''
foreach($e in $envOrder){
  $ef=$sorted | Where-Object { ([string]$_.env) -eq $e }
  $ec=@{HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}
  foreach($r in $ef){ $s=[string]$r.sev; if($ec.ContainsKey($s)){ $ec[$s]++ } }
  $envHtml+="<h3>$e</h3><p>"
  foreach($k in 'HIGH','MEDIUM','REVIEW','LOW','CLEAN'){ $envHtml+="<span class=`"counts $k`" style=`"font-size:8.5pt;padding:2pt 6pt;margin-right:4pt`">$k $($ec[$k])</span> " }
  $envHtml+="</p>"
  if($ef){
    $envHtml+="<table><tr><th>Sev</th><th>Surface</th><th>Finding</th><th>Evidence</th><th>MITRE</th><th>Action</th></tr>"
    foreach($r in $ef){ $sev=[string]$r.sev; $envHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span></td><td>$([string]$r.surface)</td><td>$(EncHtml ([string]$r.finding))</td><td>$(EncHtml ([string]$r.evidence))</td><td>$(EncHtml ([string]$r.mitre))</td><td>$(EncHtml ([string]$r.action))</td></tr>" }
    $envHtml+="</table>"
  } else { $envHtml+="<p class=`"meta`">No findings recorded for this environment.</p>" }
}
# Cross-environment / correlation findings (env spans multiple environments)
$multi=$sorted | Where-Object { ([string]$_.env) -match '\+' -or (([string]$_.env) -notin $envOrder) }
if($multi){
  $envHtml+="<h3>Cross-Environment / Correlation</h3><table><tr><th>Sev</th><th>Env(s)</th><th>Surface</th><th>Finding</th><th>Evidence</th><th>MITRE</th><th>Action</th></tr>"
  foreach($r in $multi){ $sev=[string]$r.sev; $envHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span></td><td>$(EncHtml ([string]$r.env))</td><td>$([string]$r.surface)</td><td>$(EncHtml ([string]$r.finding))</td><td>$(EncHtml ([string]$r.evidence))</td><td>$(EncHtml ([string]$r.mitre))</td><td>$(EncHtml ([string]$r.action))</td></tr>" }
  $envHtml+="</table>"
}

$detailHtml=''
foreach($r in ($sorted | Where-Object { ([string]$_.sev) -in 'HIGH','MEDIUM','REVIEW' })){
  $qUsed=if($r.query){ "<p><strong>Graylog query used:</strong> <code>$(EncHtml ([string]$r.query))</code></p>" } else { '' }
  $qInv =if($r.investigate){ "<p><strong>Investigate further (run this):</strong> <code>$(EncHtml ([string]$r.investigate))</code></p>" } else { '' }
  $detailHtml += "<div class=`"detail sev-$([string]$r.sev)`"><h3>$([string]$r.sev) - $([string]$r.env) / $([string]$r.surface)</h3><p><strong>Finding:</strong> $(EncHtml ([string]$r.finding))</p><p><strong>Evidence:</strong> $(EncHtml ([string]$r.evidence))</p><p><strong>MITRE:</strong> $(EncHtml ([string]$r.mitre))</p>$qUsed$qInv<p><strong>Action needed:</strong> $(EncHtml ([string]$r.action))</p></div>"
}
$appendix=''
foreach($k in ($reportTexts.Keys | Sort-Object)){
  # Strip the machine-readable findings-json block: it is redundant in the PDF (every finding
  # already appears in the tables above). Keep only the human-readable narrative sections.
  $clean = $reportTexts[$k] -replace '(?ms)```findings-json\s*[\r\n]+.*?[\r\n]+```',''
  $appendix += "<h3>$k</h3><pre>$(EncHtml $clean)</pre>"
}

# --- Lessons Learned / recurring-finding (noise) tracker (deterministic, ZERO Claude tokens) ---
# Tracks how many DISTINCT days each finding-signature recurs. A finding that fires day after day
# is a noise candidate: the analyst checks whether it is genuine; if benign it should be added to
# that hunt's allow-list/suppression so it stops re-flagging (and re-spending tokens) every day.
$noiseDays = 3                                   # recur on >= this many distinct days to be flagged
$histPath  = "$proj\logs\noise-history.json"
$sevRank   = @{HIGH=4;MEDIUM=3;REVIEW=2;LOW=1;CLEAN=0}
$hist = @{}
if(Test-Path $histPath){ try { $arr = Get-Content $histPath -Raw | ConvertFrom-Json; foreach($e in @($arr)){ if($e.sig){ $hist[[string]$e.sig] = $e } } } catch { $hist=@{} } }
function NoiseSig($r){
  $f = ([string]$r.finding).ToLower()
  $f = [regex]::Replace($f,'(?:\d{1,3}\.){3}\d{1,3}','<ip>')   # collapse IPs so 1.2.3.4 / 5.6.7.8 group
  $f = [regex]::Replace($f,'\d+','#')                          # collapse counts so "12 hits"/"47 hits" group
  $f = ($f -replace '\s+',' ').Trim()
  return (([string]$r.surface) + '|' + $f)
}
$todaySigs = @{}
foreach($r in ($sorted | Where-Object { ([string]$_.sev) -ne 'CLEAN' })){ $sig = NoiseSig $r; if(-not $todaySigs.ContainsKey($sig)){ $todaySigs[$sig] = $r } }
foreach($sig in $todaySigs.Keys){
  $r = $todaySigs[$sig]
  if($hist.ContainsKey($sig)){
    $h = $hist[$sig]
    if([string]$h.lastSeen -ne $dateStr){ $h.days = [int]$h.days + 1; $h.lastSeen = $dateStr }
    $h.lastSev = [string]$r.sev
    if([int]$sevRank[[string]$r.sev] -gt [int]$sevRank[[string]$h.maxSev]){ $h.maxSev = [string]$r.sev }
  } else {
    $hist[$sig] = [pscustomobject]@{ sig=$sig; days=1; firstSeen=$dateStr; lastSeen=$dateStr; surface=[string]$r.surface; example=[string]$r.finding; lastSev=[string]$r.sev; maxSev=[string]$r.sev }
  }
}
try { (@($hist.Values) | ConvertTo-Json -Depth 5) | Set-Content $histPath -Encoding UTF8 } catch {}
# Candidates = recurring on >= threshold distinct days AND fired again today (chronic + still active)
$noiseCand = @($hist.Values | Where-Object { [int]$_.days -ge $noiseDays -and [string]$_.lastSeen -eq $dateStr } | Sort-Object @{Expression={[int]$_.days};Descending=$true})
$noiseHtml=''
if($noiseCand.Count -gt 0){
  $noiseHtml += "<table><tr><th>Days seen</th><th>Surface</th><th>Sev (last / max)</th><th>Recurring finding</th><th>Why it looks like noise (logic)</th><th>Manual action</th></tr>"
  foreach($n in $noiseCand){
    $mx=[string]$n.maxSev; if(-not $mx){ $mx=[string]$n.lastSev }
    if([int]$sevRank[$mx] -ge 3){
      $why="Recurs on $([int]$n.days) distinct days (since $($n.firstSeen)) but has reached <strong>$mx</strong> - do NOT dismiss as noise; this may be a persistent real threat. Confirm before any exclusion."
      $act="Investigate as a standing finding. Do NOT allow-list while it can hit $mx."
    } else {
      $why="Recurs on $([int]$n.days) distinct days (since $($n.firstSeen)); severity never exceeded <strong>$mx</strong> and the pattern is stable - consistent with a benign / expected recurring source rather than an attack."
      $act="Verify the source manually. If confirmed benign, add to the $(EncHtml ([string]$n.surface)) hunt allow-list / suppression - it then drops off from the NEXT run."
    }
    $noiseHtml += "<tr><td>$([int]$n.days)</td><td>$(EncHtml ([string]$n.surface))</td><td><span class=`"badge $([string]$n.lastSev)`">$([string]$n.lastSev)</span> / <span class=`"badge $mx`">$mx</span></td><td>$(EncHtml ([string]$n.example))</td><td>$why</td><td>$act</td></tr>"
  }
  $noiseHtml += "</table>"
} else { $noiseHtml = "<p class=`"meta`">No finding has recurred on $noiseDays or more distinct days (and fired again today) yet. This tracker builds history across runs and populates as patterns repeat.</p>" }

$html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOC Daily Report</title>
<style>
@page { margin: 30mm 16mm 16mm 16mm; }
body { padding-top: 10px; }
.pagehdr { position: fixed; top: 0; left: 0; right: 0; height: 30px; display: flex; align-items: center; justify-content: space-between; padding: 4pt 0; border-bottom: 2px solid #111; background: #fff; }
.pagehdr img { height: 22px; }
.pagehdr .pht { color: #111; font-weight: 600; font-size: 10.5pt; }
body { font-family: 'Segoe UI', Calibri, Arial, sans-serif; font-size: 11pt; color: #222; }
h1 { color: #1a3a5c; font-size: 22pt; margin-bottom: 4pt; }
h2 { color: #1a3a5c; border-bottom: 2px solid #1a3a5c; padding-bottom: 3pt; margin-top: 18pt; }
h3 { color: #2c5282; margin-top: 10pt; }
.meta { color: #555; font-size: 10pt; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0; font-size: 9.5pt; }
th { background: #1a3a5c; color: white; padding: 5pt; text-align: left; }
td { border: 1px solid #ccc; padding: 4pt; vertical-align: top; }
tr.sev-HIGH td { background: #fee; } tr.sev-MEDIUM td { background: #fff4d4; }
tr.sev-REVIEW td { background: #fffbe6; } tr.sev-LOW td { background: #f0f9ff; }
tr.sev-CLEAN td { background: #e8f5e9; }
.detail { border-left: 4px solid #1a3a5c; background: #f7f9fc; padding: 8pt 12pt; margin: 8pt 0; }
.detail.sev-HIGH { border-left-color: #c00; } .detail.sev-MEDIUM { border-left-color: #c87000; }
pre { background: #f4f4f4; padding: 8pt; white-space: pre-wrap; font-family: Consolas, monospace; font-size: 9pt; border-left: 3px solid #1a3a5c; }
.counts { display: inline-block; padding: 4pt 8pt; margin-right: 6pt; border-radius: 3pt; font-weight: bold; color: white; }
.counts.HIGH { background: #c00; } .counts.MEDIUM { background: #c87000; } .counts.REVIEW { background: #c8a800; }
.counts.LOW { background: #5080a0; } .counts.CLEAN { background: #2e7d32; }
.fresh-ok { display:inline-block; padding:2pt 6pt; margin:2pt; border-radius:3pt; font-size:8.5pt; background:#e8f5e9; color:#1b5e20; border:1px solid #2e7d32; }
.fresh-bad { display:inline-block; padding:2pt 6pt; margin:2pt; border-radius:3pt; font-size:8.5pt; background:#fde7e7; color:#a00; border:1px solid #c00; font-weight:bold; }
.freshwarn { background:#fde7e7; border:2px solid #c00; color:#a00; padding:8pt 12pt; margin:8pt 0; font-weight:bold; border-radius:3pt; }
.hdr { display:flex; flex-direction:column; align-items:flex-start; gap:8pt; border-bottom:3px solid #1a3a5c; padding-bottom:8pt; margin-top:14pt; margin-bottom:8pt; }
.logo { height:46pt; }
.badge { display:inline-block; padding:1pt 6pt; border-radius:3pt; color:#fff; font-size:8pt; font-weight:bold; }
.badge.HIGH{background:#c00}.badge.MEDIUM{background:#c87000}.badge.REVIEW{background:#c8a800}.badge.LOW{background:#5080a0}.badge.CLEAN{background:#2e7d32}
code { background:#eef2f7; padding:1pt 4pt; border-radius:2pt; font-family:Consolas,monospace; font-size:8.5pt; word-break:break-all; }
.detail p { margin:3pt 0; }
</style></head><body>
<div class="pagehdr">$logoTag<span class="pht">Security Assessment Report</span></div>
<div class="hdr"><h1>Security Assessment Report</h1></div>
<p class="meta">Date: $dateStr | Host: $env:COMPUTERNAME | Generated: $($now.ToString('u'))</p>
$freshBanner
<h2>Data Freshness (cross-check)</h2>
<p class="meta">Run start: $($runStart.ToString('u')) — each report must be (re)written after this and carry a findings-json block.</p>
<p>$freshSpans</p>
<h2>Executive Summary</h2>
<p>
<span class="counts HIGH">HIGH: $($cnts.HIGH)</span>
<span class="counts MEDIUM">MEDIUM: $($cnts.MEDIUM)</span>
<span class="counts REVIEW">REVIEW: $($cnts.REVIEW)</span>
<span class="counts LOW">LOW: $($cnts.LOW)</span>
<span class="counts CLEAN">CLEAN: $($cnts.CLEAN)</span>
</p>
<h2>Findings by Environment</h2>
$envHtml
<h2>All Findings (flat view)</h2>
<table><tr><th>Sev</th><th>Env</th><th>Surface</th><th>Finding</th><th>Evidence</th><th>MITRE</th><th>Action</th></tr>
$findRows
</table>
<h2>Detail - HIGH / MEDIUM</h2>
$detailHtml
<h2>Lessons Learned - Recurring Findings (noise review)</h2>
<p class="meta">These findings recur day after day. The report does NOT exclude anything automatically - it gives the reasoning for <em>why</em> each looks like noise so a human can judge. After manual review confirms a finding is benign/expected, add it to that hunt's allow-list/suppression; it then drops off from the next run. Anything that has ever reached HIGH is called out as NOT dismissible. Threshold: seen on $noiseDays+ distinct days AND present again today.</p>
$noiseHtml
<h2>Appendix - Full Reports</h2>
$appendix
</body></html>
"@
[System.IO.File]::WriteAllText($htmlPath,$html,(New-Object System.Text.UTF8Encoding($false)))
$urlPath = 'file:///' + ($htmlPath -replace '\\','/')
# Render to a TEMP file (never the possibly-open target). Two fixes vs the old approach:
#  (1) --headless=new + a dedicated --user-data-dir force a SEPARATE Edge instance;
#      otherwise headless attaches to the user's already-open Edge and silently SKIPS
#      --print-to-pdf, leaving a stale PDF that the poll mistakes for success.
#  (2) Rendering to a temp path means a viewer holding the real PDF open can't block the render.
$tmpPdf="$env:TEMP\soc-render-$dateStr-$($now.ToString('HHmmss')).pdf"
if(Test-Path $tmpPdf){ Remove-Item $tmpPdf -Force -ErrorAction SilentlyContinue }
& $edge --headless=new --disable-gpu --user-data-dir="$env:TEMP\edge-soc-pdf" --no-pdf-header-footer --print-to-pdf="$tmpPdf" $urlPath 2>$null
# Poll up to ~120s for the temp PDF to exist and its size to stop growing (stable = done).
$pdfReady=$false
for($w=0; $w -lt 60; $w++){
  Start-Sleep -Seconds 1
  if(Test-Path $tmpPdf){ $sz1=(Get-Item $tmpPdf).Length; Start-Sleep -Seconds 1; $sz2=(Get-Item $tmpPdf).Length; if($sz1 -gt 0 -and $sz1 -eq $sz2){ $pdfReady=$true; break } }
}
if($pdfReady){
  try { Copy-Item $tmpPdf $pdfPath -Force -ErrorAction Stop } catch { Write-Output "WARN: $pdfPath is locked (open in a viewer?) - close it; fresh render kept at $tmpPdf" }
  Copy-Item $tmpPdf "C:\Users\VidhyaV\OneDrive - casepoint\SOC-Reports\daily-SOC-$dateStr.pdf" -Force -ErrorAction SilentlyContinue
  Write-Output "PDF: $pdfPath (rendered $((Get-Item $tmpPdf).LastWriteTime.ToString('HH:mm:ss')), also copied to OneDrive\SOC-Reports)"
} else { Write-Output "PDF render FAILED. HTML at: $htmlPath" }