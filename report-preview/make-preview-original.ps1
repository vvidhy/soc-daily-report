# PREVIEW based on the ORIGINAL generate-pdf-noskill.ps1, with 4 targeted changes:
#  (1) findings = environment-grouped only (drop duplicate flat "All Findings")
#  (2) detail = add cross-module/cross-env kill chain for HIGH/CRITICAL only
#  (3) appendix = ORIGINAL raw Full Reports (unchanged)
#  (4) lessons learned = which logs cause noise + how to confirm genuineness (human) to reduce next hunt
# READ-ONLY on production data. Output goes to D:\Vidhya\report-preview only.
$ErrorActionPreference='Continue'
$proj='C:\Users\VidhyaV\soc-monitor'
$dir="$proj\reports-noskill"
$out='D:\Vidhya\report-preview'
$now=Get-Date; $dateStr=$now.ToString('yyyy-MM-dd')
$htmlPath="$out\PREVIEW-original-layout.html"
$pdfPath ="$out\PREVIEW-original-layout.pdf"

$flag="$proj\logs-noskill\run-start.flag"
$runStart=if(Test-Path $flag){ (Get-Item $flag).LastWriteTime } else { $now.Date }

$logoTag=''
$logoPath="$proj\assets\casepoint-logo.png"
if(Test-Path $logoPath){ $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($logoPath)); $logoTag="<img class=`"logo`" src=`"data:image/png;base64,$b64`" />" }

function EncHtml([string]$s){ if(-not $s){ return '' }; ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }

# --- read per-hunt reports (same as original) ---
$files=Get-ChildItem $dir -File -Filter '*-latest.md' -ErrorAction SilentlyContinue | Sort-Object Name
$findings=@(); $reportTexts=@{}
foreach($f in $files){
  $txt=(Get-Content $f.FullName -Raw) -replace '[^\x20-\x7E\r\n]', ''
  $reportTexts[$f.BaseName]=$txt
  $m=[regex]::Match($txt,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){ try { $arr=$m.Groups[1].Value | ConvertFrom-Json; foreach($x in $arr){ $findings += $x } } catch {} }
}

# --- freshness cross-check (same as original) ---
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
$freshBanner=if($stale.Count -gt 0){ "<div class=`"freshwarn`">DATA FRESHNESS WARNING - these surfaces were NOT refreshed this run: <strong>$($stale -join ', ')</strong>.</div>" } else { '' }

$cnts=@{CRITICAL=0;HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}
foreach($r in $findings){ $s=[string]$r.sev; if($cnts.ContainsKey($s)){ $cnts[$s]++ } }
$ord=@{CRITICAL=0;HIGH=1;MEDIUM=2;REVIEW=3;LOW=4;CLEAN=5}
$sorted=$findings | Sort-Object @{Expression={ $s=[string]$_.sev; if($ord.ContainsKey($s)){ $ord[$s] } else { 99 } }}, env, surface

# ====================== kill-chain parsing (for change #2) ======================
$corr = if(Test-Path "$dir\correlation-latest.md"){ Get-Content "$dir\correlation-latest.md" -Raw } else { '' }
$blocks = if($corr){ [regex]::Split($corr,'(?m)^### ') | Where-Object { $_ -match '^KC-' } } else { @() }
$KCs=@()
foreach($b in $blocks){
  $hdr=($b -split "`n")[0]; $parts=$hdr -split '\|'
  $id=$parts[0].Trim(); $sev=if($parts.Count-gt1){$parts[1].Trim()}else{''}
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
  $KCs += [pscustomobject]@{ id=$id;sev=$sev;envs=$envs;surf=$surf;title=$title;entity=$entity;why=$why;conf=$conf;action=$action;parallel=$parallel;parLbl=$parLbl;chain=$chainHtml;contrib=$contrib }
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

# ====================== (0) Priority table: HIGH / CRITICAL at a glance ======================
$priOrder=@{CRITICAL=1;HIGH=2}
$pri=$sorted | Where-Object { [string]$_.sev -in 'CRITICAL','HIGH' } | Sort-Object @{Expression={ $s=[string]$_.sev; if($priOrder.ContainsKey($s)){$priOrder[$s]}else{9} }}, env, surface
$priHtml=''
if($pri){
  $priHtml="<table><tr><th>Sev</th><th>Env</th><th>Surface</th><th>Finding</th><th>MITRE</th><th>Action needed</th></tr>"
  foreach($r in $pri){ $sev=[string]$r.sev; $priHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span></td><td>$(([string]$r.env) -replace '-GL','')</td><td>$([string]$r.surface)</td><td>$(EncHtml ([string]$r.finding))</td><td>$(EncHtml ([string]$r.mitre))</td><td>$(EncHtml ([string]$r.action))</td></tr>" }
  $priHtml+="</table>"
} else { $priHtml="<p class=`"meta`">No HIGH or Critical findings this run.</p>" }

# ====================== (1) Findings by Environment (ORIGINAL grouping, kept) ======================
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
$multi=$sorted | Where-Object { ([string]$_.env) -match '\+' -or (([string]$_.env) -notin $envOrder) }
if($multi){
  $envHtml+="<h3>Cross-Environment / Correlation</h3><table><tr><th>Sev</th><th>Env(s)</th><th>Surface</th><th>Finding</th><th>Evidence</th><th>MITRE</th><th>Action</th></tr>"
  foreach($r in $multi){ $sev=[string]$r.sev; $envHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span></td><td>$(EncHtml ([string]$r.env))</td><td>$([string]$r.surface)</td><td>$(EncHtml ([string]$r.finding))</td><td>$(EncHtml ([string]$r.evidence))</td><td>$(EncHtml ([string]$r.mitre))</td><td>$(EncHtml ([string]$r.action))</td></tr>" }
  $envHtml+="</table>"
}

# ====================== (2) Detail - HIGH/MEDIUM (original) + kill chain for HIGH/CRITICAL ======================
$detailHtml=''
foreach($r in ($sorted | Where-Object { ([string]$_.sev) -in 'HIGH','CRITICAL','MEDIUM','REVIEW' })){
  $sev=[string]$r.sev
  $qUsed=if($r.query){ "<p><strong>Graylog query used:</strong> <code>$(EncHtml ([string]$r.query))</code></p>" } else { '' }
  $qInv =if($r.investigate){ "<p><strong>Investigate further (run this):</strong> <code>$(EncHtml ([string]$r.investigate))</code></p>" } else { '' }
  $corrBlock = if($sev -in 'HIGH','CRITICAL'){ DeepCorr $r } else { '' }
  $detailHtml += "<div class=`"detail sev-$sev`"><h3>$sev - $([string]$r.env) / $([string]$r.surface)</h3><p><strong>Finding:</strong> $(EncHtml ([string]$r.finding))</p><p><strong>Evidence:</strong> $(EncHtml ([string]$r.evidence))</p><p><strong>MITRE:</strong> $(EncHtml ([string]$r.mitre))</p>$qUsed$qInv<p><strong>Action needed:</strong> $(EncHtml ([string]$r.action))</p>$corrBlock</div>"
}

# ====================== (4) Lessons Learned - noisy logs + genuineness confirmation (human) ======================
$histPath="$proj\logs-noskill\noise-history.json"
$hist=@()
if(Test-Path $histPath){ try { $hist=@(Get-Content $histPath -Raw | ConvertFrom-Json) } catch {} }
# noise candidate surfaces from THIS run: lots of LOW/REVIEW/CLEAN, no HIGH
$surfStats=@{}
foreach($r in $findings){ $s=[string]$r.surface; if(-not $s){continue}; if(-not $surfStats.ContainsKey($s)){ $surfStats[$s]=@{n=0;noise=0;high=0;ex=''} }; $surfStats[$s].n++; if([string]$r.sev -in 'LOW','REVIEW','CLEAN'){$surfStats[$s].noise++; if(-not $surfStats[$s].ex){$surfStats[$s].ex=[string]$r.finding}}; if([string]$r.sev -in 'HIGH','CRITICAL'){$surfStats[$s].high++} }
# human-confirmation guidance per surface (how to confirm genuine vs noise)
$confirmBy=@{
  linux   = 'Confirm the source IP/host with the infra owner: is it a sanctioned vulnerability scanner (Nessus/Nikto) or config-audit job with an active change-window ticket? Check /etc/sudoers and the scanner asset record.'
  firewall= 'Cross-check the source IP against the threat-intel allow-list and the Cato egress list; confirm with network team whether the dst is an internet-facing honeypot/edge node that always draws scans.'
  iis     = 'Verify the URI pattern is a known scanner signature (404/blocked) and the service account is expected to retry; confirm with app owner whether the 401 volume is a broken/stale credential rotation.'
  sftp    = 'Confirm with the file-transfer owner whether the blocked source is a partner integration mis-config; check Cerberus auto-ban logs to confirm it never authenticated.'
  rdp     = 'Confirm the account (e.g. shared admin) maps to sanctioned automation with a change ticket; require named accounts + MFA to remove the ambiguity next run.'
  defender= 'Confirm whether detections are EICAR/test files from a scheduled AV test; verify a 1117 remediation followed. Real malware (non-EICAR) must NOT be dismissed.'
  virt    = 'Confirm the high vCenter event volume is the expected backup/clone automation window with the virtualization owner.'
  process = 'Confirm the LOLBin invocation (regsvr32/certutil) matches a known signed application deployment; baseline the command line with the app team.'
  db      = 'Confirm the ES/OpenSearch error pattern is a known Graylog indexer health issue, not data tampering; check cluster health with the platform team.'
  network = 'Baseline the talker pairs with the network owner; confirm scan-like fan-out is a sanctioned monitoring/discovery tool.'
}
function ConfirmText($s){ if($confirmBy.ContainsKey($s)){ return $confirmBy[$s] } return "Confirm with the owning team whether the source is sanctioned (scanner / automation / test) and backed by a change ticket; if so it is genuine noise." }

# build rows: prefer recurring benign signatures from history, then this-run noisy surfaces
$lessonRows=''; $seenSurf=@{}
$benign=$hist | Where-Object { [string]$_.maxSev -in 'REVIEW','LOW','CLEAN' } | Select-Object -First 6
foreach($n in $benign){
  $s=[string]$n.surface; $seenSurf[$s]=$true
  $ex=[string]$n.example; if($ex.Length -gt 130){ $ex=$ex.Substring(0,130)+'...' }
  $lessonRows+="<tr><td><strong>$(EncHtml $s)</strong></td><td>$(EncHtml $ex)</td><td>Recurs but severity has never exceeded <strong>$([string]$n.maxSev)</strong> &mdash; pattern is stable / expected.</td><td>$(EncHtml (ConfirmText $s))</td><td>Once a human confirms benign, add the identifier to the <code>$(EncHtml $s)</code> hunt allow-list/suppression &mdash; it drops from the next run.</td></tr>"
}
foreach($kv in ($surfStats.GetEnumerator() | Where-Object { $_.Value.high -eq 0 -and $_.Value.noise -ge 4 } | Sort-Object { $_.Value.noise } -Descending)){
  $s=$kv.Key; if($seenSurf.ContainsKey($s)){ continue }; $seenSurf[$s]=$true
  $ex=[string]$kv.Value.ex; if($ex.Length -gt 130){ $ex=$ex.Substring(0,130)+'...' }
  $lessonRows+="<tr><td><strong>$(EncHtml $s)</strong></td><td>$(EncHtml $ex)</td><td>$($kv.Value.noise) low/review/clean findings this run, 0 HIGH &mdash; high-volume, low-signal log source.</td><td>$(EncHtml (ConfirmText $s))</td><td>After human baseline, tune the <code>$(EncHtml $s)</code> query to exclude the confirmed-benign set so the next hunt is quieter.</td></tr>"
}
# always-on note row for the known allow-list strings
$lessonRows+="<tr><td><strong>linux (jndi / ceurufrd)</strong></td><td>jndi SSH invalid-user probes; ceurufrd recurring string</td><td>Pre-approved known-activity strings &mdash; auto-suppressed by the skill hunts but NOT in this MCP-only run.</td><td>Already human-vetted as benign in the skill allow-list; no re-confirmation needed.</td><td>Apply the same two suppressions to the no-skill linux queries to match the skill baseline.</td></tr>"
$noiseHtml="<table><tr><th>Noisy log (surface)</th><th>Recurring noise pattern</th><th>Why it looks like noise</th><th>How to confirm genuineness (human intervention)</th><th>Reduce in next hunt</th></tr>$lessonRows</table>"

# ====================== (3) Appendix - Full Reports (ORIGINAL, unchanged) ======================
$appendix=''
foreach($k in ($reportTexts.Keys | Sort-Object)){
  $clean = $reportTexts[$k] -replace '(?ms)```findings-json\s*[\r\n]+.*?[\r\n]+```',''
  $appendix += "<h3>$k</h3><pre>$(EncHtml $clean)</pre>"
}

$html=@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOC Report PREVIEW (original-based)</title>
<style>
@page { margin: 30mm 16mm 16mm 16mm; }
body { font-family:'Segoe UI',Calibri,Arial,sans-serif; font-size:11pt; color:#222; padding-top:10px; }
.pagehdr { position:fixed; top:0; left:0; right:0; height:30px; display:flex; align-items:center; justify-content:space-between; padding:4pt 0; border-bottom:2px solid #111; background:#fff; }
.pagehdr img { height:22px; } .pagehdr .pht { color:#111; font-weight:600; font-size:10.5pt; }
h1 { color:#1a3a5c; font-size:22pt; margin-bottom:4pt; }
h2 { color:#1a3a5c; border-bottom:2px solid #1a3a5c; padding-bottom:3pt; margin-top:18pt; }
h3 { color:#2c5282; margin-top:10pt; }
.meta { color:#555; font-size:10pt; }
table { border-collapse:collapse; width:100%; margin:6pt 0; font-size:9.5pt; }
th { background:#1a3a5c; color:#fff; padding:5pt; text-align:left; }
td { border:1px solid #ccc; padding:4pt; vertical-align:top; }
tr.sev-CRITICAL td { background:#fcd6d6; } tr.sev-HIGH td { background:#fee; } tr.sev-MEDIUM td { background:#fff4d4; }
tr.sev-REVIEW td { background:#fffbe6; } tr.sev-LOW td { background:#f0f9ff; } tr.sev-CLEAN td { background:#e8f5e9; }
.detail { border-left:4px solid #1a3a5c; background:#f7f9fc; padding:8pt 12pt; margin:8pt 0; }
.detail.sev-CRITICAL { border-left-color:#7a0000; } .detail.sev-HIGH { border-left-color:#c00; } .detail.sev-MEDIUM { border-left-color:#c87000; }
.detail p { margin:3pt 0; }
pre { background:#f4f4f4; padding:8pt; white-space:pre-wrap; font-family:Consolas,monospace; font-size:9pt; border-left:3px solid #1a3a5c; }
.counts { display:inline-block; padding:4pt 8pt; margin-right:6pt; border-radius:3pt; font-weight:bold; color:#fff; }
.counts.CRITICAL{background:#7a0000}.counts.HIGH{background:#c00}.counts.MEDIUM{background:#c87000}.counts.REVIEW{background:#c8a800}.counts.LOW{background:#5080a0}.counts.CLEAN{background:#2e7d32}
.fresh-ok { display:inline-block; padding:2pt 6pt; margin:2pt; border-radius:3pt; font-size:8.5pt; background:#e8f5e9; color:#1b5e20; border:1px solid #2e7d32; }
.fresh-bad { display:inline-block; padding:2pt 6pt; margin:2pt; border-radius:3pt; font-size:8.5pt; background:#fde7e7; color:#a00; border:1px solid #c00; font-weight:bold; }
.freshwarn { background:#fde7e7; border:2px solid #c00; color:#a00; padding:8pt 12pt; margin:8pt 0; font-weight:bold; border-radius:3pt; }
.hdr { border-bottom:3px solid #1a3a5c; padding-bottom:8pt; margin-top:14pt; margin-bottom:8pt; }
.logo { height:46pt; }
.badge { display:inline-block; padding:1pt 6pt; border-radius:3pt; color:#fff; font-size:8pt; font-weight:bold; }
.badge.CRITICAL{background:#7a0000}.badge.HIGH{background:#c00}.badge.MEDIUM{background:#c87000}.badge.REVIEW{background:#c8a800}.badge.LOW{background:#5080a0}.badge.CLEAN{background:#2e7d32}
code { background:#eef2f7; padding:1pt 4pt; border-radius:2pt; font-family:Consolas,monospace; font-size:8.5pt; word-break:break-all; }
.corr { margin-top:8pt; border:1.5px solid #1a3a5c; border-radius:4pt; background:#eef4fb; padding:8pt 10pt; }
.corr.nocorr { border-color:#9bbf9b; background:#eef7ee; }
.corrhd { font-weight:bold; color:#1a3a5c; margin-bottom:4pt; } .nocorrhd{ color:#2e7d32; }
.corrtitle { font-style:italic; color:#333; margin:2pt 0; } .corr ul { margin:3pt 0 3pt 18pt; } .corr li{ margin:1pt 0; }
table.kc { font-size:8.5pt; } table.kc th { background:#2c5282; }
.note { background:#fff8e1; border:1px dashed #c8a800; padding:6pt 10pt; font-size:9.5pt; border-radius:3pt; }
h2.pb { page-break-before: always; padding-top: 12mm; margin-top: 0; }
</style></head><body>
<div class="pagehdr">$logoTag<span class="pht">Security Assessment Report (No-Skill / MCP-only)</span></div>
<div class="hdr"><h1>Security Assessment Report</h1><p class="meta">No-Skill variant - hunts run directly via Graylog MCP, no SOC hunt skills loaded.</p></div>
<p class="meta">Date: $dateStr | Host: $env:COMPUTERNAME | Generated: $($now.ToString('u'))</p>
<p class="note"><strong>PREVIEW (based on the original report).</strong> Changes vs production: (1) Findings = environment-grouped only (duplicate flat table removed); (2) Detail now shows the cross-module / cross-environment <em>kill chain</em> for HIGH/Critical; (3) Appendix kept as original full reports; (4) Lessons Learned now lists noisy logs + how to confirm genuineness with human intervention. No finding dropped.</p>
$freshBanner
<h2>Data Freshness (cross-check)</h2>
<p class="meta">Run start: $($runStart.ToString('u'))</p>
<p>$freshSpans</p>
<h2>Executive Summary</h2>
<p>
<span class="counts CRITICAL">CRITICAL: $($cnts.CRITICAL)</span>
<span class="counts HIGH">HIGH: $($cnts.HIGH)</span>
<span class="counts MEDIUM">MEDIUM: $($cnts.MEDIUM)</span>
<span class="counts REVIEW">REVIEW: $($cnts.REVIEW)</span>
<span class="counts LOW">LOW: $($cnts.LOW)</span>
<span class="counts CLEAN">CLEAN: $($cnts.CLEAN)</span>
</p>
<h2>Priority Findings - HIGH / Critical (at a glance)</h2>
<p class="meta">Every HIGH/Critical finding pulled to the top, with its severity badge, environment, module and required action. Full detail (with kill chains) is in the Detail section; all findings remain in Findings by Environment below.</p>
$priHtml
<h2>Findings by Environment</h2>
$envHtml
<h2 class="pb">Detail - HIGH / MEDIUM (with cross-correlation kill chain for HIGH / Critical)</h2>
$detailHtml
<h2 class="pb">Lessons Learned - Noisy Logs &amp; Genuineness Confirmation</h2>
<p class="meta">Which log sources generate the recurring noise, why each looks benign, and the specific human-intervention check that confirms genuineness before it is suppressed in the next hunt. The report never auto-excludes &mdash; a human confirms first.</p>
$noiseHtml
<h2 class="pb">Appendix - Full Reports</h2>
$appendix
</body></html>
"@
[System.IO.File]::WriteAllText($htmlPath,$html,(New-Object System.Text.UTF8Encoding($false)))

$edge=$null
foreach($p in @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")){ if(Test-Path $p){ $edge=$p; break } }
if(-not $edge){ Write-Output 'ERROR: msedge.exe not found'; exit 1 }
$urlPath='file:///'+($htmlPath -replace '\\','/')
$tmpPdf="$env:TEMP\soc-preview-orig-render.pdf"
if(Test-Path $tmpPdf){ Remove-Item $tmpPdf -Force -ErrorAction SilentlyContinue }
& $edge --headless=new --disable-gpu --user-data-dir="$env:TEMP\edge-soc-preview-orig" --no-pdf-header-footer --print-to-pdf="$tmpPdf" $urlPath 2>$null
for($w=0;$w -lt 40;$w++){ Start-Sleep -Seconds 1; if(Test-Path $tmpPdf){ $a=(Get-Item $tmpPdf).Length; Start-Sleep -Seconds 1; $b=(Get-Item $tmpPdf).Length; if($a -gt 0 -and $a -eq $b){ break } } }
if(Test-Path $tmpPdf){ Copy-Item $tmpPdf $pdfPath -Force; Write-Output "PREVIEW PDF: $pdfPath ($([math]::Round((Get-Item $pdfPath).Length/1kb)) KB)" } else { Write-Output "Render failed; HTML at $htmlPath" }
"HIGH/Critical kill-chain links: " + (($sorted | Where-Object { [string]$_.sev -in 'HIGH','CRITICAL' } | ForEach-Object { $kc=LinkKC $_; "$($_.env)/$($_.surface)->" + $(if($kc){$kc.id}else{'standalone'}) }) -join ' | ')
