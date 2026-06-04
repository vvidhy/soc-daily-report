# STANDALONE PREVIEW generator (v2) — reads the last 2 AM run's data READ-ONLY,
# renders a mockup PDF in D:\Vidhya\report-preview. Touches NO production file.
$ErrorActionPreference='Continue'
$src='C:\Users\VidhyaV\soc-monitor\reports-noskill'
$proj='C:\Users\VidhyaV\soc-monitor'
$out='D:\Vidhya\report-preview'
$htmlPath="$out\PREVIEW-exec-grouped-correlation.html"
$pdfPath ="$out\PREVIEW-exec-grouped-correlation.pdf"

$logoTag=''
$logoPath="$proj\assets\casepoint-logo.png"
if(Test-Path $logoPath){ $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($logoPath)); $logoTag="<img class=`"logo`" src=`"data:image/png;base64,$b64`" />" }

function EncHtml([string]$s){ if(-not $s){ return '' }; ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }

# ---------------- findings ----------------
$arr = Get-Content "$src\_merged-findings.json" -Raw | ConvertFrom-Json
$cnts=@{HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}
foreach($r in $arr){ $s=[string]$r.sev; if($cnts.ContainsKey($s)){ $cnts[$s]++ } }
$ord=@{HIGH=1;MEDIUM=2;REVIEW=3;LOW=4;CLEAN=5}
$sorted=$arr | Sort-Object @{Expression={ $s=[string]$_.sev; if($ord.ContainsKey($s)){ $ord[$s] } else { 99 } }}, env, surface

# ---------------- parse kill chains (deep) ----------------
$corr = Get-Content "$src\correlation-latest.md" -Raw
$blocks = [regex]::Split($corr,'(?m)^### ') | Where-Object { $_ -match '^KC-' }
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
  # ordered kill-chain table
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
  # contributing findings by surface -> list items
  $contrib=@()
  $cM=[regex]::Match($b,'(?ms)\*\*Contributing findings.+?\*\*\s*(.+?)(?:\r?\n\r?\n|\*\*Why|\*\*Parallel|\*\*Confidence)')
  if($cM.Success){ foreach($ln in ($cM.Groups[1].Value -split "`n")){ if($ln.Trim() -match '^- '){ $contrib += ($ln.Trim() -replace '^- ','' -replace '[`]','') } } }
  $KCs += [pscustomobject]@{ id=$id;sev=$sev;envs=$envs;surf=$surf;title=$title;entity=$entity;why=$why;conf=$conf;action=$action;parallel=$parallel;parLbl=$parLbl;chain=$chainHtml;contrib=$contrib;raw=$b }
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
# DEEP correlation block for a HIGH/critical finding
function DeepCorr($r){
  $kc=LinkKC $r
  if(-not $kc){ return "<div class=`"corr nocorr`"><div class=`"corrhd nocorrhd`">No cross-module / cross-environment kill chain matched this HIGH this run &mdash; standalone. Investigate via the per-finding query above.</div></div>" }
  $contribHtml=''
  if($kc.contrib.Count -gt 0){ $contribHtml="<p><strong>Contributing findings (cross-module):</strong></p><ul>"; foreach($c in $kc.contrib){ $contribHtml+="<li>$(EncHtml $c)</li>" }; $contribHtml+="</ul>" }
  $parHtml=if($kc.parallel){ "<p><strong>$(EncHtml $kc.parLbl) (cross-environment):</strong> $(EncHtml $kc.parallel)</p>" }else{''}
  return "<div class=`"corr`"><div class=`"corrhd`">&#128279; Kill chain <strong>$($kc.id)</strong> <span class=`"badge $($kc.sev)`">$($kc.sev)</span> &nbsp;[$(EncHtml $kc.envs) / $(EncHtml $kc.surf)]</div>" +
         "<p class=`"corrtitle`">$(EncHtml $kc.title)</p>" +
         "<p><strong>Shared entity:</strong> $(EncHtml $kc.entity)</p>" +
         "<p><strong>Reconstructed kill chain (ordered):</strong></p>$($kc.chain)" +
         $contribHtml + $parHtml +
         $(if($kc.why){"<p><strong>Why this is $($kc.sev):</strong> $(EncHtml $kc.why)</p>"}) +
         $(if($kc.conf){"<p><strong>Confidence:</strong> $(EncHtml $kc.conf)</p>"}) +
         $(if($kc.action){"<p><strong>Correlated action:</strong> $(EncHtml $kc.action)</p>"}) +
         "</div>"
}

# ---------------- 1) executive summary ----------------
$execHtml="<p>"; foreach($k in 'HIGH','MEDIUM','REVIEW','LOW','CLEAN'){ $execHtml+="<span class=`"counts $k`">$k`: $($cnts[$k])</span> " }; $execHtml+="</p>"

# ---------------- 2) findings table grouped ENV -> MODULE -> SEVERITY ----------------
$envOrder='DEV-GL','PROD-GL','AZ-GL','OP-GL'
$sevOrder=@{HIGH=1;MEDIUM=2;REVIEW=3;LOW=4;CLEAN=5}
$findHtml=''
foreach($e in $envOrder){
  $ef=$sorted | Where-Object { [string]$_.env -eq $e }
  if(-not $ef){ continue }
  $ec=@{HIGH=0;MEDIUM=0;REVIEW=0;LOW=0;CLEAN=0}; foreach($r in $ef){ $s=[string]$r.sev; if($ec.ContainsKey($s)){$ec[$s]++} }
  $findHtml+="<h3>$e &mdash; $($ef.Count) findings</h3><p>"
  foreach($k in 'HIGH','MEDIUM','REVIEW','LOW','CLEAN'){ $findHtml+="<span class=`"counts $k`" style=`"font-size:8.5pt;padding:2pt 6pt;margin-right:4pt`">$k $($ec[$k])</span> " }
  $findHtml+="</p>"
  $surfaces=$ef | Select-Object -ExpandProperty surface | Sort-Object -Unique
  foreach($sf in $surfaces){
    $sff=@($ef | Where-Object { [string]$_.surface -eq $sf } | Sort-Object @{Expression={ $s=[string]$_.sev; if($sevOrder.ContainsKey($s)){$sevOrder[$s]}else{99} }})
    $findHtml+="<h4>$e &rarr; $sf ($($sff.Count))</h4>"
    $findHtml+="<table><tr><th>Sev</th><th>Finding</th><th>Evidence</th><th>MITRE</th><th>Action</th></tr>"
    foreach($r in $sff){ $sev=[string]$r.sev; $findHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span></td><td>$(EncHtml ([string]$r.finding))</td><td>$(EncHtml ([string]$r.evidence))</td><td>$(EncHtml ([string]$r.mitre))</td><td>$(EncHtml ([string]$r.action))</td></tr>" }
    $findHtml+="</table>"
  }
}

# ---------------- 3) details: HIGH deep corr, then MEDIUM/REVIEW/LOW compact ----------------
$detailHtml=''
$detailHtml+="<h3>HIGH / Critical &mdash; full detail with kill-chain correlation</h3>"
$highs=$sorted | Where-Object { [string]$_.sev -in 'HIGH','CRITICAL' }
if(-not $highs){ $detailHtml+="<p class=`"meta`">No HIGH/Critical findings this run.</p>" }
foreach($r in $highs){
  $qUsed=if($r.query){ "<p><strong>Graylog query used:</strong> <code>$(EncHtml ([string]$r.query))</code></p>" }else{''}
  $qInv =if($r.investigate){ "<p><strong>Investigate further:</strong> <code>$(EncHtml ([string]$r.investigate))</code></p>" }else{''}
  $detailHtml+="<div class=`"detail sev-$([string]$r.sev)`"><h4>$([string]$r.sev) &mdash; $([string]$r.env) / $([string]$r.surface)</h4>" +
    "<p><strong>Finding:</strong> $(EncHtml ([string]$r.finding))</p>" +
    "<p><strong>Evidence:</strong> $(EncHtml ([string]$r.evidence))</p>" +
    "<p><strong>MITRE:</strong> $(EncHtml ([string]$r.mitre))</p>$qUsed$qInv" +
    "<p><strong>Action needed:</strong> $(EncHtml ([string]$r.action))</p>" +
    (DeepCorr $r) + "</div>"
}
# compact tiers (no correlation)
foreach($band in 'MEDIUM','REVIEW','LOW'){
  $bf=$sorted | Where-Object { [string]$_.sev -eq $band }
  if(-not $bf){ continue }
  $detailHtml+="<h3><span class=`"badge $band`">$band</span> &mdash; detail ($($cnts[$band])) <span class=`"meta`">(no kill-chain correlation &mdash; correlation is reserved for HIGH/Critical)</span></h3>"
  foreach($r in $bf){
    $qInv=if($r.investigate){ " &nbsp;<code>$(EncHtml ([string]$r.investigate))</code>" }elseif($r.query){ " &nbsp;<code>$(EncHtml ([string]$r.query))</code>" }else{''}
    $detailHtml+="<div class=`"cdetail sev-$band`"><strong>$([string]$r.env) / $([string]$r.surface):</strong> $(EncHtml ([string]$r.finding)) <span class=`"meta`">[$(EncHtml ([string]$r.mitre))]</span><br><em>Evidence:</em> $(EncHtml ([string]$r.evidence)) <br><em>Action:</em> $(EncHtml ([string]$r.action))$qInv</div>"
  }
}

# ---------------- 4) lessons learned: noise + how to reduce (concise bullets) ----------------
$histPath="$proj\logs-noskill\noise-history.json"
$noiseItems=@()
if(Test-Path $histPath){ try { $h=Get-Content $histPath -Raw | ConvertFrom-Json; $noiseItems=@($h) } catch {} }
# benign-noise candidates = recurring/this-run items whose max severity never exceeded REVIEW
$benign=$noiseItems | Where-Object { [string]$_.maxSev -in 'REVIEW','LOW','CLEAN' }
# also derive noisy surfaces straight from this run (surfaces with many LOW/REVIEW/CLEAN, no HIGH)
$surfStats=@{}
foreach($r in $arr){ $s=[string]$r.surface; if(-not $surfStats.ContainsKey($s)){ $surfStats[$s]=@{n=0;noise=0;high=0} }; $surfStats[$s].n++; if([string]$r.sev -in 'LOW','REVIEW','CLEAN'){$surfStats[$s].noise++}; if([string]$r.sev -in 'HIGH','CRITICAL'){$surfStats[$s].high++} }
$noisySurf=$surfStats.GetEnumerator() | Where-Object { $_.Value.high -eq 0 -and $_.Value.noise -ge 4 } | Sort-Object { $_.Value.noise } -Descending | Select-Object -First 4
$lessons=@()
foreach($n in ($benign | Select-Object -First 4)){
  $lessons += "<li><strong>$(EncHtml ([string]$n.surface)) noise</strong> &mdash; recurring pattern: <em>$(EncHtml (([string]$n.example).Substring(0,[Math]::Min(110,([string]$n.example).Length))))</em>. <strong>Reduce next hunt:</strong> human-verify the source once; if benign, add to the <code>$(EncHtml ([string]$n.surface))</code> allow-list/suppression so it drops from the next run. (max sev seen: $([string]$n.maxSev))</li>"
}
foreach($s in $noisySurf){
  if($benign | Where-Object { [string]$_.surface -eq $s.Key }){ continue }
  $lessons += "<li><strong>$(EncHtml ([string]$s.Key)) volume</strong> &mdash; $($s.Value.noise) low/review/clean findings, 0 HIGH. <strong>Reduce next hunt:</strong> baseline the expected sources with the SOC owner; tune the $(EncHtml ([string]$s.Key)) query to exclude the confirmed-benign set.</li>"
}
$lessons += "<li><strong>Known allow-list strings</strong> (<code>jndi</code>, <code>ceurufrd</code>) are auto-suppressed by the skill hunts but NOT in this MCP-only run &mdash; <strong>reduce:</strong> apply the same two suppressions to the no-skill linux queries.</li>"
$lessonsHtml="<ul class=`"lessons`">" + ($lessons -join '') + "</ul>"

# ---------------- 5) appendix = Investigation View for Analyst (env -> module -> severity, BULLETS) ----------------
$invHtml=''
foreach($e in $envOrder){
  $ef=$sorted | Where-Object { [string]$_.env -eq $e }
  if(-not $ef){ continue }
  $invHtml+="<h3>$e &mdash; $($ef.Count) findings</h3>"
  $surfaces=$ef | Select-Object -ExpandProperty surface | Sort-Object -Unique
  foreach($sf in $surfaces){
    $sff=@($ef | Where-Object { [string]$_.surface -eq $sf } | Sort-Object @{Expression={ $s=[string]$_.sev; if($sevOrder.ContainsKey($s)){$sevOrder[$s]}else{99} }})
    $invHtml+="<h4>$e &rarr; $sf ($($sff.Count))</h4><ul class=`"inv`">"
    foreach($r in $sff){
      $sev=[string]$r.sev; $piv=if($r.investigate){[string]$r.investigate}elseif($r.query){[string]$r.query}else{''}
      $invHtml+="<li><span class=`"badge $sev`">$sev</span> <strong>$(EncHtml ([string]$r.finding))</strong><ul>" +
                "<li><em>Evidence:</em> $(EncHtml ([string]$r.evidence))</li>" +
                "<li><em>MITRE:</em> $(EncHtml ([string]$r.mitre))</li>" +
                "<li><em>Action:</em> $(EncHtml ([string]$r.action))</li>" +
                $(if($piv){"<li><em>Pivot query:</em> <code>$(EncHtml $piv)</code></li>"}) +
                "</ul></li>"
    }
    $invHtml+="</ul>"
  }
}

$now=Get-Date; $dateStr=$now.ToString('yyyy-MM-dd')
$html=@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOC Report PREVIEW</title>
<style>
@page { margin: 30mm 16mm 16mm 16mm; }
body { font-family:'Segoe UI',Calibri,Arial,sans-serif; font-size:11pt; color:#222; padding-top:10px; }
.pagehdr { position:fixed; top:0; left:0; right:0; height:30px; display:flex; align-items:center; justify-content:space-between; padding:4pt 0; border-bottom:2px solid #111; background:#fff; }
.pagehdr img { height:22px; } .pagehdr .pht { color:#111; font-weight:600; font-size:10.5pt; }
h1 { color:#1a3a5c; font-size:22pt; margin-bottom:4pt; }
h2 { color:#1a3a5c; border-bottom:2px solid #1a3a5c; padding-bottom:3pt; margin-top:18pt; }
h3 { color:#2c5282; margin-top:12pt; } h4 { color:#34506b; margin:8pt 0 2pt; }
.meta { color:#555; font-size:9.5pt; }
table { border-collapse:collapse; width:100%; margin:6pt 0; font-size:9.5pt; }
th { background:#1a3a5c; color:#fff; padding:5pt; text-align:left; }
td { border:1px solid #ccc; padding:4pt; vertical-align:top; }
tr.sev-HIGH td { background:#fee; } tr.sev-MEDIUM td { background:#fff4d4; }
tr.sev-REVIEW td { background:#fffbe6; } tr.sev-LOW td { background:#f0f9ff; } tr.sev-CLEAN td { background:#e8f5e9; }
.detail { border-left:4px solid #c00; background:#f7f9fc; padding:8pt 12pt; margin:12pt 0; }
.detail h4 { margin-top:0; color:#c00; }
.detail.sev-MEDIUM { border-left-color:#c87000; } .detail.sev-MEDIUM h4 { color:#c87000; }
.cdetail { border-left:3px solid #c8a800; background:#fffdf5; padding:5pt 9pt; margin:5pt 0; font-size:9.5pt; }
.cdetail.sev-MEDIUM { border-left-color:#c87000; } .cdetail.sev-LOW { border-left-color:#5080a0; background:#f7fbff; }
.counts { display:inline-block; padding:4pt 8pt; margin-right:6pt; border-radius:3pt; font-weight:bold; color:#fff; }
.counts.HIGH{background:#c00}.counts.MEDIUM{background:#c87000}.counts.REVIEW{background:#c8a800}.counts.LOW{background:#5080a0}.counts.CLEAN{background:#2e7d32}
.badge { display:inline-block; padding:1pt 6pt; border-radius:3pt; color:#fff; font-size:8pt; font-weight:bold; }
.badge.HIGH{background:#c00}.badge.MEDIUM{background:#c87000}.badge.REVIEW{background:#c8a800}.badge.LOW{background:#5080a0}.badge.CLEAN{background:#2e7d32}
code { background:#eef2f7; padding:1pt 4pt; border-radius:2pt; font-family:Consolas,monospace; font-size:8.5pt; word-break:break-all; }
.corr { margin-top:8pt; border:1.5px solid #1a3a5c; border-radius:4pt; background:#eef4fb; padding:8pt 10pt; }
.corr.nocorr { border-color:#9bbf9b; background:#eef7ee; }
.corrhd { font-weight:bold; color:#1a3a5c; margin-bottom:4pt; } .nocorrhd{ color:#2e7d32; }
.corrtitle { font-style:italic; color:#333; margin:2pt 0; }
.corr ul { margin:3pt 0 3pt 18pt; } .corr li { margin:1pt 0; }
table.kc { font-size:8.5pt; } table.kc th { background:#2c5282; }
.lessons li { margin:4pt 0; } .lessons { margin:6pt 0 6pt 18pt; }
ul.inv { margin:4pt 0 8pt 18pt; } ul.inv > li { margin:5pt 0; }
ul.inv ul { margin:2pt 0 4pt 16pt; } ul.inv ul li { margin:1pt 0; font-size:9.5pt; color:#333; }
.logo { height:46pt; } .hdr { border-bottom:3px solid #1a3a5c; padding-bottom:8pt; margin:14pt 0 8pt; }
.note { background:#fff8e1; border:1px dashed #c8a800; padding:6pt 10pt; font-size:9.5pt; border-radius:3pt; }
.toc { font-size:10pt; color:#333; } .toc li{ margin:2pt 0; }
</style></head><body>
<div class="pagehdr">$logoTag<span class="pht">Security Assessment Report &mdash; LAYOUT PREVIEW</span></div>
<div class="hdr"><h1>Security Assessment Report</h1>
<p class="meta">PROPOSED LAYOUT PREVIEW &mdash; built from the $dateStr 02:00 run data. No production file changed.</p></div>
<p class="note"><strong>Layout:</strong> (1) Executive Summary &rarr; (2) Findings grouped Environment&rarr;Module&rarr;Severity &rarr; (3) Details: HIGH/Critical with <em>deep cross-module &amp; cross-environment kill chains</em>, then MEDIUM/REVIEW/LOW (no correlation) &rarr; (4) Lessons Learned: where the noise is &amp; how to cut it next hunt &rarr; (5) Appendix &ldquo;Investigation View for Analyst&rdquo;: every finding in bullet form, env&rarr;module&rarr;severity, with pivot queries. No finding dropped.</p>

<h2>1. Executive Summary</h2>
$execHtml

<h2>2. Findings (Environment &rarr; Module &rarr; Severity)</h2>
$findHtml

<h2>3. Detailed Findings &amp; Correlation</h2>
<p class="meta">Correlation (kill chains) is shown only for HIGH/Critical. Lower tiers carry full detail and a pivot query so an analyst can still investigate.</p>
$detailHtml

<h2>4. Lessons Learned &mdash; Noise &amp; Reduction</h2>
<p class="meta">Where recurring/benign log noise is, and the one human action that removes it from the next hunt. The report never auto-excludes &mdash; a human confirms first.</p>
$lessonsHtml

<h2>5. Appendix &mdash; Investigation View for Analyst</h2>
<p class="meta">Complete catalogue in bullet form, grouped Environment &rarr; Module &rarr; Severity. Every finding lists evidence, MITRE, action, and a pivot query &mdash; nothing is omitted; any analyst can open this and start a deep investigation.</p>
$invHtml
</body></html>
"@
[System.IO.File]::WriteAllText($htmlPath,$html,(New-Object System.Text.UTF8Encoding($false)))

$edge=$null
foreach($p in @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")){ if(Test-Path $p){ $edge=$p; break } }
if(-not $edge){ Write-Output 'ERROR: msedge.exe not found'; exit 1 }
$urlPath='file:///'+($htmlPath -replace '\\','/')
$tmpPdf="$env:TEMP\soc-preview-render.pdf"
if(Test-Path $tmpPdf){ Remove-Item $tmpPdf -Force -ErrorAction SilentlyContinue }
& $edge --headless=new --disable-gpu --user-data-dir="$env:TEMP\edge-soc-preview" --no-pdf-header-footer --print-to-pdf="$tmpPdf" $urlPath 2>$null
for($w=0;$w -lt 40;$w++){ Start-Sleep -Seconds 1; if(Test-Path $tmpPdf){ $a=(Get-Item $tmpPdf).Length; Start-Sleep -Seconds 1; $b=(Get-Item $tmpPdf).Length; if($a -gt 0 -and $a -eq $b){ break } } }
if(Test-Path $tmpPdf){ Copy-Item $tmpPdf $pdfPath -Force; Write-Output "PREVIEW PDF: $pdfPath ($([math]::Round((Get-Item $pdfPath).Length/1kb)) KB)" } else { Write-Output "Render failed; HTML at $htmlPath" }
"HIGH linked: " + (($highs | ForEach-Object { $kc=LinkKC $_; "$($_.env)/$($_.surface)->" + $(if($kc){$kc.id}else{'standalone'}) }) -join ' | ')
