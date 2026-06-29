$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$dir="$proj\reports-noskill"
$now=Get-Date
$dateStr=$now.ToString('yyyy-MM-dd')
$htmlPath="$dir\daily-SOC-noskill-$dateStr.html"
$pdfPath ="$dir\daily-SOC-noskill-$dateStr.pdf"

$flag="$proj\logs-noskill\run-start.flag"
$runStart=if(Test-Path $flag){ (Get-Item $flag).LastWriteTime } else { $now.Date }

$logoTag=''
$logoPath="$proj\assets\casepoint-logo.png"
if(Test-Path $logoPath){ $b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($logoPath)); $logoTag="<img class=`"logo`" src=`"data:image/png;base64,$b64`" />" }

$edge=$null
foreach($p in @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")){ if(Test-Path $p){ $edge=$p; break } }
if(-not $edge){ Write-Output 'ERROR: msedge.exe not found, cannot render PDF'; exit 1 }

# --- Single consolidated report file (one daily prompt writes daily-latest.md) ---
$reportFile="$dir\daily-latest.md"
$findings=@(); $rawReport=''
if(Test-Path $reportFile){
  $rawReport=(Get-Content $reportFile -Raw) -replace '[^\x20-\x7E\r\n]', ''
  $m=[regex]::Match($rawReport,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){ try { $arr=$m.Groups[1].Value | ConvertFrom-Json; foreach($x in $arr){ if(($x.PSObject.Properties.Name -contains 'value') -and ($x.PSObject.Properties.Name -notcontains 'sev')){ foreach($sub in @($x.value)){ if($null -ne $sub){ $findings += $sub } } } else { $findings += $x } } } catch {} }
}
# Drop CLEAN / clear findings - a clear surface does not belong in the report.
$findings=@($findings | Where-Object { [string]$_.sev -ne 'CLEAN' })

# Freshness: the single daily report must be fresh this run + carry a findings block.
$fresh = (Test-Path $reportFile) -and ((Get-Item $reportFile).LastWriteTime -ge $runStart) -and ($rawReport -match 'findings-json')
$freshBanner = if(-not $fresh){ "<div class=`"freshwarn`">DATA FRESHNESS WARNING - daily-latest.md was not (re)written this run or has no findings block; this report may be stale or empty. Investigate before relying on it.</div>" } else { '' }
if($fresh){ Write-Output "REPORT FRESHNESS (noskill): daily-latest.md fresh; $($findings.Count) non-clean finding(s)." } else { Write-Output "REPORT FRESHNESS WARNING (noskill): daily-latest.md stale/missing/no-json." }

function EncHtml([string]$s){ if(-not $s){ return '' }; ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }
function SurfLabel([string]$s){ if($s -eq 'edr'){ return 'ESET' }; return $s }

# T-code -> short technique name (covers common SOC hunt + depth-module techniques)
$ttpNames = @{
  'T1190'='Exploit Public-Facing App'
  'T1595'='Active Scanning'; 'T1595.002'='Vulnerability Scanning'; 'T1595.003'='Wordlist Scanning'
  'T1021'='Remote Services'; 'T1021.001'='RDP'; 'T1021.002'='SMB/Admin Shares'; 'T1021.006'='WinRM'
  'T1570'='Lateral Tool Transfer'; 'T1550'='Alt Auth Material'; 'T1550.001'='App Access Token'
  'T1505'='Server Software Component'; 'T1505.003'='Web Shell'
  'T1059'='Command Interpreter'; 'T1059.001'='PowerShell'; 'T1059.003'='Windows CMD'
  'T1078'='Valid Accounts'; 'T1078.001'='Default Accounts'; 'T1078.004'='Cloud Accounts'
  'T1110'='Brute Force'; 'T1110.001'='Password Guessing'; 'T1110.003'='Password Spraying'; 'T1110.004'='Credential Stuffing'
  'T1566'='Phishing'; 'T1566.001'='Spearphishing Attachment'; 'T1566.002'='Spearphishing Link'
  'T1071'='App Layer Protocol'; 'T1071.001'='Web Protocols'; 'T1071.004'='DNS'
  'T1048'='Exfil Over Alt Protocol'; 'T1041'='Exfil Over C2 Channel'
  'T1003'='Credential Dumping'; 'T1003.001'='LSASS Memory'; 'T1003.003'='NTDS'
  'T1055'='Process Injection'; 'T1055.012'='Process Hollowing'
  'T1547'='Boot/Logon Autostart'; 'T1547.001'='Registry Run Keys'
  'T1053'='Scheduled Task/Job'; 'T1053.005'='Scheduled Task'
  'T1543'='Create/Modify System Process'; 'T1543.003'='Windows Service'
  'T1098'='Account Manipulation'; 'T1098.001'='Additional Cloud Credentials'
  'T1087'='Account Discovery'; 'T1087.001'='Local Account'; 'T1087.002'='Domain Account'
  'T1046'='Network Service Discovery'; 'T1082'='System Info Discovery'; 'T1083'='File/Dir Discovery'
  'T1562'='Impair Defenses'; 'T1562.001'='Disable Security Tools'
  'T1070'='Indicator Removal'; 'T1070.001'='Clear Event Logs'; 'T1070.006'='Timestomp'
  'T1074'='Data Staged'; 'T1005'='Local Data Collection'; 'T1039'='Network Share Data'
  'T1560'='Archive Collected Data'; 'T1114'='Email Collection'
  'T1528'='Steal App Access Token'; 'T1539'='Steal Web Session Cookie'
  'T1133'='External Remote Services'; 'T1572'='Protocol Tunneling'
  'T1027'='Obfuscated Files'; 'T1040'='Network Sniffing'
  'T1486'='Data Encrypted for Impact'; 'T1490'='Inhibit System Recovery'
  'T1069'='Permission Groups Discovery'; 'T1016'='Network Config Discovery'
  'T1136'='Create Account'; 'T1136.001'='Local Account Create'; 'T1136.003'='Cloud Account Create'
  'T1531'='Account Access Removal'; 'T1489'='Service Stop'
}

# Build TTP display string.
# short=$true  -> summary table: "Initial Access › T1190"  (tactic name only, first T-code)
# short=$false -> detail card:   "TA0001 Initial Access › T1190 Exploit Public-Facing App  [+N more]"
function TtpLabel([string]$tactic, [string]$mitre, [bool]$short=$false) {
  $codes = @($mitre -split '[,/;\s]+' | Where-Object { $_ -match '^T\d' } | ForEach-Object { $_.Trim() })
  $firstCode = if ($codes.Count -gt 0) { $codes[0] } else { '' }
  $name = if ($firstCode -and $ttpNames.ContainsKey($firstCode)) { $ttpNames[$firstCode] } else { '' }
  $tacName = $tactic -replace '^TA\d+\s+',''   # strip "TA0008 " prefix
  if ($short) {
    if ($firstCode) { return "$tacName &rsaquo; $firstCode" } else { return $tacName }
  } else {
    $extra = if ($codes.Count -gt 1) { " <span style='font-size:7pt;color:#888'>[+$($codes.Count-1) more]</span>" } else { '' }
    $techStr = if ($name) { "$firstCode $name" } elseif ($firstCode) { $firstCode } else { '' }
    if ($techStr) { return "$tactic &rsaquo; $techStr$extra" } else { return $tactic }
  }
}

$cnts=@{CRITICAL=0;HIGH=0;MEDIUM=0;REVIEW=0;LOW=0}
foreach($r in $findings){ $s=[string]$r.sev; if($cnts.ContainsKey($s)){ $cnts[$s]++ } }
$ord=@{CRITICAL=0;HIGH=1;MEDIUM=2;REVIEW=3;LOW=4}
$sorted=@($findings | Sort-Object @{Expression={ $s=[string]$_.sev; if($ord.ContainsKey($s)){ $ord[$s] } else { 9 } }}, env, surface)

# Kill chain progression: which stages appear in CRITICAL/HIGH/MEDIUM findings?
$kcOrder=@('Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Actions')
$kcHit=@{}
foreach($r in ($sorted | Where-Object { [string]$_.sev -in 'CRITICAL','HIGH','MEDIUM' })){
  $kc=[string]$r.killchain; if($kc){ $kcHit[$kc]=$true }
}
$kcStageHtml=''
foreach($stage in $kcOrder){
  $cls=if($kcHit.ContainsKey($stage)){'kc-stage active'} else {'kc-stage'}
  $kcStageHtml+="<span class=`"$cls`">$stage</span>"
}
$kcProgressHtml=if($kcHit.Count -gt 0){
  "<div class=`"kc-chain`"><span class=`"kc-label`">Kill Chain (HIGH/MEDIUM):</span> $kcStageHtml</div>"
} else {
  "<div class=`"kc-chain empty`"><span class=`"kc-label`">Kill Chain:</span> <span class=`"kc-stage`">No HIGH/MEDIUM findings active.</span></div>"
}

# ---- Main summary table: Severity | Streams | Environment | MITRE | Graylog Query Used | Confidence Level | Action Required ----
$tableHtml=''
if($sorted.Count -gt 0){
  $tableHtml="<table class=`"main`"><tr><th>Severity</th><th>Streams</th><th>Environment</th><th>TTP</th><th>Graylog Query Used</th><th>Confidence Level</th><th>Action Required</th></tr>"
  foreach($r in $sorted){
    $sev=[string]$r.sev
    $verd=[string]$r.verdict; $conf=[string]$r.confidence
    $verdShort=switch -Wildcard ($verd){'T*'{'TP'} 'F*'{'FP'} default{'REVIEW'}}; $vcls=switch($verdShort){'TP'{'verdict-tp'} 'FP'{'verdict-fp'} default{'verdict-review'}}
    $verdHtml="<span class=`"verdict $vcls`" style=`"font-size:7pt;white-space:nowrap`">$verdShort</span>"
    $confN=0; try{ $confN=[int]$conf } catch{}
    if($confN -eq 0){ $confN=switch($sev){'CRITICAL'{4}'HIGH'{4}'MEDIUM'{3}'REVIEW'{2}'LOW'{2}default{2}} }
    $confPctN=if($confN -gt 5){[math]::Min($confN,100)}else{$confN*20}; $confPct="$confPctN%"
    $confColor=if($confPctN -ge 80){'color:#1a7a1a'} elseif($confPctN -ge 60){'color:#c87000'} else {'color:#c00'}
    $confHtml="<span style=`"font-size:9pt;font-weight:bold;$confColor`">$confPct</span>"
    $qry=[string]$r.query; $qryHtml=if($qry){"<code>$(EncHtml $qry)</code>"}else{"<span style=`"color:#999;font-size:7.5pt`">n/a (breadth)</span>"}
    $ttpShort = TtpLabel ([string]$r.tactic) ([string]$r.mitre) $true
    $tableHtml+="<tr class=`"sev-$sev`"><td><span class=`"badge $sev`">$sev</span><br/>$verdHtml</td><td><strong>$(EncHtml (SurfLabel ([string]$r.surface)))</strong></td><td><span class=`"env`">$(EncHtml ([string]$r.env))</span></td><td class=`"ttp-cell`">$ttpShort</td><td>$qryHtml</td><td>$confHtml</td><td>$(EncHtml ([string]$r.action))</td></tr>"
  }
  $tableHtml+="</table>"
} else { $tableHtml="<p class=`"meta`">No findings to report this run - all surfaces clear or covered.</p>" }

# ---- Triage detail cards (one per finding) ----
function ConfidenceDots([string]$score, [string]$fallbackSev=''){
  $n=0; try{ $n=[int]$score } catch{}
  if($n -lt 1){ $n=switch($fallbackSev){'CRITICAL'{4}'HIGH'{4}'MEDIUM'{3}'REVIEW'{2}'LOW'{2}default{0}} }
  if($n -gt 5){ $n=5 }
  $pct=$n*20
  $dots=''; for($i=1;$i -le 5;$i++){ $cls=if($i -le $n){'dot filled'} else {'dot'}; $dots+="<span class=`"$cls`"></span>" }
  return "<span class=`"conf-dots`">$dots</span> <span class=`"conf-num`">$pct%</span>"
}
function VerdictBadge([string]$v){
  $vn=switch -Wildcard ($v){ 'T*'{'TP'} 'F*'{'FP'} default{'REVIEW'} }
  $cls=switch($vn){ 'TP'{'verdict-tp'} 'FP'{'verdict-fp'} default{'verdict-review'} }
  $label=switch($vn){ 'TP'{'TRUE POSITIVE'} 'FP'{'FALSE POSITIVE'} default{'NEEDS REVIEW'} }
  return "<span class=`"verdict $cls`">$label</span>"
}

$detailHtml=''
foreach($r in $sorted){
  $sev=[string]$r.sev; $kc=[string]$r.killchain; $tactic=[string]$r.tactic
  $corr=[string]$r.correlation
  $verdictHtml=VerdictBadge ([string]$r.verdict)
  $confHtml=ConfidenceDots ([string]$r.confidence) ([string]$r.sev)
  # Recommended Actions: action text + the query that was run
  $rqry = [string]$r.query
  $qrySection = if ($rqry) { '<br/><span class="triage-sublabel">Graylog detection query (paste-ready):</span><br/><code>' + (EncHtml $rqry) + '</code>' } else { '<br/><span class="triage-sublabel" style="color:#bbb">Query not captured (breadth finding)</span>' }
  $actionsHtml = "<div class=`"triage-row`"><span class=`"triage-icon`">&#128269;</span><div>" +
    "<span class=`"triage-label`">Recommended Actions</span><br/>" +
    "$(EncHtml ([string]$r.action))" +
    $qrySection +
    "</div></div>"
  # Correlation: what was correlated + investigation query
  $corrLabel = if($corr -and $corr -ne 'standalone'){ EncHtml $corr } elseif($sev -in 'HIGH','CRITICAL'){'Standalone - no cross-surface or cross-environment link this run.'} else {''}
  $corrHtml = ''
  if($corrLabel -or $r.investigate){
    $corrHtml = "<div class=`"triage-row`"><span class=`"triage-icon`">&#128257;</span><div>" +
      "<span class=`"triage-label`">Correlation</span><br/>" +
      "$(if($corrLabel){ $corrLabel } else {'No correlation data this run.'})" +
      "$(if($r.investigate){ '<br/><span class="triage-sublabel">Correlation / pivot query (run next):</span><br/><code>' + (EncHtml ([string]$r.investigate)) + '</code>' } else {''})" +
      "</div></div>"
  }
  $detailHtml += "<div class=`"triage-card sev-$sev`">" +
    "<div class=`"triage-hdr`"><span class=`"badge $sev`">$sev</span> <strong>$(SurfLabel ([string]$r.surface))</strong> <span class=`"env`">@ $([string]$r.env)</span> <span class=`"triage-verdict`">$verdictHtml</span></div>" +
    "<p class=`"triage-finding`">$(EncHtml ([string]$r.finding))</p>" +
    "<div class=`"triage-row`"><span class=`"triage-icon`">&#10003;</span><div><span class=`"triage-label`">Verdict (TP / FP)</span><br/>$verdictHtml</div></div>" +
    "<div class=`"triage-row`"><span class=`"triage-icon`">&#9201;</span><div><span class=`"triage-label`">Confidence Score</span><br/>$confHtml</div></div>" +
    "<div class=`"triage-row`"><span class=`"triage-icon`">&#128736;</span><div><span class=`"triage-label`">TTP (Tactic &rsaquo; Technique &rsaquo; Procedure)</span><br/><strong>$(TtpLabel $tactic ([string]$r.mitre) $false)</strong><br/><span style=`"font-size:7.5pt;color:#555`">All T-codes: <code>$(EncHtml ([string]$r.mitre))</code></span></div></div>" +
    "<div class=`"triage-row`"><span class=`"triage-icon`">&#128279;</span><div><span class=`"triage-label`">Kill Chain Stage</span><br/>$(if($kc){'<span class="kc-badge">' + $kc + '</span>'} else {([char]0x2014)})</div></div>" +
    "<div class=`"triage-row`"><span class=`"triage-icon`">&#128196;</span><div><span class=`"triage-label`">Why $(if($sev -eq 'REVIEW'){'flagged for REVIEW'}elseif($sev -eq 'LOW'){'LOW'}else{"${sev} - severity rationale"}) &amp; how detected</span><br/>$(EncHtml ([string]$r.detail))<br/><span class=`"triage-sublabel`">Evidence (raw Graylog log lines):</span><br/><pre class=`"evidence-block`">$(EncHtml ([string]$r.evidence))</pre></div></div>" +
    $actionsHtml +
    $corrHtml + "</div>"
}
if($sorted.Count -eq 0){ $detailHtml="<p class=`"meta`">Nothing to detail - no findings this run.</p>" }

# ---- Manual Correlation Queries section (MEDIUM/LOW, 0-token) ----
$corrQueriesHtml = ''
$corrQueriesFile = "$dir\correlation-queries.json"
if (Test-Path $corrQueriesFile) {
    try {
        $cqRaw = Get-Content $corrQueriesFile -Raw
        $cqArr = @($cqRaw | ConvertFrom-Json)
        if ($cqArr.Count -gt 0) {
            $cqRows = ''
            foreach ($cq in $cqArr) {
                $labelHtml  = EncHtml ([string]$cq.label)
                $pivotHtml  = EncHtml ([string]$cq.pivot)
                $surfHtml   = EncHtml ([string]$cq.surface)
                $noteHtml   = EncHtml ([string]$cq.note)
                $qHtml      = EncHtml ([string]$cq.query)
                $sevBadge   = if ([string]$cq.sev -in @('MEDIUM','LOW','pivot','pattern')) {
                    $bg = switch ([string]$cq.sev) { 'MEDIUM'{'#c87000'} 'LOW'{'#5080a0'} default{'#2c5282'} }
                    "<span class=`"badge`" style=`"background:$bg`">$([string]$cq.sev.ToUpper())</span>"
                } else { '' }
                $cqRows += "<tr><td>$sevBadge $labelHtml</td><td>$pivotHtml</td><td><code>$surfHtml</code></td><td><code class=`"cq-query`">$qHtml</code></td><td class=`"cq-note`">$noteHtml</td></tr>"
            }
            $corrQueriesHtml = @"
<h2 class="pb">Manual Correlation Queries (Medium / Low)</h2>
<p class="meta">MEDIUM and LOW findings were not Opus-correlated. Use these paste-ready Graylog queries to pivot manually. Run with rangeSeconds=86400 across all 4 Graylogs unless the Surface column specifies otherwise.</p>
<table class="cq-table"><tr><th style="width:14%">Type</th><th style="width:22%">Pivot</th><th style="width:10%">Surface</th><th style="width:36%">Graylog Query (paste-ready)</th><th style="width:18%">Note</th></tr>$cqRows</table>
"@
        }
    } catch { Write-Output "WARN: could not parse correlation-queries.json: $_" }
}

$html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOC Daily Report</title>
<style>
@page { margin: 30mm 9mm 12mm 9mm; }
.pagehdr { position: fixed; top: 0; left: 0; right: 0; height: 30px; display: flex; align-items: center; justify-content: space-between; padding: 4pt 0; border-bottom: 2px solid #111; background: #fff; }
.pagehdr img { height: 22px; }
.pagehdr .pht { color: #111; font-weight: 600; font-size: 10.5pt; }
body { font-family: 'Segoe UI', Calibri, Arial, sans-serif; font-size: 11pt; color: #222; padding-top: 10px; }
h1 { color: #1a3a5c; font-size: 22pt; margin-bottom: 4pt; }
h2 { color: #1a3a5c; border-bottom: 2px solid #1a3a5c; padding-bottom: 3pt; margin-top: 16pt; }
h3 { color: #2c5282; margin: 8pt 0 2pt 0; font-size: 11pt; }
.meta { color: #555; font-size: 10pt; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0; font-size: 9.5pt; table-layout: fixed; }
th { background: #1a3a5c; color: white; padding: 7pt 8pt; text-align: left; }
td { border: 1px solid #ccc; padding: 7pt 8pt; line-height: 1.45; vertical-align: top; word-wrap: break-word; overflow-wrap: anywhere; }
table.main th:nth-child(1){width:11%} table.main th:nth-child(2){width:7%} table.main th:nth-child(3){width:8%} table.main th:nth-child(4){width:18%} table.main th:nth-child(5){width:25%} table.main th:nth-child(6){width:7%} table.main th:nth-child(7){width:24%}
.ttp-cell { font-size:8.5pt; line-height:1.4; color:#1a3a5c; }
tr.sev-CRITICAL td { background: #fcd6d6; } tr.sev-HIGH td { background: #fee; } tr.sev-MEDIUM td { background: #fff4d4; }
tr.sev-REVIEW td { background: #fffbe6; } tr.sev-LOW td { background: #f0f9ff; }
.detail { border-left: 4px solid #1a3a5c; background: #f7f9fc; padding: 6pt 12pt; margin: 8pt 0; }
.detail.sev-CRITICAL { border-left-color: #7a0000; } .detail.sev-HIGH { border-left-color: #c00; } .detail.sev-MEDIUM { border-left-color: #c87000; } .detail.sev-REVIEW { border-left-color: #c8a800; } .detail.sev-LOW { border-left-color: #5080a0; }
.detail p { margin: 3pt 0; }
.counts { display: inline-block; padding: 4pt 8pt; margin-right: 6pt; border-radius: 3pt; font-weight: bold; color: white; }
.counts.HIGH { background: #c00; } .counts.MEDIUM { background: #c87000; } .counts.REVIEW { background: #c8a800; } .counts.LOW { background: #5080a0; }
.freshwarn { background:#fde7e7; border:2px solid #c00; color:#a00; padding:8pt 12pt; margin:8pt 0; font-weight:bold; border-radius:3pt; }
.hdr { display:flex; flex-direction:column; align-items:flex-start; gap:6pt; border-bottom:3px solid #1a3a5c; padding-bottom:8pt; margin-top:14pt; margin-bottom:8pt; }
.logo { height:42pt; }
.badge { display:inline-block; padding:1pt 6pt; border-radius:3pt; color:#fff; font-size:8pt; font-weight:bold; white-space:nowrap; }
.badge.CRITICAL{background:#7a0000}.badge.HIGH{background:#c00}.badge.MEDIUM{background:#c87000}.badge.REVIEW{background:#c8a800}.badge.LOW{background:#5080a0}
.env { color:#555; font-weight:normal; font-size:8pt; }
code { background:#eef2f7; padding:1pt 4pt; border-radius:2pt; font-family:Consolas,monospace; font-size:8pt; word-break:break-all; }
h2.pb { page-break-before: always; padding-top: 12mm; margin-top: 0; }
.kc-chain { margin:6pt 0 4pt 0; }
.kc-label { font-size:9pt; font-weight:600; color:#444; margin-right:6pt; }
.kc-stage { display:inline-block; padding:2pt 7pt; border-radius:3pt; background:#e8e8e8; color:#888; font-size:8pt; margin:1pt 2pt; }
.kc-stage.active { background:#c00; color:#fff; font-weight:bold; }
.kc-badge { display:inline-block; padding:1pt 5pt; border-radius:2pt; background:#2c5282; color:#fff; font-size:7.5pt; font-weight:bold; margin-top:2pt; }
table.main th:nth-child(5){width:12%} table.main th:nth-child(6){width:22%}
.triage-card { border:1.5px solid #ccc; border-radius:5pt; padding:8pt 12pt; margin:8pt 0; background:#fafbfc; }
.triage-card.sev-CRITICAL { border-color:#7a0000; background:#fff5f5; }
.triage-card.sev-HIGH { border-color:#c00; background:#fff8f8; }
.triage-card.sev-MEDIUM { border-color:#c87000; background:#fffbf2; }
.triage-card.sev-REVIEW { border-color:#c8a800; background:#fffef0; }
.triage-card.sev-LOW { border-color:#5080a0; background:#f5f9ff; }
.triage-hdr { margin-bottom:5pt; display:flex; align-items:center; gap:6pt; flex-wrap:wrap; }
.triage-finding { font-size:10.5pt; font-weight:600; color:#1a1a1a; margin:4pt 0 6pt 0; }
.triage-row { display:flex; gap:8pt; align-items:flex-start; margin:3pt 0; font-size:9pt; }
.triage-icon { font-size:10pt; min-width:16pt; text-align:center; }
.triage-label { font-size:7.5pt; font-weight:700; text-transform:uppercase; color:#777; letter-spacing:.3pt; display:block; margin-bottom:1pt; }
.triage-verdict { margin-left:auto; }
.verdict { display:inline-block; padding:2pt 8pt; border-radius:3pt; font-size:8pt; font-weight:bold; }
.verdict-tp { background:#1a7a1a; color:#fff; }
.verdict-fp { background:#888; color:#fff; }
.verdict-review { background:#c87000; color:#fff; }
.conf-dots { display:inline-flex; gap:3pt; vertical-align:middle; }
.dot { display:inline-block; width:9pt; height:9pt; border-radius:50%; background:#ddd; border:1pt solid #bbb; }
.dot.filled { background:#1a3a5c; border-color:#1a3a5c; }
.conf-num { font-size:9pt; color:#444; margin-left:4pt; }
.triage-sublabel { font-size:7pt; font-weight:700; text-transform:uppercase; color:#999; letter-spacing:.3pt; display:block; margin-top:4pt; margin-bottom:1pt; }
.evidence-block { background:#1e1e2e; color:#cdd6f4; font-family:Consolas,monospace; font-size:7.5pt; padding:6pt 9pt; border-radius:3pt; margin:3pt 0 0 0; white-space:pre-wrap; word-break:break-all; border-left:3pt solid #5080a0; }
.cq-table { font-size:8.5pt; }
.cq-table th { background:#2c5282; }
.cq-table td { vertical-align:top; padding:5pt 7pt; }
.cq-query { display:block; background:#1e1e2e; color:#a8d8a8; padding:3pt 6pt; border-radius:2pt; white-space:pre-wrap; word-break:break-all; font-size:7.5pt; }
.cq-note { color:#666; font-size:8pt; }
</style></head><body>
<div class="pagehdr">$logoTag<span class="pht">SOC Daily Report</span></div>
<div class="hdr"><h1>SOC Daily Report</h1><p class="meta">Daily threat-hunt across AZ-GL / PROD-GL / DEV-GL / OP-GL (last 24h). Clear surfaces are omitted; only findings that need attention are listed.</p></div>
<p class="meta">Date: $dateStr &nbsp;|&nbsp; Host: $env:COMPUTERNAME &nbsp;|&nbsp; Generated: $($now.ToString('u'))</p>
$freshBanner
<h2>Summary</h2>
<p>
$(if($cnts.CRITICAL -gt 0){"<span class=`"counts HIGH`" style=`"background:#7a0000`">CRITICAL: $($cnts.CRITICAL)</span>"})
<span class="counts HIGH">HIGH: $($cnts.HIGH)</span>
<span class="counts MEDIUM">MEDIUM: $($cnts.MEDIUM)</span>
<span class="counts REVIEW">REVIEW: $($cnts.REVIEW)</span>
<span class="counts LOW">LOW: $($cnts.LOW)</span>
</p>
$kcProgressHtml
<h2>Findings</h2>
$tableHtml
<h2 class="pb">Triage Output</h2>
<p class="meta">Each finding from the table above as a structured triage card: Verdict (TP/FP), Confidence Score (1-5), MITRE ATT&amp;CK Mapping, Kill Chain Stage, Executive Summary, and Recommended Actions.</p>
$detailHtml
$corrQueriesHtml
</body></html>
"@
[System.IO.File]::WriteAllText($htmlPath,$html,(New-Object System.Text.UTF8Encoding($false)))
$urlPath = 'file:///' + ($htmlPath -replace '\\','/')
$tmpPdf="$env:TEMP\soc-noskill-render-$dateStr-$($now.ToString('HHmmss')).pdf"
if(Test-Path $tmpPdf){ Remove-Item $tmpPdf -Force -ErrorAction SilentlyContinue }
& $edge --headless=new --disable-gpu --user-data-dir="$env:TEMP\edge-soc-pdf-noskill" --no-pdf-header-footer --print-to-pdf="$tmpPdf" $urlPath 2>$null
$pdfReady=$false
for($w=0; $w -lt 60; $w++){
  Start-Sleep -Seconds 1
  if(Test-Path $tmpPdf){ $sz1=(Get-Item $tmpPdf).Length; Start-Sleep -Seconds 1; $sz2=(Get-Item $tmpPdf).Length; if($sz1 -gt 0 -and $sz1 -eq $sz2){ $pdfReady=$true; break } }
}
if($pdfReady){
  try { Copy-Item $tmpPdf $pdfPath -Force -ErrorAction Stop } catch { Write-Output "WARN: $pdfPath is locked (open in a viewer?) - close it; fresh render kept at $tmpPdf" }
  Copy-Item $tmpPdf "C:\Users\VidhyaV\OneDrive - casepoint\SOC-Reports\daily-SOC-noskill-$dateStr.pdf" -Force -ErrorAction SilentlyContinue
  Write-Output "PDF: $pdfPath (rendered $((Get-Item $tmpPdf).LastWriteTime.ToString('HH:mm:ss')), also copied to OneDrive\SOC-Reports)"
} else { Write-Output "PDF render FAILED. HTML at: $htmlPath" }
