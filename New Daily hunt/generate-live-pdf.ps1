# generate-live-pdf.ps1
# Render reports-live\live-latest.md -> live-SOC-YYYY-MM-DD-HHmm.pdf via Edge headless.
# Copies to OneDrive\SOC-Reports\ and writes logs-noskill\live-pdf-info.json for send-live-noskill.ps1.
$ErrorActionPreference = 'Continue'
$proj     = 'D:\Vidhya\New Daily hunt'
$dir      = "$proj\reports-live"
$now      = Get-Date
$dateStr  = $now.ToString('yyyy-MM-dd')
$timeStr  = $now.ToString('HHmm')
$pdfName  = "live-SOC-$dateStr-$timeStr.pdf"
$htmlPath = "$dir\live-SOC-$dateStr-$timeStr.html"
$pdfPath  = "$dir\$pdfName"
$infoFile = "$proj\logs-noskill\live-pdf-info.json"

$edge = $null
foreach ($p in @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
                  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")) {
    if (Test-Path $p) { $edge = $p; break }
}
if (-not $edge) { Write-Output 'ERROR: msedge.exe not found - PDF skipped'; exit 1 }

$reportFile = "$dir\live-latest.md"
if (-not (Test-Path $reportFile)) { Write-Output 'ERROR: live-latest.md not found'; exit 1 }

$rawReport = (Get-Content $reportFile -Raw -Encoding utf8) -replace '[^\x20-\x7E\r\n]', ''
$m = [regex]::Match($rawReport, '(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
$findings = @()
if ($m.Success) {
    try { $findings = @($m.Groups[1].Value | ConvertFrom-Json) } catch { Write-Output "findings-json parse error: $($_.Exception.Message)" }
}
$findings = @($findings | Where-Object { [string]$_.sev -ne 'CLEAN' })

$cnts = @{ CRITICAL=0; HIGH=0; MEDIUM=0; REVIEW=0; LOW=0 }
foreach ($r in $findings) { $s = [string]$r.sev; if ($cnts.ContainsKey($s)) { $cnts[$s]++ } }
$ord = @{ CRITICAL=0; HIGH=1; MEDIUM=2; REVIEW=3; LOW=4 }
$sorted = @($findings | Sort-Object @{ Expression={ $s=[string]$_.sev; if($ord.ContainsKey($s)){$ord[$s]}else{9} } }, env, surface)

$logoTag = ''
$logoPath = "$proj\assets\casepoint-logo.png"
if (Test-Path $logoPath) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($logoPath))
    $logoTag = "<img class=`"logo`" src=`"data:image/png;base64,$b64`" />"
}

function EncHtml([string]$s) { if (-not $s) { return '' }; ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }
function SurfLabel([string]$s) { if ($s -eq 'edr') { return 'ESET' }; return $s }

# Kill chain stage strip
$kcOrder = @('Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Actions')
$kcHit = @{}
foreach ($r in ($sorted | Where-Object { [string]$_.sev -in 'CRITICAL','HIGH','MEDIUM' })) {
    $kc = [string]$r.killchain; if ($kc) { $kcHit[$kc] = $true }
}
$kcStageHtml = ''
foreach ($stage in $kcOrder) {
    $cls = if ($kcHit.ContainsKey($stage)) { 'kc-stage active' } else { 'kc-stage' }
    $kcStageHtml += "<span class=`"$cls`">$stage</span>"
}

# Summary count tiles
$tileHtml = ''
foreach ($s in @('CRITICAL','HIGH','MEDIUM','REVIEW','LOW')) {
    $n = $cnts[$s]
    $tileHtml += "<span class=`"counts ${s}`">${s}: $n</span>"
}

# Per-finding triage cards
$detailHtml = ''
foreach ($r in $sorted) {
    $sev      = [string]$r.sev
    $kc       = [string]$r.killchain
    $tactic   = [string]$r.tactic
    $mitre    = [string]$r.mitre
    $evidence = [string]$(if($r.evidence){$r.evidence}elseif($r.evidence_summary){$r.evidence_summary}else{''})
    $detail   = [string]$(if($r.detail){$r.detail}elseif($r.impact_assessment){$r.impact_assessment}else{''})
    $action   = [string]$(if($r.action){$r.action}elseif($r.recommended_actions){(@($r.recommended_actions)-join' | ')}else{''})
    $query    = [string]$r.query
    $corr     = [string]$r.correlation
    $inv      = [string]$r.investigate
    $who      = [string]$(if($r.subject -and $r.subject.username){$r.subject.username}elseif($r.upn){$r.upn}elseif($r.source_ip){$r.source_ip}elseif($r.anchor_ip){$r.anchor_ip}else{'—'})

    $corrSection = ''
    if ($corr -and $corr -ne 'standalone') {
        $invPart = if ($inv) { '<br/><code>' + (EncHtml $inv) + '</code>' } else { '' }
        $corrSection = '<div class="triage-row"><span class="triage-icon">&#128257;</span><div><span class="triage-label">Correlation</span>' + (EncHtml $corr) + $invPart + '</div></div>'
    }

    $detailHtml += "<div class=`"triage-card sev-$sev`">" +
      "<div class=`"triage-hdr`"><span class=`"badge $sev`">$sev</span> <strong>$(EncHtml (SurfLabel ([string]$r.surface)))</strong> <span class=`"env`">@ $(EncHtml ([string]$r.env))</span></div>" +
      "<p class=`"triage-finding`">$(EncHtml ([string]$r.finding))</p>" +
      "<div class=`"triage-row`"><span class=`"triage-icon`">&#128100;</span><div><span class=`"triage-label`">Who</span>$(EncHtml $who)</div></div>" +
      "<div class=`"triage-row`"><span class=`"triage-icon`">&#128736;</span><div><span class=`"triage-label`">MITRE ATT&amp;CK</span><strong>$(EncHtml $tactic)</strong> &nbsp;|&nbsp; <code>$(EncHtml $mitre)</code></div></div>" +
      "<div class=`"triage-row`"><span class=`"triage-icon`">&#128279;</span><div><span class=`"triage-label`">Kill Chain</span>$(if($kc){'<span class="kc-badge">'+$kc+'</span>'}else{'—'})</div></div>" +
      "<div class=`"triage-row`"><span class=`"triage-icon`">&#128196;</span><div><span class=`"triage-label`">Evidence (Graylog logs)</span><code>$(EncHtml $evidence)</code></div></div>" +
      "<div class=`"triage-row`"><span class=`"triage-icon`">&#9432;</span><div><span class=`"triage-label`">Why / Impact</span>$(EncHtml $detail)</div></div>" +
      "<div class=`"triage-row`"><span class=`"triage-icon`">&#128269;</span><div><span class=`"triage-label`">Recommended Actions</span>$(EncHtml $action)" +
        "$(if($query){'<br/><span class="triage-sublabel">Graylog query (paste-ready):</span><br/><code>'+(EncHtml $query)+'</code>'}else{''})" +
        "</div></div>" +
      $corrSection +
      "</div>"
}
if ($sorted.Count -eq 0) { $detailHtml = '<p class="meta">No CRITICAL / HIGH / MEDIUM / REVIEW findings this window.</p>' }

$html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOC Live Hunt - $dateStr $timeStr</title>
<style>
@page { margin: 28mm 9mm 12mm 9mm; }
.pagehdr { position:fixed;top:0;left:0;right:0;height:28px;display:flex;align-items:center;justify-content:space-between;padding:3pt 0;border-bottom:2px solid #111;background:#fff; }
.pagehdr img { height:20px; }
.pagehdr .pht { color:#111;font-weight:600;font-size:10pt; }
body { font-family:'Segoe UI',Calibri,Arial,sans-serif;font-size:11pt;color:#222;padding-top:8px; }
h1 { color:#1a3a5c;font-size:20pt;margin-bottom:4pt; }
h2 { color:#1a3a5c;border-bottom:2px solid #1a3a5c;padding-bottom:3pt;margin-top:14pt; }
.meta { color:#555;font-size:10pt; }
.logo { height:36pt; }
.hdr { display:flex;flex-direction:column;align-items:flex-start;gap:5pt;border-bottom:3px solid #1a3a5c;padding-bottom:7pt;margin-top:12pt;margin-bottom:6pt; }
.counts { display:inline-block;padding:3pt 8pt;margin-right:5pt;border-radius:3pt;font-weight:bold;color:#fff; }
.counts.CRITICAL{background:#7a0000}.counts.HIGH{background:#c00}.counts.MEDIUM{background:#c87000}.counts.REVIEW{background:#c8a800}.counts.LOW{background:#5080a0}
.badge { display:inline-block;padding:1pt 6pt;border-radius:3pt;color:#fff;font-size:8pt;font-weight:bold;white-space:nowrap; }
.badge.CRITICAL{background:#7a0000}.badge.HIGH{background:#c00}.badge.MEDIUM{background:#c87000}.badge.REVIEW{background:#c8a800}.badge.LOW{background:#5080a0}
.env { color:#555;font-weight:normal;font-size:8pt; }
code { background:#eef2f7;padding:1pt 4pt;border-radius:2pt;font-family:Consolas,monospace;font-size:8pt;word-break:break-all; }
.kc-chain { margin:5pt 0 3pt 0; }
.kc-label { font-size:9pt;font-weight:600;color:#444;margin-right:5pt; }
.kc-stage { display:inline-block;padding:2pt 7pt;border-radius:3pt;background:#e8e8e8;color:#888;font-size:8pt;margin:1pt 2pt; }
.kc-stage.active { background:#c00;color:#fff;font-weight:bold; }
.kc-badge { display:inline-block;padding:1pt 5pt;border-radius:2pt;background:#2c5282;color:#fff;font-size:7.5pt;font-weight:bold; }
.triage-card { border:1.5px solid #ccc;border-radius:5pt;padding:7pt 11pt;margin:7pt 0;background:#fafbfc; }
.triage-card.sev-CRITICAL{border-color:#7a0000;background:#fff5f5}
.triage-card.sev-HIGH{border-color:#c00;background:#fff8f8}
.triage-card.sev-MEDIUM{border-color:#c87000;background:#fffbf2}
.triage-card.sev-REVIEW{border-color:#c8a800;background:#fffef0}
.triage-card.sev-LOW{border-color:#5080a0;background:#f5f9ff}
.triage-hdr { margin-bottom:4pt;display:flex;align-items:center;gap:5pt;flex-wrap:wrap; }
.triage-finding { font-size:10.5pt;font-weight:600;color:#1a1a1a;margin:3pt 0 5pt 0; }
.triage-row { display:flex;gap:7pt;align-items:flex-start;margin:3pt 0;font-size:9pt; }
.triage-icon { font-size:10pt;min-width:15pt;text-align:center; }
.triage-label { font-size:7.5pt;font-weight:700;text-transform:uppercase;color:#777;letter-spacing:.3pt;display:block;margin-bottom:1pt; }
.triage-sublabel { font-size:7pt;font-weight:700;text-transform:uppercase;color:#999;letter-spacing:.3pt;display:block;margin-top:3pt;margin-bottom:1pt; }
</style></head><body>
<div class="pagehdr">$logoTag<span class="pht">SOC Live Hunt &mdash; Hourly</span></div>
<div class="hdr"><h1>SOC Live Hunt</h1><p class="meta">Hourly MITRE+UEBA hunt across AZ-GL / PROD-GL / DEV-GL / OP-GL (65-min window). CLEAN surfaces omitted.</p></div>
<p class="meta">Window: $dateStr $timeStr UTC &nbsp;|&nbsp; Host: $env:COMPUTERNAME</p>
<h2>Findings</h2>
<p>$tileHtml</p>
<div class="kc-chain"><span class="kc-label">Kill Chain (HIGH/MEDIUM):</span> $kcStageHtml</div>
<h2>Triage Detail</h2>
$detailHtml
</body></html>
"@

[System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($false)))

$tmpPdf = "$env:TEMP\soc-live-render-$dateStr-$timeStr.pdf"
Remove-Item $tmpPdf -Force -EA SilentlyContinue
$urlPath = 'file:///' + ($htmlPath -replace '\\', '/')
& $edge --headless=new --disable-gpu "--user-data-dir=$env:TEMP\edge-soc-live-pdf" --no-pdf-header-footer "--print-to-pdf=$tmpPdf" $urlPath 2>$null

$pdfReady = $false
for ($w = 0; $w -lt 60; $w++) {
    Start-Sleep -Seconds 1
    if (Test-Path $tmpPdf) {
        $sz1 = (Get-Item $tmpPdf).Length; Start-Sleep -Seconds 1; $sz2 = (Get-Item $tmpPdf).Length
        if ($sz1 -gt 0 -and $sz1 -eq $sz2) { $pdfReady = $true; break }
    }
}

if ($pdfReady) {
    Copy-Item $tmpPdf $pdfPath -Force -EA SilentlyContinue
    Copy-Item $tmpPdf "C:\Users\VidhyaV\OneDrive - casepoint\SOC-Reports\$pdfName" -Force -EA SilentlyContinue
    Write-Output "PDF: $pdfPath"
    @{ pdfName=$pdfName; pdfPath=$pdfPath } | ConvertTo-Json | Set-Content $infoFile -Encoding utf8
} else {
    Write-Output "PDF render FAILED. HTML: $htmlPath"
    exit 1
}
