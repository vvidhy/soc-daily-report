$ErrorActionPreference='Continue'
# Channel suppress: set SOC_SKIP_TEAMS=1 to deliver via email only (no Teams cards).
# Mirrors SOC_SKIP_EMAIL in send-csv-noskill.ps1.
if ($env:SOC_SKIP_TEAMS -eq '1') { Write-Output 'SOC_SKIP_TEAMS=1 - Teams card posting SKIPPED (email-only delivery).'; exit 0 }
$webhookFile = 'D:\Vidhya\New Daily hunt\.webhook-noskill'
$dir         = 'D:\Vidhya\New Daily hunt\reports-noskill'
$now         = Get-Date
if(-not (Test-Path $webhookFile)){ Write-Output 'ERROR: webhook file missing'; exit 1 }
$webhookUrl  = (Get-Content $webhookFile -Raw -Encoding utf8).Trim()

# Load rich card builder
. 'D:\Vidhya\New Daily hunt\noskill-alert-card.ps1'

function Post-Envelope {
  param([hashtable]$Envelope)
  $json  = $Envelope | ConvertTo-Json -Depth 20 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $webhookUrl -Method Post `
      -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 30 | Out-Null
    return $true
  } catch { Write-Output "POST FAILED: $($_.Exception.Message)"; return $false }
}

# ── Read all *-latest.md findings ────────────────────────────────────────────
$cutoff = $now.AddHours(-20)
$files  = Get-ChildItem $dir -File -Filter '*-latest.md' -EA SilentlyContinue |
          Where-Object { $_.LastWriteTime -gt $cutoff } | Sort-Object Name

$findings = @()
foreach ($f in $files) {
  $txt = (Get-Content $f.FullName -Raw -Encoding utf8) -replace '[^\x20-\x7E\r\n]',''
  $m   = [regex]::Match($txt, '(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if ($m.Success) {
    try { $arr = $m.Groups[1].Value | ConvertFrom-Json; foreach ($x in $arr) { if(($x.PSObject.Properties.Name -contains 'value') -and ($x.PSObject.Properties.Name -notcontains 'sev')){ foreach($sub in @($x.value)){ if($null -ne $sub){ $findings += $sub } } } else { $findings += $x } } }
    catch { Write-Output "Findings parse failed for $($f.Name): $($_.Exception.Message)" }
  } else { Write-Output "No findings-json block in $($f.Name)" }
}

$cnts = @{ CRITICAL=0; HIGH=0; MEDIUM=0; REVIEW=0; LOW=0; CLEAN=0 }
foreach ($r in $findings) { $s=[string]$r.sev; if ($cnts.ContainsKey($s)) { $cnts[$s]++ } }
$ord    = @{ CRITICAL=0; HIGH=1; MEDIUM=2; REVIEW=3; LOW=4; CLEAN=5 }
$sorted = @($findings | Where-Object { [string]$_.sev -ne 'CLEAN' } |
           Sort-Object @{Expression={ $s=[string]$_.sev; if($ord.ContainsKey($s)){$ord[$s]}else{99} }}, env, surface)

# ── Build SharePoint direct file URL ─────────────────────────────────────────
$shareUrl    = $null
$spBaseFile  = 'D:\Vidhya\New Daily hunt\.sharepoint-pdf-url-base'
if (Test-Path $spBaseFile) {
  $spBase      = (Get-Content $spBaseFile -Raw -Encoding utf8).Trim()
  $spFolder    = '%2Fpersonal%2Fvidhya%5Fv%5Fcasepoint%5Fin%2FDocuments%2FSOC%2DReports'
  $pdfDateEnc  = ($now.ToString('yyyy-MM-dd')).Replace('-','%2D')
  $shareUrl    = "${spBase}&id=${spFolder}%2Fdaily%2DSOC%2Dnoskill%2D${pdfDateEnc}%2Epdf&parent=${spFolder}"
  Write-Output "SharePoint direct PDF URL: $shareUrl"
}

# Upload PDF to SharePoint (for the actual file; link constructed above)
$pdf = Get-ChildItem "$dir\daily-SOC-noskill-*.pdf" -EA SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
$uploadFlowFile = 'D:\Vidhya\New Daily hunt\.upload-flow-url'
if ($pdf -and (Test-Path $uploadFlowFile)) {
  try {
    $upUrl = (Get-Content $uploadFlowFile -Raw -Encoding utf8).Trim()
    $b64   = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pdf.FullName))
    $upBody = @{ fileName=$pdf.Name; contentBase64=$b64 } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri $upUrl -Method Post -ContentType 'application/json' -Body $upBody -EA Stop | Out-Null
    Write-Output "Upload flow triggered for $($pdf.Name)"
  } catch { Write-Output "SharePoint upload failed: $($_.Exception.Message)" }
}

# ── Which HIGH/CRITICAL findings were already sent live by the watcher? ───────
# Live-watcher marks sent files in logs-noskill\sent-alerts\alert-*.json.sent
$sentDir   = 'D:\Vidhya\New Daily hunt\logs-noskill\sent-alerts'
$alreadySentFiles = @{}
if (Test-Path $sentDir) {
  foreach ($sf in (Get-ChildItem $sentDir -Filter '*.sent' -EA SilentlyContinue)) {
    $alreadySentFiles[$sf.BaseName -replace '\.json$',''] = $true
  }
}
# Build a key set from alert files written this run (alert-{surface}-{stamp}.json)
$alertFiles = Get-ChildItem $dir -Filter 'alert-*.json' -EA SilentlyContinue |
              Where-Object { $_.LastWriteTime -gt $now.Date }
$liveAlertKeys = @{}
foreach ($af in $alertFiles) {
  try {
    $obj = Get-Content $af.FullName -Raw -Encoding utf8 | ConvertFrom-Json
    $key = "$([string]$obj.sev)|$([string]$obj.env)|$([string]$obj.surface)|$(([string]$obj.finding).Substring(0,[Math]::Min(60,([string]$obj.finding).Length)))"
    $liveAlertKeys[$key] = $true
  } catch {}
}
function Was-SentLive([psobject]$r){
  $key = "$([string]$r.sev)|$([string]$r.env)|$([string]$r.surface)|$(([string]$r.finding).Substring(0,[Math]::Min(60,([string]$r.finding).Length)))"
  return $liveAlertKeys.ContainsKey($key)
}

# ── Detect surfaces skipped due to MCP failure (mcp-hung: prefix) ────────────
$hungSurfaces = @(
  $sorted |
  Where-Object { ([string]$_.finding) -match '^mcp-hung:' } |
  ForEach-Object { "$([string]$_.env)/$([string]$_.surface)" } |
  Sort-Object -Unique
)
if ($hungSurfaces.Count -gt 0) {
  Write-Output "MCP-hung surfaces detected: $($hungSurfaces -join ', ')"
  $hungEnvelope = Build-NoskillHungCard -Surfaces $hungSurfaces -DateStr ($now.ToString('yyyy-MM-dd HH:mm'))
  if (Post-Envelope $hungEnvelope) {
    Write-Output "Posted: hung-surfaces warning card ($($hungSurfaces.Count) surface(s))"
    Start-Sleep -Seconds 2
  }
}

# ── Post rich finding cards for ALL HIGH/CRITICAL/MEDIUM findings ─────────────
$cardsSent = 0
foreach ($r in ($sorted | Where-Object { ([string]$_.sev) -in 'CRITICAL','HIGH','MEDIUM' })) {
  $envelope = Build-NoskillFindingCard -Finding $r
  if (Post-Envelope $envelope) {
    Write-Output "Posted: $([string]$r.sev) $([string]$r.env)/$([string]$r.surface)"
    $cardsSent++
    Start-Sleep -Seconds 2
  }
}

# ── Final summary card (posture + counts + PDF button) ───────────────────────
$topItems = @()
$top = $sorted | Where-Object { ([string]$_.sev) -in 'CRITICAL','HIGH','MEDIUM' } | Select-Object -First 5
foreach ($t in $top) {
  $kc    = [string]$t.killchain
  $kcTag = if($kc){ "[$kc] " } else { '' }
  $topItems += "- [$([string]$t.sev)] ${kcTag}$([string]$t.env)/$([string]$t.surface): $([string]$t.action)"
}

$pdfName = if($pdf){ $pdf.Name } else { $null }
$summaryEnvelope = Build-NoskillSummaryCard `
  -Counts        $cnts `
  -DateStr       ($now.ToString('yyyy-MM-dd HH:mm')) `
  -PdfUrl        $shareUrl `
  -PdfName       $pdfName `
  -TopItems      $topItems `
  -HungSurfaces  $hungSurfaces

$posted = Post-Envelope $summaryEnvelope
if ($posted) { Write-Output "Posted: summary card" }

# ── Delivery marker ───────────────────────────────────────────────────────────
if ($posted -or $cardsSent -gt 0) {
  $marker = "D:\Vidhya\New Daily hunt\logs-noskill\delivered-$($now.ToString('yyyyMMdd')).txt"
  Set-Content -Path $marker -Value (Get-Date -Format o) -Encoding utf8
  Write-Output "Delivery marker written: $marker"
} else {
  Write-Output 'No cards posted - delivery marker NOT written'
}
