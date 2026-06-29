# Deliver LIVE hourly hunt findings to the IIS-OPGL Teams channel (.webhook-live).
# Reuses the daily card builders (noskill-alert-card.ps1). Cross-run dedup via
# live-sent.json so overlapping 65-min windows never repost a finding.
# Reads ONLY reports-live\ - never touches the daily reports-noskill\ pipeline.
#
# SCHEMA-TOLERANT: the live hunt's AI emits rich findings (severity/title/mitre[]/
# source_ip/recommended_actions). Normalize-Finding maps those (and the canonical
# sev/finding/mitre-string form) to the keys Build-NoskillFindingCard expects, so
# delivery works regardless of which shape the model produced. Findings are read
# from the authoritative per-finding alert-*.json files first, then any extra ones
# in the live-latest.md findings-json block.
$ErrorActionPreference = 'Continue'
$proj       = 'D:\Vidhya\New Daily hunt'
$webhookFile= Join-Path $proj '.webhook-live'
$dir        = Join-Path $proj 'reports-live'
$logDir     = Join-Path $proj 'logs-noskill'
$ledgerFile = Join-Path $logDir 'live-sent.json'
$now        = Get-Date

if (-not (Test-Path $webhookFile)) { Write-Output 'ERROR: .webhook-live missing'; exit 1 }
$webhookUrl = (Get-Content $webhookFile -Raw -Encoding utf8).Trim()
. (Join-Path $proj 'noskill-alert-card.ps1')

function Post-Envelope {
  param([hashtable]$Envelope)
  $json  = $Envelope | ConvertTo-Json -Depth 20 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $webhookUrl -Method Post -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 30 | Out-Null
    return $true
  } catch { Write-Output "POST FAILED: $($_.Exception.Message)"; return $false }
}

# Map the model's actual finding shape -> the canonical keys the card builder reads.
function Normalize-Finding {
  param($f)
  $o = [ordered]@{}
  $sev = if ($f.sev) { $f.sev } elseif ($f.severity) { $f.severity } else { 'REVIEW' }
  $o.sev     = ([string]$sev).ToUpper().Trim()
  $o.env     = if ($f.env) { [string]$f.env } elseif ($f.environment) { [string]$f.environment } elseif ($f.graylog) { [string]$f.graylog } else { '' }
  $o.surface = [string]$f.surface
  $o.finding = if ($f.finding) { [string]$f.finding } elseif ($f.title) { [string]$f.title } else { '' }

  $ev = if ($f.evidence) { [string]$f.evidence } elseif ($f.evidence_summary) { [string]$f.evidence_summary } else { '' }
  $sip = if ($f.anchor_ip) { [string]$f.anchor_ip } elseif ($f.source_ip) { [string]$f.source_ip } else { '' }
  $ts  = if ($f.generated_at) { [string]$f.generated_at } elseif ($f.timestamp) { [string]$f.timestamp } else { '' }
  $prefix = ''
  if ($sip -and $ev -notmatch [regex]::Escape($sip)) { $prefix += "src $sip " }
  if ($ts -and $ev -notmatch '\d{4}-\d{2}-\d{2}') { $prefix += "@ $ts " }
  $o.evidence = ($prefix + $ev).Trim()

  $o.detail = if ($f.detail) { [string]$f.detail } elseif ($f.impact_assessment) { [string]$f.impact_assessment } else { '' }
  $o.source = if ($f.source) { [string]$f.source } elseif ($f.where) { [string]$f.where } else { [string]$f.graylog }

  # Who: prefer named entity fields before falling back to evidence text extraction
  $o.who = if ($f.subject -and $f.subject.username) { [string]$f.subject.username } `
           elseif ($f.upn) { [string]$f.upn } `
           elseif ($f.user) { [string]$f.user } `
           elseif ($f.source_ip) { [string]$f.source_ip } `
           elseif ($f.anchor_ip) { [string]$f.anchor_ip } `
           else { '' }

  # mitre: normalize to array first so the iteration always works correctly.
  # ConvertFrom-Json returns a PSCustomObject for {}, an Object[] for [{},{}].
  # Wrapping in @() handles both cases uniformly.
  $mArr = if ($null -eq $f.mitre) { @() }
          elseif ($f.mitre -is [string]) { @() }   # plain string handled below
          else { @($f.mitre) }                      # array OR single object -> array

  if ($mArr.Count -gt 0) {
    $o.mitre  = ($mArr | ForEach-Object {
                    if ($_ -is [string]) { $_ }
                    elseif ($_.technique) { $_.technique }
                  } | Where-Object { $_ }) -join ', '
    $o.tactic = ($mArr | ForEach-Object { $_.tactic } | Where-Object { $_ } | Select-Object -Unique) -join ' / '
  } elseif ($f.mitre -is [string] -and $f.mitre) {
    $o.mitre  = [string]$f.mitre
    $o.tactic = ''
  } else {
    $o.mitre  = ''
    $o.tactic = ''
  }
  if (-not $o.tactic) { $o.tactic = if ($f.tactic) { [string]$f.tactic } else { '' } }

  $o.killchain = if ($f.killchain) { [string]$f.killchain } `
                 elseif ($f.kill_chain_phase) { [string]$f.kill_chain_phase } `
                 elseif ($f.killchain_phase)  { [string]$f.killchain_phase } `
                 elseif ($f.mitre -and $f.mitre.kill_chain_phase) { [string]$f.mitre.kill_chain_phase } `
                 else { '' }
  $o.action    = if ($f.action) { [string]$f.action } elseif ($f.recommended_actions) { (@($f.recommended_actions) -join ' | ') } else { '' }
  $o.query     = if ($f.query) { [string]$f.query } elseif ($f.query_template) { [string]$f.query_template } else { '' }
  $o.investigate = [string]$f.investigate
  $o.correlation = if ($f.correlation) { [string]$f.correlation } elseif ($f.pivot_significance) { [string]$f.pivot_significance } else { '' }
  $o.confidence  = [string]$f.confidence
  # ── Source: always fall back to env so Where is never blank ──────────
  $o.source = if ($f.source) { [string]$f.source } `
              elseif ($f.where) { [string]$f.where } `
              elseif ($f.graylog) { [string]$f.graylog } `
              else { [string]$f.env }
  # ── IIS / APP investigation fields ───────────────────────────────────
  $o.client_ip   = if ($f.client_ip)   { [string]$f.client_ip }  else { '' }
  $o.host        = if ($f.host)        { [string]$f.host }        else { '' }
  $o.uri_stem    = if ($f.uri_stem)    { [string]$f.uri_stem }    elseif ($f.uri)          { [string]$f.uri }          else { '' }
  $o.uri_query   = if ($f.uri_query)   { [string]$f.uri_query }   elseif ($f.query_string) { [string]$f.query_string } else { '' }
  $o.http_status = if ($f.http_status) { [string]$f.http_status } elseif ($f.status_code)  { [string]$f.status_code }  else { '' }
  # ── Windows / RDP investigation fields ───────────────────────────────
  $o.event_id   = if ($f.event_id)   { [string]$f.event_id }   else { '' }
  $o.win_host   = if ($f.win_host)   { [string]$f.win_host }   elseif ($f.hostname) { [string]$f.hostname } elseif ($f.computer) { [string]$f.computer } else { '' }
  $o.win_user   = if ($f.win_user)   { [string]$f.win_user }   elseif ($f.username) { [string]$f.username } else { '' }
  $o.logon_type = if ($f.logon_type) { [string]$f.logon_type } else { '' }
  $o.src_ip     = if ($f.src_ip)     { [string]$f.src_ip }     elseif ($f.source_ip) { [string]$f.source_ip } elseif ($f.anchor_ip) { [string]$f.anchor_ip } else { '' }
  # ── Azure / Entra investigation fields ───────────────────────────────
  $o.upn         = if ($f.upn)         { [string]$f.upn }         else { '' }
  $o.azure_ip    = if ($f.azure_ip)    { [string]$f.azure_ip }    elseif ($f.ip_address) { [string]$f.ip_address } else { '' }
  $o.result_code = if ($f.result_code) { [string]$f.result_code } elseif ($f.resultCode) { [string]$f.resultCode } else { '' }
  $o.app_name    = if ($f.app_name)    { [string]$f.app_name }    elseif ($f.app)        { [string]$f.app }        else { '' }
  $o.client_app  = if ($f.client_app)  { [string]$f.client_app }  elseif ($f.clientApp)  { [string]$f.clientApp }  else { '' }
  $o.geo_country = if ($f.geo_country) { [string]$f.geo_country } else { '' }
  # ── Linux investigation fields ────────────────────────────────────────
  $o.linux_user    = if ($f.linux_user)    { [string]$f.linux_user }    elseif ($f.username) { [string]$f.username } else { '' }
  $o.linux_src_ip  = if ($f.linux_src_ip)  { [string]$f.linux_src_ip }  else { '' }
  $o.linux_service = if ($f.linux_service) { [string]$f.linux_service } else { '' }
  # ── SFTP investigation fields ─────────────────────────────────────────
  $o.sftp_user    = if ($f.sftp_user)    { [string]$f.sftp_user }    else { '' }
  $o.sftp_size_mb = if ($f.sftp_size_mb) { [string]$f.sftp_size_mb } elseif ($f.size_mb) { [string]$f.size_mb } else { '' }
  # ── Network / FortiGate investigation fields ──────────────────────────
  $o.dst_ip       = if ($f.dst_ip)       { [string]$f.dst_ip }       else { '' }
  $o.dst_port     = if ($f.dst_port)     { [string]$f.dst_port }     else { '' }
  $o.net_action   = if ($f.net_action)   { [string]$f.net_action }   else { '' }
  $o.policy       = if ($f.policy)       { [string]$f.policy }       elseif ($f.policyname) { [string]$f.policyname } else { '' }
  $o.ips_severity = if ($f.ips_severity) { [string]$f.ips_severity } elseif ($f.crlevel)    { [string]$f.crlevel }    else { '' }
  # ── EDR / ESET investigation fields ──────────────────────────────────
  $o.edr_host    = if ($f.edr_host)    { [string]$f.edr_host }    elseif ($f.hostname) { [string]$f.hostname } else { '' }
  $o.edr_detect  = if ($f.edr_detect)  { [string]$f.edr_detect }  else { '' }
  $o.edr_process = if ($f.edr_process) { [string]$f.edr_process } else { '' }
  return [pscustomobject]$o
}

function Get-Key($r) { "$([string]$r.sev)|$([string]$r.env)|$([string]$r.surface)|$(([string]$r.finding).Substring(0,[Math]::Min(60,([string]$r.finding).Length)))" }

# ── Ingest: authoritative alert-*.json first, then extras from the md block ──
$byKey = [ordered]@{}
foreach ($af in (Get-ChildItem $dir -Filter 'alert-*.json' -EA SilentlyContinue)) {
  try { $n = Normalize-Finding (Get-Content $af.FullName -Raw -Encoding utf8 | ConvertFrom-Json); $byKey[(Get-Key $n)] = $n }
  catch { Write-Output "alert parse failed $($af.Name): $($_.Exception.Message)" }
}
# alert-*.json (rule f) is authoritative for CRITICAL/HIGH/MEDIUM. Only fall back to
# the live-latest.md block when NO alert files were written (avoids double-posting the
# same finding whose title differs slightly between the two representations).
if ($byKey.Count -eq 0) {
  $lf = Join-Path $dir 'live-latest.md'
  if (Test-Path $lf) {
    Write-Output 'no alert-*.json present - falling back to live-latest.md findings-json block'
    $txt = (Get-Content $lf -Raw -Encoding utf8) -replace '[^\x20-\x7E\r\n]',''
    $m = [regex]::Match($txt, '(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
    if ($m.Success) {
      try { foreach ($x in ($m.Groups[1].Value | ConvertFrom-Json)) { $n = Normalize-Finding $x; $byKey[(Get-Key $n)] = $n } }
      catch { Write-Output "md-block parse failed: $($_.Exception.Message)" }
    }
  }
}
$findings = @($byKey.Values)
Write-Output ("ingested {0} unique finding(s) from reports-live" -f $findings.Count)

$ord    = @{ CRITICAL=0; HIGH=1; MEDIUM=2; REVIEW=3; LOW=4; CLEAN=5 }
$sorted = @($findings | Where-Object { $_.sev -ne 'CLEAN' } | Sort-Object @{Expression={ if($ord.ContainsKey($_.sev)){$ord[$_.sev]}else{99} }}, env, surface)
$cnts = @{ CRITICAL=0; HIGH=0; MEDIUM=0; REVIEW=0; LOW=0; CLEAN=0 }
foreach ($r in $findings) { if ($cnts.ContainsKey($r.sev)) { $cnts[$r.sev]++ } }

# cross-run dedup ledger (suppress same finding within 6h)
$ledger = @{}
if (Test-Path $ledgerFile) { try { (Get-Content $ledgerFile -Raw -Encoding utf8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $ledger[$_.Name] = $_.Value } } catch {} }

$sent = 0; $skipped = 0
foreach ($r in ($sorted | Where-Object { $_.sev -in 'CRITICAL','HIGH','MEDIUM' })) {
  $k = Get-Key $r
  if ($ledger.ContainsKey($k)) { try { if ((($now - [datetime]::Parse($ledger[$k])).TotalHours) -lt 6) { $skipped++; continue } } catch {} }
  if (Post-Envelope (Build-NoskillFindingCard -Finding $r)) { $ledger[$k] = $now.ToString('o'); $sent++; Write-Output "Posted LIVE: $($r.sev) $($r.env)/$($r.surface) - $($r.finding)"; Start-Sleep -Seconds 2 }
}

# ── PDF link: read info written by generate-live-pdf.ps1 ─────────────────────
$pdfUrl  = $null
$pdfName = $null
$pdfInfoFile = Join-Path $logDir 'live-pdf-info.json'
if (Test-Path $pdfInfoFile) {
  try {
    $pdfInfo = Get-Content $pdfInfoFile -Raw -Encoding utf8 | ConvertFrom-Json
    $pdfName = [string]$pdfInfo.pdfName
    # Build SharePoint direct link (same pattern as daily send-report-noskill.ps1)
    $spBaseFile = Join-Path $proj '.sharepoint-pdf-url-base'
    if (Test-Path $spBaseFile) {
      $spBase   = (Get-Content $spBaseFile -Raw -Encoding utf8).Trim()
      $spFolder = '%2Fpersonal%2Fvidhya%5Fv%5Fcasepoint%5Fin%2FDocuments%2FSOC%2DReports'
      $pdfEnc   = $pdfName -replace '-','%2D' -replace '\.','%2E'
      $pdfUrl   = "${spBase}&id=${spFolder}%2F${pdfEnc}&parent=${spFolder}"
      Write-Output "PDF link: $pdfUrl"
    }
    # Upload PDF to SharePoint via Power Automate upload flow
    $uploadFlowFile = Join-Path $proj '.upload-flow-url'
    $pdfPath = [string]$pdfInfo.pdfPath
    if ($pdfName -and $pdfPath -and (Test-Path $pdfPath) -and (Test-Path $uploadFlowFile)) {
      try {
        $upUrl  = (Get-Content $uploadFlowFile -Raw -Encoding utf8).Trim()
        $b64    = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pdfPath))
        $upBody = @{ fileName=$pdfName; contentBase64=$b64 } | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri $upUrl -Method Post -ContentType 'application/json' -Body $upBody -TimeoutSec 60 -EA Stop | Out-Null
        Write-Output "Uploaded $pdfName to SharePoint via upload flow"
      } catch { Write-Output "SharePoint upload failed: $($_.Exception.Message)" }
    }
  } catch { Write-Output "live-pdf-info.json read failed: $($_.Exception.Message)" }
}

if ($sent -gt 0) {
  $top = @()
  foreach ($t in ($sorted | Where-Object { $_.sev -in 'CRITICAL','HIGH','MEDIUM' } | Select-Object -First 5)) { $top += "- [$($t.sev)] $($t.env)/$($t.surface): $($t.finding)" }
  $sum = Build-NoskillSummaryCard -Counts $cnts -DateStr ($now.ToString('yyyy-MM-dd HH:mm') + ' (hourly live)') -PdfUrl $pdfUrl -PdfName $pdfName -TopItems $top -HungSurfaces @()
  if (Post-Envelope $sum) { Write-Output 'Posted: live summary card' }
}

$fresh = @{}
foreach ($k in $ledger.Keys) { try { if ((($now - [datetime]::Parse($ledger[$k])).TotalHours) -lt 24) { $fresh[$k] = $ledger[$k] } } catch {} }
($fresh | ConvertTo-Json) | Set-Content -Path $ledgerFile -Encoding utf8
Write-Output "live delivery: sent=$sent skipped(dedup)=$skipped"
