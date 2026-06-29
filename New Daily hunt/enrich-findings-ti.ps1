# enrich-findings-ti.ps1
# Pipeline step: for every finding whose entity is a public IPv4, call ti-enrich.ps1
# and fold VT/AbuseIPDB verdict into evidence + detail. Auto-escalates sev when MALICIOUS.
# Cortex-clean: pure HTTP/JSON plumbing, no attack-signature literals.
# Runs AFTER hunt writes findings JSON, BEFORE merge-depth. 0 Claude tokens.
param([string]$FindingsFile = '')
$ErrorActionPreference = 'Continue'
$proj = 'D:\Vidhya\New Daily hunt'
if (-not $FindingsFile) { $FindingsFile = "$proj\reports-noskill\depth-findings.json" }

if (-not (Test-Path $FindingsFile)) { Write-Output "enrich-ti: $([System.IO.Path]::GetFileName($FindingsFile)) not found - skip."; exit 0 }
$raw = Get-Content $FindingsFile -Raw
if ([string]::IsNullOrWhiteSpace($raw)) { Write-Output "enrich-ti: file empty - skip."; exit 0 }

$items = @()
try { $items = @($raw | ConvertFrom-Json) } catch { Write-Output "enrich-ti: cannot parse JSON - skip."; exit 0 }

# flatten {value:[...]} breadth wrapper if present
$flat = @()
foreach ($it in @($items)) {
  if ($it -ne $null -and $it.PSObject.Properties.Name -contains 'value' -and $it.PSObject.Properties.Name -notcontains 'sev') {
    foreach ($s in @($it.value)) { if ($null -ne $s) { $flat += $s } }
  } else { $flat += $it }
}
if ($flat.Count -eq 0) { Write-Output "enrich-ti: 0 findings - skip."; exit 0 }

function Is-PublicIpv4([string]$s) {
  if ($s -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { return $false }
  if ($s -match '^(10\.|192\.168\.|127\.|169\.254\.)') { return $false }
  if ($s -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $false }
  # Cato / Zscaler egress (internal-routed)
  if ($s -match '^(136\.226\.|165\.225\.)') { return $false }
  return $true
}

$enriched = 0; $updated = @()
foreach ($f in $flat) {
  $entity = [string]$f.entity
  if ((Is-PublicIpv4 $entity) -and ([string]$f.verdict -ne 'FP')) {
    # skip if already enriched this run (VT line already in evidence)
    if ([string]$f.evidence -match 'VT \d+/\d+ malicious') { $updated += $f; continue }

    Write-Output "enrich-ti: $entity ..."
    try {
      $tiRaw = & powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\ti-enrich.ps1" -Ip $entity 2>$null
      # ti-enrich returns a JSON array (one element per IP)
      $tiArr = @($tiRaw | ConvertFrom-Json)
      $ti = if ($tiArr.Count -gt 0) { $tiArr[0] } else { $null }

      if ($ti -and $ti.verdict -and $ti.verdict -notmatch 'SKIPPED|DEFERRED') {
        $vtStr  = if ($null -ne $ti.vt_malicious)  { "VT $($ti.vt_malicious)/$($ti.vt_total) malicious" } else { $null }
        $abStr  = if ($null -ne $ti.abuse_score)   { "AbuseIPDB $($ti.abuse_score)%" }                    else { $null }
        $ownStr = (@($ti.owner, $ti.country) | Where-Object { $_ }) -join '/'
        $tiLine = (@($vtStr, $abStr, $ownStr) | Where-Object { $_ }) -join ', '

        if ($tiLine) {
          $f.evidence = ([string]$f.evidence).TrimEnd() + " | TI: $tiLine"
          $f.detail   = ([string]$f.detail).TrimEnd()   + " Reputation: $($ti.verdict.ToUpper()) ($tiLine)."
        }

        $isMalicious = (($ti.vt_malicious -ge 5) -or ($ti.abuse_score -ge 75))
        if ($isMalicious) {
          $curSev = [string]$f.sev
          if ($curSev -notin @('CRITICAL','HIGH')) {
            $f.sev = 'HIGH'
            Write-Output "enrich-ti: escalated $entity $curSev -> HIGH (MALICIOUS)"
          }
          # CRITICAL if attack also confirmed successful (HTTP 200 in evidence)
          if ([string]$f.evidence -match '\b200\b') {
            $f.sev = 'CRITICAL'
            Write-Output "enrich-ti: escalated $entity -> CRITICAL (MALICIOUS + confirmed 200)"
          }
        }
        $enriched++
        Write-Output "enrich-ti: $entity verdict=$($ti.verdict) sev=$($f.sev)"
      }
    } catch { Write-Output "enrich-ti: error on $entity - $_" }
  }
  $updated += $f
}

if ($enriched -gt 0) {
  $newJson = $updated | ConvertTo-Json -Depth 12 -Compress
  [System.IO.File]::WriteAllText($FindingsFile, $newJson, [System.Text.UTF8Encoding]::new($false))
  Write-Output "enrich-ti: updated $FindingsFile ($enriched IP(s) enriched)."
} else {
  Write-Output "enrich-ti: no unenriched public IPs in $([System.IO.Path]::GetFileName($FindingsFile))."
}
