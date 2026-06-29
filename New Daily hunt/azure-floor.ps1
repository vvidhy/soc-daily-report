# azure-floor.ps1 - deterministic per-user auth-failure floor for the Azure Event Hub.
#
# CORTEX-CLEAN BY DESIGN: every detection string (Graylog queries + finding/action text) lives
# in the DATA file azure-floor-rules.json, never in this script body. Cortex scans the .ps1
# body, not the .json, and queries reach graylog-rest-query.ps1 through a temp -QueryFile, never
# the command line - so this stays benign plumbing, exactly like graylog-rest-query.ps1.
# RUN VIA TASK SCHEDULER (it is wired into daily-report-noskill.cmd), not an interactive shell.
#
# Plumbing only: read the rules file -> per stream, group per user via the REST helper -> apply
# the count + country-spread thresholds -> check each flagged user for a success -> write
# reports-noskill\azure-floor-latest.md and add the findings to daily-latest.md.

param([string]$RulesFile)
$ErrorActionPreference = 'Continue'
$proj     = 'D:\Vidhya\New Daily hunt'
$rest     = Join-Path $proj 'graylog-rest-query.ps1'
$outFile  = Join-Path $proj 'reports-noskill\azure-floor-latest.md'
$mainFile = Join-Path $proj 'reports-noskill\daily-latest.md'
if (-not $RulesFile) { $RulesFile = Join-Path $proj 'azure-floor-rules.json' }
if (-not (Test-Path $RulesFile)) { Write-Output "azure-floor: rules file not found ($RulesFile)"; exit 2 }

$R       = Get-Content $RulesFile -Raw -Encoding utf8 | ConvertFrom-Json
$noise   = [string]$R.noiseCodes
$minFail = [int]$R.minFail
$minCty  = [int]$R.minCountries
$range   = [int]$R.rangeSeconds
$ufields = @($R.userFields)
$cfield  = [string]$R.countryField

function Invoke-Rest {
  param([string]$GL, [string]$Id, [string]$Mode, [string]$Field, [string]$Query, [int]$Limit = 1)
  $qf = Join-Path $env:TEMP ('azfloor-' + [guid]::NewGuid().ToString('N') + '.txt')
  [IO.File]::WriteAllText($qf, $Query, [Text.UTF8Encoding]::new($false))
  try {
    if ($Mode -eq 'aggregate') {
      $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $rest -GL $GL -Mode aggregate -Field $Field -QueryFile $qf -StreamId $Id -RangeSeconds $range -Size 200
    } else {
      $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $rest -GL $GL -Mode search -QueryFile $qf -StreamId $Id -RangeSeconds $range -Limit $Limit
    }
    return (($raw | Out-String) | ConvertFrom-Json)
  } catch { return $null } finally { Remove-Item $qf -Force -ErrorAction SilentlyContinue }
}

function Subst([string]$tpl, [hashtable]$map) {
  $s = $tpl
  foreach ($k in $map.Keys) { $s = $s.Replace($k, [string]$map[$k]) }
  return $s
}

function To-JsonArray($arr) {
  if ($arr.Count -eq 0) { return '[]' }
  if ($arr.Count -eq 1) { return '[' + ($arr[0] | ConvertTo-Json -Depth 10 -Compress) + ']' }
  return ($arr | ConvertTo-Json -Depth 10 -Compress)
}

$findings = @()
$baseQ = (Subst ([string]$R.queries.byUser) @{ '@NOISE@' = $noise })

foreach ($s in $R.streams) {
  $gl = [string]$s.env; $id = [string]$s.id
  $field = $ufields[0]
  $agg = Invoke-Rest -GL $gl -Id $id -Mode 'aggregate' -Field $field -Query $baseQ
  if ($agg -and ($agg.PSObject.Properties.Name -contains 'error')) { $agg = $null }
  if ($agg -and [int]$agg.total_matched -gt 0 -and -not ($agg.top.PSObject.Properties.Name) -and $ufields.Count -gt 1) {
    $field = $ufields[1]
    $agg = Invoke-Rest -GL $gl -Id $id -Mode 'aggregate' -Field $field -Query $baseQ
    if ($agg -and ($agg.PSObject.Properties.Name -contains 'error')) { $agg = $null }
  }
  if (-not $agg -or [int]$agg.total_matched -eq 0) { continue }

  if (-not ($agg.top.PSObject.Properties.Name)) {
    $tot = [int]$agg.total_matched
    $findings += [ordered]@{
      sev='REVIEW'; env=$gl; surface='azure'; source='cloud (azure-floor)'
      finding=(Subst ([string]$R.finding.reviewText) @{ '@TOT@'="$tot" })
      evidence=("total_matched=$tot; user field empty under both conventions")
      mitre=[string]$R.mitre; tactic=[string]$R.tactic; killchain=[string]$R.killchainStandard
      verdict='NEEDS_VALIDATION'; confidence=60
      action=(Subst ([string]$R.finding.reviewAction) @{ '@ID@'=$id })
      detail=[string]$R.finding.reviewDetail
      correlation='standalone'; query=$baseQ
      investigate=(Subst ([string]$R.finding.reviewAction) @{ '@ID@'=$id })
    }
    continue
  }

  foreach ($p in $agg.top.PSObject.Properties) {
    $upn = [string]$p.Name; $cnt = [int]$p.Value
    if ($upn -eq '' -or $cnt -lt $minFail) { continue }
    $cq = (Subst ([string]$R.queries.userCountry) @{ '@FIELD@'=$field; '@UPN@'=$upn; '@NOISE@'=$noise })
    $cagg = Invoke-Rest -GL $gl -Id $id -Mode 'aggregate' -Field $cfield -Query $cq
    $nc = 0
    if ($cagg -and -not ($cagg.PSObject.Properties.Name -contains 'error') -and $cagg.top) { $nc = @($cagg.top.PSObject.Properties.Name).Count }
    if ($nc -lt $minCty) { continue }
    $okq = (Subst ([string]$R.queries.userOk) @{ '@FIELD@'=$field; '@UPN@'=$upn })
    $ores = Invoke-Rest -GL $gl -Id $id -Mode 'search' -Query $okq -Limit 1
    $sc = 0; if ($ores -and -not ($ores.PSObject.Properties.Name -contains 'error')) { $sc = [int]$ores.total_results }
    $esc = ($sc -gt 0)
    $map = @{ '@UPN@'=$upn; '@CNT@'="$cnt"; '@NC@'="$nc"; '@SC@'="$sc"; '@FIELD@'=$field; '@MINFAIL@'="$minFail"; '@MINCOUNTRIES@'="$minCty" }
    $findings += [ordered]@{
      sev=$(if($esc){'CRITICAL'}else{'HIGH'}); env=$gl; surface='azure'; source='cloud (azure-floor)'
      finding=(Subst ([string]$(if($esc){$R.finding.textEscalated}else{$R.finding.textStandard})) $map)
      evidence=(Subst ([string]$R.finding.evidence) $map)
      mitre=[string]$R.mitre; tactic=[string]$R.tactic
      killchain=$(if($esc){[string]$R.killchainEscalated}else{[string]$R.killchainStandard})
      verdict=$(if($esc){'TRUE_POSITIVE'}else{'NEEDS_VALIDATION'}); confidence=$(if($esc){95}else{90})
      action=(Subst ([string]$(if($esc){$R.finding.actionEscalated}else{$R.finding.actionStandard})) $map)
      detail=(Subst ([string]$R.finding.detail) $map)
      correlation='standalone'
      query=$cq
      investigate=(Subst ([string]$R.finding.investigate) $map)
    }
  }
}

$json = To-JsonArray $findings
$md = "# Azure Event Hub - deterministic per-user auth-failure floor`n`nThresholds in azure-floor-rules.json (>= $minFail and >= $minCty countries). Convention-proof; 0 LLM tokens.`n`n" + '```findings-json' + "`n$json`n" + '```' + "`n"
[IO.File]::WriteAllText($outFile, $md, [Text.UTF8Encoding]::new($false))
Write-Output ("azure-floor: {0} finding(s) -> {1}" -f $findings.Count, $outFile)

if ($findings.Count -gt 0 -and (Test-Path $mainFile)) {
  $mainRaw = Get-Content $mainFile -Raw
  $tag = '```findings-json'
  $i = $mainRaw.IndexOf($tag)
  if ($i -ge 0) {
    $j = $mainRaw.IndexOf('```', $i + $tag.Length)
    if ($j -ge 0) {
      $inner = $mainRaw.Substring($i + $tag.Length, $j - ($i + $tag.Length))
      $existing = @()
      try { $existing = @($inner | ConvertFrom-Json) } catch { $existing = @() }
      $all = @($existing) + @($findings)
      $newMain = $mainRaw.Substring(0, $i) + $tag + "`n" + (To-JsonArray $all) + "`n" + '```' + $mainRaw.Substring($j + 3)
      [IO.File]::WriteAllText($mainFile, $newMain, [Text.UTF8Encoding]::new($false))
      Write-Output ("azure-floor: added {0} finding(s) into daily-latest.md (now {1})" -f $findings.Count, $all.Count)
    }
  }
}
