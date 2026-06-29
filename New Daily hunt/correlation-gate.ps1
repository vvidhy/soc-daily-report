# Conditional gate for the (token-expensive) cross-module correlation hunt.
# The correlation agent only earns its tokens when there is actually something to correlate.
# This deterministic check (zero Claude tokens) reads reports\_merged-findings.json and decides:
#   RUN the correlation agent  -> exit 1   (daily-report.cmd runs the claude -p step)
#   SKIP it                    -> exit 0   (this script writes a stub correlation-latest.md)
#
# Gate fires (RUN) when EITHER:
#   (a) any finding is HIGH or CRITICAL, OR
#   (b) any IP appears across >=2 DIFFERENT surfaces (the cross-surface pivot the single-surface
#       hunts cannot see) - this preserves chains built from individually MEDIUM/REVIEW pieces.
# Otherwise the day is quiet: skip the agent, write a valid stub so the freshness cross-check in
# generate-pdf.ps1 stays green, and rely on each finding's own query/investigate fields (already
# rendered in the PDF) for the analyst's manual pivot path.

$ErrorActionPreference = 'Stop'
$dir   = 'D:\Vidhya\New Daily hunt\reports'
$merged= Join-Path $dir '_merged-findings.json'
$stub  = Join-Path $dir 'correlation-latest.md'

# Casepoint Cato shared-egress IPs - never anchor a cross-surface pivot on these.
$cato = @('140.82.202.196','199.27.40.187','123.253.153.138')

function Write-Stub([string]$reason){
  $body = @"
## Kill Chains
No cross-surface or cross-environment kill chain reconstructed this run.

Correlation agent SKIPPED ($reason). The deterministic gate found nothing for it to correlate, so no Claude tokens were spent on this step. Per-finding pivots remain available: every surface finding in this report carries its own ``Graylog query used`` and ``Investigate further (run this)`` line - use those to pivot manually if needed.

## Correlated Entities
None - no IP appeared across two or more surfaces.

## Cross-Check Coverage
Gate evaluated all merged findings for (a) HIGH/CRITICAL severity and (b) any IP shared across >=2 surfaces. Neither condition met, so the correlation hunt was not run.

``````findings-json
[{"sev":"CLEAN","env":"ALL","surface":"correlation","finding":"No cross-surface chain; correlation agent gated off (quiet day)","evidence":"$reason","mitre":[],"action":"None - per-finding investigate queries available in report if manual pivot wanted","query":"","investigate":""}]
``````
"@
  [IO.File]::WriteAllText($stub, $body)
  Write-Output "correlation-gate: SKIP - $reason (stub written, 0 tokens)"
}

if(-not (Test-Path $merged)){
  Write-Stub "no _merged-findings.json (no findings to correlate)"
  exit 0
}

try { $findings = Get-Content $merged -Raw | ConvertFrom-Json } catch { $findings = @() }
if($null -eq $findings){ $findings = @() }
if($findings -isnot [array]){ $findings = @($findings) }

if($findings.Count -eq 0){
  Write-Stub "merged findings array empty"
  exit 0
}

# (a) HIGH / CRITICAL present?
$highCrit = @($findings | Where-Object { $_.sev -match '^(HIGH|CRITICAL)$' })
if($highCrit.Count -gt 0){
  Write-Output "correlation-gate: RUN - $($highCrit.Count) HIGH/CRITICAL finding(s) present"
  exit 1
}

# (b) any IP shared across >=2 distinct surfaces (ignore Cato egress + CLEAN entries)
$ipRegex = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
$ipToSurfaces = @{}
foreach($f in $findings){
  if($f.sev -eq 'CLEAN'){ continue }
  $surface = [string]$f.surface
  $text = ([string]$f.evidence) + ' ' + ([string]$f.finding)
  foreach($m in [regex]::Matches($text, $ipRegex)){
    $ip = $m.Value
    if($cato -contains $ip){ continue }
    if(-not $ipToSurfaces.ContainsKey($ip)){ $ipToSurfaces[$ip] = New-Object System.Collections.Generic.HashSet[string] }
    [void]$ipToSurfaces[$ip].Add($surface)
  }
}
$crossIp = $ipToSurfaces.GetEnumerator() | Where-Object { $_.Value.Count -ge 2 } | Select-Object -First 1
if($crossIp){
  Write-Output "correlation-gate: RUN - IP $($crossIp.Key) appears across surfaces: $($crossIp.Value -join ',')"
  exit 1
}

Write-Stub "no HIGH/CRITICAL and no cross-surface shared IP"
exit 0
