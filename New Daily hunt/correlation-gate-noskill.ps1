# NO-SKILL pipeline copy of correlation-gate.ps1 (reports-noskill dir).
# Deterministic gate (zero Claude tokens): RUN correlation (exit 1) when EITHER any finding is
# HIGH/CRITICAL OR any non-Cato IP appears across >=2 surfaces; otherwise write a stub and SKIP (exit 0).

$ErrorActionPreference = 'Stop'
$dir   = 'D:\Vidhya\New Daily hunt\reports-noskill'
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
  Write-Output "correlation-gate (noskill): SKIP - $reason (stub written, 0 tokens)"
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
  Write-Output "correlation-gate (noskill): RUN - $($highCrit.Count) HIGH/CRITICAL finding(s) present"
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
  Write-Output "correlation-gate (noskill): RUN - IP $($crossIp.Key) appears across surfaces: $($crossIp.Value -join ',')"
  exit 1
}

Write-Stub "no HIGH/CRITICAL and no cross-surface shared IP"
exit 0
