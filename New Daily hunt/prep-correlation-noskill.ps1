# prep-correlation-noskill.ps1
# Builds reports-noskill\_merged-findings.json (the ONLY input the opus correlation
# pass reads) from the non-CLEAN findings in daily-latest.md, and writes
# logs-noskill\run-correlation.flag ONLY if >=2 non-clean findings exist - a
# cross-surface kill chain needs at least two findings to link. If <2, the
# correlation pass is skipped (nothing to correlate).
# (daily-latest.md is the single consolidated report after the main + stale merge,
#  so it holds every surface finding; reading it alone avoids double-counting.)
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$rf="$proj\reports-noskill\daily-latest.md"
$out="$proj\reports-noskill\_merged-findings.json"
$flag="$proj\logs-noskill\run-correlation.flag"
if(Test-Path $flag){ Remove-Item $flag -Force -ErrorAction SilentlyContinue }
if(-not (Test-Path $rf)){ Write-Output 'prep-correlation: no daily-latest.md - skip'; exit 0 }
$raw=(Get-Content $rf -Raw) -replace '[^\x20-\x7E\r\n]',''
$m=[regex]::Match($raw,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
if(-not $m.Success){ Write-Output 'prep-correlation: no findings-json block - skip'; exit 0 }
$arr=@(); try{ $parsed=$m.Groups[1].Value | ConvertFrom-Json; $arr=@($parsed) } catch { Write-Output 'prep-correlation: JSON parse error - skip'; exit 0 }
# Flatten any {value:[...],Count:N} wrapper objects. The hunt sometimes nests the
# findings array inside a wrapper instead of a flat list; without this the wrapper
# slims to an empty stub and the 25+ real findings trapped inside .value never reach
# the merge (this is what reduced _merged-findings.json to 1 finding on 2026-06-16).
$flat=[System.Collections.Generic.List[object]]::new()
foreach($item in @($arr)){
  $props=@($item.PSObject.Properties.Name)
  if(($props -contains 'value') -and ($props -notcontains 'sev')){
    foreach($sub in @($item.value)){ if($null -ne $sub){ $flat.Add($sub) } }
  } else { $flat.Add($item) }
}
$arr=@($flat)
$nonclean=@($arr | Where-Object { [string]$_.sev -ne 'CLEAN' })
$highCrit=@($nonclean | Where-Object { [string]$_.sev -in @('HIGH','CRITICAL') })

# Opus correlation only runs when there is >=1 HIGH or CRITICAL finding.
# MEDIUM/LOW get paste-ready Graylog queries via build-correlation-queries.ps1 (0 tokens).
if($highCrit.Count -eq 0){
    Write-Output "prep-correlation: no HIGH/CRITICAL findings ($($nonclean.Count) non-clean total) - skipping Opus correlation. MEDIUM/LOW queries will be generated."
    exit 0
}

# Project to the keys the correlation prompt expects (include tactic/killchain so the pass can extend existing chains)
# Pass ALL non-clean findings so Opus can see the full picture, but flag which are HIGH/CRITICAL
$slim=@($nonclean | ForEach-Object { [pscustomobject]@{ sev=[string]$_.sev; env=[string]$_.env; surface=[string]$_.surface; finding=[string]$_.finding; evidence=[string]$_.evidence; mitre=[string]$_.mitre; tactic=[string]$_.tactic; killchain=[string]$_.killchain; action=[string]$_.action } })
($slim | ConvertTo-Json -Depth 6 -Compress) | Set-Content $out -Encoding utf8
[System.IO.File]::WriteAllText($flag,(Get-Date -Format o))
Write-Output "prep-correlation: wrote _merged-findings.json ($($nonclean.Count) findings, $($highCrit.Count) HIGH/CRITICAL) - Opus correlation will run."
