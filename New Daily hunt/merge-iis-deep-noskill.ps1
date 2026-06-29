# merge-iis-deep-noskill.ps1
# Folds the deep IIS hunt (iis-latest.md = full URI-content 14-class sweep over OP/PROD/AZ) into
# daily-latest.md, REPLACING the daily run's lighter IIS findings (surface=iis) with the deep ones.
# If the deep hunt produced nothing, the daily's (now mandatory URI-content) IIS triage is kept.
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$mainFile="$proj\reports-noskill\daily-latest.md"
$iisFile ="$proj\reports-noskill\iis-latest.md"
if(-not (Test-Path $iisFile)){ Write-Output 'merge-iis: no iis-latest.md (deep IIS produced no file) - keeping daily IIS triage.'; exit 0 }
if(-not (Test-Path $mainFile)){ Write-Output 'merge-iis: no daily-latest.md - cannot merge.'; exit 0 }
$clean={ param($s) ($s -replace '[^\x20-\x7E\r\n]','') }
$mainRaw=& $clean (Get-Content $mainFile -Raw)
$iisRaw =& $clean (Get-Content $iisFile -Raw)
function Get-Findings([string]$content){
  $m=[regex]::Match($content,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){ try{ $j=$m.Groups[1].Value | ConvertFrom-Json; return @($j) } catch { Write-Output "merge-iis: JSON parse error: $_" } }
  return @()
}
$mainF=Get-Findings $mainRaw
$iisF =@(Get-Findings $iisRaw | Where-Object { [string]$_.sev -ne 'CLEAN' })
if($iisF.Count -eq 0){ Write-Output 'merge-iis: deep IIS produced no non-clean findings - keeping daily IIS triage as-is.'; exit 0 }
# Drop the daily run's own IIS findings, keep all other surfaces, then add the deep IIS findings.
$kept   = @($mainF | Where-Object { [string]$_.surface -ne 'iis' })
$merged = @($kept) + @($iisF)
$newJson  = $merged | ConvertTo-Json -Depth 10 -Compress
$newBlock = '```findings-json' + "`n$newJson`n" + '```'
$newMain  = [regex]::Replace($mainRaw,'(?ms)```findings-json[\r\n]+.*?[\r\n]+```',$newBlock)
[System.IO.File]::WriteAllText($mainFile,$newMain,[System.Text.UTF8Encoding]::new($false))
Write-Output "merge-iis: replaced daily IIS with $($iisF.Count) deep-IIS finding(s); report now has $($merged.Count) findings."
