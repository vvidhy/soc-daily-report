# merge-correlation-noskill.ps1
# Merges the opus correlation pass output (correlation-latest.md) into daily-latest.md
# so the cross-surface kill-chain findings appear in the PDF, CSV/workbook and Teams.
# Correlation findings use surface="correlation" so they never collide with surface hunts.
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$mainFile="$proj\reports-noskill\daily-latest.md"
$corrFile="$proj\reports-noskill\correlation-latest.md"
if(-not (Test-Path $corrFile)){ Write-Output 'merge-correlation: no correlation-latest.md - nothing to merge.'; exit 0 }
if(-not (Test-Path $mainFile)){ Write-Output 'merge-correlation: no daily-latest.md - cannot merge.'; exit 0 }
$clean={ param($s) ($s -replace '[^\x20-\x7E\r\n]','') }
$mainRaw=& $clean (Get-Content $mainFile -Raw)
$corrRaw=& $clean (Get-Content $corrFile -Raw)
function Get-Findings([string]$content){
  $m=[regex]::Match($content,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){ try{ $j=$m.Groups[1].Value | ConvertFrom-Json; return @($j) } catch { Write-Output "merge-correlation: JSON parse error: $_" } }
  return @()
}
$mainF=Get-Findings $mainRaw
$corrF=@(Get-Findings $corrRaw | Where-Object { [string]$_.sev -ne 'CLEAN' })
if($corrF.Count -eq 0){ Write-Output 'merge-correlation: no non-clean correlation findings - nothing to add.'; exit 0 }
$merged=@($mainF)+@($corrF)
$newJson=$merged | ConvertTo-Json -Depth 10 -Compress
$newBlock='```findings-json' + "`n$newJson`n" + '```'
$newMain=[regex]::Replace($mainRaw,'(?ms)```findings-json[\r\n]+.*?[\r\n]+```',$newBlock)
[System.IO.File]::WriteAllText($mainFile,$newMain,[System.Text.UTF8Encoding]::new($false))
Write-Output "merge-correlation: added $($corrF.Count) correlation finding(s) to daily-latest.md ($($merged.Count) total)."
