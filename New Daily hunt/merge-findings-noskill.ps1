# Merges daily-stale-latest.md findings into daily-latest.md after a stale-retry pass.
# Updates coverage-gaps.json to remove surfaces that are now covered.
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$mainFile="$proj\reports-noskill\daily-latest.md"
$staleFile="$proj\reports-noskill\daily-stale-latest.md"
$gapsFile="$proj\reports-noskill\coverage-gaps.json"

if(-not (Test-Path $staleFile)){ Write-Output "merge: no stale file to merge."; exit 0 }
if(-not (Test-Path $mainFile)){
    Write-Output "merge: no main file - promoting stale to daily-latest.md."
    Copy-Item $staleFile $mainFile -Force; exit 0
}

$clean={ param($s) ($s -replace '[^\x20-\x7E\r\n]','') }
$mainRaw=& $clean (Get-Content $mainFile -Raw)
$staleRaw=& $clean (Get-Content $staleFile -Raw)

function Get-Findings([string]$content){
    $m=[regex]::Match($content,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
    if($m.Success){ try{ $j=$m.Groups[1].Value | ConvertFrom-Json; return @($j) } catch{ Write-Output "merge: JSON parse error: $_" } }
    return @()
}

$mainF=Get-Findings $mainRaw
$staleF=Get-Findings $staleRaw
if($staleF.Count -eq 0){ Write-Output "merge: stale file has no findings-json block - nothing to merge."; exit 0 }

# Supplement: add stale findings only for env+surface combos not already in main
$mainKeys=@{}
foreach($r in $mainF){ $mainKeys["$([string]$r.env)|$([string]$r.surface)"]=$true }
$toAdd=@($staleF | Where-Object { -not $mainKeys.ContainsKey("$([string]$_.env)|$([string]$_.surface)") })
$merged=@($mainF)+@($toAdd)
Write-Output "merge: $($mainF.Count) main + $($toAdd.Count) from stale = $($merged.Count) total findings."

# Replace the findings-json block in the main file
$newJson=$merged | ConvertTo-Json -Depth 10 -Compress
$newBlock='```findings-json' + "`n$newJson`n" + '```'
$newMain=[regex]::Replace($mainRaw,'(?ms)```findings-json[\r\n]+.*?[\r\n]+```',$newBlock)
[System.IO.File]::WriteAllText($mainFile,$newMain,[System.Text.UTF8Encoding]::new($false))
Write-Output "merge: daily-latest.md updated ($($merged.Count) total findings)."

# Refresh coverage-gaps.json: remove surfaces that now have findings in the merged set
if(Test-Path $gapsFile){
    try {
        $gaps=@(Get-Content $gapsFile -Raw | ConvertFrom-Json | ForEach-Object { [string]$_ })
        $covered=@($merged | ForEach-Object { [string]$_.surface } | Sort-Object -Unique)
        $remaining=@($gaps | Where-Object { $_ -notin $covered })
        $remaining | ConvertTo-Json | Set-Content $gapsFile -Encoding utf8
        Write-Output "merge: coverage-gaps.json updated - $($remaining.Count) surface(s) still pending: $($remaining -join ', ')"
    } catch { Write-Output "merge: coverage-gaps.json update failed: $_" }
}
