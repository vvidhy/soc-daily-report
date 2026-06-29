# run-sub-hunt.ps1
# Non-fatal wrapper: runs one focused surface hunt, detects token exhaustion,
# and marks the surface as a coverage gap if exhausted. Always exits 0 so the
# pipeline continues to the next surface hunt regardless.
param(
    [Parameter(Mandatory=$true)][string]$Key,      # hunt key in noskill-hunts.json
    [Parameter(Mandatory=$true)][string]$Surfaces  # comma-separated surface names for coverage-gaps.json
)
$ErrorActionPreference = 'Continue'
$proj    = 'D:\Vidhya\New Daily hunt'
$logFile = "$proj\logs-noskill\daily.log"
$gapFile = "$proj\reports-noskill\coverage-gaps.json"

# Resume checkpoint: skip if this key already produced a valid findings-json today.
# Prevents re-running completed surfaces when the pipeline is restarted after a
# token-limit interruption mid-run.
$keyToOutput = @{
    'iis'='iis-latest.md'; 'rdp'='rdp-latest.md'; 'azure'='azure-latest.md'
    'linux'='linux-latest.md'; 'sftp'='sftp-latest.md'; 'network'='network-latest.md'
    'db'='db-latest.md'; 'infra'='infra-latest.md'; 'app'='app-latest.md'
    'app-pt'='app-pt-latest.md'; 'dev'='dev-latest.md'
}
if ($keyToOutput.ContainsKey($Key)) {
    $outFile = "$proj\reports-noskill\$($keyToOutput[$Key])"
    if (Test-Path $outFile) {
        $writtenDate = (Get-Item $outFile).LastWriteTime.Date
        $today       = (Get-Date).Date
        $content     = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
        if ($writtenDate -ge $today -and $content -match 'findings-json') {
            Write-Output "[$(Get-Date -Format HH:mm:ss)] run-sub-hunt: KEY=$Key already completed today - SKIPPING (resume)"
            exit 0
        }
    }
}

Write-Output "[$(Get-Date -Format HH:mm:ss)] run-sub-hunt: KEY=$Key SURFACES=$Surfaces starting"

& powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\run-noskill-hunt.ps1" -Key $Key

# Check the log tail for token / API exhaustion
$logTail = Get-Content $logFile -Tail 120 -ErrorAction SilentlyContinue
$logText = ($logTail -join ' ')
$exhausted = $logText -match 'rate_limit_error|insufficient_quota|overloaded_error|too many requests|context window|credit|session limit|weekly limit'

if ($exhausted) {
    Write-Output "[$(Get-Date -Format HH:mm:ss)] run-sub-hunt: KEY=$Key token/API exhausted - marking as gap, pipeline continues"

    $existing = @()
    if (Test-Path $gapFile) {
        try { $existing = @(Get-Content $gapFile -Raw | ConvertFrom-Json | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' }) } catch {}
    }
    $newSurfaces = $Surfaces -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    $merged = @($existing + $newSurfaces | Sort-Object -Unique)
    [System.IO.File]::WriteAllText($gapFile, ($merged | ConvertTo-Json -Depth 2), [System.Text.UTF8Encoding]::new($false))
    Write-Output "[$(Get-Date -Format HH:mm:ss)] run-sub-hunt: KEY=$Key gap written: $($newSurfaces -join ', ')"
} else {
    Write-Output "[$(Get-Date -Format HH:mm:ss)] run-sub-hunt: KEY=$Key complete"
}

exit 0
