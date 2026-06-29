# retry-targeted-noskill.ps1
# Targeted stale retry: reads coverage-gaps.json and runs the specific hunt key
# for each surface. More efficient than the generic daily-stale key because:
#   - Each surface uses its correct MCP scope (8-24 tools vs 32)
#   - Shorter turn budget (20-50t per surface vs 50t for all surfaces)
#   - MCP auth failure on one GL doesn't burn the whole retry budget
#
# Exits 0 when all gaps resolved or max passes reached (writes NOT HUNTED section).
# Exits 1 on token/session exhaustion - caller posts Teams alert and sets flag.

$ErrorActionPreference = 'Continue'
$proj      = 'D:\Vidhya\New Daily hunt'
$gapFile   = "$proj\reports-noskill\coverage-gaps.json"
$logFile   = "$proj\logs-noskill\daily.log"
$maxPasses = 2
$passesUsed = 0

$surfaceToKey = @{
    'iis'      = 'iis'
    'rdp'      = 'rdp'
    'azure'    = 'azure'
    'linux'    = 'linux'
    'sftp'     = 'sftp'
    'dtc'      = 'sftp'
    'firewall' = 'network'
    'switch'   = 'network'
    'lb'       = 'network'
    'db'       = 'db'
    'edr'      = 'infra'
    'mfa'      = 'infra'
    'virt'     = 'infra'
    'hw'       = 'infra'
    'app'      = 'app'
}

$keyToOutputFile = @{
    'iis'     = 'reports-noskill\iis-latest.md'
    'rdp'     = 'reports-noskill\rdp-latest.md'
    'azure'   = 'reports-noskill\azure-latest.md'
    'linux'   = 'reports-noskill\linux-latest.md'
    'sftp'    = 'reports-noskill\sftp-latest.md'
    'network' = 'reports-noskill\network-latest.md'
    'db'      = 'reports-noskill\db-latest.md'
    'infra'   = 'reports-noskill\infra-latest.md'
    'app'     = 'reports-noskill\app-latest.md'
}

for ($pass = 1; $pass -le ($maxPasses + 2); $pass++) {
    if ($passesUsed -ge $maxPasses) {
        Write-Output "[retry-targeted] Max productive passes ($maxPasses) reached."
        break
    }

    if (-not (Test-Path $gapFile)) {
        Write-Output "[retry-targeted pass $pass] No coverage-gaps.json - all surfaces covered."
        break
    }

    $parsed = $null
    try { $parsed = Get-Content $gapFile -Raw | ConvertFrom-Json }
    catch { Write-Output "[retry-targeted] coverage-gaps.json parse error: $_ - aborting."; break }

    $gaps = @($parsed | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
    if ($gaps.Count -eq 0) { Write-Output "[retry-targeted pass $pass] All surfaces covered."; break }

    Write-Output "[retry-targeted pass $pass (productive=$passesUsed/$maxPasses)] Gaps: $($gaps -join ', ')"

    # Map surfaces to unique hunt keys (dedup)
    $keysToRun = @($gaps | ForEach-Object {
        if ($surfaceToKey.ContainsKey($_)) { $surfaceToKey[$_] } else {
            Write-Output "[retry-targeted] No hunt key for surface '$_' - skipped"
            $null
        }
    } | Where-Object { $_ } | Sort-Object -Unique)

    if ($keysToRun.Count -eq 0) { Write-Output "[retry-targeted pass $pass] No valid keys for gaps."; break }
    Write-Output "[retry-targeted pass $pass] Running keys: $($keysToRun -join ', ')"

    $anyOutput = $false

    foreach ($key in $keysToRun) {
        $outRel  = $keyToOutputFile[$key]
        $outFile = if ($outRel) { "$proj\$outRel" } else { '' }

        # Remove prior stale file so we can detect fresh output
        if ($outFile -and (Test-Path $outFile)) {
            Remove-Item $outFile -Force -ErrorAction SilentlyContinue
        }

        Write-Output "[retry-targeted pass $pass] Key: $key"
        & powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\run-noskill-hunt.ps1" -Key $key

        # Check for exhaustion
        $tail = (Get-Content $logFile -Tail 120 -ErrorAction SilentlyContinue) -join ' '
        if ($tail -match 'session limit|weekly limit') {
            Write-Output "[retry-targeted pass $pass] Session/weekly limit hit - stopping retries."
            [System.IO.File]::WriteAllText("$proj\logs-noskill\token-exhausted.flag", (Get-Date -Format o), [System.Text.UTF8Encoding]::new($false))
            exit 1
        }
        if ($tail -match 'rate_limit_error|insufficient_quota|overloaded_error|too many requests|context window|credit') {
            Write-Output "[retry-targeted pass $pass] Token/API exhaustion on key $key - writing flag."
            [System.IO.File]::WriteAllText("$proj\logs-noskill\token-exhausted.flag", (Get-Date -Format o), [System.Text.UTF8Encoding]::new($false))
            exit 1
        }

        if ($outFile -and (Test-Path $outFile)) {
            Write-Output "[retry-targeted pass $pass] Key $key produced output - merging"
            & powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\merge-all-noskill.ps1"
            $anyOutput = $true
        } else {
            Write-Output "[retry-targeted pass $pass] WARNING: key $key - no output file written"
        }
    }

    if ($anyOutput) {
        $passesUsed++
        if (-not (Test-Path $gapFile)) { Write-Output "[retry-targeted pass $pass] All covered."; break }
        try {
            $newGaps = @(Get-Content $gapFile -Raw | ConvertFrom-Json | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
            if ($newGaps.Count -eq 0) { Write-Output "[retry-targeted pass $pass] All gaps closed."; break }
            Write-Output "[retry-targeted pass $pass] Remaining: $($newGaps -join ', ')"
        } catch { break }
    } else {
        # No output at all this pass - restore gaps so they persist for next hourly window
        $gapsJson = '[' + (($gaps | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
        [System.IO.File]::WriteAllText($gapFile, $gapsJson, [System.Text.UTF8Encoding]::new($false))
        Write-Output "[retry-targeted pass $pass] No output from any key - gaps preserved for next window."
    }
}

$finalGaps = if (Test-Path $gapFile) { $raw = Get-Content $gapFile -Raw; if ($raw) { $raw.Trim() } else { '[]' } } else { '[]' }
Write-Output "[retry-targeted] Complete. Final gaps: $finalGaps"

# Append NOT HUNTED section if gaps remain after max passes
if ($finalGaps -ne '[]' -and $finalGaps -ne '' -and $finalGaps -ne 'null') {
    try {
        $remaining = Get-Content $gapFile -Raw | ConvertFrom-Json
        $remainingSurfaces = @($remaining | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
        if ($remainingSurfaces.Count -gt 0) {
            $dailyMd = "$proj\reports-noskill\daily-latest.md"
            $notHuntedBlock = @"

## NOT HUNTED (targeted retry exhausted $maxPasses passes)

Surfaces below could not be assessed after $maxPasses targeted retry passes.
Hunt key ran but produced no output file. Manual Graylog review recommended.

| Surface | Status |
|---------|--------|
$(($remainingSurfaces | ForEach-Object { "| $_ | NOT HUNTED - no output after $maxPasses passes |" }) -join "`n")

> Cleared from retry queue. Re-run manually or check Graylog directly.
"@
            if (Test-Path $dailyMd) {
                Add-Content -Path $dailyMd -Value $notHuntedBlock -Encoding UTF8
                Write-Output "[retry-targeted] NOT HUNTED section appended for $($remainingSurfaces.Count) surface(s)"
            }
            [System.IO.File]::WriteAllText($gapFile, '[]', [System.Text.UTF8Encoding]::new($false))
            Write-Output "[retry-targeted] coverage-gaps.json cleared - surfaces documented in report"
        }
    } catch {
        Write-Output "[retry-targeted] WARNING: could not write NOT HUNTED block: $_"
    }
}

exit 0
