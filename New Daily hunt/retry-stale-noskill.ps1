# Retries surfaces listed in coverage-gaps.json that the main daily hunt could not reach.
# Called by daily-report-noskill.cmd after the main hunt exits.
# Exits 0 when all gaps resolved or max passes reached (best effort).
# Exits 1 on token/API exhaustion - caller posts Teams alert + writes flag for hourly retry.
#
# Pass accounting: a pass where the hunt produced NO output (stale-latest.md not written)
# does NOT count toward maxRetries so a silent crash doesn't waste the retry budget.
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$gapsFile="$proj\reports-noskill\coverage-gaps.json"
$stalePromptFile="$proj\noskill-prompts\daily-stale.txt"
$staleOut="$proj\reports-noskill\daily-stale-latest.md"
$logFile="$proj\logs-noskill\daily.log"
$maxRetries=2
$passesUsed=0

for($pass=1; $pass -le ($maxRetries + 2); $pass++){   # +2 headroom for no-output passes
    if($passesUsed -ge $maxRetries){
        Write-Output "[stale-retry] Max productive passes ($maxRetries) reached."
        break
    }

    if(-not (Test-Path $gapsFile)){
        Write-Output "[stale-retry] No coverage-gaps.json - all surfaces covered."
        break
    }
    try {
        $parsed = Get-Content $gapsFile -Raw | ConvertFrom-Json
        # Handle both formats: flat array ["sfc1",...] or nested {gaps:[...], _meta:{...}}
        if ($parsed -is [array]) {
            $gaps = @($parsed | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
        } elseif ($null -ne $parsed.gaps) {
            $gaps = @($parsed.gaps | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
        } else {
            $gaps = @()
        }
    }
    catch { Write-Output "[stale-retry] coverage-gaps.json parse error: $_ - aborting."; break }
    if($gaps.Count -eq 0){
        Write-Output "[stale-retry pass $pass] All surfaces covered."
        break
    }

    $surfaceList=$gaps -join ', '
    Write-Output "[stale-retry pass $pass (productive=$passesUsed/$maxRetries)] Surfaces: $surfaceList"

    # Write focused prompt for this pass
    $sp="STALE-RETRY FINAL PASS. A prior hunt this calendar day could not reach these surfaces: $surfaceList`nAssess ONLY those surfaces; skip all others entirely.`nRead D:\Vidhya\New Daily hunt\noskill-prompts\daily-single.txt for DETECTION LOGIC ONLY (HARD RULES, ALLOW-LIST, GEO-ACL, MITRE, per-surface signatures and verified field maps). IGNORE every output/file-writing instruction inside daily-single.txt - its 'write daily-latest.md / findings-<surface>.json / alert-<surface>.json' rules DO NOT apply to you.`nYou write EXACTLY ONE file: reports-noskill\daily-stale-latest.md (same format: ## AZ-GL / ## PROD-GL / ## DEV-GL / ## OP-GL sections, then a findings-json fenced block). Do NOT create or modify daily-latest.md, findings-<surface>.json, or alert-<surface>.json.`nMITRE tactic/killchain/mitre fields are mandatory. Read streams.json and infra-streams.json for stream IDs; never call list_streams; rangeSeconds=86400.`nIf an MCP call fails or returns no data after ONE try, leave that surface in the gap list and move on; do not retry failing calls.`nWHEN DONE you MUST have written daily-stale-latest.md, THEN update reports-noskill\coverage-gaps.json: write [] ONLY if daily-stale-latest.md assessed EVERY listed surface, otherwise a JSON array of the surfaces you could not assess. NEVER write [] unless daily-stale-latest.md exists."
    [System.IO.File]::WriteAllText($stalePromptFile,$sp,[System.Text.UTF8Encoding]::new($false))

    # Remove prior stale output
    if(Test-Path $staleOut){ Remove-Item $staleOut -Force -ErrorAction SilentlyContinue }

    & powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\run-noskill-hunt.ps1" -Key daily-stale
    $huntExit=$LASTEXITCODE

    # Detect token/API exhaustion
    $exhausted=$false
    if(Test-Path $logFile){
        $tail=(Get-Content $logFile -Tail 120 -ErrorAction SilentlyContinue) -join ' '
        if($tail -match 'rate_limit_error|insufficient_quota|overloaded_error|too many requests|context window|credit'){
            $exhausted=$true
        }
        # Daily session limit hit - stop retrying immediately, don't burn more session slots
        if($tail -match "session limit|weekly limit"){
            Write-Output "[stale-retry pass $pass] Session/weekly limit hit - stopping retries to preserve remaining session quota."
            [System.IO.File]::WriteAllText("$proj\logs-noskill\token-exhausted.flag",(Get-Date -Format o),[System.Text.UTF8Encoding]::new($false))
            exit 1
        }
    }
    if($exhausted -or $huntExit -ge 2){
        Write-Output "[stale-retry pass $pass] Token/API exhaustion (exitCode=$huntExit) - writing flag for 1h retry."
        [System.IO.File]::WriteAllText("$proj\logs-noskill\token-exhausted.flag",(Get-Date -Format o),[System.Text.UTF8Encoding]::new($false))
        exit 1
    }

    # GAP-CLOSURE REQUIRES PROOF OF ASSESSMENT (daily-stale-latest.md written THIS pass).
    # A session that produced no stale file is NEVER trusted to have closed gaps - even if it
    # left coverage-gaps.json=[] (a crashed/misbehaving session can do that; observed 2026-06-14
    # when the stale session wrote daily-latest.md + [] but no daily-stale-latest.md, and the old
    # code falsely declared "all gaps closed").
    if(Test-Path $staleOut){
        Write-Output "[stale-retry pass $pass] Output produced - merging into daily-latest.md."
        & powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\merge-findings-noskill.ps1"
        Remove-Item $staleOut -Force -ErrorAction SilentlyContinue
        $passesUsed++   # only count passes that actually produced output

        # Re-read gaps - trustworthy ONLY because real output was produced and merged this pass
        if(-not (Test-Path $gapsFile)){ Write-Output "[stale-retry pass $pass] Gaps file gone - all surfaces covered."; break }
        try {
            $np = Get-Content $gapsFile -Raw | ConvertFrom-Json
            $newGaps = if($np){ @($np | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' }) } else { @() }
        }
        catch { break }
        if($newGaps.Count -eq 0){ Write-Output "[stale-retry pass $pass] All gaps closed (assessed + merged)."; break }
        Write-Output "[stale-retry pass $pass] Still pending: $($newGaps -join ', ')"
    } else {
        # NO proof of assessment - do NOT trust coverage-gaps.json. Restore the surfaces we were
        # trying to cover so they PERSIST: the cmd then sets gaps-rerun.flag and the next hourly
        # trigger re-runs :gaps_only ("try at last"). Never break with "all gaps closed" here.
        $gapsJson = '[' + (($gaps | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
        [System.IO.File]::WriteAllText($gapsFile,$gapsJson,[System.Text.UTF8Encoding]::new($false))
        Write-Output "[stale-retry pass $pass] WARNING: no daily-stale-latest.md (crash/blocked or wrong output target). Restored $($gaps.Count) gap(s); NOT closing - retry this pass / next hourly run."
        # Do not increment $passesUsed so the loop retries the same surfaces (bounded by headroom)
    }
}

$finalGaps=if(Test-Path $gapsFile){ (Get-Content $gapsFile -Raw).Trim() } else { '[]' }
Write-Output "[stale-retry] Complete. Final coverage-gaps: $finalGaps"

# If gaps remain after max passes: write NOT HUNTED into the report and clear
# coverage-gaps.json so hourly :gaps_only does NOT keep retrying (saves tokens).
if($finalGaps -ne '[]' -and $finalGaps -ne '' -and $finalGaps -ne 'null'){
    try {
        $remaining = Get-Content $gapsFile -Raw | ConvertFrom-Json
        $remainingSurfaces = if ($remaining -is [array]) {
            @($remaining | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
        } elseif ($null -ne $remaining.gaps) {
            @($remaining.gaps | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
        } else { @() }

        if ($remainingSurfaces.Count -gt 0) {
            $dailyMd = "$proj\reports-noskill\daily-latest.md"
            $notHuntedBlock = @"

## NOT HUNTED (stale after $maxRetries retry passes)

The following surfaces could not be assessed in this run after $maxRetries stale retry attempts.
MCP calls failed or produced no output on both passes. Manual review recommended.

| Surface | Status |
|---------|--------|
$(($remainingSurfaces | ForEach-Object { "| $_ | NOT HUNTED - MCP/REST failed after $maxRetries passes |" }) -join "`n")

> These surfaces are cleared from the retry queue. Re-run manually or check Graylog directly.
"@
            if (Test-Path $dailyMd) {
                Add-Content -Path $dailyMd -Value $notHuntedBlock -Encoding UTF8
                Write-Output "[stale-retry] Appended NOT HUNTED section for $($remainingSurfaces.Count) surface(s) to daily-latest.md"
            }
            # Clear gaps so :gaps_only does not retry - report already documents the miss
            [System.IO.File]::WriteAllText($gapsFile,'[]',[System.Text.UTF8Encoding]::new($false))
            Write-Output "[stale-retry] coverage-gaps.json cleared - no further retries (surfaces documented in report)"
        }
    } catch {
        Write-Output "[stale-retry] WARNING: could not write NOT HUNTED block: $_"
    }
}

exit 0
