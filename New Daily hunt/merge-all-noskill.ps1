# merge-all-noskill.ps1
# Assembles reports-noskill\daily-latest.md from all surface *-latest.md files
# produced by focused sub-hunts. Also rebuilds coverage-gaps.json with the
# authoritative list of surfaces that still have no valid output.
# Called after all 11 sub-hunts complete, and again after each targeted retry pass.

$ErrorActionPreference = 'Continue'
$proj = 'D:\Vidhya\New Daily hunt'
$rpt  = "$proj\reports-noskill"

# File -> surfaces it covers (insertion-ordered: last wins on duplicates)
$surfaceMap = [ordered]@{
    'iis-latest.md'     = @('iis')
    'rdp-latest.md'     = @('rdp')
    'azure-latest.md'   = @('azure')
    'linux-latest.md'   = @('linux')
    'sftp-latest.md'    = @('sftp','dtc')
    'network-latest.md' = @('firewall','switch','lb')
    'db-latest.md'      = @('db')
    'infra-latest.md'   = @('edr','mfa','virt','hw')
    'app-latest.md'     = @('app')
    'app-pt-latest.md'  = @('app')
    'dev-latest.md'     = @('linux','rdp','iis','sftp','dtc','azure','firewall','app')
}

function Get-FindingsBlock([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    $raw = [System.IO.File]::ReadAllText($path)
    $raw = $raw -replace '[^\x20-\x7E\r\n]', ''
    $m = [regex]::Match($raw, '(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
    if (-not $m.Success) { return $null }
    try { return @($m.Groups[1].Value | ConvertFrom-Json) }
    catch { Write-Output "merge-all: JSON parse error in $path : $_"; return $null }
}

function Get-MarkdownBody([string]$path) {
    if (-not (Test-Path $path)) { return '' }
    $raw = [System.IO.File]::ReadAllText($path)
    $raw = $raw -replace '[^\x20-\x7E\r\n]', ''
    return ([regex]::Replace($raw, '(?ms)```findings-json[\r\n]+.*?[\r\n]+```', '')).Trim()
}

$allFindings  = [System.Collections.Generic.List[object]]::new()
$gaps         = [System.Collections.Generic.List[string]]::new()
$coveredSurfs = [System.Collections.Generic.HashSet[string]]::new()
$mdSections   = [System.Collections.Generic.List[string]]::new()

$dt = Get-Date -Format 'yyyy-MM-dd HH:mm'
$mdSections.Add("# SOC Daily Hunt Report -- $dt`n")
$mdSections.Add("**Coverage:** iis / rdp / azure / linux / sftp / network / db / infra / app / app-pt / dev`n")
$mdSections.Add("---`n")

foreach ($entry in $surfaceMap.GetEnumerator()) {
    $file     = $entry.Key
    $surfaces = $entry.Value
    $path     = "$rpt\$file"

    $findings = Get-FindingsBlock $path

    if ($null -eq $findings) {
        # File missing or no findings-json block -> gap (only add surfaces not yet covered)
        foreach ($s in $surfaces) {
            if (-not $coveredSurfs.Contains($s) -and $s -notin $gaps) {
                $gaps.Add($s)
            }
        }
        Write-Output "merge-all: $file - no output -> gap: $($surfaces | Where-Object { -not $coveredSurfs.Contains($_) } | Select-Object -Unique)"
    } else {
        # Valid findings-json -> covered; remove from gaps if previously added
        foreach ($s in $surfaces) {
            [void]$coveredSurfs.Add($s)
            $gaps.Remove($s)
        }
        foreach ($f in $findings) { $allFindings.Add($f) }
        $nonClean = @($findings | Where-Object { [string]$_.sev -ne 'CLEAN' })
        Write-Output "merge-all: $file - $($findings.Count) findings ($($nonClean.Count) non-CLEAN)"
    }

    # Append markdown narrative
    $body = Get-MarkdownBody $path
    if ($body) {
        $label = ($file -replace '-latest\.md$','').ToUpper()
        $mdSections.Add("## $label`n`n$body`n`n---`n")
    }
}

# Write authoritative coverage-gaps.json
$gapFile   = "$rpt\coverage-gaps.json"
$finalGaps = @($gaps | Sort-Object -Unique)
[System.IO.File]::WriteAllText($gapFile, ($finalGaps | ConvertTo-Json -Depth 2), [System.Text.UTF8Encoding]::new($false))
if ($finalGaps.Count -gt 0) {
    Write-Output "merge-all: coverage gaps -> $($finalGaps -join ', ')"
} else {
    Write-Output "merge-all: all surfaces covered"
}

# Build daily-latest.md
$mdBody  = ($mdSections -join "`n")
$jsonArr = if ($allFindings.Count -eq 0) { '[]' } else { @($allFindings) | ConvertTo-Json -Depth 10 -Compress }
$block   = '```findings-json' + "`n" + $jsonArr + "`n" + '```'
$fullMd  = $mdBody + "`n`n" + $block

[System.IO.File]::WriteAllText("$rpt\daily-latest.md", $fullMd, [System.Text.UTF8Encoding]::new($false))
Write-Output "merge-all: daily-latest.md written -- $($allFindings.Count) findings, $($finalGaps.Count) gap(s)"
