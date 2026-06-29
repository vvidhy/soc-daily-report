# extract-queries-noskill.ps1
# Collects every Graylog query that ran during the daily hunt into a single
# cache file: reports-noskill\query-cache.json
# Sources (in priority order):
#   1. alert-*.json files  (one per CRITICAL/HIGH finding, has a 'query' field)
#   2. findings-json block in daily-latest.md (all findings, has a 'query' field)
# Output schema per entry:
#   { date, surface, sev, finding, query, source }
# Non-fatal: if nothing found, writes an empty array.
$ErrorActionPreference = 'Continue'
$proj   = 'D:\Vidhya\New Daily hunt'
$out    = "$proj\reports-noskill\query-cache.json"
$date   = Get-Date -Format 'yyyy-MM-dd'
$clean  = { param($s) ($s -replace '[^\x20-\x7E\r\n]','') }
$results = [System.Collections.Generic.List[object]]::new()

# --- Source 1: alert-*.json (CRITICAL/HIGH per-finding files) ---
$alertFiles = Get-ChildItem "$proj\reports-noskill\alert-*.json" -EA SilentlyContinue
foreach ($f in $alertFiles) {
    try {
        $raw = & $clean (Get-Content $f.FullName -Raw)
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        $q = [string]$obj.query
        if ($q -and $q.Trim() -ne '') {
            $results.Add([pscustomobject]@{
                date    = $date
                surface = [string]$obj.surface
                sev     = [string]$obj.sev
                finding = [string]$obj.finding
                query   = $q.Trim()
                source  = 'alert-file'
            })
        }
    } catch { Write-Output "extract-queries: skipping $($f.Name) - $_" }
}

# --- Source 2: findings-json block in daily-latest.md ---
$mdFile = "$proj\reports-noskill\daily-latest.md"
if (Test-Path $mdFile) {
    try {
        $mdRaw = & $clean (Get-Content $mdFile -Raw)
        $m = [regex]::Match($mdRaw, '(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
        if ($m.Success) {
            $findings = @($m.Groups[1].Value | ConvertFrom-Json -ErrorAction Stop)
            # flatten {value:[...]} wrapper if present
            $flat = @()
            foreach ($it in $findings) {
                if ($null -ne $it -and $it.PSObject.Properties.Name -contains 'value' -and $it.PSObject.Properties.Name -notcontains 'sev') {
                    foreach ($s in @($it.value)) { if ($null -ne $s) { $flat += $s } }
                } else { $flat += $it }
            }
            foreach ($f in $flat) {
                $q = [string]$f.query
                if ($q -and $q.Trim() -ne '') {
                    # skip if already captured from alert file (same surface+finding)
                    $dup = $results | Where-Object { $_.surface -eq [string]$f.surface -and $_.finding -eq [string]$f.finding }
                    if (-not $dup) {
                        $results.Add([pscustomobject]@{
                            date    = $date
                            surface = [string]$f.surface
                            sev     = [string]$f.sev
                            finding = [string]$f.finding
                            query   = $q.Trim()
                            source  = 'daily-latest'
                        })
                    }
                }
            }
        }
    } catch { Write-Output "extract-queries: could not parse daily-latest.md - $_" }
}

$json = $results | ConvertTo-Json -Depth 5 -Compress
[System.IO.File]::WriteAllText($out, $json, [System.Text.UTF8Encoding]::new($false))
Write-Output "extract-queries: $($results.Count) queries cached -> reports-noskill\query-cache.json"
