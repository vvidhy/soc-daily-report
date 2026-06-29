# build-correlation-queries.ps1
# Zero-token script for MEDIUM and LOW findings only.
# HIGH/CRITICAL findings get full Opus cross-surface correlation (prep-correlation-noskill.ps1).
# Reads findings-json from daily-latest.md, extracts IPs/users from MEDIUM/LOW findings,
# generates structured cross-surface Graylog queries, and writes:
#   reports-noskill\correlation-queries.json  <- read by generate-pdf-noskill.ps1 for the PDF

$ErrorActionPreference = 'Continue'
$proj     = 'D:\Vidhya\New Daily hunt'
$alertDir = "$proj\reports-noskill"
$dailyMd  = "$alertDir\daily-latest.md"
$outJson  = "$alertDir\correlation-queries.json"

if (-not (Test-Path $dailyMd)) {
    Write-Output "[corr-queries] No daily-latest.md - nothing to correlate."
    exit 0
}

$ips      = [System.Collections.Generic.HashSet[string]]::new()
$users    = [System.Collections.Generic.HashSet[string]]::new()
$surfaces = [System.Collections.Generic.HashSet[string]]::new()

# Per-finding list so we can attach the source finding to each query row
$medLowFindings = [System.Collections.Generic.List[object]]::new()

$mdText = Get-Content $dailyMd -Raw -ErrorAction SilentlyContinue
if ($mdText) {
    $jMatch = [regex]::Match($mdText, '(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
    if ($jMatch.Success) {
        try {
            $parsed = $jMatch.Groups[1].Value | ConvertFrom-Json
            # Unwrap {value:[...]} wrapper if present
            if ($parsed -isnot [array] -and $parsed.PSObject.Properties['value'] -and
                -not $parsed.PSObject.Properties['sev']) { $parsed = $parsed.value }

            foreach ($f in @($parsed)) {
                $sev = [string]$f.sev
                if ($sev -notin @('MEDIUM','LOW')) { continue }
                $medLowFindings.Add($f)
                if ($f.surface) { [void]$surfaces.Add([string]$f.surface) }
                $text = [string]$f.finding + ' ' + [string]$f.evidence + ' ' + [string]$f.detail
                # IPs
                [regex]::Matches($text, '\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b') |
                    ForEach-Object { [void]$ips.Add($_.Value) }
                # casepoint users
                [regex]::Matches($text, '\b[\w.\-]+@casepoint\.(com|in)\b', 'IgnoreCase') |
                    ForEach-Object { [void]$users.Add($_.Value) }
            }
        } catch { Write-Output "[corr-queries] findings-json parse error: $_" }
    }
}

foreach ($drop in @('127.0.0.1','0.0.0.0','255.255.255.255')) { [void]$ips.Remove($drop) }

if ($medLowFindings.Count -eq 0) {
    Write-Output "[corr-queries] No MEDIUM/LOW findings - no manual correlation queries needed."
    # Write empty array so PDF generator knows the section is intentionally empty
    [System.IO.File]::WriteAllText($outJson, '[]', [System.Text.UTF8Encoding]::new($false))
    exit 0
}

Write-Output "[corr-queries] $($medLowFindings.Count) MEDIUM/LOW findings. IPs: $($ips.Count), Users: $($users.Count)"

# Build structured query objects
$rows = [System.Collections.Generic.List[object]]::new()

foreach ($ip in ($ips | Sort-Object)) {
    $rows.Add([pscustomobject]@{
        label   = "IP cross-surface"
        pivot   = $ip
        surface = "all"
        sev     = "pivot"
        query   = "Client_ip:`"$ip`" OR src_ip:`"$ip`" OR source_ip:`"$ip`" OR properties_callerIpAddress:`"$ip`" OR message:`"$ip`""
        note    = "Run across all 4 Graylogs. rangeSeconds=86400"
    })
}

foreach ($u in ($users | Sort-Object)) {
    $safe = $u -replace '"','`"'
    $rows.Add([pscustomobject]@{
        label   = "User cross-surface"
        pivot   = $u
        surface = "all"
        sev     = "pivot"
        query   = "properties_userPrincipalName:`"$u`" OR properties_userId:`"$u`" OR message:`"$u`""
        note    = "Run across all 4 Graylogs. rangeSeconds=86400"
    })
}

# Surface-pair patterns
if (($surfaces -contains 'azure') -or ($surfaces -contains 'rdp')) {
    $rows.Add([pscustomobject]@{
        label   = "Azure→RDP pivot"
        pivot   = "Azure MEDIUM/LOW user → Windows RDP"
        surface = "azure + windows"
        sev     = "pattern"
        query   = "EventID:4624 OR EventID:4625 OR EventID:4648"
        note    = "Run on PROD-GL / AZ-GL. Cross-reference with Azure MEDIUM/LOW user accounts"
    })
}
if (($surfaces -contains 'iis') -or ($surfaces -contains 'azure')) {
    $rows.Add([pscustomobject]@{
        label   = "IIS→Azure correlation"
        pivot   = "IIS attacker IP in Azure failed auth"
        surface = "iis + azure"
        sev     = "pattern"
        query   = "result_value:`"Failure`" AND properties_callerIpAddress:*"
        note    = "Run on AZ-GL. Filter by IPs from IIS MEDIUM/LOW findings above"
    })
}
if (($surfaces -contains 'sftp') -or ($surfaces -contains 'linux')) {
    $rows.Add([pscustomobject]@{
        label   = "SFTP→Linux lateral"
        pivot   = "SFTP brute-force IP in Linux SSH"
        surface = "sftp + linux"
        sev     = "pattern"
        query   = "message:*Failed password* OR message:*Invalid user*"
        note    = "Run on PROD-GL. Cross-reference SFTP client IPs with Linux auth failures"
    })
}
if (($surfaces -contains 'network') -or ($surfaces -contains 'firewall')) {
    $rows.Add([pscustomobject]@{
        label   = "FortiGate→IIS web"
        pivot   = "FortiGate-blocked IP probing IIS"
        surface = "network + iis"
        sev     = "pattern"
        query   = "action:deny AND proto:6"
        note    = "Run on PROD-GL. Cross-reference denied src IPs with IIS URI_Stream findings"
    })
}

# Attach per-finding queries using the hunt's own .query field if present
foreach ($f in $medLowFindings) {
    $fq = [string]$f.query
    if ($fq -and $fq -ne 'n/a') {
        $rows.Add([pscustomobject]@{
            label   = "Re-run: $([string]$f.sev) $([string]$f.surface)"
            pivot   = [string]$f.finding
            surface = [string]$f.surface
            sev     = [string]$f.sev
            query   = $fq
            note    = "Original detection query from the hunt. Widen time range to pivot further"
        })
    }
}

$json = $rows | ConvertTo-Json -Depth 4 -Compress
[System.IO.File]::WriteAllText($outJson, $json, [System.Text.UTF8Encoding]::new($false))
Write-Output "[corr-queries] Wrote $($rows.Count) query rows to correlation-queries.json"
exit 0
