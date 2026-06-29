# ip-rep-cache.ps1 — shared IP reputation lookup with persistent cache
# Usage: . .\ip-rep-cache.ps1
#        $rep = Get-IpReputation "1.2.3.4"
#        if ($rep.score -ge 50 -or $rep.tor) { ... }
#
# Zero Claude tokens. Calls AbuseIPDB only on cache miss or stale entry.
# Cache file: ip-reputation-cache.json (same folder, persists across runs)

$CACHE_FILE  = Join-Path $PSScriptRoot "ip-reputation-cache.json"
$CACHE_TTL_DAYS = 7
$ABUSEIPDB_KEY  = "9b89a343d86238378976336fcdf474eb0f286493b1ee8a4b3b5e8f28cc572e269b3794e20acaa448"

# RFC1918 + loopback + link-local — no point checking these
$PRIVATE_RANGES = @(
    '^10\.',
    '^172\.(1[6-9]|2\d|3[01])\.',
    '^192\.168\.',
    '^127\.',
    '^169\.254\.',
    '^::1$',
    '^fc',
    '^fd'
)

function _IsPrivateIp($ip) {
    foreach ($pat in $PRIVATE_RANGES) {
        if ($ip -match $pat) { return $true }
    }
    return $false
}

function _LoadCache {
    if (Test-Path $CACHE_FILE) {
        try { return Get-Content $CACHE_FILE -Raw | ConvertFrom-Json } catch {}
    }
    return [PSCustomObject]@{}
}

function _SaveCache($cache) {
    $cache | ConvertTo-Json -Depth 3 | Set-Content $CACHE_FILE -Encoding UTF8
}

function _QueryAbuseIPDB($ip) {
    try {
        $r = Invoke-RestMethod `
            -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" `
            -Headers @{ "Key" = $ABUSEIPDB_KEY; "Accept" = "application/json" } `
            -Method GET -TimeoutSec 10
        $d = $r.data
        return [PSCustomObject]@{
            score   = [int]$d.abuseConfidenceScore
            reports = [int]$d.totalReports
            country = $d.countryCode
            isp     = $d.isp
            tor     = [bool]$d.isTor
            checked = (Get-Date -Format "yyyy-MM-dd")
            source  = "abuseipdb"
        }
    } catch {
        # Return a neutral result on API failure so hunts aren't blocked
        return [PSCustomObject]@{
            score   = -1
            reports = -1
            country = ""
            isp     = ""
            tor     = $false
            checked = (Get-Date -Format "yyyy-MM-dd")
            source  = "error:$_"
        }
    }
}

function Get-IpReputation($ip) {
    $ip = $ip.Trim()

    # Skip private/internal IPs
    if (_IsPrivateIp $ip) {
        return [PSCustomObject]@{ score=0; reports=0; country="PRIVATE"; isp="internal"; tor=$false; source="skip" }
    }

    $cache = _LoadCache

    # Cache hit — check age
    if ($cache.PSObject.Properties[$ip]) {
        $entry = $cache.$ip
        $age = (Get-Date) - [datetime]$entry.checked
        if ($age.TotalDays -lt $CACHE_TTL_DAYS) {
            $entry | Add-Member -NotePropertyName "cache_hit" -NotePropertyValue $true -Force
            return $entry
        }
    }

    # Cache miss or stale — query AbuseIPDB
    $result = _QueryAbuseIPDB $ip
    $cache | Add-Member -NotePropertyName $ip -NotePropertyValue $result -Force
    _SaveCache $cache
    $result | Add-Member -NotePropertyName "cache_hit" -NotePropertyValue $false -Force
    return $result
}

function Get-IpReputationBulk($ips) {
    # Deduplicate + skip private, then lookup in sequence
    $unique = $ips | Where-Object { $_ -and -not (_IsPrivateIp $_) } | Sort-Object -Unique
    $results = @{}
    foreach ($ip in $unique) {
        $results[$ip] = Get-IpReputation $ip
    }
    return $results
}

# Risk classification helper — returns "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
function Get-IpRiskLevel($rep) {
    if ($rep.source -eq "skip")   { return "SKIP" }
    if ($rep.score -lt 0)         { return "UNKNOWN" }
    if ($rep.tor -eq $true)       { return "CRITICAL" }
    if ($rep.score -ge 80)        { return "CRITICAL" }
    if ($rep.score -ge 50)        { return "HIGH" }
    if ($rep.score -ge 20)        { return "MEDIUM" }
    if ($rep.score -ge 5)         { return "LOW" }
    return "CLEAN"
}
