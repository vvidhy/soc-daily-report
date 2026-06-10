# entity-risk-engine.ps1
# Unit 3 — Entity Risk Engine (O-phase Observe)
# LOCK framework: Observe phase — entity registry with zero cold-start gap.
# Dot-source this file to import Register-IISEntity, Test-RateThreshold, Update-EntityRegistry.

$Script:RegistryPath = 'D:\Vidhya\threat-hunting-agent\baselines\iis-opgl\entity-registry.json'

# ---------------------------------------------------------------------------
# Internal helper: load registry from disk
# ---------------------------------------------------------------------------
function _Load-Registry {
    if (-not (Test-Path $Script:RegistryPath)) {
        return @{ ips = @{}; users = @{}; uris = @{}; hosts = @{} }
    }
    $raw = Get-Content -Path $Script:RegistryPath -Raw -Encoding utf8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @{ ips = @{}; users = @{}; uris = @{}; hosts = @{} }
    }
    $parsed = $raw | ConvertFrom-Json
    # Convert PSCustomObject sections to hashtables for easy mutation
    $registry = @{
        ips   = @{}
        users = @{}
        uris  = @{}
        hosts = @{}
    }
    # ips and users carry geo-metadata; uris and hosts are identifier-only (schema contract)
    foreach ($section in @('ips', 'users')) {
        if ($parsed.$section) {
            foreach ($prop in $parsed.$section.PSObject.Properties) {
                $entry = $prop.Value
                $registry[$section][$prop.Name] = @{
                    first_seen  = [string]$entry.first_seen
                    last_seen   = [string]$entry.last_seen
                    seen_count  = [int]$entry.seen_count
                    countries   = [System.Collections.Generic.List[string]]@($entry.countries | Where-Object { $_ -ne $null })
                    src_ips     = [System.Collections.Generic.List[string]]@($entry.src_ips | Where-Object { $_ -ne $null })
                }
            }
        }
    }
    foreach ($section in @('uris', 'hosts')) {
        if ($parsed.$section) {
            foreach ($prop in $parsed.$section.PSObject.Properties) {
                $entry = $prop.Value
                $registry[$section][$prop.Name] = @{
                    first_seen = [string]$entry.first_seen
                    last_seen  = [string]$entry.last_seen
                    seen_count = [int]$entry.seen_count
                }
            }
        }
    }
    return $registry
}

# ---------------------------------------------------------------------------
# Internal helper: save registry to disk
# ---------------------------------------------------------------------------
function _Save-Registry {
    param([hashtable]$Registry)

    $dir = Split-Path $Script:RegistryPath -Parent
    if (-not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Force -Path $dir
    }

    # Normalise lists to plain arrays for JSON serialisation
    $serialisable = @{
        ips   = @{}
        users = @{}
        uris  = @{}
        hosts = @{}
    }
    # ips and users carry geo-metadata
    foreach ($section in @('ips', 'users')) {
        foreach ($id in $Registry[$section].Keys) {
            $e = $Registry[$section][$id]
            $serialisable[$section][$id] = [ordered]@{
                first_seen = $e.first_seen
                last_seen  = $e.last_seen
                seen_count = $e.seen_count
                countries  = @($e.countries)
                src_ips    = @($e.src_ips)
            }
        }
    }
    # uris and hosts are identifier-only (no geo fields per schema)
    foreach ($section in @('uris', 'hosts')) {
        foreach ($id in $Registry[$section].Keys) {
            $e = $Registry[$section][$id]
            $serialisable[$section][$id] = [ordered]@{
                first_seen = $e.first_seen
                last_seen  = $e.last_seen
                seen_count = $e.seen_count
            }
        }
    }
    $serialisable | ConvertTo-Json -Depth 10 | Out-File -FilePath $Script:RegistryPath -Encoding utf8
}

# ---------------------------------------------------------------------------
# FUNCTION 1: Register-IISEntity
# ---------------------------------------------------------------------------
function Register-IISEntity {
    <#
    .SYNOPSIS
        Register an entity (IP, user, URI, or host) in the persistent entity registry.
    .PARAMETER Type
        Entity type: "ip" | "user" | "uri" | "host"
    .PARAMETER Id
        Entity identifier string (IP address, username, URI path, or host header).
    .PARAMETER Meta
        Optional hashtable with supplemental data keys: 'country', 'src_ip'.
    .OUTPUTS
        PSCustomObject with fields: is_new, first_seen, last_seen, seen_count,
        known_countries, known_ips.
    #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Id,
        [Parameter()][hashtable]$Meta = @{}
    )

    # Map Type to registry key
    $keyMap = @{ ip = 'ips'; user = 'users'; uri = 'uris'; host = 'hosts' }
    if (-not $keyMap.ContainsKey($Type)) {
        throw "Register-IISEntity: unsupported Type '$Type'. Must be one of: ip, user, uri, host."
    }
    $section = $keyMap[$Type]

    $registry = _Load-Registry
    $now      = [datetime]::UtcNow.ToString('o')
    $is_new   = $false

    if (-not $registry[$section].ContainsKey($Id)) {
        # New entity
        $is_new = $true
        $countries = [System.Collections.Generic.List[string]]::new()
        $src_ips   = [System.Collections.Generic.List[string]]::new()

        if ($Meta.ContainsKey('country') -and -not [string]::IsNullOrWhiteSpace($Meta['country'])) {
            $countries.Add($Meta['country'])
        }
        if ($Meta.ContainsKey('src_ip') -and -not [string]::IsNullOrWhiteSpace($Meta['src_ip'])) {
            $src_ips.Add($Meta['src_ip'])
        }

        $registry[$section][$Id] = @{
            first_seen  = $now
            last_seen   = $now
            seen_count  = 1
            countries   = $countries
            src_ips     = $src_ips
        }
    }
    else {
        # Known entity — update
        $entry = $registry[$section][$Id]
        $entry['last_seen']  = $now
        $entry['seen_count'] = [int]$entry['seen_count'] + 1

        if ($Meta.ContainsKey('country') -and -not [string]::IsNullOrWhiteSpace($Meta['country'])) {
            if ($entry['countries'] -notcontains $Meta['country']) {
                $entry['countries'].Add($Meta['country'])
            }
        }

        if ($Meta.ContainsKey('src_ip') -and -not [string]::IsNullOrWhiteSpace($Meta['src_ip'])) {
            if ($entry['src_ips'] -notcontains $Meta['src_ip']) {
                $entry['src_ips'].Add($Meta['src_ip'])
            }
        }
    }

    _Save-Registry -Registry $registry

    $finalEntry = $registry[$section][$Id]

    return [PSCustomObject]@{
        is_new           = $is_new
        first_seen       = [string]$finalEntry['first_seen']
        last_seen        = [string]$finalEntry['last_seen']
        seen_count       = [int]$finalEntry['seen_count']
        known_countries  = [string[]]@($finalEntry['countries'])
        known_ips        = [string[]]@($finalEntry['src_ips'])
    }
}

# ---------------------------------------------------------------------------
# FUNCTION 2: Test-RateThreshold
# ---------------------------------------------------------------------------
function Test-RateThreshold {
    <#
    .SYNOPSIS
        Pure in-memory rate threshold check — no file I/O, no Graylog calls.
    .PARAMETER Type
        Counter type: "401" | "404" | "bytes" | "beacon_pairs"
    .PARAMETER EntityId
        Entity identifier (used for context only; does not affect logic).
    .PARAMETER Count
        Observed count value for this window.
    .PARAMETER WindowMinutes
        Window duration in minutes (context only; threshold is type-driven).
    .PARAMETER Config
        PSCustomObject with an all_thresholds sub-object containing:
            auth_401_per_15min, enum_404_per_1hr, exfil_bytes_per_hr,
            beacon_same_pair_windows
    .OUTPUTS
        PSCustomObject with fields: exceeded, threshold, actual, margin.
    #>
    param(
        [Parameter(Mandatory)][string]    $Type,
        [Parameter(Mandatory)][string]    $EntityId,
        [Parameter(Mandatory)][long]      $Count,
        [Parameter(Mandatory)][int]       $WindowMinutes,
        [Parameter(Mandatory)][PSCustomObject] $Config
    )

    $thresholds = $Config.all_thresholds

    $threshold = switch ($Type) {
        '401'          { [long]$thresholds.auth_401_per_15min }
        '404'          { [long]$thresholds.enum_404_per_1hr }
        'bytes'        { [long]$thresholds.exfil_bytes_per_hr }
        'beacon_pairs' { [long]$thresholds.beacon_same_pair_windows }
        default        { throw "Test-RateThreshold: unsupported Type '$Type'. Must be one of: 401, 404, bytes, beacon_pairs." }
    }

    $exceeded = $Count -gt $threshold
    $margin   = $Count - $threshold

    return [PSCustomObject]@{
        exceeded  = $exceeded
        threshold = $threshold
        actual    = $Count
        margin    = $margin
    }
}

# ---------------------------------------------------------------------------
# FUNCTION 3: Update-EntityRegistry
# ---------------------------------------------------------------------------
function Update-EntityRegistry {
    <#
    .SYNOPSIS
        K-phase (Keep) hook — registers all anchors from a findings array into
        the persistent entity registry. Called by the orchestrator after all
        findings are processed. Returns nothing.
    .PARAMETER Findings
        Array of FindingObject hashtables or PSCustomObjects from lock-detector.ps1.
        Recognised anchor fields: anchor_ip, anchor_user, anchor_host.
    #>
    param(
        [Parameter(Mandatory)][array]$Findings
    )

    foreach ($finding in $Findings) {
        # anchor_ip
        $anchorIp = if ($finding -is [hashtable]) { $finding['anchor_ip'] } else { $finding.anchor_ip }
        if (-not [string]::IsNullOrWhiteSpace($anchorIp) -and $anchorIp -ne '-') {
            $null = Register-IISEntity -Type 'ip' -Id $anchorIp -Meta @{}
        }

        # anchor_user
        $anchorUser = if ($finding -is [hashtable]) { $finding['anchor_user'] } else { $finding.anchor_user }
        if (-not [string]::IsNullOrWhiteSpace($anchorUser) -and $anchorUser -ne '-') {
            $null = Register-IISEntity -Type 'user' -Id $anchorUser -Meta @{}
        }

        # anchor_host
        $anchorHost = if ($finding -is [hashtable]) { $finding['anchor_host'] } else { $finding.anchor_host }
        if (-not [string]::IsNullOrWhiteSpace($anchorHost) -and $anchorHost -ne '-') {
            $null = Register-IISEntity -Type 'host' -Id $anchorHost -Meta @{}
        }
    }
}
