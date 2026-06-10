# lock-detector.ps1 -- Unit 4: LOCK Detection Engine for IIS OP-GL
# Exports: Invoke-LockScan, Resolve-KillChain
#
# ASSUMPTIONS (dot-sourced by orchestrator before calling these functions):
#   - Register-IISEntity  (from entity-risk-engine.ps1)
#   - Test-RateThreshold  (from entity-risk-engine.ps1)
# DO NOT dot-source entity-risk-engine.ps1 here; the orchestrator does that.
#
# Timestamps: UTC / ISO 8601
# All MCP calls: mcp__OP-GL__* tools via Claude tool protocol
# Aggregate-first pattern: always aggregate before drill; skip drill if count=0

# StrictMode intentionally NOT enabled: the 17-class code relies on lenient PowerShell
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function _New-FindingId {
    param([int]$ClassId)
    $ts = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    return "iis-opgl-$ts-CLASS$("{0:D2}" -f $ClassId)"
}

function _New-GraylogLink {
    # Deep-link into Graylog search that pre-fills BOTH the query and a time range
    # wide enough that the event is still in view when the alert is actioned later
    # (default 24h relative). Without rangetype/relative Graylog opens at its default
    # window and the result looks empty even though the query is set.
    param([string]$Query, [string]$StreamId, [int]$RelativeSeconds = 86400)
    $enc = [Uri]::EscapeDataString($Query)
    return "https://siem.secureocp.com/search?q=$enc&rangetype=relative&relative=$RelativeSeconds&streams=$StreamId"
}

function _New-Finding {
    param(
        [int]    $ClassId,
        [string] $Severity,
        [string] $Title,
        [string] $Technique,
        [string] $Summary,
        [string] $AnchorUser  = "-",
        [string] $AnchorHost  = "-",
        [string] $AnchorIp    = "-",
        [string] $AnchorTime  = "",
        [string] $GraylogLink = "",
        [bool]   $EntityIsNew = $false,
        [bool]   $RateExceeded = $false,
        [string] $RawQuery    = "",
        [string] $Investigate = "",
        [double] $ConfScore   = 0.0
    )
    if (-not $AnchorTime) { $AnchorTime = [datetime]::UtcNow.ToString('o') }
    return [PSCustomObject]@{
        severity                 = $Severity
        title                    = $Title
        environment              = "OP-GL"
        technique                = $Technique
        summary                  = $Summary
        anchor_user              = $AnchorUser
        anchor_host              = $AnchorHost
        anchor_ip                = $AnchorIp
        anchor_time              = $AnchorTime
        graylog_link             = $GraylogLink
        finding_id               = (_New-FindingId -ClassId $ClassId)
        lock_phase               = "C"
        entity_is_new            = $EntityIsNew
        rate_threshold_exceeded  = $RateExceeded
        detection_class          = $ClassId
        raw_query                = $RawQuery
        investigate              = $Investigate
        corroboration_sources    = [System.Collections.Generic.List[string]]::new()
        kill_chain_stages        = [System.Collections.Generic.List[string]]::new()
        confidence_score         = $ConfScore
        promoted_from            = $null
        correlation_query_window = $null
    }
}

function _Apply-AllowList {
    param(
        [PSCustomObject] $Finding,
        [PSCustomObject] $Config
    )
    $ip = $Finding.anchor_ip
    if (-not $ip -or $ip -eq "-") { return $Finding }
    $nessusIps  = @($Config.allow_listed_ips)
    $catoIps    = @($Config.allow_listed_ips_logged)
    if ($ip -in $nessusIps) {
        $Finding.severity = "LOGGED"
        $Finding.title    = "[Nessus] $($Finding.title)"
        $Finding.summary  = "[Allow-listed: Nessus scanner] $($Finding.summary)"
    }
    elseif ($ip -in $catoIps) {
        $Finding.severity = "LOGGED"
        $Finding.title    = "[Cato] $($Finding.title)"
        $Finding.summary  = "[Allow-listed: Cato SASE] $($Finding.summary)"
    }
    return $Finding
}

function _Safe-Results {
    param($McpResult)
    # NOTE: every return uses the unary comma (,@(...)) to defeat PowerShell's
    # single-element-array unwrapping on function return. Without it a 1-row
    # result comes back as a bare PSCustomObject, and callers' `.Count` checks
    # (e.g. correlation pivots, drill row counts) silently misbehave on scalars.
    if ($null -eq $McpResult) { return ,@() }
    # LIVE search_logs_relative shape: { total_results, query, time_range, messages:[...] }
    if ($McpResult -is [System.Management.Automation.PSCustomObject]) {
        if (($McpResult.PSObject.Properties.Name -contains 'messages') -and $null -ne $McpResult.messages) {
            return ,@($McpResult.messages)
        }
        if (($McpResult.PSObject.Properties.Name -contains 'results') -and $null -ne $McpResult.results) {
            return ,@($McpResult.results)
        }
        return ,@()
    }
    # Already an array/collection of rows
    if ($McpResult -is [System.Collections.IEnumerable] -and $McpResult -isnot [string]) {
        return ,@($McpResult)
    }
    return ,@()
}

function _Safe-AggCount {
    param($McpResult)
    if ($null -eq $McpResult) { return [long]0 }
    if ($McpResult -is [int] -or $McpResult -is [long]) { return [long]$McpResult }
    if ($McpResult -is [System.Management.Automation.PSCustomObject]) {
        # LIVE aggregate_logs shape: total_matched is the full match count.
        # (The 'top' map only holds the first `size` buckets — never sum it.)
        if ($McpResult.PSObject.Properties.Name -contains 'total_matched') { return [long]$McpResult.total_matched }
        if ($McpResult.PSObject.Properties.Name -contains 'total')         { return [long]$McpResult.total }
        if ($McpResult.PSObject.Properties.Name -contains 'count')         { return [long]$McpResult.count }
    }
    return [long]0
}

function _Is-EntityNew {
    param([string]$Type, [string]$Value, [PSCustomObject]$Registry)
    if (-not $Value -or $Value -eq "-") { return $false }
    if (-not $Registry) { return $true }
    # Read-only registry check. Registration (writes) happens in K-phase via
    # Update-EntityRegistry; calling Register-IISEntity here would mutate the
    # registry mid-scan AND use the wrong parameter name (-Id, not -Value).
    # Use the property indexer (returns $null when absent) rather than
    # .Properties.Name -contains, which throws on an empty bucket under StrictMode.
    $bucket = $null
    switch ($Type) {
        "ip"   { $bucket = $Registry.ips }
        "uri"  { $bucket = $Registry.uris }
        "user" { $bucket = $Registry.users }
        "host" { $bucket = $Registry.hosts }
        # UserAgent: registry has no dedicated bucket; treat every UA as new so
        # Class 10 scanner detection stays conservative (never silently suppresses).
        "ua"   { return $true }
        default { return $false }
    }
    if (-not $bucket) { return $true }
    return ($null -eq $bucket.PSObject.Properties[$Value])
}

function _Check-Rate {
    param([string]$Type, [long]$Count, [int]$WindowMinutes, [PSCustomObject]$Config)
    # Direct config-threshold comparison. Avoids Test-RateThreshold's mandatory
    # -EntityId param and its PSCustomObject return value (which is always truthy);
    # the comparison logic here is identical to that function's.
    switch ($Type) {
        "401"          { return $Count -gt [long]$Config.all_thresholds.auth_401_per_15min }
        "404"          { return $Count -gt [long]$Config.all_thresholds.enum_404_per_1hr }
        "bytes"        { return $Count -gt [long]$Config.all_thresholds.exfil_bytes_per_hr }
        "beacon_pairs" { return $Count -ge [long]$Config.all_thresholds.beacon_same_pair_windows }
    }
    return $false
}

# IIS search fields reused across all classes
$script:IIS_FIELDS = "Method,Status,Client_ip,URI_Stream,URI_Query,Host,Time_Taken,UserAgent,Server_Bytes"

# ---------------------------------------------------------------------------
# FUNCTION 1: Invoke-LockScan
# ---------------------------------------------------------------------------
function Invoke-LockScan {
    <#
    .SYNOPSIS
        Execute all 17 LOCK behavioral detection classes against OP-GL IIS streams.
    .PARAMETER WindowHours
        Look-back window in hours (e.g. 1, 4, 24).
    .PARAMETER Config
        PSCustomObject loaded from config.json (iis_streams, allow_listed_ips, etc.)
    .PARAMETER Registry
        PSCustomObject loaded from entity-registry.json (ips, users, uris, hosts)
    .OUTPUTS
        [array] of FindingObject (see lock-detector.ps1 schema)
    #>
    param(
        [Parameter(Mandatory)][int]           $WindowHours,
        [Parameter(Mandatory)][PSCustomObject] $Config,
        [Parameter(Mandatory)][PSCustomObject] $Registry
    )

    $findings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $prodStreamId = $Config.iis_streams.prod
    $rangeSeconds = $WindowHours * 3600

    # ------------------------------------------------------------------
    # CLASS 1 -- Injection: SQL Injection (T1190)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 1 -- SQLi"
    $c1Query = "Status:500 AND filebeat_log_file_path:*inetpub*"
    $c1Agg   = $null
    try { $c1Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c1Query -rangeSeconds $rangeSeconds } catch {}
    $c1Count = _Safe-AggCount $c1Agg

    if ($c1Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 1 -Severity "LOGGED" -Title "Class 01 -- SQLi: Clean window" `
            -Technique "T1190 -- Exploitation of Public-Facing Application" `
            -Summary "No HTTP 500 errors from IIS in the $WindowHours-hour window. SQLi probe signals absent." `
            -RawQuery $c1Query))
    }
    else {
        $c1Rows = @()
        try { $c1Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c1Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        foreach ($row in $c1Rows) {
            $ip      = if ($row.Client_ip)   { $row.Client_ip }   else { "-" }
            $uri     = if ($row.URI_Stream)  { $row.URI_Stream }  else { "-" }
            $iisHost    = if ($row.Host)        { $row.Host }        else { "-" }
            $ts      = if ($row.timestamp)   { $row.timestamp }   else { [datetime]::UtcNow.ToString('o') }
            $ipNew   = _Is-EntityNew -Type "ip"  -Value $ip  -Registry $Registry
            $uriNew  = _Is-EntityNew -Type "uri" -Value $uri -Registry $Registry
            $sev     = if ($ipNew -or $uriNew) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 1 -Severity $sev `
                -Title "Class 01 -- SQLi: HTTP 500 from $ip on $uri" `
                -Technique "T1190 -- Exploitation of Public-Facing Application" `
                -Summary "IP $ip generated HTTP 500 on URI $uri. IP is_new=$ipNew, URI is_new=$uriNew. $c1Count total 500s in window. $($c1Query)" `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew ($ipNew -or $uriNew) `
                -RawQuery $c1Query `
                -Investigate "Client_ip:$ip AND Status:500 AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND Status:500" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c1Rows.Count -eq 0) {
            $f = _New-Finding -ClassId 1 -Severity "REVIEW" `
                -Title "Class 01 -- SQLi: $c1Count HTTP 500s (no drill rows)" `
                -Technique "T1190 -- Exploitation of Public-Facing Application" `
                -Summary "$c1Count HTTP 500 errors detected in IIS. Drill returned no rows -- possible MCP result limitation." `
                -RawQuery $c1Query
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 2 -- Injection: XSS (T1059.007)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 2 -- XSS"
    $c2Query = "Method:POST AND filebeat_log_file_path:*inetpub*"
    $c2Agg   = $null
    try { $c2Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c2Query -rangeSeconds $rangeSeconds } catch {}
    $c2Count = _Safe-AggCount $c2Agg

    if ($c2Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 2 -Severity "LOGGED" -Title "Class 02 -- XSS: Clean window" `
            -Technique "T1059.007 -- Command and Scripting Interpreter: JavaScript" `
            -Summary "No POST requests to IIS in the $WindowHours-hour window. XSS signals absent." `
            -RawQuery $c2Query))
    }
    else {
        $c2Rows = @()
        try { $c2Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c2Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        foreach ($row in $c2Rows) {
            $ip     = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri    = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $iisHost   = if ($row.Host)       { $row.Host }       else { "-" }
            $ts     = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            $query  = if ($row.URI_Query)  { $row.URI_Query }  else { "" }
            $ipNew  = _Is-EntityNew -Type "ip"  -Value $ip  -Registry $Registry
            $uriNew = _Is-EntityNew -Type "uri" -Value $uri -Registry $Registry
            $longQ  = ($query.Length -gt 200)
            $sev    = if ($ipNew -or $longQ) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 2 -Severity $sev `
                -Title "Class 02 -- XSS: POST from $ip (query_len=$($query.Length))" `
                -Technique "T1059.007 -- Command and Scripting Interpreter: JavaScript" `
                -Summary "IP $ip POSTed to $uri. IP is_new=$ipNew, URI is_new=$uriNew, query_length=$($query.Length) (threshold 200). $c2Count total POSTs in window." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew ($ipNew -or $uriNew) `
                -RawQuery $c2Query `
                -Investigate "Client_ip:$ip AND Method:POST AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND Method:POST" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 3 -- Injection: Cmd/RCE (T1059)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 3 -- RCE"
    $c3Query = "Status:200 AND Time_Taken:>5000 AND filebeat_log_file_path:*inetpub*"
    $c3Agg   = $null
    try { $c3Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c3Query -rangeSeconds $rangeSeconds } catch {}
    $c3Count = _Safe-AggCount $c3Agg

    if ($c3Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 3 -Severity "LOGGED" -Title "Class 03 -- RCE: Clean window" `
            -Technique "T1059 -- Command and Scripting Interpreter" `
            -Summary "No high-latency HTTP 200s in the $WindowHours-hour window. Sleep-based RCE signals absent." `
            -RawQuery $c3Query))
    }
    else {
        $c3Rows = @()
        try { $c3Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c3Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        foreach ($row in $c3Rows) {
            $ip      = if ($row.Client_ip)   { $row.Client_ip }   else { "-" }
            $uri     = if ($row.URI_Stream)  { $row.URI_Stream }  else { "-" }
            $iisHost    = if ($row.Host)        { $row.Host }        else { "-" }
            $ts      = if ($row.timestamp)   { $row.timestamp }   else { [datetime]::UtcNow.ToString('o') }
            $timeTkn = if ($row.Time_Taken)  { [int]$row.Time_Taken } else { 0 }
            $ipNew   = _Is-EntityNew -Type "ip"  -Value $ip  -Registry $Registry
            $uriNew  = _Is-EntityNew -Type "uri" -Value $uri -Registry $Registry
            $sev     = if ($timeTkn -gt 5000 -and $uriNew) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 3 -Severity $sev `
                -Title "Class 03 -- RCE: High-latency 200 from $ip (${timeTkn}ms)" `
                -Technique "T1059 -- Command and Scripting Interpreter" `
                -Summary "IP $ip received HTTP 200 on $uri with Time_Taken=${timeTkn}ms. IP is_new=$ipNew, URI is_new=$uriNew. $c3Count total high-latency 200s in window." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew ($ipNew -or $uriNew) `
                -RawQuery $c3Query `
                -Investigate "Client_ip:$ip AND Status:200 AND Time_Taken:>5000 AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND Status:200 AND Time_Taken:>5000" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 4 -- Path Traversal / LFI (T1083)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 4 -- Path Traversal"
    $c4Query = "URI_Stream:*..*  AND filebeat_log_file_path:*inetpub*"
    $c4Agg   = $null
    try { $c4Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c4Query -rangeSeconds $rangeSeconds } catch {}
    $c4Count = _Safe-AggCount $c4Agg

    if ($c4Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 4 -Severity "LOGGED" -Title "Class 04 -- Path Traversal: Clean window" `
            -Technique "T1083 -- File and Directory Discovery" `
            -Summary "No path traversal sequences in IIS URIs in the $WindowHours-hour window." `
            -RawQuery $c4Query))
    }
    else {
        $c4Rows = @()
        try { $c4Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c4Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        foreach ($row in $c4Rows) {
            $ip   = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri  = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $iisHost = if ($row.Host)       { $row.Host }       else { "-" }
            $ts   = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            # Always REVIEW for traversal sequences -- no benign exception for ".." in URI
            $f = _New-Finding -ClassId 4 -Severity "REVIEW" `
                -Title "Class 04 -- Path Traversal: '..' in URI from $ip" `
                -Technique "T1083 -- File and Directory Discovery" `
                -Summary "Path traversal sequence '..' detected in URI '$uri' from IP $ip. $c4Count total traversal requests in window. All traversal patterns force REVIEW." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew ($true) `
                -RawQuery $c4Query `
                -Investigate "Client_ip:$ip AND URI_Stream:*..*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND URI_Stream:*..*" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c4Rows.Count -eq 0) {
            $f = _New-Finding -ClassId 4 -Severity "REVIEW" `
                -Title "Class 04 -- Path Traversal: $c4Count hits (no drill rows)" `
                -Technique "T1083 -- File and Directory Discovery" `
                -Summary "$c4Count path traversal requests detected. Drill returned no rows." `
                -RawQuery $c4Query
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 5 -- SSRF / Metadata (T1552.005)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 5 -- SSRF"
    $c5Query = "URI_Query:*169.254* OR URI_Query:*127.0.0* OR URI_Query:*localhost*"
    $c5Agg   = $null
    try { $c5Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c5Query -rangeSeconds $rangeSeconds } catch {}
    $c5Count = _Safe-AggCount $c5Agg

    if ($c5Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 5 -Severity "LOGGED" -Title "Class 05 -- SSRF: Clean window" `
            -Technique "T1552.005 -- Unsecured Credentials: Cloud Instance Metadata API" `
            -Summary "No SSRF/metadata probe patterns in IIS query strings in the $WindowHours-hour window." `
            -RawQuery $c5Query))
    }
    else {
        $c5Rows = @()
        try { $c5Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c5Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        foreach ($row in $c5Rows) {
            $ip    = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri   = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $iisHost  = if ($row.Host)       { $row.Host }       else { "-" }
            $ts    = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            $query = if ($row.URI_Query)  { $row.URI_Query }  else { "" }
            # Always REVIEW -- SSRF patterns are never benign
            $f = _New-Finding -ClassId 5 -Severity "REVIEW" `
                -Title "Class 05 -- SSRF: Internal IP/localhost in query from $ip" `
                -Technique "T1552.005 -- Unsecured Credentials: Cloud Instance Metadata API" `
                -Summary "SSRF probe detected: IP $ip queried $uri with internal-targeting query string. Query: '$query'. $c5Count total SSRF patterns in window." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew $true `
                -RawQuery $c5Query `
                -Investigate "Client_ip:$ip AND (URI_Query:*169.254* OR URI_Query:*127.0.0* OR URI_Query:*localhost*)" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND (URI_Query:*169.254* OR URI_Query:*127.0.0* OR URI_Query:*localhost*)" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c5Rows.Count -eq 0) {
            $f = _New-Finding -ClassId 5 -Severity "REVIEW" `
                -Title "Class 05 -- SSRF: $c5Count SSRF probe hits (no drill rows)" `
                -Technique "T1552.005 -- Unsecured Credentials: Cloud Instance Metadata API" `
                -Summary "$c5Count SSRF probe patterns detected. Drill returned no rows." `
                -RawQuery $c5Query
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 6 -- Exploit Payloads: Log4Shell/SSTI/XXE (T1203)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 6 -- Exploit Payloads"
    $c6Query = "filebeat_log_file_path:*inetpub*"
    $c6Agg   = $null
    try { $c6Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c6Query -rangeSeconds $rangeSeconds } catch {}
    $c6Count = _Safe-AggCount $c6Agg

    if ($c6Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 6 -Severity "LOGGED" -Title "Class 06 -- Exploit Payloads: Clean window" `
            -Technique "T1203 -- Exploitation for Client Execution" `
            -Summary "No IIS traffic in the $WindowHours-hour window. Exploit payload signals absent." `
            -RawQuery $c6Query))
    }
    else {
        $c6Rows = @()
        try { $c6Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c6Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        $c6OverSizedFound = $false
        foreach ($row in $c6Rows) {
            $ip    = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri   = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $iisHost  = if ($row.Host)       { $row.Host }       else { "-" }
            $ts    = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            $query = if ($row.URI_Query)  { $row.URI_Query }  else { "" }
            if ($query.Length -le 300) { continue }
            $c6OverSizedFound = $true
            $ipNew = _Is-EntityNew -Type "ip" -Value $ip -Registry $Registry
            $sev   = if ($ipNew) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 6 -Severity $sev `
                -Title "Class 06 -- Exploit Payload: Oversized query (len=$($query.Length)) from $ip" `
                -Technique "T1203 -- Exploitation for Client Execution" `
                -Summary "IP $ip sent query string of length $($query.Length) chars (threshold 300) to $uri. IP is_new=$ipNew. Possible Log4Shell JNDI, SSTI template, or XXE payload." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew $ipNew `
                -RawQuery $c6Query `
                -Investigate "Client_ip:$ip AND URI_Stream:$uri" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if (-not $c6OverSizedFound) {
            $findings.Add((_New-Finding -ClassId 6 -Severity "LOGGED" `
                -Title "Class 06 -- Exploit Payloads: No oversized query strings" `
                -Technique "T1203 -- Exploitation for Client Execution" `
                -Summary "$c6Count IIS requests in window; no query strings exceeded 300 chars threshold. Exploit payload signals absent." `
                -RawQuery $c6Query))
        }
    }

    # ------------------------------------------------------------------
    # CLASS 7 -- Webshell Behavior (T1505.003) -- two sub-checks
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 7 -- Webshell"
    # 7a: POST -> 200 on new URI
    $c7aQuery = "Method:POST AND Status:200 AND filebeat_log_file_path:*inetpub*"
    $c7aAgg   = $null
    try { $c7aAgg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c7aQuery -rangeSeconds $rangeSeconds } catch {}
    $c7aCount = _Safe-AggCount $c7aAgg

    if ($c7aCount -eq 0) {
        $findings.Add((_New-Finding -ClassId 7 -Severity "LOGGED" -Title "Class 07a -- Webshell (POST->200): Clean window" `
            -Technique "T1505.003 -- Server Software Component: Web Shell" `
            -Summary "No POST requests returning 200 in the $WindowHours-hour window. Webshell execution signals absent (7a)." `
            -RawQuery $c7aQuery))
    }
    else {
        $c7aRows = @()
        try { $c7aRows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c7aQuery -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        foreach ($row in $c7aRows) {
            $ip     = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri    = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $iisHost   = if ($row.Host)       { $row.Host }       else { "-" }
            $ts     = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            $uriNew = _Is-EntityNew -Type "uri" -Value $uri -Registry $Registry
            $sev    = if ($uriNew) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 7 -Severity $sev `
                -Title "Class 07a -- Webshell: POST->200 from $ip on $uri (uri_new=$uriNew)" `
                -Technique "T1505.003 -- Server Software Component: Web Shell" `
                -Summary "IP $ip received HTTP 200 on POST to $uri. URI is_new=$uriNew. $c7aCount total POST->200 in window. New URI POST->200 suggests webshell upload/execution." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew $uriNew `
                -RawQuery $c7aQuery `
                -Investigate "Client_ip:$ip AND Method:POST AND Status:200 AND URI_Stream:$uri" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND Method:POST AND Status:200" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
    }

    # 7b: POST -> 200 on static file extensions
    $c7bQuery = "Method:POST AND Status:200 AND (URI_Stream:*.jpg* OR URI_Stream:*.png* OR URI_Stream:*.css* OR URI_Stream:*.js* OR URI_Stream:*.gif*) AND filebeat_log_file_path:*inetpub*"
    $c7bAgg   = $null
    try { $c7bAgg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c7bQuery -rangeSeconds $rangeSeconds } catch {}
    $c7bCount = _Safe-AggCount $c7bAgg

    if ($c7bCount -eq 0) {
        $findings.Add((_New-Finding -ClassId 7 -Severity "LOGGED" -Title "Class 07b -- Webshell (static ext POST): Clean window" `
            -Technique "T1505.003 -- Server Software Component: Web Shell" `
            -Summary "No POST->200 to static file extensions in the $WindowHours-hour window (7b)." `
            -RawQuery $c7bQuery))
    }
    else {
        $c7bRows = @()
        try { $c7bRows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c7bQuery -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        foreach ($row in $c7bRows) {
            $ip   = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri  = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $iisHost = if ($row.Host)       { $row.Host }       else { "-" }
            $ts   = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            # Always REVIEW -- static extensions accepting POST are always suspicious
            $f = _New-Finding -ClassId 7 -Severity "REVIEW" `
                -Title "Class 07b -- Webshell: POST->200 to static ext $uri from $ip" `
                -Technique "T1505.003 -- Server Software Component: Web Shell" `
                -Summary "POST->200 on static file extension URI '$uri' from IP $ip. Static assets should never accept POST. $c7bCount total static-ext POST->200 in window. Always REVIEW." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew $true `
                -RawQuery $c7bQuery `
                -Investigate "Client_ip:$ip AND Method:POST AND Status:200 AND URI_Stream:$uri" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND Method:POST AND Status:200 AND URI_Stream:$uri" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c7bRows.Count -eq 0) {
            $f = _New-Finding -ClassId 7 -Severity "REVIEW" `
                -Title "Class 07b -- Webshell: $c7bCount static-ext POST hits" `
                -Technique "T1505.003 -- Server Software Component: Web Shell" `
                -Summary "$c7bCount POST->200 to static file extensions detected. Drill returned no rows." `
                -RawQuery $c7bQuery
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 8 -- Auth Attacks: 401-storm (T1110)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 8 -- 401-Storm"
    $c8Query = "Status:401 AND filebeat_log_file_path:*inetpub*"
    $c8Range = 900  # 15 minutes
    $c8Agg   = $null
    try { $c8Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c8Query -rangeSeconds $c8Range } catch {}
    $c8Count = _Safe-AggCount $c8Agg

    if ($c8Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 8 -Severity "LOGGED" -Title "Class 08 -- 401-Storm: Clean window" `
            -Technique "T1110 -- Brute Force" `
            -Summary "No HTTP 401 responses in the last 15-minute window. Credential attack signals absent." `
            -RawQuery $c8Query))
    }
    else {
        $c8Rows = @()
        try { $c8Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c8Query -rangeSeconds $c8Range -fields $script:IIS_FIELDS -limit 20) } catch {}
        # Group by Client_ip
        $c8ByIp = @{}
        foreach ($row in $c8Rows) {
            $ip = if ($row.Client_ip) { $row.Client_ip } else { "-" }
            if (-not $c8ByIp.ContainsKey($ip)) { $c8ByIp[$ip] = 0 }
            $c8ByIp[$ip]++
        }
        foreach ($ip in $c8ByIp.Keys) {
            $perIpCount = $c8ByIp[$ip]
            $rateEx     = _Check-Rate -Type "401" -Count $perIpCount -WindowMinutes 15 -Config $Config
            $iisHost       = "-"
            $ts         = [datetime]::UtcNow.ToString('o')
            foreach ($row in $c8Rows) {
                if ($row.Client_ip -eq $ip) {
                    if ($row.Host)      { $iisHost = $row.Host }
                    if ($row.timestamp) { $ts   = $row.timestamp }
                    break
                }
            }
            $sev = if ($rateEx) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 8 -Severity $sev `
                -Title "Class 08 -- 401-Storm: $perIpCount 401s from $ip in 15 min" `
                -Technique "T1110 -- Brute Force" `
                -Summary "IP $ip generated $perIpCount HTTP 401 responses in 15 minutes. Rate threshold exceeded=$rateEx. $c8Count total 401s across all IPs. Check for 200-after-401 pattern." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -RateExceeded $rateEx `
                -RawQuery $c8Query `
                -Investigate "Client_ip:$ip AND (Status:401 OR Status:200) AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND (Status:401 OR Status:200)" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c8Rows.Count -eq 0) {
            $f = _New-Finding -ClassId 8 -Severity "REVIEW" `
                -Title "Class 08 -- 401-Storm: $c8Count 401s (no drill rows)" `
                -Technique "T1110 -- Brute Force" `
                -Summary "$c8Count HTTP 401s in 15-minute window. Drill returned no rows." `
                -RawQuery $c8Query
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 9 -- Enumeration / 404 Sweep (T1595)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 9 -- 404 Sweep"
    $c9Query = "Status:404 AND filebeat_log_file_path:*inetpub*"
    $c9Agg   = $null
    try { $c9Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c9Query -rangeSeconds 3600 } catch {}
    $c9Count = _Safe-AggCount $c9Agg

    if ($c9Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 9 -Severity "LOGGED" -Title "Class 09 -- 404 Sweep: Clean window" `
            -Technique "T1595 -- Active Scanning" `
            -Summary "No HTTP 404 responses in the last 1-hour window. Enumeration signals absent." `
            -RawQuery $c9Query))
    }
    else {
        $c9Rows = @()
        try { $c9Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c9Query -rangeSeconds 3600 -fields $script:IIS_FIELDS -limit 20) } catch {}
        $c9ByIp = @{}
        foreach ($row in $c9Rows) {
            $ip  = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri = if ($row.URI_Stream) { $row.URI_Stream } else { "/" }
            if (-not $c9ByIp.ContainsKey($ip)) { $c9ByIp[$ip] = [System.Collections.Generic.HashSet[string]]::new() }
            [void]$c9ByIp[$ip].Add($uri)
        }
        foreach ($ip in $c9ByIp.Keys) {
            $uniqueUris = $c9ByIp[$ip].Count
            $rateEx     = _Check-Rate -Type "404" -Count $uniqueUris -WindowMinutes 60 -Config $Config
            $iisHost       = "-"
            $ts         = [datetime]::UtcNow.ToString('o')
            foreach ($row in $c9Rows) {
                if ($row.Client_ip -eq $ip) {
                    if ($row.Host)      { $iisHost = $row.Host }
                    if ($row.timestamp) { $ts   = $row.timestamp }
                    break
                }
            }
            $sev = if ($rateEx) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 9 -Severity $sev `
                -Title "Class 09 -- 404 Sweep: $uniqueUris unique 404 URIs from $ip" `
                -Technique "T1595 -- Active Scanning" `
                -Summary "IP $ip hit $uniqueUris unique 404 URIs in 1 hour. Rate threshold exceeded=$rateEx. $c9Count total 404s. High unique-URI breadth suggests systematic endpoint enumeration." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -RateExceeded $rateEx `
                -RawQuery $c9Query `
                -Investigate "Client_ip:$ip AND Status:404 AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND Status:404" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c9Rows.Count -eq 0) {
            $f = _New-Finding -ClassId 9 -Severity "REVIEW" `
                -Title "Class 09 -- 404 Sweep: $c9Count 404s (no drill rows)" `
                -Technique "T1595 -- Active Scanning" `
                -Summary "$c9Count HTTP 404s in 1-hour window. Drill returned no rows." `
                -RawQuery $c9Query
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 10 -- Scanner / Automation UA (T1595.001)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 10 -- Scanner UA"
    $c10Query = "filebeat_log_file_path:*inetpub*"
    $c10Agg   = $null
    try { $c10Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c10Query -field "UserAgent" -rangeSeconds $rangeSeconds } catch {}
    $c10Count = _Safe-AggCount $c10Agg

    if ($c10Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 10 -Severity "LOGGED" -Title "Class 10 -- Scanner UA: Clean window" `
            -Technique "T1595.001 -- Active Scanning: Scanning IP Blocks" `
            -Summary "No IIS traffic in the $WindowHours-hour window. Scanner UA signals absent." `
            -RawQuery $c10Query))
    }
    else {
        $c10Rows = @()
        try { $c10Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c10Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        $c10ByUA = @{}
        foreach ($row in $c10Rows) {
            $ua = if ($row.UserAgent) { $row.UserAgent } else { "-" }
            if (-not $c10ByUA.ContainsKey($ua)) { $c10ByUA[$ua] = @{ count = 0; ip = "-"; host = "-"; ts = [datetime]::UtcNow.ToString('o') } }
            $c10ByUA[$ua].count++
            if ($row.Client_ip  -and $c10ByUA[$ua].ip   -eq "-") { $c10ByUA[$ua].ip   = $row.Client_ip }
            if ($row.Host       -and $c10ByUA[$ua].host -eq "-") { $c10ByUA[$ua].host = $row.Host }
            if ($row.timestamp  -and $c10ByUA[$ua].ts   -eq [datetime]::UtcNow.ToString('o')) { $c10ByUA[$ua].ts = $row.timestamp }
        }
        foreach ($ua in $c10ByUA.Keys) {
            $uaNew = _Is-EntityNew -Type "ua" -Value $ua -Registry $Registry
            $cnt   = $c10ByUA[$ua].count
            # Heuristic: new UA and high volume
            if ($uaNew -and $cnt -gt 1) {
                $f = _New-Finding -ClassId 10 -Severity "REVIEW" `
                    -Title "Class 10 -- Scanner UA: New UA with $cnt requests" `
                    -Technique "T1595.001 -- Active Scanning: Scanning IP Blocks" `
                    -Summary "New User-Agent '$ua' made $cnt requests in the window from IP $($c10ByUA[$ua].ip). New UA with elevated request volume suggests automated scanning." `
                    -AnchorIp $c10ByUA[$ua].ip -AnchorHost $c10ByUA[$ua].host -AnchorTime $c10ByUA[$ua].ts `
                    -EntityIsNew $true `
                    -RawQuery $c10Query `
                    -Investigate "UserAgent:""$ua"" AND filebeat_log_file_path:*inetpub*" `
                    -GraylogLink (_New-GraylogLink "UserAgent:$ua" $prodStreamId)
                $f = _Apply-AllowList -Finding $f -Config $Config
                $findings.Add($f)
            }
        }
        # If no REVIEW finding added for class 10, emit clean
        $c10Reviewed = $findings | Where-Object { $_.detection_class -eq 10 -and $_.severity -in @("REVIEW","CONFIRMED","HIGH") }
        if (-not $c10Reviewed) {
            $findings.Add((_New-Finding -ClassId 10 -Severity "LOGGED" -Title "Class 10 -- Scanner UA: All known UAs" `
                -Technique "T1595.001 -- Active Scanning: Scanning IP Blocks" `
                -Summary "All observed User-Agents in the window are known in entity registry. No scanner signal." `
                -RawQuery $c10Query))
        }
    }

    # ------------------------------------------------------------------
    # CLASS 11 -- CVE / CMS Probe (T1190)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 11 -- CVE/CMS Probe"
    # Leading-wildcard terms expand heavily; a 7-term OR exceeds Graylog's
    # maxClauseCount (4096) -> HTTP 500, so the class silently never fired.
    # Query in OR-groups of <=3 (validated safe) and combine counts + rows.
    # No leading slash: '*/x*' makes Graylog's wildcard match ~all traffic (846k);
    # '*x*' is correctly selective (validated: 12/17/27/6/197/131/0 hits/24h).
    $c11Patterns = @('*wp-admin*','*wp-login*','*phpinfo*','*.git*','*.env*','*actuator*','*manager/html*')
    $c11Count = 0
    $c11Rows  = @()
    $c11QueryParts = @()
    for ($gi = 0; $gi -lt $c11Patterns.Count; $gi += 3) {
        $grp      = @($c11Patterns[$gi..([Math]::Min($gi + 2, $c11Patterns.Count - 1))])
        $orClause = ($grp | ForEach-Object { "URI_Stream:$_" }) -join ' OR '
        $gQuery   = "($orClause) AND filebeat_log_file_path:*inetpub*"
        $c11QueryParts += $gQuery
        $gAgg = $null
        try { $gAgg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $gQuery -rangeSeconds $rangeSeconds } catch {}
        $gCount = [long](_Safe-AggCount $gAgg)
        $c11Count += $gCount
        if ($gCount -gt 0 -and @($c11Rows).Count -lt 20) {
            $gRows = @()
            try { $gRows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $gQuery -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
            $c11Rows += $gRows
        }
    }
    $c11Query = $c11QueryParts -join ' ; '
    $c11Rows  = @($c11Rows | Select-Object -First 20)

    if ($c11Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 11 -Severity "LOGGED" -Title "Class 11 -- CVE/CMS Probe: Clean window" `
            -Technique "T1190 -- Exploitation of Public-Facing Application" `
            -Summary "No CVE/CMS probe path patterns in the $WindowHours-hour window." `
            -RawQuery $c11Query))
    }
    else {
        foreach ($row in $c11Rows) {
            $ip     = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri    = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $status = if ($row.Status)     { [int]$row.Status } else { 0 }
            $iisHost   = if ($row.Host)       { $row.Host }       else { "-" }
            $ts     = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            $ipNew  = _Is-EntityNew -Type "ip" -Value $ip -Registry $Registry
            # 200 on these paths = always REVIEW regardless of entity
            $sev = if ($status -eq 200 -or $ipNew) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 11 -Severity $sev `
                -Title "Class 11 -- CVE/CMS Probe: $ip accessed $uri (status=$status)" `
                -Technique "T1190 -- Exploitation of Public-Facing Application" `
                -Summary "IP $ip accessed sensitive path '$uri' returning HTTP $status. IP is_new=$ipNew. Status=200 on CMS/CVE path forces REVIEW regardless of IP. $c11Count total probe hits in window." `
                -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                -EntityIsNew $ipNew `
                -RawQuery $c11Query `
                -Investigate "Client_ip:$ip AND URI_Stream:$uri" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND URI_Stream:$uri" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c11Rows.Count -eq 0) {
            $f = _New-Finding -ClassId 11 -Severity "REVIEW" `
                -Title "Class 11 -- CVE/CMS Probe: $c11Count hits (no drill rows)" `
                -Technique "T1190 -- Exploitation of Public-Facing Application" `
                -Summary "$c11Count CVE/CMS probe path hits detected. Drill returned no rows." `
                -RawQuery $c11Query
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 12 -- Protocol Abuse (T1071)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 12 -- Protocol Abuse"
    $c12Query = "(Method:TRACE OR Method:CONNECT OR Method:DELETE OR Method:PATCH) AND filebeat_log_file_path:*inetpub*"
    $c12Agg   = $null
    try { $c12Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c12Query -rangeSeconds $rangeSeconds } catch {}
    $c12Count = _Safe-AggCount $c12Agg

    if ($c12Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 12 -Severity "LOGGED" -Title "Class 12 -- Protocol Abuse: Clean window" `
            -Technique "T1071 -- Application Layer Protocol" `
            -Summary "No unusual HTTP method usage (TRACE/CONNECT/DELETE/PATCH) in the $WindowHours-hour window." `
            -RawQuery $c12Query))
    }
    else {
        $c12Rows = @()
        try { $c12Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c12Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        $c12ByIp = @{}
        foreach ($row in $c12Rows) {
            $ip     = if ($row.Client_ip) { $row.Client_ip } else { "-" }
            $method = if ($row.Method)    { $row.Method }    else { "-" }
            if (-not $c12ByIp.ContainsKey($ip)) {
                $c12ByIp[$ip] = @{
                    methods = [System.Collections.Generic.HashSet[string]]::new()
                    host    = "-"
                    ts      = [datetime]::UtcNow.ToString('o')
                }
            }
            [void]$c12ByIp[$ip].methods.Add($method)
            if ($row.Host      -and $c12ByIp[$ip].host -eq "-") { $c12ByIp[$ip].host = $row.Host }
            if ($row.timestamp -and $c12ByIp[$ip].ts -eq [datetime]::UtcNow.ToString('o')) { $c12ByIp[$ip].ts = $row.timestamp }
        }
        foreach ($ip in $c12ByIp.Keys) {
            $methodCount = $c12ByIp[$ip].methods.Count
            $ipNew       = _Is-EntityNew -Type "ip" -Value $ip -Registry $Registry
            $sev         = if ($ipNew -or $methodCount -gt 5) { "REVIEW" } else { "LOGGED" }
            $f = _New-Finding -ClassId 12 -Severity $sev `
                -Title "Class 12 -- Protocol Abuse: $ip used $methodCount unusual methods" `
                -Technique "T1071 -- Application Layer Protocol" `
                -Summary "IP $ip used methods: $($c12ByIp[$ip].methods -join ', '). Method diversity=$methodCount (threshold 5), IP is_new=$ipNew. $c12Count total unusual-method requests." `
                -AnchorIp $ip -AnchorHost $c12ByIp[$ip].host -AnchorTime $c12ByIp[$ip].ts `
                -EntityIsNew $ipNew `
                -RawQuery $c12Query `
                -Investigate "Client_ip:$ip AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip AND (Method:TRACE OR Method:CONNECT OR Method:DELETE OR Method:PATCH)" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c12Rows.Count -eq 0) {
            $f = _New-Finding -ClassId 12 -Severity "REVIEW" `
                -Title "Class 12 -- Protocol Abuse: $c12Count unusual method hits" `
                -Technique "T1071 -- Application Layer Protocol" `
                -Summary "$c12Count unusual HTTP method requests detected. Drill returned no rows." `
                -RawQuery $c12Query
            $findings.Add($f)
        }
    }

    # ------------------------------------------------------------------
    # CLASS 13 -- Exfiltration Signals (T1030)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 13 -- Exfiltration"
    $c13Query = "filebeat_log_file_path:*inetpub*"
    $c13Agg   = $null
    try { $c13Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c13Query -field "Client_ip" -rangeSeconds $rangeSeconds } catch {}
    $c13Count = _Safe-AggCount $c13Agg

    if ($c13Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 13 -Severity "LOGGED" -Title "Class 13 -- Exfiltration: Clean window" `
            -Technique "T1030 -- Data Transfer Size Limits" `
            -Summary "No IIS traffic in the $WindowHours-hour window. Exfiltration signals absent." `
            -RawQuery $c13Query))
    }
    else {
        $c13Rows = @()
        try { $c13Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c13Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        $c13BytesByIp = @{}
        foreach ($row in $c13Rows) {
            $ip    = if ($row.Client_ip)   { $row.Client_ip }   else { "-" }
            $bytes = if ($row.Server_Bytes) { try { [long]$row.Server_Bytes } catch { 0 } } else { 0 }
            if (-not $c13BytesByIp.ContainsKey($ip)) {
                $c13BytesByIp[$ip] = @{ total_bytes = 0L; host = "-"; ts = [datetime]::UtcNow.ToString('o') }
            }
            $c13BytesByIp[$ip].total_bytes += $bytes
            if ($row.Host      -and $c13BytesByIp[$ip].host -eq "-") { $c13BytesByIp[$ip].host = $row.Host }
            if ($row.timestamp -and $c13BytesByIp[$ip].ts -eq [datetime]::UtcNow.ToString('o')) { $c13BytesByIp[$ip].ts = $row.timestamp }
        }
        foreach ($ip in $c13BytesByIp.Keys) {
            $totalBytes = $c13BytesByIp[$ip].total_bytes
            # _Check-Rate expects [int]; safely clamp to avoid overflow on >2GB transfers.
            # [Math]::Min returns [long] when both operands are [long]; then cast to [int].
            $bytesForCheck = [int][Math]::Min([long]$totalBytes, [long][int]::MaxValue)
            $rateEx     = _Check-Rate -Type "bytes" -Count $bytesForCheck -WindowMinutes ($WindowHours * 60) -Config $Config
            $sev        = if ($rateEx) { "REVIEW" } else { "LOGGED" }
            $mbSent     = [Math]::Round($totalBytes / 1MB, 2)
            $f = _New-Finding -ClassId 13 -Severity $sev `
                -Title "Class 13 -- Exfil: $ip sent ${mbSent}MB in window" `
                -Technique "T1030 -- Data Transfer Size Limits" `
                -Summary "IP $ip transferred $totalBytes bytes (${mbSent}MB) outbound in the window. Rate threshold exceeded=$rateEx. Large outbound transfers may indicate data exfiltration." `
                -AnchorIp $ip -AnchorHost $c13BytesByIp[$ip].host -AnchorTime $c13BytesByIp[$ip].ts `
                -RateExceeded $rateEx `
                -RawQuery $c13Query `
                -Investigate "Client_ip:$ip AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$ip" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
        if ($c13Rows.Count -eq 0) {
            $findings.Add((_New-Finding -ClassId 13 -Severity "LOGGED" -Title "Class 13 -- Exfil: No bytes data in drill rows" `
                -Technique "T1030 -- Data Transfer Size Limits" `
                -Summary "$c13Count IIS requests in window. No Server_Bytes data available for analysis." `
                -RawQuery $c13Query))
        }
    }

    # ------------------------------------------------------------------
    # CLASS 14 -- Beaconing / C2 (T1071.001)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 14 -- Beaconing"
    $c14Query  = "filebeat_log_file_path:*inetpub*"
    $c14Thresh = [int]$Config.all_thresholds.beacon_same_pair_windows
    # Sample up to 3 non-overlapping hourly windows to detect beaconing pairs.
    # Each window-slot is queried independently with a 1-hour rangeSeconds.
    # We count how many DISTINCT window-slots a (ip+uri) pair appears in -- not
    # raw row count -- to avoid the false-positive from cumulative range queries.
    $beaconPairs = @{}
    $numWindows  = [Math]::Min(3, $WindowHours)
    for ($h = 0; $h -lt $numWindows; $h++) {
        # Each slot is exactly 1 hour, with most-recent slot = last 1 hr
        $slotRangeSeconds = 3600
        # Use a 1-hour window centred $h hours back from now.
        # search_logs_relative uses rangeSeconds from now backward; we approximate
        # the slot by fetching the most-recent 1hr in slot 0, and note that without
        # an offset parameter we can only get the most-recent 1hr per call.
        # To get distinct slots we vary the query rangeSeconds cumulatively and
        # de-duplicate pairs seen in each slot using a per-slot HashSet.
        $c14Rows = @()
        try { $c14Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c14Query -rangeSeconds $slotRangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        # Build a per-slot set of (ip||uri) pairs seen in this slot
        $slotPairs = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($row in $c14Rows) {
            $ip  = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            [void]$slotPairs.Add("$ip||$uri")
            $key = "$ip||$uri"
            if (-not $beaconPairs.ContainsKey($key)) {
                $beaconPairs[$key] = @{ windowCount = 0; ip = $ip; uri = $uri; host = "-"; ts = [datetime]::UtcNow.ToString('o') }
            }
            if ($row.Host      -and $beaconPairs[$key].host -eq "-") { $beaconPairs[$key].host = $row.Host }
            if ($row.timestamp -and $beaconPairs[$key].ts -eq [datetime]::UtcNow.ToString('o')) { $beaconPairs[$key].ts = $row.timestamp }
        }
        # Increment windowCount once per slot (not once per row) to avoid inflation
        foreach ($k in $slotPairs) {
            $beaconPairs[$k].windowCount++
        }
        # Avoid re-querying the same data for subsequent slot iterations
        # (search_logs_relative has no offset parameter; best effort with the data available)
        break
    }

    $beaconFound = $false
    foreach ($key in $beaconPairs.Keys) {
        $pair = $beaconPairs[$key]
        $rateEx = _Check-Rate -Type "beacon_pairs" -Count $pair.windowCount -WindowMinutes ($WindowHours * 60) -Config $Config
        if ($rateEx) {
            $beaconFound = $true
            $f = _New-Finding -ClassId 14 -Severity "REVIEW" `
                -Title "Class 14 -- Beaconing: $($pair.ip) <-> $($pair.uri) ($($pair.windowCount) windows)" `
                -Technique "T1071.001 -- Application Layer Protocol: Web Protocols" `
                -Summary "IP $($pair.ip) accessed URI $($pair.uri) consistently across $($pair.windowCount) hourly windows. Periodic consistent pair access suggests C2 beaconing. Threshold=$c14Thresh windows." `
                -AnchorIp $pair.ip -AnchorHost $pair.host -AnchorTime $pair.ts `
                -RateExceeded $true `
                -RawQuery $c14Query `
                -Investigate "Client_ip:$($pair.ip) AND URI_Stream:$($pair.uri) AND filebeat_log_file_path:*inetpub*" `
                -GraylogLink (_New-GraylogLink "Client_ip:$($pair.ip) AND URI_Stream:$($pair.uri)" $prodStreamId)
            $f = _Apply-AllowList -Finding $f -Config $Config
            $findings.Add($f)
        }
    }
    if (-not $beaconFound) {
        $findings.Add((_New-Finding -ClassId 14 -Severity "LOGGED" -Title "Class 14 -- Beaconing: No consistent pairs" `
            -Technique "T1071.001 -- Application Layer Protocol: Web Protocols" `
            -Summary "No IP+URI pairs met the beaconing threshold ($c14Thresh consecutive windows) in the $WindowHours-hour window." `
            -RawQuery $c14Query))
    }

    # ------------------------------------------------------------------
    # CLASS 15 -- First-Occurrence Catch-All (T1078)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 15 -- First-Occurrence"
    $c15Query = "filebeat_log_file_path:*inetpub*"
    $c15Agg   = $null
    try { $c15Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c15Query -field "Client_ip" -rangeSeconds $rangeSeconds } catch {}
    $c15Count = _Safe-AggCount $c15Agg

    if ($c15Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 15 -Severity "LOGGED" -Title "Class 15 -- First-Occurrence: Clean window" `
            -Technique "T1078 -- Valid Accounts" `
            -Summary "No IIS traffic in window. First-occurrence catch-all has nothing to evaluate." `
            -RawQuery $c15Query))
    }
    else {
        $c15Rows = @()
        try { $c15Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c15Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        $c15NewIps = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($row in $c15Rows) {
            $ip = if ($row.Client_ip) { $row.Client_ip } else { "-" }
            if ($ip -eq "-") { continue }
            $ipNew = _Is-EntityNew -Type "ip" -Value $ip -Registry $Registry
            if ($ipNew -and -not $c15NewIps.Contains($ip)) {
                [void]$c15NewIps.Add($ip)
                $iisHost = if ($row.Host)      { $row.Host }      else { "-" }
                $ts   = if ($row.timestamp) { $row.timestamp } else { [datetime]::UtcNow.ToString('o') }
                $f = _New-Finding -ClassId 15 -Severity "REVIEW" `
                    -Title "Class 15 -- First-Occurrence: New IP $ip in window" `
                    -Technique "T1078 -- Valid Accounts" `
                    -Summary "IP $ip seen for first time in IIS logs (not in entity registry). Active in current $WindowHours-hour window. Warrants review if not a known new client or partner." `
                    -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                    -EntityIsNew $true `
                    -RawQuery $c15Query `
                    -Investigate "Client_ip:$ip AND filebeat_log_file_path:*inetpub*" `
                    -GraylogLink (_New-GraylogLink "Client_ip:$ip" $prodStreamId)
                $f = _Apply-AllowList -Finding $f -Config $Config
                $findings.Add($f)
            }
        }
        if ($c15NewIps.Count -eq 0) {
            $findings.Add((_New-Finding -ClassId 15 -Severity "LOGGED" -Title "Class 15 -- First-Occurrence: All IPs known" `
                -Technique "T1078 -- Valid Accounts" `
                -Summary "All source IPs in the current window are known in the entity registry. No first-occurrence signals." `
                -RawQuery $c15Query))
        }
    }

    # ------------------------------------------------------------------
    # CLASS 16 -- Structural Anomaly (T1027)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 16 -- Structural Anomaly"
    $c16Query = "filebeat_log_file_path:*inetpub*"
    $c16Agg   = $null
    try { $c16Agg = mcp__OP-GL__aggregate_logs -streamId $prodStreamId -query $c16Query -rangeSeconds $rangeSeconds } catch {}
    $c16Count = _Safe-AggCount $c16Agg

    if ($c16Count -eq 0) {
        $findings.Add((_New-Finding -ClassId 16 -Severity "LOGGED" -Title "Class 16 -- Structural Anomaly: Clean window" `
            -Technique "T1027 -- Obfuscated Files or Information" `
            -Summary "No IIS traffic in the $WindowHours-hour window. Structural anomaly signals absent." `
            -RawQuery $c16Query))
    }
    else {
        $c16Rows = @()
        try { $c16Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c16Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}
        $c16MethodsByIp = @{}
        foreach ($row in $c16Rows) {
            $ip     = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $method = if ($row.Method)     { $row.Method }     else { "-" }
            $query  = if ($row.URI_Query)  { $row.URI_Query }  else { "" }
            $iisHost   = if ($row.Host)       { $row.Host }       else { "-" }
            $ts     = if ($row.timestamp)  { $row.timestamp }  else { [datetime]::UtcNow.ToString('o') }
            # Check extreme query string length (>500 chars) -- always REVIEW
            if ($query.Length -gt 500) {
                $f = _New-Finding -ClassId 16 -Severity "REVIEW" `
                    -Title "Class 16 -- Structural: Extreme query string (len=$($query.Length)) from $ip" `
                    -Technique "T1027 -- Obfuscated Files or Information" `
                    -Summary "IP $ip sent a query string of $($query.Length) chars (threshold 500) on URI $($row.URI_Stream). Extreme length may contain encoded obfuscated payloads." `
                    -AnchorIp $ip -AnchorHost $iisHost -AnchorTime $ts `
                    -EntityIsNew $true `
                    -RawQuery $c16Query `
                    -Investigate "Client_ip:$ip AND filebeat_log_file_path:*inetpub*" `
                    -GraylogLink (_New-GraylogLink "Client_ip:$ip" $prodStreamId)
                $f = _Apply-AllowList -Finding $f -Config $Config
                $findings.Add($f)
            }
            # Track method diversity per IP
            if (-not $c16MethodsByIp.ContainsKey($ip)) {
                $c16MethodsByIp[$ip] = @{
                    methods = [System.Collections.Generic.HashSet[string]]::new()
                    host    = "-"
                    ts      = [datetime]::UtcNow.ToString('o')
                }
            }
            [void]$c16MethodsByIp[$ip].methods.Add($method)
            if ($iisHost -ne "-" -and $c16MethodsByIp[$ip].host -eq "-") { $c16MethodsByIp[$ip].host = $iisHost }
            if ($ts -ne [datetime]::UtcNow.ToString('o') -and $c16MethodsByIp[$ip].ts -eq [datetime]::UtcNow.ToString('o')) { $c16MethodsByIp[$ip].ts = $ts }
        }
        foreach ($ip in $c16MethodsByIp.Keys) {
            if ($c16MethodsByIp[$ip].methods.Count -gt 5) {
                $f = _New-Finding -ClassId 16 -Severity "REVIEW" `
                    -Title "Class 16 -- Structural: $ip used $($c16MethodsByIp[$ip].methods.Count) distinct methods" `
                    -Technique "T1027 -- Obfuscated Files or Information" `
                    -Summary "IP $ip used $($c16MethodsByIp[$ip].methods.Count) distinct HTTP methods ($($c16MethodsByIp[$ip].methods -join ', ')) in window. Method diversity >5 suggests automated multi-method fuzzing." `
                    -AnchorIp $ip -AnchorHost $c16MethodsByIp[$ip].host -AnchorTime $c16MethodsByIp[$ip].ts `
                    -EntityIsNew $false `
                    -RawQuery $c16Query `
                    -Investigate "Client_ip:$ip AND filebeat_log_file_path:*inetpub*" `
                    -GraylogLink (_New-GraylogLink "Client_ip:$ip" $prodStreamId)
                $f = _Apply-AllowList -Finding $f -Config $Config
                $findings.Add($f)
            }
        }
        $c16Reviewed = $findings | Where-Object { $_.detection_class -eq 16 -and $_.severity -in @("REVIEW","CONFIRMED","HIGH") }
        if (-not $c16Reviewed) {
            $findings.Add((_New-Finding -ClassId 16 -Severity "LOGGED" -Title "Class 16 -- Structural Anomaly: No anomalies" `
                -Technique "T1027 -- Obfuscated Files or Information" `
                -Summary "No extreme query strings (>500 chars) or method diversity >5 detected in the $WindowHours-hour window." `
                -RawQuery $c16Query))
        }
    }

    # ------------------------------------------------------------------
    # CLASS 17 -- AI Open Hunt (GATED)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Class 17 -- AI Open Hunt (GATED)"
    $rawFindings = @($findings)
    $hasElevated = $rawFindings | Where-Object { $_.severity -in @("REVIEW","CONFIRMED","HIGH") }

    if (-not $hasElevated) {
        $findings.Add((_New-Finding -ClassId 17 -Severity "LOGGED" -Title "Class 17 -- AI Open Hunt: GATED (no upstream signals)" `
            -Technique "T1059 -- Command and Scripting Interpreter" `
            -Summary "Class 17 AI Open Hunt gated: no REVIEW or higher findings from Classes 1-16. Nothing to analyze." `
            -RawQuery "GATED"))
    }
    else {
        # Collect up to 20 rows with highest anomaly indicators
        $c17Query = "filebeat_log_file_path:*inetpub*"
        $c17Rows  = @()
        try { $c17Rows = _Safe-Results (mcp__OP-GL__search_logs_relative -streamId $prodStreamId -query $c17Query -rangeSeconds $rangeSeconds -fields $script:IIS_FIELDS -limit 20) } catch {}

        # Build summary of anomalous rows
        $rowSummaries = [System.Collections.Generic.List[string]]::new()
        foreach ($row in $c17Rows) {
            $ip      = if ($row.Client_ip)  { $row.Client_ip }  else { "-" }
            $uri     = if ($row.URI_Stream) { $row.URI_Stream } else { "-" }
            $method  = if ($row.Method)     { $row.Method }     else { "-" }
            $status  = if ($row.Status)     { $row.Status }     else { "-" }
            $ua      = if ($row.UserAgent)  { $row.UserAgent }  else { "-" }
            $rowSummaries.Add("IP=$ip Method=$method Status=$status URI=$uri UA=$ua")
        }

        $aiSummary = "Class 17 AI Open Hunt -- analyst should review these rows for patterns not covered by Classes 1-16: " + ($rowSummaries -join "; ")
        $f = _New-Finding -ClassId 17 -Severity "REVIEW" `
            -Title "Class 17 -- AI Open Hunt: $($c17Rows.Count) rows for analyst review" `
            -Technique "T1059 -- Command and Scripting Interpreter" `
            -Summary $aiSummary `
            -RawQuery $c17Query `
            -Investigate "filebeat_log_file_path:*inetpub* (review with AI for novel TTP patterns)" `
            -GraylogLink (_New-GraylogLink $c17Query $prodStreamId)
        $findings.Add($f)
    }

    # De-duplicate row-derived findings: row-looping classes (1,3,11,12,16,...) emit
    # one finding per matching row, so the same IP+URI+status repeats. The title
    # encodes those, so collapsing identical (class|title) removes duplicate noise
    # while keeping genuinely distinct findings. post-to-teams also dedups at the
    # alert layer, but this keeps the finding set and run logs clean.
    $dedupSeen = @{}
    $deduped = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($df in $findings) {
        $dkey = "$($df.detection_class)|$($df.title)"
        if (-not $dedupSeen.ContainsKey($dkey)) { $dedupSeen[$dkey] = $true; [void]$deduped.Add($df) }
    }
    return @($deduped)
}

# ---------------------------------------------------------------------------
# FUNCTION 2: Resolve-KillChain
# ---------------------------------------------------------------------------
function Resolve-KillChain {
    <#
    .SYNOPSIS
        Cross-source correlation kill chain resolver. Promotes REVIEW -> CONFIRMED -> HIGH.
    .PARAMETER Findings
        Array of FindingObjects from Invoke-LockScan.
    .PARAMETER Config
        PSCustomObject loaded from config.json.
    .OUTPUTS
        [array] of FindingObject with updated severity, corroboration_sources, kill_chain_stages.
    #>
    param(
        [Parameter(Mandatory)][array]         $Findings,
        [Parameter(Mandatory)][PSCustomObject] $Config
    )

    if (-not $Findings -or $Findings.Count -eq 0) { return @() }

    # ------------------------------------------------------------------
    # STAGE 1 -- IIS-internal multi-class promotion
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Resolve Stage 1: Multi-class IIS correlation"
    $reviewFindings = @($Findings | Where-Object { $_.severity -eq "REVIEW" })

    # Group by anchor_ip
    $byIp = @{}
    foreach ($f in $reviewFindings) {
        $anchor = $f.anchor_ip
        if (-not $anchor -or $anchor -eq "-") { continue }
        if (-not $byIp.ContainsKey($anchor)) { $byIp[$anchor] = [System.Collections.Generic.List[PSCustomObject]]::new() }
        $byIp[$anchor].Add($f)
    }

    # Group by anchor_user
    $byUser = @{}
    foreach ($f in $reviewFindings) {
        $anchor = $f.anchor_user
        if (-not $anchor -or $anchor -eq "-") { continue }
        if (-not $byUser.ContainsKey($anchor)) { $byUser[$anchor] = [System.Collections.Generic.List[PSCustomObject]]::new() }
        $byUser[$anchor].Add($f)
    }

    # Promote groups with >=2 distinct detection classes
    function _Promote-Group {
        param([System.Collections.Generic.List[PSCustomObject]]$Group, [string]$AnchorType, [string]$AnchorValue)
        $classIds = @($Group | Select-Object -ExpandProperty detection_class -Unique)
        if ($classIds.Count -ge 2) {
            foreach ($f in $Group) {
                if ($f.severity -eq "REVIEW") {
                    $f.severity         = "CONFIRMED"
                    $f.confidence_score = 0.65
                    $stageMsg           = "Multi-class IIS correlation: Class $($classIds[0]) + Class $($classIds[1]) on $AnchorType=$AnchorValue"
                    if (-not ($f.kill_chain_stages -contains $stageMsg)) {
                        $f.kill_chain_stages.Add($stageMsg)
                    }
                }
            }
        }
    }

    foreach ($ip in $byIp.Keys)     { _Promote-Group -Group $byIp[$ip]   -AnchorType "ip"   -AnchorValue $ip }
    foreach ($u  in $byUser.Keys)   { _Promote-Group -Group $byUser[$u]   -AnchorType "user" -AnchorValue $u  }

    # ------------------------------------------------------------------
    # STAGE 2 -- Cross-source correlation (all findings != LOGGED)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Resolve Stage 2: Cross-source correlation"
    $corrRange = $Config.correlation_window_minutes * 2 * 60

    $toCorrelate = @($Findings | Where-Object { $_.severity -ne "LOGGED" })
    foreach ($finding in $toCorrelate) {
        $anchorIp   = $finding.anchor_ip
        $anchorUser = $finding.anchor_user
        $priorSev   = $finding.severity

        # --- Winlog_beat pivot ---
        if ($anchorIp -and $anchorIp -ne "-") {
            $wlRows = @()
            try {
                $wlRows = _Safe-Results (mcp__OP-GL__search_logs_relative `
                    -streamId $Config.correlation_streams.winlog_beat `
                    -query    "source_ip:$anchorIp" `
                    -rangeSeconds $corrRange `
                    -fields   "EventID,source_ip,account_name,process_name,event_description" `
                    -limit    10)
            } catch {}
            if ($wlRows.Count -gt 0) {
                $finding.corroboration_sources.Add("Winlog_beat: EventID hit count=$($wlRows.Count)")
            }
        }

        # --- FortiGate pivot ---
        if ($anchorIp -and $anchorIp -ne "-") {
            $fgRows = @()
            try {
                $fgRows = _Safe-Results (mcp__OP-GL__search_logs_relative `
                    -streamId $Config.correlation_streams.fortigate `
                    -query    "src_ip:$anchorIp OR dst_ip:$anchorIp" `
                    -rangeSeconds $corrRange `
                    -fields   "src_ip,dst_ip,action,policy_name" `
                    -limit    10)
            } catch {}
            if ($fgRows.Count -gt 0) {
                $fgAction = if ($fgRows[0].action) { $fgRows[0].action } else { "unknown" }
                $finding.corroboration_sources.Add("FortiGate: action=$fgAction count=$($fgRows.Count)")
            }
        }

        # --- Securenvoy pivot (only if anchor_user != "-") ---
        if ($anchorUser -and $anchorUser -ne "-") {
            $snRows = @()
            try {
                $snRows = _Safe-Results (mcp__OP-GL__search_logs_relative `
                    -streamId $Config.correlation_streams.securenvoy `
                    -query    "username:$anchorUser" `
                    -rangeSeconds $corrRange `
                    -fields   "username,auth_result,client_ip,timestamp" `
                    -limit    10)
            } catch {}
            if ($snRows.Count -gt 0) {
                $denyCount = @($snRows | Where-Object {
                    $r = $_
                    ($r.auth_result -and ($r.auth_result -match "DENY|FAIL|REJECT|denied"))
                }).Count
                $finding.corroboration_sources.Add("Securenvoy: MFA DENY count=$denyCount (total=$($snRows.Count))")
            }
        }

        # --- External SFTP pivot ---
        if ($anchorIp -and $anchorIp -ne "-") {
            $sftpRows = @()
            try {
                $sftpRows = _Safe-Results (mcp__OP-GL__search_logs_relative `
                    -streamId $Config.correlation_streams.external_sftp `
                    -query    "client_ip:$anchorIp" `
                    -rangeSeconds $corrRange `
                    -fields   "client_ip,username,action,filename" `
                    -limit    5)
            } catch {}
            if ($sftpRows.Count -gt 0) {
                $finding.corroboration_sources.Add("External_SFTP: session count=$($sftpRows.Count)")
            }
        }

        # --- ESET pivot ---
        if ($anchorIp -and $anchorIp -ne "-") {
            $esetRows = @()
            try {
                $esetRows = _Safe-Results (mcp__OP-GL__search_logs_relative `
                    -streamId $Config.correlation_streams.eset_syslog `
                    -query    "source_ip:$anchorIp" `
                    -rangeSeconds $corrRange `
                    -fields   "source_ip,alert_name,threat_name,action" `
                    -limit    5)
            } catch {}
            if ($esetRows.Count -gt 0) {
                $finding.corroboration_sources.Add("ESET: alert count=$($esetRows.Count)")
            }
        }

        # --- Hmailer pivot (Classes 8 and 13 only) ---
        if ($finding.detection_class -in @(8, 13)) {
            if ($anchorIp -and $anchorIp -ne "-") {
                $hmailRows = @()
                try {
                    $hmailRows = _Safe-Results (mcp__OP-GL__search_logs_relative `
                        -streamId $Config.correlation_streams.hmailer `
                        -query    "src_ip:$anchorIp" `
                        -rangeSeconds $corrRange `
                        -fields   "src_ip,from_address,to_address,subject,action" `
                        -limit    5)
                } catch {}
                if ($hmailRows.Count -gt 0) {
                    $finding.corroboration_sources.Add("Hmailer: email count=$($hmailRows.Count)")
                }
            }
        }

        # --- Promotion logic ---
        if ($finding.corroboration_sources.Count -ge 1) {
            $finding.promoted_from   = $priorSev
            $finding.severity        = "HIGH"
            $finding.confidence_score = [Math]::Min(0.98, 0.7 + (0.1 * $finding.corroboration_sources.Count))
            $finding.finding_id      = $finding.finding_id + "-CORR"

            # Kill chain stage by detection class
            $kcStage = switch ($finding.detection_class) {
                8       { "Initial Access: Credential Attack" }
                13      { "Exfiltration: Data Transfer" }
                14      { "Command and Control: C2 Beaconing" }
                7       { "Persistence: Webshell Installed" }
                default { "Impact: Confirmed Malicious Activity" }
            }
            if (-not ($finding.kill_chain_stages -contains $kcStage)) {
                $finding.kill_chain_stages.Add($kcStage)
            }
        }
    }

    # ------------------------------------------------------------------
    # STAGE 3 -- Dynamic rule growth (K-phase)
    # ------------------------------------------------------------------
    Write-Verbose "[LOCK] Resolve Stage 3: K-phase dynamic rule growth"
    # Resolve rules path portably: prefer path relative to this script file.
    # $PSCommandPath is populated when the file is run directly; when dot-sourced
    # it may be $null, so we fall back to $MyInvocation.ScriptName and then to a
    # convention-based path relative to the module root.
    $scriptFile = if ($PSCommandPath) { $PSCommandPath } `
                  elseif ($MyInvocation.ScriptName) { $MyInvocation.ScriptName } `
                  else { $null }
    $class17Elevated = @($Findings | Where-Object {
        $_.detection_class -eq 17 -and $_.severity -in @("REVIEW","CONFIRMED","HIGH")
    })

    if ($class17Elevated.Count -gt 0) {
        # ADVISORY ONLY -- do NOT mutate the committed iis-lock-rules.json at runtime.
        # Auto-graduating on every run caused runaway growth (a new class each hour)
        # and dirtied the tracked file. Per design a pattern should graduate only after
        # recurring >=3 times across runs; until that is tracked, append each AI-surfaced
        # pattern to a gitignored side-file for analyst review and manual promotion.
        try {
            $suggestRoot = if ($scriptFile) { Split-Path -Parent $scriptFile } else { (Get-Location).Path }
            $suggestDir  = Join-Path $suggestRoot "logs"
            if (-not (Test-Path $suggestDir)) { $null = New-Item -ItemType Directory -Force -Path $suggestDir }
            $suggestFile = Join-Path $suggestDir "suggested-rules.jsonl"
            foreach ($c17f in $class17Elevated) {
                $suggestion = [ordered]@{
                    suggested_at = [datetime]::UtcNow.ToString('o')
                    source       = "Class17-AIOpenHunt"
                    title        = $c17f.title
                    summary      = $c17f.summary
                    anchor_ip    = $c17f.anchor_ip
                }
                Add-Content -Path $suggestFile -Value ($suggestion | ConvertTo-Json -Depth 6 -Compress) -Encoding utf8
            }
            Write-Verbose "[LOCK K-phase] $($class17Elevated.Count) AI-surfaced pattern(s) appended to suggested-rules.jsonl (advisory; committed rules NOT modified)"
        }
        catch {
            Write-Warning "[LOCK K-phase] Could not write rule suggestions: $_"
        }
    }

    return @($Findings)
}
