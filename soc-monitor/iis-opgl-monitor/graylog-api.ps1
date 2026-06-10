<#
  graylog-api.ps1 - OP-GL Graylog REST data layer for the IIS monitor.

  WHY: mcp__OP-GL__* are Claude agent tools, NOT PowerShell cmdlets, so a
  scheduled powershell.exe run cannot call them (proven: "term not recognized").
  The OP-GL MCP server is just `mcp-server-graylog` bridging to Graylog's REST API
  (see soc-monitor\.mcp.json). This file reimplements the two functions the
  detector needs as direct Invoke-RestMethod calls to that same REST API, so the
  entire 1,400-line detector + correlation engine runs unchanged and unattended.

  All OP-GL streams (IIS, Winlog_beat, FortiGate, Securenvoy, SFTP, ESET, Hmailer)
  live on the one OP-GL Graylog, so a single base URL + token serves every query.

  Config (from secrets.local.ps1, gitignored):
    $env:OPGL_BASE_URL   e.g. https://siem.secureocp.com
    $env:OPGL_API_TOKEN  read-scoped Graylog API token

  Returns the SAME shapes the MCP tools return:
    aggregate_logs        -> { total_matched, top, ... }
    search_logs_relative  -> { total_results, messages:[ {flat field map} ] }

  Run directly with -Probe for a live self-test (requires OP-GL REST access).
#>
[CmdletBinding()]
param([switch] $Probe)

$script:OPGL_BASE  = $env:OPGL_BASE_URL
$script:OPGL_TOKEN = $env:OPGL_API_TOKEN

function _OPGL-Headers {
    if (-not $script:OPGL_TOKEN) { throw 'OPGL_API_TOKEN not set - dot-source secrets.local.ps1 first' }
    # Graylog API-token auth: token as username, literal "token" as password.
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($script:OPGL_TOKEN):token"))
    return @{ Authorization = "Basic $b64"; 'X-Requested-By' = 'iis-opgl-monitor'; Accept = 'application/json' }
}

function _OPGL-Search {
    # Core Graylog relative search (universal/relative). Returns the raw response,
    # or $null on error (callers degrade gracefully).
    param([string]$Query, [int]$RangeSeconds, [string]$Fields, [int]$Limit, [string]$StreamId)
    if (-not $script:OPGL_BASE) { throw 'OPGL_BASE_URL not set - dot-source secrets.local.ps1 first' }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $qp = @("query=$([uri]::EscapeDataString($Query))", "range=$RangeSeconds")
    if ($Limit -gt 0)            { $qp += "limit=$Limit" }
    if ($Fields)                 { $qp += "fields=$([uri]::EscapeDataString($Fields))" }
    if ($StreamId)               { $qp += "filter=$([uri]::EscapeDataString("streams:$StreamId"))" }
    $qp += 'decorate=false'
    $uri = "$($script:OPGL_BASE)/api/search/universal/relative?" + ($qp -join '&')
    return Invoke-RestMethod -Uri $uri -Headers (_OPGL-Headers) -Method Get -TimeoutSec 90
}

function mcp__OP-GL__aggregate_logs {
    # Count-only: the detector's _Safe-AggCount reads total_matched. Per-entity
    # grouping is done client-side from drilled rows, so top{} is left empty.
    param([string]$query, [string]$field, [int]$rangeSeconds, [string]$streamId, $from, $to, $fetchLimit, $size)
    try {
        $r = _OPGL-Search -Query $query -RangeSeconds $rangeSeconds -Limit 1 -StreamId $streamId
        $total = if ($r -and $null -ne $r.total_results) { [long]$r.total_results } else { [long]0 }
    } catch {
        Write-Verbose "[graylog-api] aggregate '$query' failed: $($_.Exception.Message)"
        $total = [long]0
    }
    return [pscustomobject]@{
        field = $field; query = $query; total_matched = $total
        messages_aggregated = 0; truncated = $false; unique_groups = 0; top = @{}; other = 0; missing = 0
    }
}

function mcp__OP-GL__search_logs_relative {
    # Drill: returns flat row objects under .messages (matching the MCP tool shape).
    param([string]$query, [int]$rangeSeconds, [string]$fields, [int]$limit, [string]$streamId, $from, $to)
    $lim = if ($limit -gt 0) { $limit } else { 20 }
    $rows = @()
    $total = [long]0
    try {
        $r = _OPGL-Search -Query $query -RangeSeconds $rangeSeconds -Fields $fields -Limit $lim -StreamId $streamId
        if ($r) {
            if ($null -ne $r.total_results) { $total = [long]$r.total_results }
            if ($r.messages) {
                # Graylog wraps each hit as { message:{...}, index, ... }; flatten to the field map.
                $rows = @($r.messages | ForEach-Object { if ($_.PSObject.Properties['message'] -and $_.message) { $_.message } else { $_ } })
            }
        }
    } catch {
        Write-Verbose "[graylog-api] search '$query' failed: $($_.Exception.Message)"
    }
    return [pscustomobject]@{ total_results = $total; query = $query; messages = $rows }
}

if ($Probe) {
    Write-Host "=== OP-GL REST probe ==="
    Write-Host ("base = {0}" -f $script:OPGL_BASE)
    $agg = mcp__OP-GL__aggregate_logs -query 'filebeat_log_file_path:*inetpub*' -rangeSeconds 3600 -streamId '69837caf557da7352164b45c'
    Write-Host ("aggregate total_matched = {0}" -f $agg.total_matched)
    $srch = mcp__OP-GL__search_logs_relative -query 'filebeat_log_file_path:*inetpub* AND Status:401' -rangeSeconds 3600 -fields 'Method,Status,Client_ip,URI_Stream,Host,Server_Bytes' -limit 2 -streamId '69837caf557da7352164b45c'
    Write-Host ("search total_results = {0}  rows_returned = {1}" -f $srch.total_results, @($srch.messages).Count)
    if (@($srch.messages).Count -gt 0) {
        Write-Host ("row0 fields = {0}" -f (($srch.messages[0].PSObject.Properties.Name) -join ','))
    }
}
