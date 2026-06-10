# log-validator.ps1 — Unit 2: IIS OP-GL Log Integrity Validator (L-phase Learn)
#
# Exports:  Invoke-LogValidation
# Purpose:  Computes IIS filter-ratio (parsed/total) and stream health flags for
#           the LOCK framework Learn phase. Returns a ValidationResult object
#           consumed by the Unit 5 orchestrator (iis-opgl-monitor.ps1).
#
# Dot-source usage:
#   . .\log-validator.ps1
#   $result = Invoke-LogValidation -WindowHours 24 -Config $cfg

# ---------------------------------------------------------------------------
# Private helper: extract a log-count integer from an aggregate_logs result.
#
# Handles three shapes aggregate_logs may return:
#   1. PSCustomObject with a 'total' property  -> use .total
#   2. PSCustomObject with a 'count' property  -> use .count
#   3. Raw scalar (int/long/double)            -> cast directly
#
# NOTE: We deliberately do NOT use PSObject.Properties['count'] because
# PowerShell's property-name lookup is case-insensitive and an Object[] array
# also exposes a 'Count' property equal to the number of elements — which would
# silently return the bucket-count instead of the log-count when aggregate_logs
# returns an array of term-buckets.  Instead we gate on the concrete type first.
# ---------------------------------------------------------------------------
function script:Get-AggregateCount {
    param($RawResult)

    if ($null -eq $RawResult) { return [long]0 }

    # Raw scalar — returned directly by some MCP shims
    if ($RawResult -is [int] -or $RawResult -is [long] -or $RawResult -is [double]) {
        return [long]$RawResult
    }

    # PSCustomObject with a top-level 'total' field (standard Graylog shape)
    if ($RawResult -is [System.Management.Automation.PSCustomObject]) {
        if ($null -ne $RawResult.PSObject.Properties['total']  -and
            $null -ne $RawResult.total) {
            try { return [long]$RawResult.total  } catch { return [long]0 }
        }
        # Fallback: some endpoints use 'count' at the top level
        if ($null -ne $RawResult.PSObject.Properties['count'] -and
            $null -ne $RawResult.count) {
            try { return [long]$RawResult.count } catch { return [long]0 }
        }
    }

    # Unrecognised shape — treat as zero rather than silently misreporting
    return [long]0
}

function Invoke-LogValidation {
    <#
    .SYNOPSIS
        Validates IIS log ingestion completeness for OP-GL streams.

    .DESCRIPTION
        Queries OP-GL via aggregate_logs to measure:
          - Total IIS log volume (filebeat_log_file_path:*inetpub*)
          - Parsed (structured) log volume (Status + Client_ip fields present)
          - Per-stream IIS health (prod, uat non-zero inetpub traffic check, C13 control)

        Returns a ValidationResult PSCustomObject. Does NOT post Teams alerts;
        the orchestrator acts on alert_required.

    .PARAMETER WindowHours
        Lookback window in hours (1–8760). Converted internally to seconds.

    .PARAMETER Config
        PSCustomObject with:
          .log_filter_drift_threshold  [double]  e.g. 0.05
          .iis_streams.prod            [string]  Graylog stream ID
          .iis_streams.uat             [string]  Graylog stream ID

    .OUTPUTS
        PSCustomObject with:
          total_iis_logs  [long]    (changed from [int] to avoid Int32 overflow)
          parsed_logs     [long]
          filter_ratio    [double]  always in [0.0, 1.0]; clamped if skew occurs
          alert_required  [bool]
          streams_checked [string[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 8760)]
        [int] $WindowHours,

        [Parameter(Mandatory = $true)]
        [PSCustomObject] $Config
    )

    $rangeSeconds = $WindowHours * 3600
    Write-Verbose ("[log-validator] WindowHours={0}  rangeSeconds={1}  threshold={2}" -f $WindowHours, $rangeSeconds, $Config.log_filter_drift_threshold)

    # ------------------------------------------------------------------
    # Step 2 — Total IIS log count (all filebeat paths under inetpub)
    # ------------------------------------------------------------------
    Write-Verbose "[log-validator] Querying total IIS log count (prod stream)..."
    $totalRaw = $null
    try {
        $totalRaw = mcp__OP-GL__aggregate_logs `
            -query "filebeat_log_file_path:*inetpub*" `
            -field "filebeat_log_file_path" `
            -rangeSeconds $rangeSeconds `
            -streamId $Config.iis_streams.prod
    } catch {
        Write-Verbose ("[log-validator] aggregate_logs (total) threw: {0}" -f $_.Exception.Message)
    }

    [long]$total_iis_logs = script:Get-AggregateCount $totalRaw
    Write-Verbose ("[log-validator] total_iis_logs={0}" -f $total_iis_logs)

    # ------------------------------------------------------------------
    # Step 3 — Parsed/structured IIS log count (Status + Client_ip exist)
    # ------------------------------------------------------------------
    Write-Verbose "[log-validator] Querying parsed IIS log count (prod stream)..."
    $parsedRaw = $null
    try {
        $parsedRaw = mcp__OP-GL__aggregate_logs `
            -query "filebeat_log_file_path:*inetpub* AND _exists_:Status AND _exists_:Client_ip AND Status:[100 TO 599]" `
            -field "filebeat_log_file_path" `
            -rangeSeconds $rangeSeconds `
            -streamId $Config.iis_streams.prod
    } catch {
        Write-Verbose ("[log-validator] aggregate_logs (parsed) threw: {0}" -f $_.Exception.Message)
    }

    [long]$parsed_logs = script:Get-AggregateCount $parsedRaw
    Write-Verbose ("[log-validator] parsed_logs={0}" -f $parsed_logs)

    # ------------------------------------------------------------------
    # Step 4 — Filter ratio (fraction of logs that did NOT parse cleanly)
    # Clamp to [0, 1]: parsed_logs can momentarily exceed total_iis_logs due
    # to time-window skew between two sequential queries (new logs arriving
    # between call 1 and call 2 inflate the parsed count).
    # ------------------------------------------------------------------
    [double]$filter_ratio = 0.0
    if ($total_iis_logs -gt 0) {
        $raw_ratio = ($total_iis_logs - $parsed_logs) / [double]$total_iis_logs
        $filter_ratio = [Math]::Max(0.0, [Math]::Min(1.0, $raw_ratio))
    }
    Write-Verbose ("[log-validator] filter_ratio={0:F4}" -f $filter_ratio)

    # ------------------------------------------------------------------
    # Step 5 — Alert gate
    # ------------------------------------------------------------------
    [bool]$alert_required = $filter_ratio -gt $Config.log_filter_drift_threshold
    Write-Verbose ("[log-validator] alert_required={0}  (threshold={1})" -f $alert_required, $Config.log_filter_drift_threshold)

    # ------------------------------------------------------------------
    # Step 6 — C13 completeness control: per-stream IIS traffic check
    # Uses the same inetpub-scoped query as Step 2 (not query="*") so that
    # a stream with non-IIS traffic does not falsely report as "OK".
    # ------------------------------------------------------------------
    $streams_checked = [System.Collections.Generic.List[string]]::new()
    foreach ($streamName in @("prod", "uat")) {
        $streamId = $Config.iis_streams.$streamName
        Write-Verbose ("[log-validator] Checking stream '{0}' (id={1})..." -f $streamName, $streamId)
        $streamRaw = $null
        try {
            $streamRaw = mcp__OP-GL__aggregate_logs `
                -query "filebeat_log_file_path:*inetpub*" `
                -field "filebeat_log_file_path" `
                -rangeSeconds $rangeSeconds `
                -streamId $streamId
        } catch {
            Write-Verbose ("[log-validator] aggregate_logs (stream={0}) threw: {1}" -f $streamName, $_.Exception.Message)
        }

        [long]$streamCount = script:Get-AggregateCount $streamRaw

        if ($streamCount -gt 0) {
            $streams_checked.Add("${streamName}:OK")
            Write-Verbose ("[log-validator] stream '{0}': OK (count={1})" -f $streamName, $streamCount)
        } else {
            $streams_checked.Add("${streamName}:EMPTY")
            Write-Verbose ("[log-validator] stream '{0}': EMPTY" -f $streamName)
        }
    }

    # ------------------------------------------------------------------
    # Step 7 — Return ValidationResult
    # ------------------------------------------------------------------
    return [PSCustomObject]@{
        total_iis_logs  = $total_iis_logs
        parsed_logs     = $parsed_logs
        filter_ratio    = $filter_ratio
        alert_required  = $alert_required
        streams_checked = $streams_checked.ToArray()
    }
}
