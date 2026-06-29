# iis-preparse.ps1
# Zero-token STEP 0: REST pre-aggregation for IIS surfaces (OP-GL, PROD-GL, AZ-GL).
# Called by common-preparse.ps1 after RDP/Linux/Azure/SFTP surfaces.
# Writes: reports-noskill\iis-preparse.json
#
# PS5.1 compatible — no ?? operator, no foreach inside hash literals.
param(
  [int]$RangeSeconds = 86400
)
$ErrorActionPreference = 'Continue'
$proj = 'D:\Vidhya\New Daily hunt'
Set-Location $proj

Write-Output "iis-preparse: starting (range=$RangeSeconds s)"

# --- Auth + SSL ---
$mcpCfg = Get-Content "$proj\.mcp.json" -Raw | ConvertFrom-Json
$Cfg    = Get-Content "$proj\preparse-config.json" -Raw | ConvertFrom-Json

Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class IISPreTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s,
  X509Certificate c, WebRequest r, int p){ return true; } }
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object IISPreTrust -ErrorAction SilentlyContinue
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- GL connection table ---
$glCfg = @{
    'OP-GL'   = @{ base  = $mcpCfg.mcpServers.'OP-GL'.env.BASE_URL.TrimEnd('/')
                   token = $mcpCfg.mcpServers.'OP-GL'.env.API_TOKEN }
    'PROD-GL' = @{ base  = $mcpCfg.mcpServers.'PROD-GL'.env.BASE_URL.TrimEnd('/')
                   token = $mcpCfg.mcpServers.'PROD-GL'.env.API_TOKEN }
    'AZ-GL'   = @{ base  = $mcpCfg.mcpServers.'AZ-GL'.env.BASE_URL.TrimEnd('/')
                   token = $mcpCfg.mcpServers.'AZ-GL'.env.API_TOKEN }
}

# --- Allowlist helpers (from preparse-config.json) ---
$allowlistExact = @($Cfg.allowlist.nessus_ips) + @($Cfg.allowlist.cato_ips)
function Test-AllowListed {
    param([string]$ip)
    if ($allowlistExact -contains $ip) { return $true }
    foreach ($pfx in $Cfg.allowlist.zscaler_prefixes) {
        if ($ip.StartsWith($pfx)) { return $true }
    }
    return $false
}
function Test-Internal {
    param([string]$ip)
    if ($ip -match '^10\.' -or $ip -match '^192\.168\.' -or
        $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
    if ($ip -match '^169\.254\.' -or $ip -match '^127\.') { return $true }
    return $false
}

# --- REST helpers ---
function Invoke-GlCount {
    param([string]$Base, [string]$Token, [string]$Query)
    $b64  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Token + ':token'))
    $hdrs = @{ Authorization = "Basic $b64"; 'X-Requested-By' = 'iis-preparse'; Accept = 'application/json' }
    $url  = "$Base/api/search/universal/relative?query=" + [uri]::EscapeDataString($Query) +
            "&range=$RangeSeconds&limit=1&fields=source"
    try { return [int](Invoke-RestMethod -Uri $url -Headers $hdrs -TimeoutSec 60).total_results }
    catch { return -1 }
}

function Get-TopN {
    param([string]$Base, [string]$Token, [string]$Query, [string]$Field,
          [int]$FetchLimit = 5000, [int]$TopN = 20)
    $b64  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Token + ':token'))
    $hdrs = @{ Authorization = "Basic $b64"; 'X-Requested-By' = 'iis-preparse'; Accept = 'application/json' }
    $url  = "$Base/api/search/universal/relative?query=" + [uri]::EscapeDataString($Query) +
            "&range=$RangeSeconds&limit=$FetchLimit&fields=" + [uri]::EscapeDataString("$Field,source")
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $hdrs -TimeoutSec 90
        $vals = @($resp.messages | ForEach-Object { [string]$_.message.$Field } |
                  Where-Object { $_ -and $_ -ne '-' })
        $grp  = $vals | Group-Object | Sort-Object Count -Descending | Select-Object -First $TopN
        $top  = [ordered]@{}
        foreach ($g in $grp) { $top[$g.Name] = $g.Count }
        return @{ total_matched = [int]$resp.total_results; top = $top; error = $null }
    } catch {
        return @{ total_matched = 0; top = [ordered]@{}; error = $_.Exception.Message }
    }
}

# --- Anomaly thresholds ---
$T401 = 5; $T403 = 5; $T404 = 50; $T5xx = 10; $T200ext = 20

$baseQ = 'filebeat_log_file_path:*inetpub*'

$output = [ordered]@{
    generated      = (Get-Date -Format o)
    range_seconds  = $RangeSeconds
    schema_version = 2
    envs           = [ordered]@{}
}

foreach ($gl in @('OP-GL', 'PROD-GL', 'AZ-GL')) {
    Write-Output "iis-preparse: [$gl] starting"
    $base  = $glCfg[$gl].base
    $token = $glCfg[$gl].token
    $parsed = ($gl -eq 'OP-GL')

    $env = [ordered]@{
        env           = $gl
        generated     = (Get-Date -Format o)
        field_quality = if ($parsed) { 'parsed' } else { 'partial' }
        bucket_counts = [ordered]@{}
        anomalies     = @()
        allowlisted   = @()
        active_servers = @()
        step2         = [ordered]@{}
        coverage_note = ''
        errors        = @()
    }

    # Active servers from source field
    $srcR = Get-TopN -Base $base -Token $token -Query $baseQ -Field 'source' -FetchLimit 1000 -TopN 20
    if ($srcR.total_matched -gt 0) { $env.active_servers = @($srcR.top.Keys | Select-Object -First 20) }

    # Status bucket counts
    foreach ($bucket in @('200','401','403','404','500','503')) {
        $env.bucket_counts[$bucket] = Invoke-GlCount -Base $base -Token $token -Query ($baseQ + ' AND Status:' + $bucket)
    }

    # Build anomaly list
    $anomList  = [System.Collections.ArrayList]::new()
    $seenIps   = [System.Collections.Hashtable]::new()
    $allowList = [System.Collections.ArrayList]::new()

    $bucketChecks = @(
        @{ status='401'; thresh=$T401 },
        @{ status='403'; thresh=$T403 },
        @{ status='404'; thresh=$T404 },
        @{ status='500'; thresh=$T5xx }
    )

    if ($parsed) {
        # OP-GL: named fields reliable
        foreach ($bc in $bucketChecks) {
            $q = $baseQ + ' AND Status:' + $bc.status
            $r = Get-TopN -Base $base -Token $token -Query $q -Field 'Client_ip' -FetchLimit 5000 -TopN 15
            if ($r.error) { $env.errors += ('ip-agg-' + $bc.status + ': ' + $r.error) }
            foreach ($ip in $r.top.Keys) {
                $cnt = [int]$r.top[$ip]
                if ($cnt -lt [int]$bc.thresh) { continue }
                if (-not $ip -or $ip -eq '-') { continue }
                if (Test-AllowListed $ip) {
                    # PS5.1: no ?? — use if/else
                    $reason = if ($allowlistExact -contains $ip) { 'nessus/cato' } else { 'zscaler-prefix' }
                    $null = $allowList.Add([ordered]@{ ip=$ip; reason=$reason; status=$bc.status; count=$cnt })
                    continue
                }
                if ($seenIps.ContainsKey($ip)) { continue }
                $seenIps[$ip] = 1
                $null = $anomList.Add([ordered]@{
                    type        = 'status-' + $bc.status
                    ip          = $ip
                    count       = $cnt
                    is_internal = (Test-Internal $ip)
                })
            }
        }

        # External high-volume 200 (potential exfil)
        $q200 = $baseQ + ' AND Status:200 AND _exists_:Client_ip AND NOT Client_ip:10.* AND NOT Client_ip:192.168.*'
        $r200 = Get-TopN -Base $base -Token $token -Query $q200 -Field 'Client_ip' -FetchLimit 3000 -TopN 10
        foreach ($ip in $r200.top.Keys) {
            $cnt = [int]$r200.top[$ip]
            if ($cnt -lt $T200ext) { continue }
            if (-not $ip -or $ip -eq '-') { continue }
            if (Test-AllowListed $ip) { continue }
            if ($seenIps.ContainsKey($ip)) { continue }
            $seenIps[$ip] = 1
            $null = $anomList.Add([ordered]@{ type='ext-200'; ip=$ip; count=$cnt; is_internal=$false })
        }

        # STEP 2 — Methods
        $mthR = Get-TopN -Base $base -Token $token -Query $baseQ -Field 'Method' -FetchLimit 2000 -TopN 20
        $dangerousMethods = @('PUT','DELETE','TRACE','TRACK','CONNECT','PROPFIND','MKCOL','MOVE','COPY')
        $dangerousFound   = @($mthR.top.Keys | Where-Object { $dangerousMethods -contains $_ })
        $mthTop = [ordered]@{}
        foreach ($k in $mthR.top.Keys) { $mthTop[$k] = $mthR.top[$k] }
        $env.step2['methods'] = [ordered]@{
            top             = $mthTop
            dangerous_count = $dangerousFound.Count
            dangerous_list  = $dangerousFound
            note            = if ($dangerousFound.Count -gt 0) { 'MEDIUM: ' + ($dangerousFound -join ',') + ' found' } else { 'CLEAN' }
        }

        # STEP 2 — Scanner UAs
        $uaPatterns = @('python-requests','Go-http-client','curl/','wget/','libwww','fasthttp',
                        'masscan','zgrab','nuclei','nikto','sqlmap','acunetix','nmap','WPScan',
                        'CensysInspect','Shodan','InternetMeasurement','Expanse')
        $uaR = Get-TopN -Base $base -Token $token -Query $baseQ -Field 'UserAgent' -FetchLimit 3000 -TopN 30
        $flaggedUAs = @($uaR.top.Keys | Where-Object {
            $ua = $_
            $hit = $false
            foreach ($p in $uaPatterns) { if ($ua -match [regex]::Escape($p)) { $hit = $true; break } }
            $hit
        })
        $uaDetail = [ordered]@{}
        foreach ($ua in $flaggedUAs) { $uaDetail[$ua] = $uaR.top[$ua] }
        $env.step2['scanner_uas'] = [ordered]@{
            flagged_count = $flaggedUAs.Count
            flagged       = $uaDetail
            note          = if ($flaggedUAs.Count -gt 0) { 'MEDIUM: ' + ($flaggedUAs -join '; ') + ' found' } else { 'CLEAN' }
        }

        # STEP 2 — Volumetric (all-status top IPs)
        $volR   = Get-TopN -Base $base -Token $token -Query $baseQ -Field 'Client_ip' -FetchLimit 5000 -TopN 20
        $volTop = [ordered]@{}
        foreach ($ip in $volR.top.Keys) {
            if (-not $ip -or $ip -eq '-') { continue }
            if (Test-AllowListed $ip) { continue }
            $volTop[$ip] = $volR.top[$ip]
        }
        $env.step2['volumetric_top']  = $volTop
        # Off-hours query: external IPs with 200 or 206 outside 06:00-22:00 IST (UTC+5:30 = 00:30-16:30 UTC).
        # Graylog stores timestamps in UTC; "off-hours IST" = UTC 18:30-23:59 OR 00:00-00:30.
        # Use two relative ranges OR combine with a broad query and let Claude filter by hour in the results.
        $env.step2['offhours_note']   = 'filebeat_log_file_path:*inetpub* AND (Status:200 OR Status:206) AND _exists_:Client_ip AND NOT Client_ip:10.* AND NOT Client_ip:192.168.* AND NOT Client_ip:172.16.* — NOTE: filter results to timestamps 22:00-06:00 IST (18:30-00:30 UTC)'

        $env.coverage_note = 'OP-GL fully parsed. anomalies[] capped at 12. step2 has methods/scanner_uas/volumetric_top.'

    } else {
        # PROD-GL / AZ-GL: named fields partially null — grab what we can
        foreach ($bc in $bucketChecks) {
            $q = $baseQ + ' AND Status:' + $bc.status + ' AND _exists_:Client_ip'
            $r = Get-TopN -Base $base -Token $token -Query $q -Field 'Client_ip' -FetchLimit 3000 -TopN 10
            if ($r.error) { $env.errors += ('ip-agg-' + $bc.status + ': ' + $r.error) }
            foreach ($ip in $r.top.Keys) {
                $cnt = [int]$r.top[$ip]
                if ($cnt -lt [int]$bc.thresh) { continue }
                if (-not $ip -or $ip -eq '-') { continue }
                if (Test-AllowListed $ip) { continue }
                if ($seenIps.ContainsKey($ip)) { continue }
                $seenIps[$ip] = 1
                $null = $anomList.Add([ordered]@{
                    type        = 'status-' + $bc.status
                    ip          = $ip
                    count       = $cnt
                    is_internal = (Test-Internal $ip)
                })
            }
        }
        $env.step2 = [ordered]@{
            methods     = [ordered]@{ note = 'PARTIAL: named fields unreliable on ' + $gl + '. Run live aggregate.' }
            scanner_uas = [ordered]@{ note = 'PARTIAL: UA field unreliable on ' + $gl + '. Run live aggregate.' }
        }
        $env.coverage_note = $gl + ' fields partially null. Validate anomalies via raw message: filebeat_log_file_path:*inetpub* AND message:*<ip>*'
    }

    # Cap at 3 per env — prompt budgets "1-2 turns × max 3 anomalies per env" for STEP 1.
    # Sorted descending by count so the highest-signal IPs are picked first.
    $env.anomalies   = @($anomList  | Sort-Object { -[int]$_.count } | Select-Object -First 3)
    $env.allowlisted = @($allowList | Select-Object -First 20)

    Write-Output ("iis-preparse: [" + $gl + "] done - anomalies=" + $env.anomalies.Count +
                  " allowlisted=" + $env.allowlisted.Count + " buckets=" + ($env.bucket_counts.Keys -join '/'))
    $output.envs[$gl] = $env
}

$json = $output | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText("$proj\reports-noskill\iis-preparse.json", $json, [Text.Encoding]::UTF8)
Write-Output "iis-preparse: written -> reports-noskill\iis-preparse.json"
