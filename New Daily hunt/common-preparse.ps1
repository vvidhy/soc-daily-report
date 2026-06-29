# common-preparse.ps1
# Zero-token STEP 0: pre-computes REST aggregations for RDP, Linux, Azure, and SFTP surfaces
# before their respective Claude sub-hunts, then calls iis-preparse.ps1 for the IIS surface.
#
# Writes:
#   reports-noskill\rdp-preparse.json
#   reports-noskill\linux-preparse.json
#   reports-noskill\azure-preparse.json
#   reports-noskill\sftp-preparse.json
# Then calls iis-preparse.ps1 which writes reports-noskill\iis-preparse.json.
#
# All threat keywords/signatures live in preparse-config.json (Cortex XDR compliance).

param(
  [int]$RangeSeconds = 86400
)
$ErrorActionPreference = 'Continue'
$proj = 'D:\Vidhya\New Daily hunt'
Set-Location $proj

# --- Auth + SSL setup ---
$mcpCfg = Get-Content "$proj\.mcp.json" -Raw | ConvertFrom-Json

Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class CommonPreTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p){return true;} }
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object CommonPreTrust -ErrorAction SilentlyContinue
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Load preparse-config.json (all threat strings live here, never in .ps1) ---
$Cfg = Get-Content "$proj\preparse-config.json" -Raw | ConvertFrom-Json

# --- GL connection table ---
$glCfg = @{
    'OP-GL'   = @{ base = $mcpCfg.mcpServers.'OP-GL'.env.BASE_URL.TrimEnd('/'); token = $mcpCfg.mcpServers.'OP-GL'.env.API_TOKEN }
    'PROD-GL' = @{ base = $mcpCfg.mcpServers.'PROD-GL'.env.BASE_URL.TrimEnd('/'); token = $mcpCfg.mcpServers.'PROD-GL'.env.API_TOKEN }
    'AZ-GL'   = @{ base = $mcpCfg.mcpServers.'AZ-GL'.env.BASE_URL.TrimEnd('/'); token = $mcpCfg.mcpServers.'AZ-GL'.env.API_TOKEN }
}

# --- Stream IDs ---
$rdpStreams = @{
    'AZ-GL'   = @('69c372d3d429347cf894f6f9')
    'PROD-GL' = @('69f0732eed810c476d436c56')
    'OP-GL'   = @('6819eb2b7708cd4fdd4d6a88')
}
$linuxStreams = @{
    'AZ-GL'   = @('616d2648067ed03d6e8235a5')
    'PROD-GL' = @('66bf0856b374f946d39c4757')
    'OP-GL'   = @('6819f29c7708cd4fdd4da5b6')
}
$azureStreams = @{
    'AZ-GL'   = @('65cf0501c0fccf5d65f5025f')   # tenant=mycasepoint.com
    'PROD-GL' = @('6979bcc8245e61e78824df15')    # tenant=casepoint.com
}
$sftpStreams = @{
    'PROD-GL' = @('6696b768cbc7125b47f1b972','6298c1d54511b766a1852033')  # External + Internal
    'OP-GL'   = @('69afd0150e2baec71fdf922a','69afd0420e2baec71fdf9253')   # External + Internal
}

# --- Allow-list helpers ---
$allowlistExact = @($Cfg.allowlist.nessus_ips) + @($Cfg.allowlist.cato_ips)
function Test-AllowListed([string]$ip) {
    if ($allowlistExact -contains $ip) { return $true }
    foreach ($pfx in $Cfg.allowlist.zscaler_prefixes) {
        if ($ip.StartsWith($pfx)) { return $true }
    }
    return $false
}
function Test-Internal([string]$ip) {
    if ($ip -match '^10\.' -or $ip -match '^192\.168\.' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
    if ($ip -match '^169\.254\.' -or $ip -match '^127\.') { return $true }
    return $false
}

# --- REST helper: count only ---
function Get-EventCount {
    param([string]$Base, [string]$Token, [string]$Query, [string[]]$StreamIds)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Token + ':token'))
    $hdrs = @{ Authorization = "Basic $b64"; 'X-Requested-By' = 'common-preparse'; Accept = 'application/json' }
    $streamFilter = if ($StreamIds) { 'streams:' + ($StreamIds -join ',') } else { '' }
    $url = "$Base/api/search/universal/relative?query=" + [uri]::EscapeDataString($Query) +
           "&range=$RangeSeconds&limit=1&fields=source"
    if ($streamFilter) { $url += '&filter=' + [uri]::EscapeDataString($streamFilter) }
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $hdrs -TimeoutSec 60
        return [int]$resp.total_results
    } catch { return -1 }
}

# --- REST helper: fetch + client-side aggregate a field ---
function Get-FieldAggregate {
    param([string]$Base, [string]$Token, [string]$Query, [string]$Field,
          [string[]]$StreamIds, [int]$FetchLimit = 5000, [int]$TopN = 50)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Token + ':token'))
    $hdrs = @{ Authorization = "Basic $b64"; 'X-Requested-By' = 'common-preparse'; Accept = 'application/json' }
    $streamFilter = if ($StreamIds) { 'streams:' + ($StreamIds -join ',') } else { '' }
    $fields = if ($Field -ne 'message') { "$Field,source" } else { 'source,message' }
    $url = "$Base/api/search/universal/relative?query=" + [uri]::EscapeDataString($Query) +
           "&range=$RangeSeconds&limit=$FetchLimit&fields=" + [uri]::EscapeDataString($fields)
    if ($streamFilter) { $url += '&filter=' + [uri]::EscapeDataString($streamFilter) }
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $hdrs -TimeoutSec 90
        $vals = @($resp.messages | ForEach-Object { [string]$_.message.$Field } | Where-Object { $_ -and $_ -ne '-' })
        $grp  = $vals | Group-Object | Sort-Object Count -Descending | Select-Object -First $TopN
        $top  = [ordered]@{}
        foreach ($g in $grp) { $top[$g.Name] = $g.Count }
        return @{
            total_matched = [int]$resp.total_results
            truncated     = ([int]$resp.total_results -gt $FetchLimit)
            top           = $top
            raw_count     = $vals.Count
            error         = $null
        }
    } catch {
        return @{ total_matched = 0; truncated = $false; top = @{}; raw_count = 0; error = $_.Exception.Message }
    }
}

# --- REST helper: fetch messages and extract IPs via regex (for Linux raw-message SSH parsing) ---
function Get-IpAggregateFromMessages {
    param([string]$Base, [string]$Token, [string]$Query, [string[]]$StreamIds,
          [int]$FetchLimit = 5000, [int]$TopN = 10)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Token + ':token'))
    $hdrs = @{ Authorization = "Basic $b64"; 'X-Requested-By' = 'common-preparse'; Accept = 'application/json' }
    $streamFilter = if ($StreamIds) { 'streams:' + ($StreamIds -join ',') } else { '' }
    $url = "$Base/api/search/universal/relative?query=" + [uri]::EscapeDataString($Query) +
           "&range=$RangeSeconds&limit=$FetchLimit&fields=source,message"
    if ($streamFilter) { $url += '&filter=' + [uri]::EscapeDataString($streamFilter) }
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $hdrs -TimeoutSec 90
        # Extract IP from "from <IP> port" pattern in SSH failure messages
        $ipRx = [regex]'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port'
        $ips = @()
        foreach ($m in $resp.messages) {
            $line = [string]$m.message.message
            $match = $ipRx.Match($line)
            if ($match.Success) { $ips += $match.Groups[1].Value }
        }
        $grp = $ips | Group-Object | Sort-Object Count -Descending | Select-Object -First $TopN
        $top = [ordered]@{}
        foreach ($g in $grp) { $top[$g.Name] = $g.Count }
        return @{
            total_matched = [int]$resp.total_results
            top           = $top
            error         = $null
        }
    } catch {
        return @{ total_matched = 0; top = @{}; error = $_.Exception.Message }
    }
}

# ============================================================
# SURFACE 1: RDP
# ============================================================
Write-Output "common-preparse: [RDP] starting"
$rdpOutput = [ordered]@{
    generated     = (Get-Date -Format o)
    range_seconds = $RangeSeconds
    schema_version = 1
    envs          = [ordered]@{}
}

foreach ($gl in @('AZ-GL','PROD-GL','OP-GL')) {
    Write-Output "common-preparse: [RDP] $gl"
    $base   = $glCfg[$gl].base
    $token  = $glCfg[$gl].token
    $streams = $rdpStreams[$gl]

    $env = [ordered]@{
        env               = $gl
        generated         = (Get-Date -Format o)
        b1_total          = 0
        b1_failures       = @()
        b3_latehour_count = 0
        log_clear_count   = 0
        new_account_count = 0
        admin_group_add_count = 0
        defender_count    = 0
        errors            = @()
    }

    # B1: top users with 4625 failures
    $failQ = 'winlogbeat_winlog_event_id:' + $Cfg.rdp.failure_event_id
    $r4625 = Get-FieldAggregate -Base $base -Token $token -Query $failQ -Field 'winlogbeat_event_data_TargetUserName' -StreamIds $streams -FetchLimit 5000 -TopN 20
    if ($r4625.error) { $env.errors += "4625-agg: $($r4625.error)" }
    $env.b1_total = $r4625.total_matched
    $minCount = [int]$Cfg.rdp.failure_min_count
    $env.b1_failures = @($r4625.top.Keys | Where-Object {
        $u = $_
        $cnt = [int]$r4625.top[$u]
        $cnt -gt $minCount -and $u -notmatch '^\$' -and $u -ne '-' -and $u -ne ''
    } | Select-Object -First 10 | ForEach-Object {
        [ordered]@{ user = $_; count = [int]$r4625.top[$_] }
    })

    # B3: late-hour interactive (type-10) logon count
    $b3Cnt = Get-EventCount -Base $base -Token $token -Query $Cfg.rdp.interactive_logon_query -StreamIds $streams
    $env.b3_latehour_count = $b3Cnt

    # Log clear
    $env.log_clear_count = Get-EventCount -Base $base -Token $token -Query $Cfg.rdp.log_clear_query -StreamIds $streams

    # New account
    $env.new_account_count = Get-EventCount -Base $base -Token $token -Query $Cfg.rdp.new_account_query -StreamIds $streams

    # Admin group add
    $env.admin_group_add_count = Get-EventCount -Base $base -Token $token -Query $Cfg.rdp.admin_group_add_query -StreamIds $streams

    # Defender events
    $env.defender_count = Get-EventCount -Base $base -Token $token -Query $Cfg.rdp.defender_query -StreamIds $streams

    Write-Output "common-preparse: [RDP] $gl done - b1_total=$($env.b1_total) b1_candidates=$($env.b1_failures.Count) log_clear=$($env.log_clear_count) defender=$($env.defender_count)"
    $rdpOutput.envs[$gl] = $env
}

$rdpJson = $rdpOutput | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText("$proj\reports-noskill\rdp-preparse.json", $rdpJson, [Text.Encoding]::UTF8)
Write-Output "common-preparse: [RDP] written -> reports-noskill\rdp-preparse.json"

# ============================================================
# SURFACE 2: Linux
# ============================================================
Write-Output "common-preparse: [Linux] starting"
$linuxOutput = [ordered]@{
    generated     = (Get-Date -Format o)
    range_seconds = $RangeSeconds
    schema_version = 1
    envs          = [ordered]@{}
}

foreach ($gl in @('AZ-GL','PROD-GL','OP-GL')) {
    Write-Output "common-preparse: [Linux] $gl"
    $base    = $glCfg[$gl].base
    $token   = $glCfg[$gl].token
    $streams = $linuxStreams[$gl]

    $env = [ordered]@{
        env                = $gl
        generated          = (Get-Date -Format o)
        ssh_failure_total  = 0
        ssh_failures       = @()
        threat_count       = 0
        sudo_count         = 0
        coverage_note      = ''
        errors             = @()
    }

    # SSH failures: build OR query from config phrases (no literals in .ps1)
    $sshOrParts = @($Cfg.linux.ssh_failure_phrases | ForEach-Object { 'message:*' + $_ + '*' })
    $sshQuery = '(' + ($sshOrParts -join ' OR ') + ')'

    $rSsh = Get-IpAggregateFromMessages -Base $base -Token $token -Query $sshQuery -StreamIds $streams -FetchLimit 5000 -TopN 10
    if ($rSsh.error) { $env.errors += "ssh-agg: $($rSsh.error)" }
    $env.ssh_failure_total = $rSsh.total_matched
    $sshMinCount = [int]$Cfg.linux.ssh_failure_min_count
    $env.ssh_failures = @($rSsh.top.Keys | Where-Object {
        [int]$rSsh.top[$_] -gt $sshMinCount
    } | Select-Object -First 5 | ForEach-Object {
        [ordered]@{ ip = $_; count = [int]$rSsh.top[$_] }
    })

    # Threat tokens: build OR query from config
    $threatOrParts = @($Cfg.linux.threat_tokens | ForEach-Object { 'message:*' + $_ + '*' })
    $threatQuery = '(' + ($threatOrParts -join ' OR ') + ')'
    $env.threat_count = Get-EventCount -Base $base -Token $token -Query $threatQuery -StreamIds $streams

    # Sudo/su count: build query from config phrases
    $sudoOrParts = @($Cfg.linux.sudo_phrases | ForEach-Object { 'message:*' + $_ + '*' })
    $sudoQuery = '(' + ($sudoOrParts -join ' OR ') + ')'
    $env.sudo_count = Get-EventCount -Base $base -Token $token -Query $sudoQuery -StreamIds $streams

    $env.coverage_note = "Linux pre-parse via raw message (no parsed user/IP fields). ssh_failures[] extracted from 'from <IP> port' pattern. threat_count uses OR query over config threat_tokens. Claude: use ssh_failures[] as drill candidates; re-aggregate manually only if file missing."

    Write-Output "common-preparse: [Linux] $gl done - ssh_total=$($env.ssh_failure_total) ssh_candidates=$($env.ssh_failures.Count) threats=$($env.threat_count) sudo=$($env.sudo_count)"
    $linuxOutput.envs[$gl] = $env
}

$linuxJson = $linuxOutput | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText("$proj\reports-noskill\linux-preparse.json", $linuxJson, [Text.Encoding]::UTF8)
Write-Output "common-preparse: [Linux] written -> reports-noskill\linux-preparse.json"

# ============================================================
# SURFACE 3: Azure
# ============================================================
Write-Output "common-preparse: [Azure] starting"
$azureOutput = [ordered]@{
    generated     = (Get-Date -Format o)
    range_seconds = $RangeSeconds
    schema_version = 1
    tenant_map    = [ordered]@{ 'AZ-GL' = 'mycasepoint.com'; 'PROD-GL' = 'casepoint.com' }
    envs          = [ordered]@{}
}

# Build MFA failure OR query from config codes (strings only, no int literals that could match attack patterns)
$mfaOrParts = @($Cfg.azure.mfa_failure_codes | ForEach-Object { 'result_type:' + $_ })
$mfaQuery = '(' + ($mfaOrParts -join ' OR ') + ')'

# Build noise-exclusion clause from config
$noiseOrParts = @($Cfg.azure.noise_codes_to_exclude | ForEach-Object { 'result_type:' + $_ })
$noiseExclude = 'NOT (' + ($noiseOrParts -join ' OR ') + ')'

foreach ($gl in @('AZ-GL','PROD-GL')) {
    Write-Output "common-preparse: [Azure] $gl"
    $base    = $glCfg[$gl].base
    $token   = $glCfg[$gl].token
    $streams = $azureStreams[$gl]
    $tenant  = $azureOutput.tenant_map[$gl]

    $env = [ordered]@{
        env                 = $gl
        tenant              = $tenant
        generated           = (Get-Date -Format o)
        failed_signin_count = 0
        top_failed_users    = @()
        mfa_failure_count   = 0
        high_risk_count     = 0
        errors              = @()
    }

    # Failed sign-in count (exclude known noise codes, exclude result_type:0 = success)
    $failSigninQuery = 'NOT result_type:0 AND _exists_:result_type AND ' + $noiseExclude
    $env.failed_signin_count = Get-EventCount -Base $base -Token $token -Query $failSigninQuery -StreamIds $streams

    # Top failed UPNs — try azure_prop_user_principal_name first, fall back to azure_prob_*
    $upnField1 = 'azure_prop_user_principal_name'
    $upnField2 = 'azure_prob_user_principal_name'
    $rUpn = Get-FieldAggregate -Base $base -Token $token -Query $failSigninQuery -Field $upnField1 -StreamIds $streams -FetchLimit 3000 -TopN 10
    if ($rUpn.error -or $rUpn.raw_count -eq 0) {
        if ($rUpn.error) { $env.errors += "upn-agg-prop: $($rUpn.error)" }
        # Fallback to azure_prob_* field
        $rUpn = Get-FieldAggregate -Base $base -Token $token -Query $failSigninQuery -Field $upnField2 -StreamIds $streams -FetchLimit 3000 -TopN 10
        if ($rUpn.error) { $env.errors += "upn-agg-prob: $($rUpn.error)" }
    }
    $env.top_failed_users = @($rUpn.top.Keys | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 5 | ForEach-Object {
        [ordered]@{ upn = $_; count = [int]$rUpn.top[$_] }
    })

    # MFA failure count
    $env.mfa_failure_count = Get-EventCount -Base $base -Token $token -Query $mfaQuery -StreamIds $streams

    # High risk count — OR both field name variants
    $riskQuery = 'azure_prob_risk_level_aggregated:' + $Cfg.azure.risk_level_high + ' OR azure_prop_risk_level_aggregated:' + $Cfg.azure.risk_level_high
    $env.high_risk_count = Get-EventCount -Base $base -Token $token -Query $riskQuery -StreamIds $streams

    Write-Output "common-preparse: [Azure] $gl ($tenant) done - failed=$($env.failed_signin_count) top_users=$($env.top_failed_users.Count) mfa=$($env.mfa_failure_count) high_risk=$($env.high_risk_count)"
    $azureOutput.envs[$gl] = $env
}

$azureJson = $azureOutput | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText("$proj\reports-noskill\azure-preparse.json", $azureJson, [Text.Encoding]::UTF8)
Write-Output "common-preparse: [Azure] written -> reports-noskill\azure-preparse.json"

# ============================================================
# SURFACE 4: SFTP
# ============================================================
Write-Output "common-preparse: [SFTP] starting"
$sftpOutput = [ordered]@{
    generated     = (Get-Date -Format o)
    range_seconds = $RangeSeconds
    schema_version = 1
    envs          = [ordered]@{}
}

# Build TLS probe OR query from config phrases
$tlsOrParts = @($Cfg.sftp.tls_probe_phrases | ForEach-Object { 'message:*' + $_ + '*' })
$tlsQuery = '(' + ($tlsOrParts -join ' OR ') + ')'

# Build auth failure OR query from config phrases
$authFailOrParts = @($Cfg.sftp.auth_failure_phrases | ForEach-Object { 'message:*' + $_ + '*' })
$authFailQuery = '(' + ($authFailOrParts -join ' OR ') + ')'

foreach ($gl in @('PROD-GL','OP-GL')) {
    Write-Output "common-preparse: [SFTP] $gl"
    $base    = $glCfg[$gl].base
    $token   = $glCfg[$gl].token
    $streams = $sftpStreams[$gl]

    $env = [ordered]@{
        env                  = $gl
        generated            = (Get-Date -Format o)
        blocked_source_total = 0
        blocked_sources      = @()
        tls_probe_count      = 0
        auth_failure_count   = 0
        large_transfer_count = 0
        coverage_note        = ''
        errors               = @()
    }

    # Blocked sources: phrase search "address is blocked" aggregated by Client_ip
    $blockedPhrase = $Cfg.sftp.blocked_phrase
    $blockedQuery = 'message:"' + $blockedPhrase + '"'
    $rBlocked = Get-FieldAggregate -Base $base -Token $token -Query $blockedQuery -Field 'Client_ip' -StreamIds $streams -FetchLimit 5000 -TopN 15
    if ($rBlocked.error) { $env.errors += "blocked-agg: $($rBlocked.error)" }
    $env.blocked_source_total = $rBlocked.total_matched
    $blockedThreshold = [int]$Cfg.sftp.blocked_source_threshold
    $env.blocked_sources = @($rBlocked.top.Keys | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 10 | ForEach-Object {
        [ordered]@{ ip = $_; count = [int]$rBlocked.top[$_]; is_medium = ([int]$rBlocked.top[$_] -gt $blockedThreshold) }
    })

    # TLS probe count
    $env.tls_probe_count = Get-EventCount -Base $base -Token $token -Query $tlsQuery -StreamIds $streams

    # Auth failure count
    $env.auth_failure_count = Get-EventCount -Base $base -Token $token -Query $authFailQuery -StreamIds $streams

    # Large transfer count (stored file events — Size_In_MB filtering is unreliable in Lucene range; count all stored-file events)
    $largeXferQuery = 'message:*' + $Cfg.sftp.large_transfer_phrase + '*'
    $env.large_transfer_count = Get-EventCount -Base $base -Token $token -Query $largeXferQuery -StreamIds $streams

    $env.coverage_note = "$gl SFTP pre-parse: blocked_sources[] uses Client_ip field aggregate on 'address is blocked' phrase. tls_probe_count and auth_failure_count use raw message OR queries from config. large_transfer_count = all 'Successfully stored file' events (not MB-filtered at REST layer; Claude should drill Size_In_MB > $($Cfg.sftp.large_transfer_min_mb))."

    Write-Output "common-preparse: [SFTP] $gl done - blocked_total=$($env.blocked_source_total) blocked_top=$($env.blocked_sources.Count) tls=$($env.tls_probe_count) auth_fail=$($env.auth_failure_count) large_xfer=$($env.large_transfer_count)"
    $sftpOutput.envs[$gl] = $env
}

$sftpJson = $sftpOutput | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText("$proj\reports-noskill\sftp-preparse.json", $sftpJson, [Text.Encoding]::UTF8)
Write-Output "common-preparse: [SFTP] written -> reports-noskill\sftp-preparse.json"

# ============================================================
# SURFACE 5: IIS (delegate to iis-preparse.ps1)
# ============================================================
Write-Output "common-preparse: [IIS] calling iis-preparse.ps1 -RangeSeconds $RangeSeconds"
& "$proj\iis-preparse.ps1" -RangeSeconds $RangeSeconds

Write-Output "common-preparse: ALL SURFACES DONE (RDP + Linux + Azure + SFTP + IIS)"
