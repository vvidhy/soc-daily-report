# depth-catchup-rest.ps1
# Zero-token replacement for the AI depth-catchup pass.
# Reads depth-coverage.json, finds modules with status "budget" (not reached due to turn limit),
# runs each module's primary detection query via Graylog REST, and writes depth-catchup.json.
#
# count > 0  -> REVIEW finding (raw count + paste-ready query for analyst)
# count == 0 -> CLEAN finding for that module
# No AI analysis: results go straight to the report as manual-action items.
#
# Output: reports-noskill\depth-catchup.json (same schema as depth-findings.json)
# Wired into daily-report-noskill.cmd after the depth pass.

$ErrorActionPreference = 'Continue'
$proj   = 'D:\Vidhya\New Daily hunt'
$covF   = "$proj\reports-noskill\depth-coverage.json"
$outF   = "$proj\reports-noskill\depth-catchup.json"
$modDir = "$proj\depth-modules"

# --- REST helpers ---------------------------------------------------------
add-type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class GLDepthRestTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p){return true;} }
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object GLDepthRestTrust
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$mcp = Get-Content "$proj\.mcp.json" -Raw | ConvertFrom-Json

function Invoke-GLCount {
    param([string]$GL, [string]$Query, [int]$Range = 86400)
    $srv = $mcp.mcpServers.$GL
    if (-not $srv) { return -1 }
    $base = $srv.env.BASE_URL.TrimEnd('/')
    $tok  = $srv.env.API_TOKEN
    $b64  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($tok + ':token'))
    $hdrs = @{ Authorization = "Basic $b64"; 'X-Requested-By' = 'depth-catchup-rest'; Accept = 'application/json' }
    $url  = $base + '/api/search/universal/relative?query=' + [uri]::EscapeDataString($Query) + '&range=' + $Range + '&limit=0'
    try {
        $r = Invoke-RestMethod -Uri $url -Headers $hdrs -TimeoutSec 60
        return [int]$r.total_results
    } catch {
        Write-Host "[depth-catchup-rest] REST error GL=$GL : $_"
        return -1
    }
}

# Strip unresolvable <placeholder> tokens from a query template.
# Removes patterns like: AND field:"<value>" or AND field:<value>
function Clean-QueryTemplate {
    param([string]$q)
    # Remove AND clauses containing angle-bracket placeholders
    $q = $q -replace '\s+AND\s+\S+:"<[^>]+"', ''
    $q = $q -replace '\s+AND\s+\S+:<[^>]+>', ''
    # Remove leading/trailing AND
    $q = $q.Trim().TrimStart('AND').TrimEnd('AND').Trim()
    return $q
}

# Pick the best runnable query from a module JSON.
# Priority: method[].query fields (first one without placeholders) ->
#           output_findings_json.query_template (cleaned) ->
#           surface-based fallback
function Get-ModuleQuery {
    param($mod)

    # Try method steps with a query field
    foreach ($step in $mod.method) {
        if ($step.query) {
            $q = Clean-QueryTemplate $step.query
            if ($q -and $q -ne '*' -and $q.Length -gt 5) { return $q }
        }
    }

    # Try query_template from output schema
    $qt = $mod.output_findings_json.query_template
    if ($qt -and $qt -notmatch '^<' -and $qt -notmatch '; ') {
        $q = Clean-QueryTemplate $qt
        if ($q -and $q.Length -gt 5) { return $q }
    }

    # Surface-based fallback
    switch ($mod.surface) {
        'iis'     { return 'filebeat_log_file_path:*inetpub* AND Status:200' }
        'windows' { return 'winlogbeat_winlog_channel:Security AND winlogbeat_winlog_event_id:(4624 OR 4625 OR 4688)' }
        'linux'   { return 'message:*ssh* OR message:*sudo* OR message:*Failed*' }
        'azure'   { return 'properties_category:SignInLogs OR properties_category:AuditLogs' }
        'network' { return 'gl2_source_input:*forti* OR source:*fortigate*' }
        default   { return '*' }
    }
}

# --- Main -----------------------------------------------------------------

if (-not (Test-Path $covF)) {
    Write-Host "[depth-catchup-rest] depth-coverage.json not found - nothing to catch up."
    '[]' | Set-Content $outF -Encoding UTF8
    exit 0
}

$coverage = Get-Content $covF -Raw | ConvertFrom-Json
$budget   = @($coverage | Where-Object { $_.status -eq 'budget' })

if ($budget.Count -eq 0) {
    Write-Host "[depth-catchup-rest] No budget-skipped modules - full depth coverage achieved."
    '[]' | Set-Content $outF -Encoding UTF8
    exit 0
}

Write-Host "[depth-catchup-rest] $($budget.Count) budget-skipped module(s) to check via REST."

$findings = [System.Collections.Generic.List[object]]::new()
$now      = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'

foreach ($entry in $budget) {
    $modName = $entry.module
    $modFile = "$modDir\$modName.json"

    if (-not (Test-Path $modFile)) {
        Write-Host "[depth-catchup-rest] Module file not found: $modFile - skipping."
        continue
    }

    $mod   = Get-Content $modFile -Raw | ConvertFrom-Json
    $query = Get-ModuleQuery $mod
    $gls   = @($mod.applies_to_gl)

    Write-Host "[depth-catchup-rest] Module: $modName | Query: $query | GLs: $($gls -join ',')"

    $totalCount = 0
    $glCounts   = [ordered]@{}

    foreach ($gl in $gls) {
        $cnt = Invoke-GLCount -GL $gl -Query $query
        if ($cnt -gt 0) { $totalCount += $cnt }
        $glCounts[$gl] = $cnt
    }

    $glSummary = ($glCounts.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" }) -join ' | '

    if ($totalCount -gt 0) {
        $findings.Add([ordered]@{
            sev                   = 'REVIEW'
            env                   = ($gls -join ',')
            surface               = [string]$mod.surface
            source                = [string]$mod.output_findings_json.source
            entity                = "module:$modName"
            mitre                 = [string]($mod.mitre -join ', ')
            tactic                = [string]$mod.tactic
            killchain             = 'Actions on Objectives'
            finding               = "[$modName] $totalCount events matched - manual triage required (depth not reached)"
            detail                = "Depth pass did not reach this module (turn budget). REST count found $totalCount matching events. AI triage was not performed - paste the query into Graylog and review manually. Technique: $($mod.technique)"
            evidence              = "REST count 24h: $glSummary | query: $query"
            action                = "Run in Graylog: $query - review results for $($mod.technique)"
            query                 = $query
            verdict               = 'REVIEW'
            confidence            = 2
            change                = 'known-gap'
            links_breadth_finding = ''
            rest_counts           = $glCounts
            checked_at            = $now
        })
    } else {
        Write-Host "[depth-catchup-rest] CLEAN (0 events): $modName - not added to report"
    }
}

$json = $findings | ConvertTo-Json -Depth 8
if ($findings.Count -eq 1) { $json = "[$json]" }
$json | Set-Content $outF -Encoding UTF8

Write-Host "[depth-catchup-rest] Done. $($findings.Count) finding(s) written to depth-catchup.json"
Write-Host "[depth-catchup-rest] REVIEW: $(($findings | Where-Object {$_.sev -eq 'REVIEW'}).Count) | CLEAN: $(($findings | Where-Object {$_.sev -eq 'CLEAN'}).Count)"
