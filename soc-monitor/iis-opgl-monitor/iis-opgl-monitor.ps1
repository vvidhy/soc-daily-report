<#
  iis-opgl-monitor.ps1 - entry point for the IIS OP-GL behavioral monitor.

  Runs the full LOCK cycle each invocation:
    L (Learn)   load config + prior dedup context; validate IIS feed integrity
    O (Observe) load the entity registry (first-occurrence + rate scoring source)
    C (Check)   Invoke-LockScan - 17 behavioral detection classes over OP-GL
    K (Keep)    Resolve-KillChain (cross-source correlation -> HIGH),
                update registry, render HTML, post HIGH findings to Teams

  Alerts fire ONLY for severity == HIGH, routed to the dedicated channel
  ($env:SOC_IIS_OPGL_WEBHOOK). Dedup is owned by post-to-teams.ps1.

  Runtime note: the detection layer issues mcp__OP-GL__* queries; this script
  must run in a context where those calls resolve (the SOC claude.exe runtime).

  Params:
    -Window   look-back window in hours (default 1)
    -DryRun   run everything but do not POST to Teams (passed to post-to-teams)
    -TestMode reserved flag for test harness parity
#>
[CmdletBinding()]
param(
    [int]    $Window = 1,
    [switch] $DryRun,
    [switch] $TestMode
)

$ErrorActionPreference = 'Stop'
$here     = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\soc-monitor\iis-opgl-monitor -> repo root

# --- paths ---
$logDir       = Join-Path $here 'logs'
$logFile      = Join-Path $logDir 'iis-opgl-monitor.log'
$findingsDir  = Join-Path $here 'findings'
$configPath   = Join-Path $here 'config.json'
$registryPath = Join-Path $repoRoot 'threat-hunting-agent\baselines\iis-opgl\entity-registry.json'
$postScript   = Join-Path $repoRoot 'soc-monitor\scripts\post-to-teams.ps1'
$secretsPath  = Join-Path $repoRoot 'soc-monitor\config\secrets.local.ps1'
$postedPath   = Join-Path $repoRoot 'soc-monitor\state\posted.json'

$null = New-Item -ItemType Directory -Force -Path $logDir, $findingsDir

function Write-IISLog {
    param([ValidateSet('INFO','WARN','ERROR')][string] $Level, [string] $Message)
    $line = '{0} [{1}] {2}' -f ([datetime]::UtcNow.ToString('o')), $Level, $Message
    Add-Content -Path $logFile -Value $line -Encoding utf8
    if     ($Level -eq 'ERROR') { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq 'WARN')  { Write-Host $line -ForegroundColor Yellow }
    else                        { Write-Verbose $line }
}

# Count PSCustomObject NoteProperties safely. $obj.PSObject.Properties.Count can
# return a multi-value Object[] in WinPS 5.1; wrapping in @() forces a scalar.
function Get-PropCount { param($Obj) if ($null -eq $Obj) { return 0 } return @($Obj.PSObject.Properties).Count }

# --- secrets first: sets $env:OPGL_BASE_URL/OPGL_API_TOKEN + webhook env ---
if (Test-Path $secretsPath) { . $secretsPath }

# --- dependencies ---
# graylog-api.ps1 defines the mcp__OP-GL__* functions (Graylog REST wrappers) the
# detector calls. It MUST load after secrets (reads $env:OPGL_*) and before L/C.
. (Join-Path $here 'graylog-api.ps1')
. (Join-Path $here 'log-validator.ps1')
. (Join-Path $here 'entity-risk-engine.ps1')
. (Join-Path $here 'lock-detector.ps1')
. (Join-Path $here 'alert-html.ps1')
. (Join-Path $here 'alert-formatter.ps1')
. (Join-Path $here 'opus-investigate.ps1')   # Tier 2 AI deep-dive (HIGH only)

Write-IISLog INFO ("=== SOC IIS OP-GL Monitor start === Window={0}h DryRun={1} TestMode={2}" -f $Window, [bool]$DryRun, [bool]$TestMode)

# ------------------------------------------------------------------ L: Learn
$config = Get-Content $configPath -Raw -Encoding utf8 | ConvertFrom-Json   # NB: no -Depth (invalid in PS 5.1)
Write-IISLog INFO 'L: config loaded'

$priorCount = 0
if (Test-Path $postedPath) {
    try { $priorCount = Get-PropCount ((Get-Content $postedPath -Raw -Encoding utf8) | ConvertFrom-Json) } catch {}
}
Write-IISLog INFO ("L: prior dedup entries={0}" -f $priorCount)

$validation = Invoke-LogValidation -WindowHours $Window -Config $config
Write-IISLog INFO ("L: total_iis={0} parsed={1} filter_ratio={2} streams={3}" -f `
    $validation.total_iis_logs, $validation.parsed_logs, [Math]::Round([double]$validation.filter_ratio, 4), ($validation.streams_checked -join ','))
if ($validation.alert_required) { Write-IISLog WARN ("L: IIS_FILTER_DRIFT filter_ratio={0}" -f $validation.filter_ratio) }
if ([long]$validation.total_iis_logs -eq 0) { Write-IISLog WARN 'L: no IIS logs in window - aborting scan'; return }

# ------------------------------------------------------------------ O: Observe
$registry = $null
if (Test-Path $registryPath) {
    try { $registry = Get-Content $registryPath -Raw -Encoding utf8 | ConvertFrom-Json } catch { $registry = $null }
}
if (-not $registry) { $registry = [PSCustomObject]@{ ips = @{}; users = @{}; uris = @{}; hosts = @{} } }
Write-IISLog INFO ("O: entity registry loaded ip_count={0}" -f (Get-PropCount $registry.ips))

# ------------------------------------------------------------------ C: Check
Write-IISLog INFO 'C: Invoke-LockScan (17 behavioral classes)'
$rawFindings = @(Invoke-LockScan -WindowHours $Window -Config $config -Registry $registry)
$nonLogged   = @($rawFindings | Where-Object { $_.severity -ne 'LOGGED' })
Write-IISLog INFO ("C: raw_findings={0} non_logged={1}" -f $rawFindings.Count, $nonLogged.Count)

# ------------------------------------------------------------------ K: Keep
$findings  = @(Resolve-KillChain -Findings $rawFindings -Config $config)
$high      = @($findings | Where-Object { $_.severity -eq 'HIGH' })
$confirmed = @($findings | Where-Object { $_.severity -eq 'CONFIRMED' })
$review    = @($findings | Where-Object { $_.severity -eq 'REVIEW' })
Write-IISLog INFO ("K: HIGH={0} CONFIRMED={1} REVIEW={2} LOGGED={3}" -f `
    $high.Count, $confirmed.Count, $review.Count, @($findings | Where-Object { $_.severity -eq 'LOGGED' }).Count)

try { Update-EntityRegistry -Findings $findings; Write-IISLog INFO 'K: entity registry updated' }
catch { Write-IISLog ERROR ("K: entity registry update failed: {0}" -f $_.Exception.Message) }

# Tier 2: opus deep-dive on HIGH findings only (rare, capped <=2/run, advisory).
# Token-bounded (opus only); NEVER changes severity; if opus fails it's a no-op and
# the alert still fires with the deterministic data. Beyond the cap, extra HIGH
# findings still alert (deterministic card) but skip the AI deep-dive.
if ($high.Count -gt 0 -and (Get-Command Invoke-OpusDeepDive -ErrorAction SilentlyContinue)) {
    $ddDone = 0
    foreach ($hf in $high) {
        if ($ddDone -ge 2) { break }
        $analysis = $null
        try { $analysis = Invoke-OpusDeepDive -Finding $hf -Config $config } catch { $analysis = $null }
        if ($analysis) {
            if ($hf.PSObject.Properties['deep_analysis']) { $hf.deep_analysis = $analysis }
            else { $hf | Add-Member -NotePropertyName deep_analysis -NotePropertyValue $analysis -Force }
            Write-IISLog INFO ("K: opus deep-dive attached (anchor {0})" -f $hf.anchor_ip)
        } else {
            Write-IISLog WARN ("K: opus deep-dive unavailable for {0} - alert uses deterministic data only" -f $hf.anchor_ip)
        }
        $ddDone++
    }
}

if ($high.Count -gt 0) {
    $findingsFile = Format-Findings -Findings $high -FindingsDir $findingsDir
    if (-not $findingsFile) {
        Write-IISLog WARN 'K: Format-Findings returned no file despite HIGH findings'
    } else {
        Write-IISLog INFO ("K: {0} HIGH finding(s) written to {1}" -f $high.Count, $findingsFile)
        if (Test-Path $secretsPath) { . $secretsPath }
        $webhook = $env:SOC_IIS_OPGL_WEBHOOK
        if (-not $webhook) { Write-IISLog WARN 'K: SOC_IIS_OPGL_WEBHOOK not set - post-to-teams will fall back to default channel' }

        $postArgs = @{ Path = $findingsFile; MinSeverity = 'HIGH'; AsAdaptiveCard = $true }
        if ($webhook) { $postArgs['WebhookUrl'] = $webhook }
        if ($DryRun)  { $postArgs['DryRun'] = $true }

        $global:LASTEXITCODE = 0
        try {
            & $postScript @postArgs
            $code = $LASTEXITCODE
            if ($code -ne 0) { Write-IISLog ERROR ("K: post-to-teams.ps1 exit={0} - delivery FAILED" -f $code) }
            else { Write-IISLog INFO ("K: posted {0} HIGH finding(s) (dryrun={1})" -f $high.Count, [bool]$DryRun) }
        } catch {
            Write-IISLog ERROR ("K: post-to-teams.ps1 threw: {0}" -f $_.Exception.Message)
        }
    }
} else {
    Write-IISLog INFO 'K: no HIGH findings - no Teams alert'
}

# Run summary
$summary = [ordered]@{
    run_time           = [datetime]::UtcNow.ToString('o')
    window_hours       = $Window
    total_iis_logs     = $validation.total_iis_logs
    parsed_logs        = $validation.parsed_logs
    filter_ratio       = $validation.filter_ratio
    filter_drift_alert = $validation.alert_required
    raw_findings       = $rawFindings.Count
    review             = $review.Count
    confirmed          = $confirmed.Count
    high               = $high.Count
}
$summary | ConvertTo-Json -Depth 5 | Out-File (Join-Path $logDir 'last-run.json') -Encoding utf8

# Daily digest accumulation -- append every non-clean finding (HIGH/CONFIRMED/REVIEW +
# notable LOGGED probe hits) to a dated file so the once-daily digest can surface the
# full Critical/High/Moderate/Low picture WITHOUT lowering the alert bar. Best-effort:
# wrapped so it can never affect a run. ('Clean window'/'below threshold' = no activity.)
try {
    $digestFile = Join-Path $logDir ("digest-{0}.jsonl" -f ([datetime]::UtcNow.ToString('yyyyMMdd')))
    $loggedNotable = @($findings | Where-Object { $_.severity -eq 'LOGGED' -and ([string]$_.title -notmatch 'Clean window|below threshold|No ') })
    foreach ($df in (@($high) + @($confirmed) + @($review) + $loggedNotable)) {
        ([ordered]@{
            ts        = [datetime]::UtcNow.ToString('o')
            severity  = [string]$df.severity
            class     = $df.detection_class
            technique = [string]$df.technique
            ip        = [string]$df.anchor_ip
            host      = [string]$df.anchor_host
            title     = [string]$df.title
            corr      = ((@($df.corroboration_sources)) -join '; ')   # the "why" for CRITICAL (cross-stream evidence)
        } | ConvertTo-Json -Compress) | Add-Content -Path $digestFile -Encoding utf8
    }
} catch { Write-IISLog WARN ("digest accumulation failed: {0}" -f $_.Exception.Message) }

Write-IISLog INFO '=== run complete ==='
