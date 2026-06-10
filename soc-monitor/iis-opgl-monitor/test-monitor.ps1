<#
  test-monitor.ps1 - E2E harness for the IIS OP-GL alert path.

  Injects a synthetic CLASS-8 HIGH finding and drives it through the real
  Format-Findings -> post-to-teams.ps1 round-trip so the HTML render and the
  dedicated-channel routing can be confirmed without waiting for a live attack.

  Usage:
    .\test-monitor.ps1 -InjectFinding -DryRun     # no live POST; prints payload
    .\test-monitor.ps1 -InjectFinding             # live POST to SOC_IIS_OPGL_WEBHOOK
#>
[CmdletBinding()]
param(
    [switch] $InjectFinding,
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
$here        = $PSScriptRoot
$repoRoot    = Split-Path -Parent (Split-Path -Parent $here)
$secretsPath = Join-Path $repoRoot 'soc-monitor\config\secrets.local.ps1'
$postScript  = Join-Path $repoRoot 'soc-monitor\scripts\post-to-teams.ps1'
$postedPath  = Join-Path $repoRoot 'soc-monitor\state\posted.json'
$findingsDir = Join-Path $here 'findings'

. (Join-Path $here 'alert-html.ps1')
. (Join-Path $here 'alert-formatter.ps1')

if (-not $InjectFinding) {
    Write-Host 'Nothing to do. Pass -InjectFinding to run the synthetic HIGH alert round-trip.'
    return
}

Write-Host 'Injecting synthetic CLASS-8 HIGH finding...'
$now = [datetime]::UtcNow
$synthetic = [PSCustomObject]@{
    severity                 = 'HIGH'
    title                    = '[TEST] Auth Storm + MFA Bypass Attempt'
    environment              = 'OP-GL'
    technique                = 'T1110 - Brute Force'
    summary                  = 'SYNTHETIC TEST FINDING: 192.0.2.50 made 142 failed logins to /portal/login in 15 min (threshold 20), then one 200. Corroborated by Windows 4625 x50 and Securenvoy MFA DENY. Safe to ignore.'
    anchor_user              = 'test.user'
    anchor_host              = 'eportal-test.casepoint.com'
    anchor_ip                = '192.0.2.50'
    anchor_time              = $now.ToString('o')
    graylog_link             = 'https://siem.secureocp.com/search?q=Status%3A401+AND+Client_ip%3A192.0.2.50&rangetype=relative&relative=3600'
    finding_id               = ('iis-opgl-{0}-CLASS08-TEST' -f $now.ToString('yyyyMMdd-HHmmss'))
    lock_phase               = 'K'
    entity_is_new            = $true
    rate_threshold_exceeded  = $true
    detection_class          = 8
    raw_query                = 'Status:401 AND Client_ip:192.0.2.50'
    investigate              = 'Client_ip:192.0.2.50 AND Status:200 AND URI_Stream:"/portal/login"'
    corroboration_sources    = @('Winlog_beat: EventID 4625 x50', 'Securenvoy: MFA DENY x3')
    kill_chain_stages        = @('Initial Access: Credential Attack', 'Defense Evasion: MFA Bypass Attempt')
    confidence_score         = 0.92
    promoted_from            = 'REVIEW'
    correlation_query_window = ('{0}/{1}' -f $now.AddMinutes(-15).ToString('o'), $now.ToString('o'))
}

$file = Format-Findings -Findings @($synthetic) -FindingsDir $findingsDir
if (-not $file) { Write-Warning 'Format-Findings produced no file (finding not HIGH?).'; return }
Write-Host "Findings file: $file"

# Confirm the html field was attached
$written = (Get-Content $file -Raw -Encoding utf8) | ConvertFrom-Json
$htmlLen = if ($written.html) { $written.html.Length } else { 0 }
Write-Host "Attached html length: $htmlLen $(if ($htmlLen -gt 0){'(OK)'}else{'(MISSING!)'})"

if (Test-Path $secretsPath) { . $secretsPath }
$webhook = $env:SOC_IIS_OPGL_WEBHOOK
if ($webhook) { Write-Host ("Routing to dedicated IIS channel (SOC_IIS_OPGL_WEBHOOK ...{0})" -f $webhook.Substring([Math]::Max(0,$webhook.Length-12))) }
else { Write-Warning 'SOC_IIS_OPGL_WEBHOOK not set - post-to-teams will use the default channel.' }

$postArgs = @{ Path = $file; MinSeverity = 'HIGH'; AsAdaptiveCard = $true }
if ($webhook) { $postArgs['WebhookUrl'] = $webhook }
if ($DryRun)  { $postArgs['DryRun'] = $true }

$global:LASTEXITCODE = 0
& $postScript @postArgs
Write-Host "post-to-teams.ps1 exit: $LASTEXITCODE"

if (Test-Path $postedPath) {
    try {
        $posted = (Get-Content $postedPath -Raw -Encoding utf8) | ConvertFrom-Json
        Write-Host ("Dedup state entries: {0}" -f @($posted.PSObject.Properties).Count)
    } catch { Write-Host 'Dedup state: (unreadable)' }
}
Write-Host 'Test complete. Re-run immediately to confirm dedup suppresses the second send.'
