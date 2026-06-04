# Production Teams notifier for the SOC monitor.
#
# Reads one or more findings (JSON file or JSONL stream), filters by severity,
# dedups against state/posted.json, and POSTs each survivor to the Power
# Automate webhook with retry. Every attempt is appended to logs/notifier.log.
#
# Usage:
#   .\post-to-teams.ps1 -Path .\findings\some-finding.json
#   .\post-to-teams.ps1 -Path .\findings\findings.jsonl
#   .\post-to-teams.ps1 -Path .\findings\f.json -MinSeverity HIGH -DryRun

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [ValidateSet('HIGH', 'REVIEW', 'INFO')]
    [string] $MinSeverity = 'REVIEW',

    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'config\secrets.local.ps1')

if (-not $env:SOC_TEAMS_WEBHOOK) {
    Write-Error 'SOC_TEAMS_WEBHOOK not set. Check config/secrets.local.ps1'
    exit 1
}

$stateDir = Join-Path $root 'state'
$logsDir  = Join-Path $root 'logs'
$null = New-Item -ItemType Directory -Force -Path $stateDir, $logsDir
$postedFile = Join-Path $stateDir 'posted.json'
$logFile    = Join-Path $logsDir 'notifier.log'

# --- helpers -----------------------------------------------------------------

function Write-Log {
    param([string] $Level, [string] $Message)
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('o'), $Level, $Message
    Add-Content -Path $logFile -Value $line -Encoding utf8
    if ($Level -eq 'ERROR') { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line }
}

function Load-Posted {
    if (Test-Path $postedFile) {
        try { return (Get-Content $postedFile -Raw | ConvertFrom-Json) }
        catch { Write-Log WARN "posted.json corrupt, starting fresh: $($_.Exception.Message)"; return @{} }
    }
    return @{}
}

function Save-Posted {
    param($map)
    ($map | ConvertTo-Json -Depth 5) | Set-Content -Path $postedFile -Encoding utf8
}

function Get-AnchorHash {
    param($finding)
    # Stable hash across the fields that define "the same finding":
    # env + technique + user + host + ip. Time intentionally excluded so two
    # bursts of the same attack within the dedup window collapse to one card.
    $key = '{0}|{1}|{2}|{3}|{4}' -f `
        $finding.environment, $finding.technique, $finding.anchor_user, `
        $finding.anchor_host, $finding.anchor_ip
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($key)
    return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-').ToLower()
}

function Test-SeverityGate {
    param([string] $finding, [string] $min)
    $rank = @{ HIGH = 3; REVIEW = 2; INFO = 1 }
    return $rank[$finding] -ge $rank[$min]
}

function Send-Finding {
    param($finding)
    $json = $finding | ConvertTo-Json -Depth 5 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    $delays = @(0, 2, 8)
    foreach ($i in 0..($delays.Count - 1)) {
        if ($delays[$i] -gt 0) { Start-Sleep -Seconds $delays[$i] }
        try {
            Invoke-RestMethod `
                -Uri $env:SOC_TEAMS_WEBHOOK `
                -Method Post `
                -ContentType 'application/json; charset=utf-8' `
                -Body $bytes `
                -TimeoutSec 30 | Out-Null
            return $true
        } catch {
            $code = $null
            if ($_.Exception.Response) { $code = $_.Exception.Response.StatusCode.value__ }
            Write-Log WARN ("attempt {0}/{1} failed (status={2}): {3}" -f ($i + 1), $delays.Count, $code, $_.Exception.Message)
            # 4xx is a client problem — no point retrying.
            if ($code -ge 400 -and $code -lt 500) { return $false }
        }
    }
    return $false
}

# --- load findings -----------------------------------------------------------

if (-not (Test-Path $Path)) {
    Write-Log ERROR "input file not found: $Path"
    exit 1
}

$raw = Get-Content -Path $Path -Raw -Encoding utf8
$findings = @()

# Try JSON array first, then single object, then JSONL.
try {
    $parsed = $raw | ConvertFrom-Json
    if ($parsed -is [System.Array]) { $findings = $parsed }
    else { $findings = @($parsed) }
} catch {
    foreach ($line in ($raw -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $findings += ($line | ConvertFrom-Json) }
        catch { Write-Log WARN "skipping unparseable JSONL line: $($line.Substring(0, [Math]::Min(80, $line.Length)))" }
    }
}

Write-Log INFO "loaded $($findings.Count) finding(s) from $Path"

# --- process -----------------------------------------------------------------

$posted = Load-Posted
$postedMap = @{}
if ($posted) { $posted.PSObject.Properties | ForEach-Object { $postedMap[$_.Name] = $_.Value } }

$sent = 0; $skipped = 0; $failed = 0; $dropped = 0

foreach ($f in $findings) {
    if (-not $f.severity) {
        Write-Log WARN "finding has no severity, defaulting to REVIEW"
        $f | Add-Member -NotePropertyName severity -NotePropertyValue 'REVIEW' -Force
    }
    if (-not (Test-SeverityGate $f.severity $MinSeverity)) {
        $dropped++
        continue
    }

    $hash = Get-AnchorHash $f
    if ($postedMap.ContainsKey($hash)) {
        $last = [datetime]::Parse($postedMap[$hash])
        $age = (Get-Date) - $last
        if ($age.TotalHours -lt 6) {
            Write-Log INFO "dedup: $hash already alerted $([int]$age.TotalMinutes)m ago"
            $skipped++
            continue
        }
    }

    if ($DryRun) {
        Write-Log INFO "[dry-run] would send: $($f.severity) | $($f.title)"
        $sent++
        continue
    }

    if (Send-Finding $f) {
        $postedMap[$hash] = (Get-Date).ToString('o')
        $sent++
        Write-Log INFO "sent: $($f.severity) | $($f.title) | hash=$hash"
    } else {
        $failed++
        Write-Log ERROR "gave up after retries: $($f.title)"
    }
}

if (-not $DryRun) { Save-Posted $postedMap }

Write-Log INFO ("done: sent={0} skipped={1} failed={2} dropped_by_severity={3}" -f $sent, $skipped, $failed, $dropped)
if ($failed -gt 0) { exit 2 }
