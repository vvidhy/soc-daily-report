# bootstrap.ps1 — IIS OP-GL Monitor deployment scaffold
# Fully idempotent; safe to re-run without overwriting existing data.
# No #Requires directives; no module imports.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Directory paths ──────────────────────────────────────────────────────────
$dirs = @(
    'D:\Vidhya\soc-monitor\iis-opgl-monitor\logs',
    'D:\Vidhya\soc-monitor\state',
    'D:\Vidhya\threat-hunting-agent\baselines\iis-opgl',
    'D:\Vidhya\threat-hunting-agent\detection_rules\lock'
)

foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Host "[bootstrap] Created directory: $dir"
    } else {
        Write-Host "[bootstrap] Directory already exists (skipped): $dir"
    }
}

# ── JSON seed files (create only if absent) ──────────────────────────────────
function Initialize-JsonFile {
    param(
        [string]$Path,
        [string]$Content
    )
    if (-not (Test-Path $Path)) {
        [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
        Write-Host "[bootstrap] Created: $Path"
    } else {
        Write-Host "[bootstrap] Already exists (skipped): $Path"
    }
}

Initialize-JsonFile `
    -Path 'D:\Vidhya\threat-hunting-agent\baselines\iis-opgl\entity-registry.json' `
    -Content '{ "ips": {}, "users": {}, "uris": {}, "hosts": {} }'

Initialize-JsonFile `
    -Path 'D:\Vidhya\threat-hunting-agent\baselines\iis-opgl\rate-counters.json' `
    -Content '{}'

Initialize-JsonFile `
    -Path 'D:\Vidhya\soc-monitor\state\posted.json' `
    -Content '{}'

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host "[bootstrap] Bootstrap completed at $([datetime]::UtcNow.ToString('o')) UTC"
