# alert-formatter.ps1 - K-phase: prepare HIGH findings for delivery.
#
# Responsibilities (deliberately narrow):
#   1. Filter to severity == HIGH (alerts fire ONLY at HIGH).
#   2. Attach an `html` field (Build-FindingHtml) - Power Automate posts this as
#      the Teams channel message body (HTML, not an adaptive card).
#   3. Write the HIGH FindingObject[] to a JSON file and return its path.
#
# Dedup is intentionally NOT done here. post-to-teams.ps1 owns the canonical 6h
# SHA1 dedup keyed on environment|technique|anchor_user|anchor_host|anchor_ip.
# Re-implementing it here would (a) duplicate state and (b) risk a key-order
# mismatch. We pass raw FindingObjects straight through.
#
# Requires Build-FindingHtml (alert-html.ps1) to be dot-sourced by the caller.

function Format-Findings {
    <#
      .SYNOPSIS
        Filter findings to HIGH, attach HTML, write to a findings file.
      .OUTPUTS
        [string] path to the written JSON file, or $null when there is nothing
        to send.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array] $Findings,
        [Parameter(Mandatory)][string] $FindingsDir
    )

    $high = @($Findings | Where-Object { $_.severity -eq 'HIGH' })
    if ($high.Count -eq 0) { return $null }

    foreach ($f in $high) {
        $html = ''
        if (Get-Command Build-FindingHtml -ErrorAction SilentlyContinue) {
            try { $html = Build-FindingHtml -Finding $f }
            catch { $html = '' }
        }
        if ($f.PSObject.Properties['html']) { $f.html = $html }
        else { $f | Add-Member -NotePropertyName html -NotePropertyValue $html -Force }
    }

    if (-not (Test-Path $FindingsDir)) {
        New-Item -ItemType Directory -Force -Path $FindingsDir | Out-Null
    }

    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $file  = Join-Path $FindingsDir ("iis-opgl-high-$stamp.json")

    # post-to-teams.ps1 accepts a JSON array OR a single object, so single-finding
    # unwrapping by ConvertTo-Json is harmless. Write BOM-free UTF-8 (PS 5.1
    # Out-File -Encoding utf8 emits a BOM that some JSON parsers reject).
    $json = $high | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($file, $json, [System.Text.UTF8Encoding]::new($false))

    return $file
}
