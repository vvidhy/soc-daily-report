<#
  iis-opgl-digest.ps1 - once-daily ACTIVITY DIGEST (0 tokens, pure file + REST).

  Surfaces what the 30-min monitor caught BELOW the HIGH alert bar (REVIEW/CONFIRMED),
  so the channel has visibility without lowering the alert bar. Reads the day's
  accumulated findings (logs\digest-YYYYMMDD.jsonl, appended by the monitor each run),
  dedups, and posts ONE clean Adaptive Card: a plain-language posture line + counts for
  management, then a confirmed-items list and a by-type review breakdown for the SOC.

  No opus, no detection re-run -- just reads the file the monitor already wrote.
  Param -Date YYYYMMDD (default: today UTC).
#>
[CmdletBinding()]
param([string] $Date)

$ErrorActionPreference = 'Stop'
$here        = $PSScriptRoot
$repoRoot    = Split-Path -Parent (Split-Path -Parent $here)
$secretsPath = Join-Path $repoRoot 'soc-monitor\config\secrets.local.ps1'
$logDir      = Join-Path $here 'logs'
$logFile     = Join-Path $logDir 'iis-opgl-monitor.log'
function Write-DigestLog { param([string]$L,[string]$M) "$([datetime]::UtcNow.ToString('o')) [$L] digest: $M" | Add-Content $logFile -Encoding utf8 }

if (Test-Path $secretsPath) { . $secretsPath }
. (Join-Path $here 'alert-card.ps1')
$cfg = Get-Content (Join-Path $here 'config.json') -Raw -Encoding utf8 | ConvertFrom-Json

if (-not $Date) { $Date = [datetime]::UtcNow.ToString('yyyyMMdd') }
$file = Join-Path $logDir "digest-$Date.jsonl"

# plain-language label per detection class (management-readable)
$labels = @{
    1='SQL injection (500s)'; 2='XSS / long POST'; 3='High-latency response'; 4='Path traversal'
    5='SSRF / cloud-metadata'; 6='Exploit payload'; 7='Webshell behavior'; 8='Auth brute-force (401)'
    9='Enumeration / API-object'; 10='Scanner User-Agent'; 11='CVE / admin-API probe'; 12='Protocol abuse'
    13='Exfiltration volume'; 14='Beaconing / C2'; 15='New entity (first seen)'; 16='Obfuscation / anomaly'; 17='AI open hunt'
}
function _Label($c) { $ci=[int]$c; if ($labels.ContainsKey($ci)) { $labels[$ci] } else { "class $ci" } }

$records = @()
if (Test-Path $file) {
    $records = Get-Content $file | Where-Object { $_ } | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } | Where-Object { $_ }
}
Write-DigestLog INFO ("read {0} record(s) from {1}" -f @($records).Count, (Split-Path $file -Leaf))

# Dedup by class|ip per tier (one row per distinct source+pattern across the day).
$hi = @{}; $conf = @{}; $rev = @{}
foreach ($r in $records) {
    $key = "{0}|{1}" -f $r.class, $r.ip
    switch ([string]$r.severity) {
        'HIGH'      { $hi[$key]   = $r }
        'CONFIRMED' { $conf[$key] = $r }
        default     { $rev[$key]  = $r }
    }
}
# A source confirmed/high for a class shouldn't also be double-counted under review.
foreach ($k in @($rev.Keys)) { if ($conf.ContainsKey($k) -or $hi.ContainsKey($k)) { $rev.Remove($k) } }

$confItems = @($conf.Values | ForEach-Object { @{ ip = [string]$_.ip; host = [string]$_.host; what = (_Label $_.class) } } | Select-Object -First 12)
$revCats   = @($rev.Values | Group-Object class | ForEach-Object {
                 @{ name = (_Label $_.Name); count = $_.Count
                    ip = @($_.Group | ForEach-Object { $_.ip } | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 1) }
             } | Sort-Object { -$_.count } | Select-Object -First 10)

$dateDisp = try { [datetime]::ParseExact($Date,'yyyyMMdd',$null).ToString('yyyy-MM-dd') } catch { $Date }
$glink = 'https://siem.secureocp.com/search?q=' + [Uri]::EscapeDataString('filebeat_log_file_path:*inetpub*') +
         "&rangetype=relative&relative=86400&streams=$($cfg.iis_streams.prod)"

$digest = @{
    date            = $dateDisp
    high            = @($hi.Keys).Count
    confirmed_count = @($conf.Keys).Count
    review_count    = @($rev.Keys).Count
    confirmed       = $confItems
    review_cats     = $revCats
    graylog_link    = $glink
}

Write-Host ("Digest {0}: HIGH={1} CONFIRMED={2} REVIEW(distinct)={3}" -f $dateDisp, $digest.high, $digest.confirmed_count, $digest.review_count)

if ($env:SOC_IIS_OPGL_WEBHOOK) {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $payload = (Build-DigestCardEnvelope -Digest $digest) | ConvertTo-Json -Depth 25 -Compress
        $resp = Invoke-WebRequest -Uri $env:SOC_IIS_OPGL_WEBHOOK -Method Post -ContentType 'application/json; charset=utf-8' `
                    -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -UseBasicParsing -TimeoutSec 30
        Write-DigestLog INFO ("channel post: {0} {1}" -f [int]$resp.StatusCode, $resp.StatusDescription)
        Write-Host ("Channel post: {0} {1}" -f [int]$resp.StatusCode, $resp.StatusDescription)
    } catch {
        Write-DigestLog ERROR ("channel post failed: {0}" -f $_.Exception.Message)
        Write-Host ("Channel post FAILED: {0}" -f $_.Exception.Message)
    }
} else {
    Write-DigestLog WARN 'SOC_IIS_OPGL_WEBHOOK not set - digest not posted'
}
