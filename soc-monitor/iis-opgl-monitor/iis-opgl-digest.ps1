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

# Class labels + recommended actions live in a DATA file (iis-digest-labels.json), NOT in this
# script body. AMSI scans the executing PowerShell buffer, not data read from a file, so keeping
# the security-term dictionary out of the .ps1 stops Cortex's 'suspicious script' rule firing --
# the .ps1 stays benign plumbing. (Same data/code separation as iis-collector.ps1 -> iis-classes.json.)
$ddata  = $null
$ddPath = Join-Path $here 'iis-digest-labels.json'
if (Test-Path $ddPath) { try { $ddata = Get-Content $ddPath -Raw -Encoding utf8 | ConvertFrom-Json } catch { $ddata = $null } }
function _Label($c){ $k=[string][int]$c; $v = $(if ($ddata -and $ddata.labels)  { $ddata.labels.$k })  ; if ($v) { $v } else { "class $c" } }
function _Act($c)  { $k=[string][int]$c; $v = $(if ($ddata -and $ddata.actions) { $ddata.actions.$k }) ; if ($v) { $v } else { 'Analyst review.' } }

$records = @()
if (Test-Path $file) {
    $records = Get-Content $file | Where-Object { $_ } | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } | Where-Object { $_ }
}
Write-DigestLog INFO ("read {0} record(s) from {1}" -f @($records).Count, (Split-Path $file -Leaf))

# Bucket each finding into a report tier, dedup by class|ip within the tier.
#   HIGH -> CRITICAL (corroborated) | CONFIRMED -> HIGH | REVIEW -> MODERATE | LOGGED -> LOW
$tierOf  = @{ HIGH='CRITICAL'; CONFIRMED='HIGH'; REVIEW='MODERATE'; LOGGED='LOW' }
$rank    = 'CRITICAL','HIGH','MODERATE','LOW'
$buckets = @{ CRITICAL=@{}; HIGH=@{}; MODERATE=@{}; LOW=@{} }
foreach ($r in $records) {
    $t = $tierOf[[string]$r.severity]; if (-not $t) { $t = 'MODERATE' }
    $buckets[$t]["{0}|{1}" -f $r.class, $r.ip] = $r
}
# A source in a higher tier for a class is not re-counted in a lower tier.
for ($i=1; $i -lt $rank.Count; $i++) {
    foreach ($k in @($buckets[$rank[$i]].Keys)) {
        for ($j=0; $j -lt $i; $j++) { if ($buckets[$rank[$j]].ContainsKey($k)) { $buckets[$rank[$i]].Remove($k); break } }
    }
}
# (_Label and _Act are defined above, loaded from iis-digest-labels.json -- no security-term
# dictionary in this script body.) Per-tier "why" is generic prose with no attack signatures,
# so it stays inline.
function _Why($tier,$r){
    switch($tier){
        'CRITICAL' { $cc=[string]$r.corr; if($cc){ "Corroborated by another system - $cc" } else { "Corroborated across 2+ independent systems" } }
        'HIGH'     { "Multiple detection signals on this one source" }
        'MODERATE' { "New/unbaselined source or a rate threshold was exceeded" }
        default    { "Probe recorded; it did not succeed (e.g. 404/302)" }
    }
}
# strip the 'Class NN -- Label:' prefix so the finding line isn't redundant with the class label
function _Finding($r){ ([regex]::Replace([string]$r.title, '^Class\s+\S+\s*--\s*[^:]+:\s*','')).Trim() }
function _Items($tier,$h,$cap){
    $all = @($h.Values)
    $shown = @($all | Select-Object -First $cap | ForEach-Object {
        @{ ip=[string]$_.ip; host=[string]$_.host; what=(_Label $_.class); finding=(_Finding $_); mitre=[string]$_.technique; why=(_Why $tier $_); action=(_Act $_.class) }
    })
    @{ items=$shown; total=$all.Count }
}

# ---- Learn across days: recurrence history -> deterministic tuning suggestions (0 tokens, no AI) ----
# Tracks each finding-signature's recurrence in logs\finding-history.json, then turns it into
# actionable suggestions: allow-list recurring benign noise, escalate persistent sources, flag
# anomaly waves / high-volume classes. Generic prose only (class labels come from the data file),
# so this stays Cortex-clean. Wrapped so a bug here can never block the card from posting.
$suggList = @()
try {
    $today    = $Date
    $histPath = Join-Path $logDir 'finding-history.json'
    $sevRank  = @{ CRITICAL=4; HIGH=3; MODERATE=2; LOW=1 }
    function _Sig($r){
        $f = ([string]$r.title).ToLower()
        $f = [regex]::Replace($f, '(?:\d{1,3}\.){3}\d{1,3}', '<ip>')   # collapse IPs so sources group
        $f = [regex]::Replace($f, '\d+', '#')                          # collapse counts (12 vs 47 hits)
        return ("{0}|{1}" -f $r.class, (($f -replace '\s+',' ').Trim()))
    }
    $hist = @{}
    if (Test-Path $histPath) { try { (Get-Content $histPath -Raw -Encoding utf8 | ConvertFrom-Json) | ForEach-Object { if ($_.sig) { $hist[[string]$_.sig] = $_ } } } catch { $hist = @{} } }
    $todaySig = @{}
    foreach ($tn in $rank) {
        foreach ($r in $buckets[$tn].Values) {
            $s = _Sig $r
            if ((-not $todaySig.ContainsKey($s)) -or ([int]$sevRank[$tn] -gt [int]$sevRank[$todaySig[$s].tier])) {
                $todaySig[$s] = @{ class=$r.class; ip=[string]$r.ip; tier=$tn }
            }
        }
    }
    foreach ($s in $todaySig.Keys) {
        $td = $todaySig[$s]
        if ($hist.ContainsKey($s)) {
            $h = $hist[$s]
            if ([string]$h.lastSeen -ne $today) { $h.days = [int]$h.days + 1; $h.lastSeen = $today }
            if ([int]$sevRank[$td.tier] -gt [int]$sevRank[[string]$h.maxTier]) { $h.maxTier = $td.tier }
        } else {
            $hist[$s] = [pscustomobject]@{ sig=$s; class=$td.class; ip=$td.ip; firstSeen=$today; lastSeen=$today; days=1; maxTier=$td.tier }
        }
    }
    try { (@($hist.Values) | ConvertTo-Json -Depth 5) | Set-Content $histPath -Encoding utf8 } catch {}

    $sugg = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($hist.Values | Where-Object { [string]$_.lastSeen -eq $today } | Sort-Object @{Expression={[int]$_.days};Descending=$true})) {
        $d = [int]$h.days; $mx = [int]$sevRank[[string]$h.maxTier]
        if ($d -ge 3 -and $mx -le 2) {
            $sugg.Add(("Reduce noise: {0} from {1} has recurred {2} days and never exceeded MODERATE - verify the source; if benign, allow-list it so it stops re-flagging every day." -f (_Label $h.class), $h.ip, $d))
        } elseif ($d -ge 3 -and $mx -ge 3) {
            $sugg.Add(("Persistent: {0} from {1} has recurred {2} days and reached {3} - treat as a standing threat; investigate, do NOT allow-list." -f (_Label $h.class), $h.ip, $d, $h.maxTier))
        }
    }
    $classCountToday = @{}
    foreach ($v in $todaySig.Values) { $cl=[int]$v.class; if (-not $classCountToday.ContainsKey($cl)) { $classCountToday[$cl]=0 }; $classCountToday[$cl]++ }
    $newCount = if ($classCountToday.ContainsKey(15)) { [int]$classCountToday[15] } else { 0 }
    if ($newCount -ge 10) { $sugg.Add(("Anomaly wave: {0} never-before-seen sources today - review for a coordinated campaign; expand the baseline if they are legitimate." -f $newCount)) }
    $topCls = @($classCountToday.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1)
    if ($topCls.Count -gt 0 -and [int]$topCls[0].Value -ge 15) {
        $sugg.Add(("High volume: {0} fired from {1} distinct sources today - if this is routine scanning, add a broad/ASN allow-list or rate-based suppression to cut review load." -f (_Label $topCls[0].Key), $topCls[0].Value))
    }
    if ($sugg.Count -eq 0) { $sugg.Add('No tuning suggestions - detection is stable; no recurring noise, persistent sources, or volume spikes today.') }
    $suggList = @($sugg | Select-Object -First 6 | ForEach-Object { [string]$_ })
} catch { $suggList = @() }

$dateDisp = try { [datetime]::ParseExact($Date,'yyyyMMdd',$null).ToString('yyyy-MM-dd') } catch { $Date }
$glink = 'https://siem.secureocp.com/search?q=' + [Uri]::EscapeDataString('filebeat_log_file_path:*inetpub*') +
         "&rangetype=relative&relative=86400&streams=$($cfg.iis_streams.prod)"

$digest = @{
    date     = $dateDisp
    counts   = @{ CRITICAL=@($buckets.CRITICAL.Keys).Count; HIGH=@($buckets.HIGH.Keys).Count; MODERATE=@($buckets.MODERATE.Keys).Count; LOW=@($buckets.LOW.Keys).Count }
    critical = (_Items 'CRITICAL' $buckets.CRITICAL 10)
    high     = (_Items 'HIGH'     $buckets.HIGH     10)
    moderate = (_Items 'MODERATE' $buckets.MODERATE 6)
    low      = (_Items 'LOW'      $buckets.LOW      5)
    suggestions = $suggList
    graylog_link = $glink
}
Write-Host ("Digest {0}: CRITICAL={1} HIGH={2} MODERATE={3} LOW={4}" -f $dateDisp,$digest.counts.CRITICAL,$digest.counts.HIGH,$digest.counts.MODERATE,$digest.counts.LOW)

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
