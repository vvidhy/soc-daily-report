<#
  ti-lookup.ps1 - IP threat-intel reputation lookup for the SOC hunts.
  Queries VirusTotal (v3) + AbuseIPDB (v2) + AlienVault OTX - uses whichever keys
  are present in .ti-keys.json. Cortex-clean: pure HTTP plumbing, no attack-signature
  literals in the body. Skips RFC1918/loopback (verdict=internal) and the SOC
  allow-list (Cato egress). Caches verdicts 24h in logs-noskill\ti-cache.json to
  stay well under free-tier rate limits (VT free = 4/min, 500/day).

  Usage:  ti-lookup.ps1 -Ip 1.2.3.4        -> one-line JSON verdict on stdout
          ti-lookup.ps1 -Ip 1.2.3.4 -NoCache
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Ip,
  [int]$CacheHours = 168,
  [switch]$NoCache
)
$ErrorActionPreference = 'Stop'
$proj = 'D:\Vidhya\New Daily hunt'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Emit($o) { $o | ConvertTo-Json -Depth 6 -Compress }

# --- validate -------------------------------------------------------------
$parsed = $null
if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) { Emit @{ ip=$Ip; verdict='invalid'; error='not an IP' }; return }

# --- allow-list + internal (no API call) ----------------------------------
$allow = @('140.82.202.196','199.27.40.187','123.253.153.138')   # Cato egress
if ($allow -contains $Ip) { Emit @{ ip=$Ip; verdict='allowlisted'; note='Cato egress' }; return }
function Test-Private([string]$s) {
  if ($s -match '^(10\.|127\.|169\.254\.|192\.168\.)') { return $true }
  if ($s -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
  if ($s -match '^(::1$|fe80:|fc|fd)') { return $true }
  return $false
}
if (Test-Private $Ip) { Emit @{ ip=$Ip; verdict='internal'; note='RFC1918/loopback - not checked' }; return }

# --- cache ----------------------------------------------------------------
$cacheFile = Join-Path $proj 'logs-noskill\ti-cache.json'
$cache = @{}
if ((Test-Path $cacheFile)) { try { (Get-Content $cacheFile -Raw -Encoding utf8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cache[$_.Name] = $_.Value } } catch {} }
if ($cache.ContainsKey($Ip) -and -not $NoCache) {
  try { if ((((Get-Date) - [datetime]::Parse([string]$cache[$Ip].checked_at)).TotalHours) -lt $CacheHours) { $c = $cache[$Ip]; $c | Add-Member -NotePropertyName cached -NotePropertyValue $true -Force; Emit $c; return } } catch {}
}

# --- keys (ignore empty / placeholder values) -----------------------------
$keys = $null
$kf = Join-Path $proj '.ti-keys.json'
if (Test-Path $kf) { try { $keys = Get-Content $kf -Raw -Encoding utf8 | ConvertFrom-Json } catch {} }
function Real-Key($v) { if ($v -and ($v -notmatch 'PUT-|YOUR-|<.*>') -and ($v.Trim().Length -gt 8)) { return $v.Trim() } return $null }
$vt  = if ($keys) { Real-Key $keys.virustotal } else { $null }
$ab  = if ($keys) { Real-Key $keys.abuseipdb }  else { $null }
$otx = if ($keys) { Real-Key $keys.otx }        else { $null }

$checked = @()
$vtMal=$null; $vtSus=$null; $vtRep=$null; $asOwner=$null; $country=$null
$abConf=$null; $abReports=$null; $isp=$null; $usage=$null; $otxPulses=$null

if ($vt) { try {
  $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$Ip" -Headers @{ 'x-apikey'=$vt } -TimeoutSec 25
  $st=$r.data.attributes.last_analysis_stats; $vtMal=[int]$st.malicious; $vtSus=[int]$st.suspicious
  $vtRep=[int]$r.data.attributes.reputation; $asOwner=[string]$r.data.attributes.as_owner; $country=[string]$r.data.attributes.country
  $checked += 'virustotal'
} catch {} }
if ($ab) { try {
  $r = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$Ip&maxAgeInDays=90" -Headers @{ Key=$ab; Accept='application/json' } -TimeoutSec 25
  $abConf=[int]$r.data.abuseConfidenceScore; $abReports=[int]$r.data.totalReports; $isp=[string]$r.data.isp; $usage=[string]$r.data.usageType
  if (-not $country) { $country=[string]$r.data.countryCode }
  $checked += 'abuseipdb'
} catch {} }
if ($otx) { try {
  $r = Invoke-RestMethod -Uri "https://otx.alienvault.com/api/v1/indicators/IPv4/$Ip/general" -Headers @{ 'X-OTX-API-KEY'=$otx } -TimeoutSec 25
  $otxPulses=[int]$r.pulse_info.count
  $checked += 'otx'
} catch {} }

# --- verdict --------------------------------------------------------------
$verdict='no-data'; $score=0
if ($checked.Count -gt 0) {
  $isMal = (($vtMal -ge 3) -or ($abConf -ge 50) -or ($otxPulses -ge 5))
  $isSus = (($vtMal -ge 1) -or ($abConf -ge 25) -or ($otxPulses -ge 1))
  if ($isMal) { $verdict='malicious' } elseif ($isSus) { $verdict='suspicious' } else { $verdict='clean' }
  $cand=@()
  if ($null -ne $abConf)    { $cand += $abConf }
  if ($null -ne $vtMal)     { $cand += [Math]::Min($vtMal*10,100) }
  if ($null -ne $otxPulses) { $cand += [Math]::Min($otxPulses*10,100) }
  if ($cand.Count) { $score=[int]($cand | Measure-Object -Maximum).Maximum }
}

$out = [ordered]@{
  ip=$Ip; verdict=$verdict; score=$score; sources_checked=$checked; country=$country
  virustotal=@{ malicious=$vtMal; suspicious=$vtSus; reputation=$vtRep; as_owner=$asOwner }
  abuseipdb=@{ confidence=$abConf; reports=$abReports; isp=$isp; usage=$usage }
  otx=@{ pulses=$otxPulses }
  checked_at=(Get-Date -Format o); cached=$false
}
if (-not $NoCache) { $cache[$Ip]=$out; try { ($cache | ConvertTo-Json -Depth 6) | Set-Content -Path $cacheFile -Encoding utf8 } catch {} }
Emit $out
