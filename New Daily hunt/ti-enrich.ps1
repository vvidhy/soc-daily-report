# ti-enrich.ps1
# Threat-intel reputation lookup for one or more IPs against VirusTotal (v3) + AbuseIPDB.
# Used by the IIS hunt: when an EXPLOITATION token is confirmed in URI content, reputation-check
# the EXTERNAL Client_ip. 0 Claude tokens; Cortex-clean (HTTP plumbing only, no attack signatures).
#
# Keys (you provide): soc-monitor\.ti-keys.json  ->  { "virustotal": "<key>", "abuseipdb": "<key>" }
#   (abuseipdb optional; if either key is absent that feed is simply skipped)
# Cache: soc-monitor\reports-noskill\ti-cache.json  (TTL hours below; also limits free-tier API spend)
#
# Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File ti-enrich.ps1 -Ip 109.105.210.85
#         powershell ... -File ti-enrich.ps1 -Ip 1.2.3.4,5.6.7.8 -CacheHours 24
# Returns: JSON array, one record per IP, with verdict MALICIOUS | SUSPICIOUS | clean/unknown | SKIPPED.

param(
  [Parameter(Mandatory)][string[]]$Ip,
  [int]$CacheHours = 168,
  [int]$MaxNewLookups = 8
)
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$keyFile="$proj\.ti-keys.json"
$cacheFile="$proj\logs-noskill\ti-cache.json"

# RFC1918 + known-good egress -> never spend a lookup on these
$catoEtc=@('140.82.202.196','199.27.40.187','123.253.153.138')
function Is-Internal([string]$i){
  if($i -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)'){ return $true }
  if($i -match '^(136\.226\.|165\.225\.)'){ return $true }   # Zscaler egress
  if($catoEtc -contains $i){ return $true }
  return $false
}

if(-not (Test-Path $keyFile)){
  Write-Output '[{"error":"no-ti-key","hint":"create soc-monitor\\.ti-keys.json = { \"virustotal\":\"KEY\", \"abuseipdb\":\"KEY\" }"}]'
  exit 0
}
$keys=Get-Content $keyFile -Raw | ConvertFrom-Json
$vtKey=[string]$keys.virustotal
$abKey=[string]$keys.abuseipdb

$cache=@{}
if(Test-Path $cacheFile){ try{ (Get-Content $cacheFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cache[$_.Name]=$_.Value } }catch{} }

[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$out=@(); $new=0
foreach($i in ($Ip | Select-Object -Unique)){
  if(Is-Internal $i){ $out+=[pscustomobject]@{ip=$i;verdict='SKIPPED-internal-or-allowlisted'}; continue }
  if($cache.ContainsKey($i)){
    $c=$cache[$i]; $age=[timespan]::FromHours(999)
    try{ $age=(Get-Date)-([datetime]$c.ts) }catch{}
    if($age.TotalHours -lt $CacheHours){ $out+=$c; continue }
  }
  if($new -ge $MaxNewLookups){ $out+=[pscustomobject]@{ip=$i;verdict='DEFERRED-rate-limit';note="exceeded $MaxNewLookups new lookups this run"}; continue }
  $rec=[ordered]@{ip=$i;vt_malicious=$null;vt_suspicious=$null;vt_total=$null;vt_reputation=$null;abuse_score=$null;abuse_reports=$null;owner=$null;country=$null;verdict='unknown';ts=(Get-Date -Format o)}
  if($vtKey){
    if($new -gt 0){ Start-Sleep -Seconds 16 }   # VT free tier = 4 req/min
    try{
      $r=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$i" -Headers @{'x-apikey'=$vtKey} -TimeoutSec 25
      $st=$r.data.attributes.last_analysis_stats
      $rec.vt_malicious=[int]$st.malicious; $rec.vt_suspicious=[int]$st.suspicious
      $rec.vt_total=[int]($st.malicious+$st.suspicious+$st.harmless+$st.undetected)
      $rec.vt_reputation=[int]$r.data.attributes.reputation
      $rec.owner=[string]$r.data.attributes.as_owner; $rec.country=[string]$r.data.attributes.country
    }catch{ $rec.vt_error=$_.Exception.Message }
  }
  if($abKey){
    try{
      $a=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$i&maxAgeInDays=90" -Headers @{'Key'=$abKey;'Accept'='application/json'} -TimeoutSec 25
      $rec.abuse_score=[int]$a.data.abuseConfidenceScore; $rec.abuse_reports=[int]$a.data.totalReports
      if(-not $rec.owner){ $rec.owner=[string]$a.data.isp }
      if(-not $rec.country){ $rec.country=[string]$a.data.countryCode }
    }catch{ $rec.abuse_error=$_.Exception.Message }
  }
  $mal=(($rec.vt_malicious -ge 5) -or ($rec.abuse_score -ge 75))
  $sus=(($rec.vt_malicious -ge 1) -or ($rec.vt_suspicious -ge 2) -or ($rec.abuse_score -ge 25))
  $rec.verdict= if($mal){'MALICIOUS'} elseif($sus){'SUSPICIOUS'} else {'clean-or-unknown'}
  $obj=[pscustomobject]$rec; $cache[$i]=$obj; $out+=$obj; $new++
}
try{ ($cache | ConvertTo-Json -Depth 6) | Set-Content $cacheFile -Encoding utf8 }catch{}
$out | ConvertTo-Json -Depth 6
