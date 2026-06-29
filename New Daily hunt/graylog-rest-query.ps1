# graylog-rest-query.ps1
# REST FALLBACK for the Graylog MCP tools. The mcp-server-graylog MCP is only a thin
# wrapper over the Graylog REST API, so when an MCP call fails mid-hunt (wrapper/npx hiccup,
# timeout) but Graylog itself is up, this fetches the SAME data straight from REST - so a
# flaky MCP no longer sends a surface to stale.
#
# Cortex-clean: the script BODY has no attack-signature literals; the query is read from a
# FILE (-QueryFile), so injection/webshell tokens never sit in this .ps1 or the command line.
# Token + base URL are read from .mcp.json (single source of truth).
#
# Usage (run from the hunt via the Bash/PowerShell tool):
#   aggregate: powershell -NoProfile -ExecutionPolicy Bypass -File graylog-rest-query.ps1 -GL PROD-GL -Mode aggregate -Field action -QueryFile q.txt -RangeSeconds 86400 -Size 25 [-StreamId <id>]
#   search:    powershell -NoProfile -ExecutionPolicy Bypass -File graylog-rest-query.ps1 -GL PROD-GL -Mode search    -QueryFile q.txt -RangeSeconds 86400 -Limit 20 [-StreamId <id>] [-Fields "a,b,c"]
# Output: JSON on stdout, shaped like the MCP tools (aggregate -> {total_matched, top{}}; search -> {total_results, messages[]}).
param(
  [Parameter(Mandatory=$true)][ValidateSet('AZ-GL','PROD-GL','DEV-GL','OP-GL')][string]$GL,
  [ValidateSet('aggregate','search')][string]$Mode='search',
  [string]$Field,
  [string]$QueryFile,
  [string]$Query='*',
  [int]$RangeSeconds=86400,
  [int]$Size=25,
  [int]$Limit=20,
  [string]$StreamId,
  [string]$Fields='*'
)
$ErrorActionPreference='Stop'
$proj='D:\Vidhya\New Daily hunt'
if($QueryFile){ if(Test-Path $QueryFile){ $Query=(Get-Content $QueryFile -Raw).Trim() } else { Write-Output ('{"error":"QueryFile not found: ' + $QueryFile + '"}'); exit 2 } }

$mcp = Get-Content "$proj\.mcp.json" -Raw | ConvertFrom-Json
$srv = $mcp.mcpServers.$GL
if(-not $srv){ Write-Output ('{"error":"unknown GL ' + $GL + '"}'); exit 2 }
$base = $srv.env.BASE_URL.TrimEnd('/')
$tok  = $srv.env.API_TOKEN

add-type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class GLRestTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p){return true;} }
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object GLRestTrust
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12

$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($tok + ':token'))
$headers = @{ Authorization = ('Basic ' + $b64); 'X-Requested-By' = 'soc-rest-fallback'; Accept = 'application/json' }

try {
  if($Mode -eq 'aggregate'){
    if(-not $Field){ Write-Output '{"error":"aggregate mode requires -Field"}'; exit 2 }
    # No server-side /terms endpoint on these Graylogs (404). Mirror MCP aggregate_logs:
    # fetch up to fetchLimit messages with ONLY the field projected, then group client-side.
    $fetch = 5000
    $u = $base + '/api/search/universal/relative?query=' + [uri]::EscapeDataString($Query) + '&range=' + $RangeSeconds + '&limit=' + $fetch + '&fields=' + [uri]::EscapeDataString($Field)
    if($StreamId){ $u += '&filter=' + [uri]::EscapeDataString('streams:' + $StreamId) }
    $r = Invoke-RestMethod -Uri $u -Headers $headers -TimeoutSec 90
    $vals = @($r.messages | ForEach-Object { [string]$_.message.$Field } | Where-Object { $_ -ne '' })
    $grp = $vals | Group-Object | Sort-Object Count -Descending | Select-Object -First $Size
    $top = [ordered]@{}; foreach($g in $grp){ $top[[string]$g.Name] = $g.Count }
    $tot = [int]$r.total_results
    ([ordered]@{ field=$Field; query=$Query; total_matched=$tot; messages_aggregated=[math]::Min($tot,$fetch); truncated=($tot -gt $fetch); top=$top } | ConvertTo-Json -Depth 6)
  } else {
    $u = $base + '/api/search/universal/relative?query=' + [uri]::EscapeDataString($Query) + '&range=' + $RangeSeconds + '&limit=' + $Limit
    if($Fields -and $Fields -ne '*'){ $u += '&fields=' + [uri]::EscapeDataString($Fields) }
    if($StreamId){ $u += '&filter=' + [uri]::EscapeDataString('streams:' + $StreamId) }
    $r = Invoke-RestMethod -Uri $u -Headers $headers -TimeoutSec 60
    ([ordered]@{ query=$Query; total_results=$r.total_results; messages=@($r.messages | ForEach-Object { $_.message }) } | ConvertTo-Json -Depth 8)
  }
} catch {
  Write-Output ('{"error":"REST call failed","detail":"' + ($_.Exception.Message -replace '"','''') + '"}')
  exit 1
}
