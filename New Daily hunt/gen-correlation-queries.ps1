# gen-correlation-queries.ps1
# Zero-token correlation path: when no HIGH/CRITICAL findings exist, extracts
# cross-surface entities (IPs, users) from merged-findings.json and writes
# Graylog investigation queries to correlation-latest.md - no claude invocation.
# Called by daily-report-noskill.cmd when correlation-gate exits 0 (no HIGH/CRIT).
#
# LOGGING: writes ONLY to stdout - caller owns the log via >> daily.log 2>&1.
$ErrorActionPreference = 'Continue'
$proj   = 'D:\Vidhya\New Daily hunt'
$dir    = "$proj\reports-noskill"
$merged = "$dir\_merged-findings.json"
$out    = "$dir\correlation-latest.md"
$cato   = @('140.82.202.196','199.27.40.187','123.253.153.138')

function Save-Correlation {
  param([string[]]$BodyLines, [object[]]$FjObjects)
  $jsonStr = '[]'
  if($FjObjects -and $FjObjects.Count -gt 0){
    $jsonStr = $FjObjects | ConvertTo-Json -Depth 5 -Compress
    if($FjObjects.Count -eq 1){ $jsonStr = "[$jsonStr]" }
  }
  $fence   = '```'
  $block   = "$fence`findings-json`n$jsonStr`n$fence"
  [IO.File]::WriteAllText($out, ($BodyLines -join "`n") + "`n" + $block, [Text.Encoding]::UTF8)
}

# ---- no merged file ----
if(-not (Test-Path $merged)){
  Write-Output "gen-correlation-queries: no merged-findings.json - writing empty correlation"
  $body = @(
    '## Kill Chains'
    'No HIGH/CRITICAL findings. Correlation skipped.'
    ''
    '## Correlated Entities'
    'None.'
    ''
    '## Cross-Check Coverage'
    'Query-only mode - no HIGH/CRITICAL findings this run.'
  )
  $fj = @([pscustomobject]@{
    sev='CLEAN'; env='ALL'; surface='correlation'
    finding='No HIGH/CRITICAL findings - correlation not warranted'
    evidence='0 high/crit findings'; mitre=''; action='No action required'
    query=''; investigate=''
  })
  Save-Correlation -BodyLines $body -FjObjects $fj
  exit 0
}

# ---- parse merged findings ----
try { $findings = Get-Content $merged -Raw | ConvertFrom-Json }
catch {
  Write-Output "gen-correlation-queries: cannot parse merged findings - $($_.Exception.Message)"
  exit 1
}
if($null -eq $findings){ $findings = @() }
if($findings -isnot [array]){ $findings = @($findings) }

# ---- entity extraction ----
$ipRe   = [regex]'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
$userRe = [regex]'(?:user|username|account|login)[:\s]+([a-zA-Z0-9._@\\-]{3,64})'
$skipW  = 'the','for','from','this','that','with','not','via','any','all','has','was','its'

$entityMap = @{}  # key -> @{type; hits[]}

foreach($f in $findings){
  if([string]$f.sev -eq 'CLEAN'){ continue }
  $text = "$($f.finding) $($f.evidence)"

  # IPs (skip Cato; keep RFC-1918 only if context is privileged)
  $ips = $ipRe.Matches($text) | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
  foreach($ip in $ips){
    if($ip -in $cato){ continue }
    $isPrivate = $ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
    if($isPrivate -and $text -notmatch 'privilege|admin|root|exploit|lateral'){ continue }
    $k = "ip:$ip"
    if(-not $entityMap.ContainsKey($k)){ $entityMap[$k] = @{ type='ip'; entity=$ip; hits=@() } }
    $entityMap[$k].hits += [pscustomobject]@{
      surface=[string]$f.surface; env=[string]$f.env; sev=[string]$f.sev; finding=[string]$f.finding }
  }

  # Usernames
  $users = $userRe.Matches($text) | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
  foreach($u in $users){
    if($u -in $skipW -or $u.Length -lt 4){ continue }
    $k = "user:$u"
    if(-not $entityMap.ContainsKey($k)){ $entityMap[$k] = @{ type='user'; entity=$u; hits=@() } }
    $entityMap[$k].hits += [pscustomobject]@{
      surface=[string]$f.surface; env=[string]$f.env; sev=[string]$f.sev; finding=[string]$f.finding }
  }
}

# keep entities seen across 2+ distinct surfaces
$cross = @($entityMap.GetEnumerator() | Where-Object {
  ($_.Value.hits | Select-Object -ExpandProperty surface | Sort-Object -Unique).Count -ge 2
} | Sort-Object { -$_.Value.hits.Count })

# ---- build markdown body ----
$body  = [System.Collections.ArrayList]::new()
$fjArr = [System.Collections.ArrayList]::new()

[void]$body.Add('## Kill Chains')
[void]$body.Add('No HIGH/CRITICAL findings this run. Opus correlation not warranted. Cross-surface entities below for analyst follow-up.')
[void]$body.Add('')
[void]$body.Add('## Correlated Entities')

if($cross.Count -gt 0){
  foreach($e in $cross){
    $etype  = $e.Value.type
    $entity = $e.Value.entity
    $hits   = $e.Value.hits
    $surfaces = ($hits | Select-Object -ExpandProperty surface | Sort-Object -Unique) -join ', '
    $envs     = ($hits | Select-Object -ExpandProperty env     | Sort-Object -Unique) -join ', '
    $sevs     = $hits | Select-Object -ExpandProperty sev | Sort-Object -Unique
    $maxSev   = if('HIGH' -in $sevs){'HIGH'} elseif('MEDIUM' -in $sevs){'MEDIUM'} else {'REVIEW'}

    [void]$body.Add("### [$etype] $entity  (max: $maxSev)")
    [void]$body.Add("Surfaces: $surfaces | Envs: $envs")
    foreach($h in $hits){ [void]$body.Add("- [$($h.surface)/$($h.env)] $($h.finding)") }
    [void]$body.Add('')
    [void]$body.Add("**Graylog queries to investigate ${entity} :**")
    [void]$body.Add('```')

    if($etype -eq 'ip'){
      [void]$body.Add("# Firewall - all traffic from/to this IP")
      [void]$body.Add("src_ip:$entity OR dst_ip:$entity")
      [void]$body.Add('')
      [void]$body.Add("# IIS / web - requests from this IP (OP-GL IIS_PROD / IIS_UAT)")
      [void]$body.Add("Client_ip:$entity OR message:$entity")
      [void]$body.Add('')
      [void]$body.Add("# Linux syslog / SSH")
      [void]$body.Add("message:$entity")
      [void]$body.Add('')
      [void]$body.Add("# Azure / Entra - sign-ins from this IP")
      [void]$body.Add("azure_prob_ip_address:$entity OR azure_prop_ip_address:$entity")
      [void]$body.Add('')
      [void]$body.Add("# Windows - logon / network connection events")
      [void]$body.Add("winlogbeat_event_data_IpAddress:$entity OR winlogbeat_event_data_WorkstationName:$entity")
      [void]$body.Add('')
      [void]$body.Add("# SFTP / Rebex - file transfer activity")
      [void]$body.Add("source_ip:$entity OR message:$entity")
      $investQ = "src_ip:$entity OR dst_ip:$entity OR message:$entity"
    } else {
      [void]$body.Add("# All GLs - any log mentioning this account")
      [void]$body.Add("message:$entity")
      [void]$body.Add('')
      [void]$body.Add("# Azure / Entra - sign-in history")
      [void]$body.Add("azure_prob_user_principal_name:$entity OR azure_prop_user_principal_name:$entity")
      [void]$body.Add('')
      [void]$body.Add("# Windows - logon events for this user")
      [void]$body.Add("winlogbeat_event_data_SubjectUserName:$entity OR winlogbeat_event_data_TargetUserName:$entity")
      [void]$body.Add('')
      [void]$body.Add("# Linux sudo / su activity")
      [void]$body.Add("message:$entity AND (message:sudo OR message:su OR message:useradd)")
      $investQ = "message:$entity"
    }

    [void]$body.Add('```')
    [void]$body.Add('')

    [void]$fjArr.Add([pscustomobject]@{
      sev='REVIEW'; env=$envs; surface='correlation'
      finding="Cross-surface $etype $entity seen on: $surfaces"
      evidence="surfaces: $surfaces; envs: $envs; max_sev: $maxSev"
      mitre=''
      action="Run the Graylog queries above to pivot on $entity"
      query=''
      investigate=$investQ
    })
  }
} else {
  [void]$body.Add('No entities appeared across 2 or more surfaces at REVIEW or higher.')
  [void]$fjArr.Add([pscustomobject]@{
    sev='CLEAN'; env='ALL'; surface='correlation'
    finding='No cross-surface entity correlation found at any severity level'
    evidence='0 shared entities across surfaces'; mitre=''
    action='No action required'; query=''; investigate=''
  })
}

[void]$body.Add('## Cross-Check Coverage')
[void]$body.Add("Query-only mode (no HIGH/CRITICAL). $($cross.Count) cross-surface entities extracted. Run the queries above for any warranting analyst review.")

Save-Correlation -BodyLines @($body) -FjObjects @($fjArr)
Write-Output "gen-correlation-queries: wrote correlation-latest.md - $($cross.Count) cross-surface entities, $($fjArr.Count) findings-json entries"
