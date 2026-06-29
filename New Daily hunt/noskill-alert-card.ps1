# noskill-alert-card.ps1
# Rich Adaptive Card builder for no-skill SOC findings.
# Finding card: W5 layout (Who / What / When / Where / Why) + MITRE + Kill Chain + Action + Query
# Summary card: posture bar + count tiles + PDF button.
# Dot-source before calling Build-NoskillFindingCard / Build-NoskillSummaryCard.

function Build-NoskillFindingCard {
  [CmdletBinding()]
  param([Parameter(Mandatory)][psobject] $Finding)

  $sev     = if($Finding.sev)     { [string]$Finding.sev }     else { 'REVIEW' }
  $glEnv   = if($Finding.env)     { [string]$Finding.env }     else { '' }
  $surface = if($Finding.surface) { if([string]$Finding.surface -eq 'edr'){'ESET'}else{[string]$Finding.surface} } else { '' }
  $sevColor = switch ($sev) {
    'CRITICAL' { 'Attention' } 'HIGH' { 'Attention' }
    'MEDIUM'   { 'Warning'   } default { 'Accent' }
  }

  $findingText = [string]$Finding.finding
  $evidence    = [string]$Finding.evidence
  $detail      = [string]$Finding.detail
  $source      = [string]$Finding.source
  $mitre       = [string]$Finding.mitre
  $tactic      = [string]$Finding.tactic
  $killchain   = [string]$Finding.killchain
  $action      = [string]$Finding.action
  $query       = [string]$Finding.query
  $investigate = [string]$Finding.investigate

  # ── Who: named entity field first, then regex extraction from evidence ──
  $namedWho = [string]$Finding.who
  $who = ''
  if ($namedWho) {
    $who = $namedWho
  } else {
    $ipPat = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    $whoM  = [regex]::Match($evidence, $ipPat)
    if (-not $whoM.Success) { $whoM = [regex]::Match($findingText, $ipPat) }
    if ($whoM.Success) {
      $who = $whoM.Value
    } else {
      $emailM = [regex]::Match($evidence + ' ' + $findingText, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
      if ($emailM.Success) {
        $who = $emailM.Value
      } else {
        $byM = [regex]::Match($evidence + ' ' + $findingText, '(?i)(?:user|account|username|by|from|src)[:\s]+([a-zA-Z0-9._\\/-]+)')
        $who = if ($byM.Success) { $byM.Groups[1].Value } `
               else { if ($evidence.Length -gt 60) { $evidence.Substring(0,60)+'...' } `
                      else { if($evidence){ $evidence } else { '-' } } }
      }
    }
  }

  # ── When: date/datetime patterns in evidence ──
  $whenM = [regex]::Match($evidence, '\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?')
  if (-not $whenM.Success) { $whenM = [regex]::Match($evidence, '\d{2}-\d{2}\s\d{2}:\d{2}(?:\s?UTC)?') }
  $when = if ($whenM.Success) { $whenM.Value + ' UTC' } else { '24h window' }

  # ── Why: detail capped at 200 chars ──
  $why = if ($detail.Length -gt 200) { $detail.Substring(0,200)+'...' } `
         else { if($detail){ $detail } else { '-' } }

  # ── MITRE line ──
  $mitreLine = if ($mitre -and $tactic) { "$mitre -- $tactic" } `
               elseif ($mitre) { $mitre } elseif ($tactic) { $tactic } else { '-' }

  $body = New-Object System.Collections.Generic.List[object]

  # ── Title bar ───────────────────────────────────────────────────────────────
  $body.Add(@{ type='TextBlock'; text="$sev - $glEnv / $surface"; color=$sevColor; weight='Bolder'; size='Medium'; wrap=$true })

  # ── W5 + MITRE + Kill Chain + Action + Investigate FactSet ──────────────────
  $facts = New-Object System.Collections.Generic.List[object]
  $facts.Add(@{ title='Who';       value=$who })
  $facts.Add(@{ title='What';      value=$findingText })
  $facts.Add(@{ title='When';      value=$when })
  $facts.Add(@{ title='Where';     value=if($source){ $source } elseif($glEnv -and $surface){ "$glEnv / $surface" } else { '-' } })
  $facts.Add(@{ title='Why';       value=$why })
  $facts.Add(@{ title='MITRE';     value=$mitreLine })
  if ($killchain)  { $facts.Add(@{ title='Kill Chain';  value=$killchain }) }
  if ($action)     { $facts.Add(@{ title='Action';      value=$action }) }
  if ($investigate){ $facts.Add(@{ title='Investigate'; value=$investigate }) }
  $body.Add(@{ type='FactSet'; facts=$facts.ToArray() })

  # ── Evidence: actual Graylog log data ───────────────────────────────────────
  if ($evidence) {
    $body.Add(@{ type='TextBlock'; text='Evidence (Graylog):'; weight='Bolder'; spacing='Medium'; wrap=$true; size='Small' })
    $body.Add(@{ type='TextBlock'; text=$evidence; wrap=$true; fontType='Monospace'; isSubtle=$true; spacing='None'; size='Small' })
  }

  # ── Investigation context: surface-aware key fields + GL stream ───────────────
  $invFacts = New-Object System.Collections.Generic.List[object]
  $surfLow  = ([string]$Finding.surface).ToLower()
  $glStream = if ($glEnv -and $surface) { "$glEnv / $surface" } elseif ($glEnv) { $glEnv } else { $surface }

  if ($surfLow -match 'iis|app') {
    $clientIp   = [string]$Finding.client_ip
    $hostHdr    = [string]$Finding.host
    $uriStem    = [string]$Finding.uri_stem
    $uriQuery   = [string]$Finding.uri_query
    $httpStatus = [string]$Finding.http_status
    if ($clientIp) { $invFacts.Add(@{ title='Source IP';   value=$clientIp }) }
    if ($hostHdr)  { $invFacts.Add(@{ title='Host';        value=$hostHdr }) }
    if ($uriStem)  { $invFacts.Add(@{ title='URI';         value=$uriStem }) }
    if ($uriQuery) { $invFacts.Add(@{ title='URI Query';   value=$uriQuery }) }
    $invFacts.Add(@{ title='HTTP Status'; value=if($httpStatus){$httpStatus}else{'-'} })
  } elseif ($surfLow -match 'windows|rdp') {
    $evId    = [string]$Finding.event_id
    $winHost = [string]$Finding.win_host
    $winUser = [string]$Finding.win_user
    $ltype   = [string]$Finding.logon_type
    $srcIp   = [string]$Finding.src_ip
    if ($evId)    { $invFacts.Add(@{ title='Event ID';    value=$evId }) }
    if ($winHost) { $invFacts.Add(@{ title='Host';        value=$winHost }) }
    if ($winUser) { $invFacts.Add(@{ title='User';        value=$winUser }) }
    if ($ltype)   { $invFacts.Add(@{ title='Logon Type';  value=$ltype }) }
    if ($srcIp)   { $invFacts.Add(@{ title='Source IP';   value=$srcIp }) }
  } elseif ($surfLow -match 'azure|entra') {
    $azUpn    = [string]$Finding.upn
    $azIp     = [string]$Finding.azure_ip
    $azResult = [string]$Finding.result_code
    $azApp    = [string]$Finding.app_name
    $azCApp   = [string]$Finding.client_app
    $azCtry   = [string]$Finding.geo_country
    if ($azUpn)    { $invFacts.Add(@{ title='UPN';         value=$azUpn }) }
    if ($azIp)     { $invFacts.Add(@{ title='IP Address';  value=$azIp }) }
    if ($azResult) { $invFacts.Add(@{ title='Result Code'; value=$azResult }) }
    if ($azApp)    { $invFacts.Add(@{ title='App';         value=$azApp }) }
    if ($azCApp)   { $invFacts.Add(@{ title='Client App';  value=$azCApp }) }
    if ($azCtry)   { $invFacts.Add(@{ title='Country';     value=$azCtry }) }
  } elseif ($surfLow -match 'linux') {
    $lxUser = [string]$Finding.linux_user
    $lxSrc  = [string]$Finding.linux_src_ip
    $lxSvc  = [string]$Finding.linux_service
    if ($lxUser) { $invFacts.Add(@{ title='User';      value=$lxUser }) }
    if ($lxSrc)  { $invFacts.Add(@{ title='Source IP'; value=$lxSrc }) }
    if ($lxSvc)  { $invFacts.Add(@{ title='Service';   value=$lxSvc }) }
  } elseif ($surfLow -match 'sftp') {
    $sftpIp   = [string]$Finding.client_ip
    $sftpUser = [string]$Finding.sftp_user
    $sftpSize = [string]$Finding.sftp_size_mb
    if ($sftpIp)   { $invFacts.Add(@{ title='Client IP'; value=$sftpIp }) }
    if ($sftpUser) { $invFacts.Add(@{ title='User';      value=$sftpUser }) }
    if ($sftpSize) { $invFacts.Add(@{ title='Size (MB)'; value=$sftpSize }) }
  } elseif ($surfLow -match 'network|forti|fw') {
    $netSrc  = [string]$Finding.src_ip
    $netDst  = [string]$Finding.dst_ip
    $netPort = [string]$Finding.dst_port
    $netAct  = [string]$Finding.net_action
    $netPol  = [string]$Finding.policy
    $netIps  = [string]$Finding.ips_severity
    if ($netSrc)  { $invFacts.Add(@{ title='Source IP';  value=$netSrc }) }
    if ($netDst)  { $invFacts.Add(@{ title='Dest IP';    value=$netDst }) }
    if ($netPort) { $invFacts.Add(@{ title='Dest Port';  value=$netPort }) }
    if ($netAct)  { $invFacts.Add(@{ title='Action';     value=$netAct }) }
    if ($netPol)  { $invFacts.Add(@{ title='Policy';     value=$netPol }) }
    if ($netIps)  { $invFacts.Add(@{ title='IPS Level';  value=$netIps }) }
  } elseif ($surfLow -match 'edr|eset') {
    $edrHost   = [string]$Finding.edr_host
    $edrDetect = [string]$Finding.edr_detect
    $edrProc   = [string]$Finding.edr_process
    if ($edrHost)   { $invFacts.Add(@{ title='Host';      value=$edrHost }) }
    if ($edrDetect) { $invFacts.Add(@{ title='Detection'; value=$edrDetect }) }
    if ($edrProc)   { $invFacts.Add(@{ title='Process';   value=$edrProc }) }
  }
  $invFacts.Add(@{ title='GL / Stream'; value=$glStream })
  if ($invFacts.Count -gt 1) {
    $body.Add(@{ type='TextBlock'; text='Investigation Details:'; weight='Bolder'; spacing='Medium'; wrap=$true; size='Small' })
    $body.Add(@{ type='FactSet'; facts=$invFacts.ToArray(); spacing='None' })
  }

  # ── Query as monospace block ─────────────────────────────────────────────────
  if ($query) {
    $body.Add(@{ type='TextBlock'; text="Query: $query"; wrap=$true; fontType='Monospace'; isSubtle=$true; spacing='Small'; size='Small' })
  }

  # ── Correlation / standalone container ──────────────────────────────────────
  $corrText = [string]$Finding.correlation
  $isCorr   = ($surface -eq 'correlation') -or
              ($corrText -and $corrText -ne 'standalone' -and $corrText -ne '')

  if ($isCorr) {
    $corrItems = New-Object System.Collections.Generic.List[object]
    if ($surface -eq 'correlation') {
      $kcLabel  = if($killchain) { "Cross-correlation kill chain $killchain $sev" } else { "Cross-correlation kill chain $sev" }
      $modLabel = if($corrText -and $corrText -ne 'standalone') { "  [modules/env: $corrText]" } else { '' }
      $corrItems.Add(@{ type='TextBlock'; text="$kcLabel$modLabel"; weight='Bolder'; color='Accent'; wrap=$true })
      if ($detail) { $corrItems.Add(@{ type='TextBlock'; text=$detail; wrap=$true }) }
      $conf = [string]$Finding.confidence
      if ($conf) { $cn=0; try{$cn=[int]$conf}catch{}; $cp=if($cn -gt 5){[math]::Min($cn,100)}else{$cn*20}; $corrItems.Add(@{ type='TextBlock'; text="Confidence: $cp%"; weight='Bolder'; wrap=$true; spacing='Small' }) }
      if ($query) { $corrItems.Add(@{ type='TextBlock'; text="Graylog queries: $query"; wrap=$true; isSubtle=$true; fontType='Monospace' }) }
    } else {
      $kcLabel = if($killchain) { "Part of kill chain $killchain : $corrText" } else { "Cross-surface link: $corrText" }
      $corrItems.Add(@{ type='TextBlock'; text=$kcLabel; weight='Bolder'; color='Accent'; wrap=$true })
      if ($detail) { $corrItems.Add(@{ type='TextBlock'; text=$detail; wrap=$true }) }
      $conf = [string]$Finding.confidence
      if ($conf) { $cn=0; try{$cn=[int]$conf}catch{}; $cp=if($cn -gt 5){[math]::Min($cn,100)}else{$cn*20}; $corrItems.Add(@{ type='TextBlock'; text="Confidence: $cp%"; weight='Bolder'; wrap=$true; spacing='Small' }) }
    }
    $body.Add(@{ type='Container'; style='emphasis'; separator=$true; spacing='Medium'; items=$corrItems.ToArray() })
  } else {
    $body.Add(@{
      type='Container'; style='good'; separator=$true; spacing='Medium'
      items=@(@{ type='TextBlock'; wrap=$true; isSubtle=$true; text="Standalone -- no cross-surface kill chain. Pivot via the query above." })
    })
  }

  $card = [ordered]@{
    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
    type      = 'AdaptiveCard'; version = '1.4'
    body      = $body.ToArray()
  }
  return @{
    type        = 'message'
    attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
  }
}

function Build-NoskillHungCard {
  # Warning card posted BEFORE finding cards when MCP tool failures caused surfaces to be skipped.
  # Surfaces = array of "ENV/surface" strings extracted from mcp-hung: findings.
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]] $Surfaces,
    [string] $DateStr
  )

  $surfaceList = $Surfaces -join ', '
  $body = [System.Collections.Generic.List[object]]::new()
  $body.Add(@{
    type='TextBlock'; text='SURFACES NOT HUNTED -- MCP Tool Failure'
    color='Warning'; weight='Bolder'; size='Medium'; wrap=$true
  })
  if ($DateStr) {
    $body.Add(@{ type='TextBlock'; text=$DateStr; isSubtle=$true; size='Small'; spacing='None' })
  }
  $body.Add(@{
    type='TextBlock'
    text="The following surfaces had MCP tool failures during the hunt. No queries were run and no threat data was collected for them."
    wrap=$true; spacing='Small'
  })

  $facts = $Surfaces | ForEach-Object { @{ title='NOT HUNTED'; value=$_ } }
  $body.Add(@{ type='FactSet'; facts=@($facts); spacing='Small' })

  $body.Add(@{
    type='Container'; style='attention'; spacing='Medium'
    items=@(@{
      type='TextBlock'
      text="Threat posture for these surfaces is UNKNOWN for today. They are queued for the next retry window. If immediate coverage is required, run a manual check."
      wrap=$true; weight='Bolder'
    })
  })

  $card = [ordered]@{
    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
    type      = 'AdaptiveCard'; version = '1.4'
    body      = $body.ToArray()
  }
  return @{
    type        = 'message'
    attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
  }
}

function Build-NoskillSummaryCard {
  # Final card posted after hunt completes: posture line + counts + PDF button.
  [CmdletBinding()]
  param(
    [hashtable] $Counts,
    [string]    $DateStr,
    [string]    $PdfUrl,
    [string]    $PdfName,
    [string[]]  $TopItems,      # up to 5 "- [sev] env/surface: action" lines
    [string[]]  $HungSurfaces   # surfaces skipped due to MCP failure (shown as warning)
  )

  $nC=[int]$Counts.CRITICAL; $nH=[int]$Counts.HIGH; $nM=[int]$Counts.MEDIUM
  $nR=[int]$Counts.REVIEW;   $nL=[int]$Counts.LOW
  $postureColor = if($nC -gt 0) { 'Attention' } elseif($nH -gt 0) { 'Warning' } else { 'Good' }
  $postureText  = if($nC -gt 0) { "ACTION REQUIRED - $nC critical corroborated finding(s)" } `
                  elseif($nH -gt 0) { "REVIEW - $nH HIGH finding(s); no corroborated critical" } `
                  else { "NOMINAL - no critical or high findings today" }

  $body = @(
    @{ type='TextBlock'; text="SOC No-Skill Daily Hunt - $DateStr"; weight='Bolder'; size='Large'; color='Accent'; wrap=$true }
    @{ type='TextBlock'; text="Posture: $postureText"; color=$postureColor; weight='Bolder'; size='Medium'; wrap=$true; spacing='Small' }
    @{ type='ColumnSet'; spacing='Medium'; columns=@(
        @{ type='Column'; width='stretch'; style='emphasis'; items=@( @{ type='TextBlock'; text=[string]$nC; size='ExtraLarge'; weight='Bolder'; color='Attention'; horizontalAlignment='Center' }, @{ type='TextBlock'; text='CRITICAL'; size='Small'; weight='Bolder'; isSubtle=$true; horizontalAlignment='Center'; spacing='None' } ) }
        @{ type='Column'; width='stretch'; style='emphasis'; items=@( @{ type='TextBlock'; text=[string]$nH; size='ExtraLarge'; weight='Bolder'; color='Warning';   horizontalAlignment='Center' }, @{ type='TextBlock'; text='HIGH';     size='Small'; weight='Bolder'; isSubtle=$true; horizontalAlignment='Center'; spacing='None' } ) }
        @{ type='Column'; width='stretch'; style='emphasis'; items=@( @{ type='TextBlock'; text=[string]$nM; size='ExtraLarge'; weight='Bolder'; color='Accent';    horizontalAlignment='Center' }, @{ type='TextBlock'; text='MEDIUM';   size='Small'; weight='Bolder'; isSubtle=$true; horizontalAlignment='Center'; spacing='None' } ) }
        @{ type='Column'; width='stretch'; style='emphasis'; items=@( @{ type='TextBlock'; text=[string]$nR; size='ExtraLarge'; weight='Bolder'; color='Default';   horizontalAlignment='Center' }, @{ type='TextBlock'; text='REVIEW';   size='Small'; weight='Bolder'; isSubtle=$true; horizontalAlignment='Center'; spacing='None' } ) }
        @{ type='Column'; width='stretch'; style='emphasis'; items=@( @{ type='TextBlock'; text=[string]$nL; size='ExtraLarge'; weight='Bolder'; color='Good';      horizontalAlignment='Center' }, @{ type='TextBlock'; text='LOW';      size='Small'; weight='Bolder'; isSubtle=$true; horizontalAlignment='Center'; spacing='None' } ) }
    ) }
  )

  if ($TopItems -and $TopItems.Count -gt 0) {
    $body += @{ type='TextBlock'; text='Top actionable items:'; weight='Bolder'; spacing='Medium'; wrap=$true }
    foreach ($line in $TopItems) {
      $body += @{ type='TextBlock'; text=$line; wrap=$true; spacing='Small' }
    }
  }

  if ($HungSurfaces -and $HungSurfaces.Count -gt 0) {
    $hungList = $HungSurfaces -join ', '
    $body += @{
      type='Container'; style='attention'; separator=$true; spacing='Medium'
      items=@(
        @{ type='TextBlock'; text='MCP FAILURES -- surfaces not hunted:'; weight='Bolder'; color='Attention'; wrap=$true }
        @{ type='TextBlock'; text=$hungList; wrap=$true; spacing='Small' }
        @{ type='TextBlock'; text='These surfaces have UNKNOWN posture today. Queued for next retry window.'; wrap=$true; isSubtle=$true; size='Small'; spacing='Small' }
      )
    }
  }

  if ($PdfName) {
    $body += @{ type='TextBlock'; text="PDF: $PdfName"; wrap=$true; isSubtle=$true; spacing='Medium' }
  }

  $body += @{ type='TextBlock'; text='Full detail in the PDF report.'; wrap=$true; isSubtle=$true; spacing='Small' }

  $actions = @()
  if ($PdfUrl) { $actions += @{ type='Action.OpenUrl'; title='Open PDF report'; url=$PdfUrl } }

  $card = [ordered]@{
    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
    type      = 'AdaptiveCard'; version = '1.4'
    body      = $body; actions = $actions
  }
  return @{
    type        = 'message'
    attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
  }
}
