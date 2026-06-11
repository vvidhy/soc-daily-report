<#
  alert-card.ps1 - Adaptive Card presentation for the IIS OP-GL monitor.

  The Teams "Send webhook alerts" workflow (OOTB template) renders Adaptive Cards,
  so HIGH findings are delivered as an Adaptive Card wrapped in the Teams message
  envelope the workflow expects:
     { type:"message", attachments:[ { contentType:"application/vnd.microsoft.card.adaptive", content:{...} } ] }

  Build-AdaptiveCardEnvelope -Finding  ->  the envelope hashtable (ConvertTo-Json -Depth 20).
  Pure formatting; no model calls, no network. Severity gating is done upstream
  (only HIGH findings are posted).
#>

$script:CardDeepInvestUrl = 'https://github.com/mukul975/Anthropic-Cybersecurity-Skills'

function Build-AdaptiveCardEnvelope {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject] $Finding)

    $sev = if ($Finding.severity) { [string]$Finding.severity } else { 'REVIEW' }
    $sevColor = switch ($sev) { 'HIGH' {'Attention'} 'CONFIRMED' {'Warning'} 'REVIEW' {'Accent'} default {'Default'} }

    $facts = New-Object System.Collections.Generic.List[object]
    $facts.Add(@{ title = 'Severity';        value = $sev })
    $facts.Add(@{ title = 'Technique';       value = [string]$Finding.technique })
    $facts.Add(@{ title = 'Detection class'; value = ("Class {0}" -f $Finding.detection_class) })
    $facts.Add(@{ title = 'Anchor IP';       value = [string]$Finding.anchor_ip })
    $facts.Add(@{ title = 'Anchor user';     value = [string]$Finding.anchor_user })
    $facts.Add(@{ title = 'Anchor host';     value = [string]$Finding.anchor_host })
    $facts.Add(@{ title = 'Time (UTC)';      value = [string]$Finding.anchor_time })
    if ($null -ne $Finding.confidence_score) {
        try { $facts.Add(@{ title = 'Confidence'; value = ('{0}%' -f [int]([double]$Finding.confidence_score * 100)) }) } catch {}
    }
    $facts.Add(@{ title = 'Finding ID'; value = [string]$Finding.finding_id })

    $body = New-Object System.Collections.Generic.List[object]
    $body.Add(@{ type='TextBlock'; size='Large'; weight='Bolder'; color=$sevColor; wrap=$true; text=("[{0}] {1}" -f $sev, [string]$Finding.title) })
    if ($Finding.summary) { $body.Add(@{ type='TextBlock'; wrap=$true; text=[string]$Finding.summary }) }
    $body.Add(@{ type='FactSet'; facts=$facts.ToArray() })

    if ($Finding.corroboration_sources -and @($Finding.corroboration_sources).Count -gt 0) {
        $body.Add(@{ type='TextBlock'; weight='Bolder'; spacing='Medium'; text='Corroboration' })
        $body.Add(@{ type='TextBlock'; wrap=$true; text=(@($Finding.corroboration_sources) -join "`n") })
    }
    if ($Finding.kill_chain_stages -and @($Finding.kill_chain_stages).Count -gt 0) {
        $body.Add(@{ type='TextBlock'; wrap=$true; isSubtle=$true; text=('Kill chain: ' + (@($Finding.kill_chain_stages) -join ' -> ')) })
    }
    if (($Finding.PSObject.Properties['deep_analysis']) -and $Finding.deep_analysis) {
        # The deep-dive returns "[skill applied: <name>]\n<analysis>". Lift the skill
        # into the heading and render the body markdown in an emphasis box so the
        # Verdict / Do now / Investigate-further sections are easy to scan and act on.
        $rawAnalysis = [string]$Finding.deep_analysis
        $skillName   = ''
        $m = [regex]::Match($rawAnalysis, '(?s)^\s*\[skill applied:\s*(.+?)\]\s*(.*)$')
        if ($m.Success) { $skillName = $m.Groups[1].Value.Trim(); $rawAnalysis = $m.Groups[2].Value.Trim() }
        $invHeader = if ($skillName) { "AI investigation  (skill: $skillName)" } else { 'AI investigation (opus)' }
        $body.Add(@{
            type='Container'; separator=$true; spacing='Medium'; style='emphasis'
            items=@(
                @{ type='TextBlock'; weight='Bolder'; size='Medium'; color='Accent'; wrap=$true; text=$invHeader },
                @{ type='TextBlock'; wrap=$true; text=$rawAnalysis }
            )
        })
    }
    if ($Finding.investigate) {
        $body.Add(@{ type='TextBlock'; wrap=$true; isSubtle=$true; fontType='Monospace'; text=('Investigate: ' + [string]$Finding.investigate) })
    }

    $actions = New-Object System.Collections.Generic.List[object]
    if ($Finding.graylog_link) { $actions.Add(@{ type='Action.OpenUrl'; title='Open in Graylog'; url=[string]$Finding.graylog_link }) }

    $card = [ordered]@{
        '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
        type      = 'AdaptiveCard'
        version   = '1.4'
        body      = $body.ToArray()
        actions   = $actions.ToArray()
    }
    return @{
        type        = 'message'
        attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
    }
}

function Build-SweepCardEnvelope {
    # Tier-3 daily completeness sweep card. INFORMATIONAL / advisory - deliberately
    # styled apart from HIGH alerts (Accent header, "advisory" footer) so the channel
    # reader never confuses a sweep note with a corroborated HIGH alert.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ReportText,
        [int]    $WindowHours = 24,
        [string] $GeneratedUtc,
        [string] $GraylogLink
    )
    $txt = if ($ReportText.Length -gt 6000) { $ReportText.Substring(0,6000) + "`r`n... (truncated; see full report file)" } else { $ReportText }
    # Lift the "Sweep verdict:" line into a prominent banner; item blocks render below.
    $verdict = ''
    $m = [regex]::Match($txt, '(?im)^\s*\*\*Sweep verdict:\*\*\s*(.+?)\s*$')
    if ($m.Success) { $verdict = $m.Groups[1].Value.Trim(); $txt = $txt.Remove($m.Index, $m.Length).Trim() }
    $vColor = if ($verdict -match '(?i)no novel|clean|routine|no candidate') { 'Good' } else { 'Warning' }

    $body = New-Object System.Collections.Generic.List[object]
    $body.Add(@{ type='TextBlock'; size='Large'; weight='Bolder'; color='Accent'; wrap=$true; text='IIS OP-GL - Daily completeness sweep' })
    $body.Add(@{ type='TextBlock'; isSubtle=$true; spacing='None'; wrap=$true; text=("Tier 3 - opus - ADVISORY - last {0}h - {1}" -f $WindowHours, $GeneratedUtc) })
    if ($verdict) { $body.Add(@{ type='TextBlock'; weight='Bolder'; size='Medium'; color=$vColor; spacing='Medium'; wrap=$true; text=("Verdict: {0}" -f $verdict) }) }
    if ($txt)     { $body.Add(@{ type='Container'; style='emphasis'; separator=$true; items=@(@{ type='TextBlock'; wrap=$true; text=$txt }) }) }
    $body.Add(@{ type='TextBlock'; isSubtle=$true; wrap=$true; text='Advisory only - not a HIGH alert; AI hunches are never auto-escalated.' })

    $actions = New-Object System.Collections.Generic.List[object]
    if ($GraylogLink) { $actions.Add(@{ type='Action.OpenUrl'; title='Open in Graylog'; url=$GraylogLink }) }

    $card = [ordered]@{
        '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
        type      = 'AdaptiveCard'
        version   = '1.4'
        body      = $body.ToArray()
        actions   = $actions.ToArray()
    }
    return @{
        type        = 'message'
        attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
    }
}

function Build-DigestCardEnvelope {
    # Daily activity digest -- VISIBILITY into what was caught below the HIGH alert bar.
    # Two audiences in one clean card: a plain-language posture line + counts for
    # management, then a confirmed-items list and a by-type review breakdown for the SOC.
    # $Digest = @{ date; high; confirmed_count; review_count;
    #              confirmed=@(@{ip;host;what}); review_cats=@(@{name;count;ip}); graylog_link }
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Digest)

    $c = $Digest.counts
    $nCrit=[int]$c.CRITICAL; $nHigh=[int]$c.HIGH; $nMod=[int]$c.MODERATE; $nLow=[int]$c.LOW
    $postureColor = if ($nCrit -gt 0) { 'Attention' } elseif ($nHigh -gt 0) { 'Warning' } else { 'Good' }
    $postureText  = if ($nCrit -gt 0) { "ACTION - $nCrit critical (corroborated) finding(s) today" } elseif ($nHigh -gt 0) { "REVIEW - $nHigh high finding(s); no corroborated critical" } else { "NOMINAL - no critical or high findings today" }

    function _Tile($n,$label,$col){
        @{ type='Column'; width='stretch'; style='emphasis'; spacing='Small'; items=@(
            @{ type='TextBlock'; text=[string]$n; size='ExtraLarge'; weight='Bolder'; color=$col; horizontalAlignment='Center'; spacing='None' },
            @{ type='TextBlock'; text=$label; size='Small'; weight='Bolder'; isSubtle=$true; horizontalAlignment='Center'; spacing='None' }
        ) }
    }

    $body = New-Object System.Collections.Generic.List[object]
    $body.Add(@{ type='TextBlock'; size='Large'; weight='Bolder'; color='Accent'; wrap=$true; text='IIS OP-GL - Daily Security Digest' })
    $body.Add(@{ type='TextBlock'; isSubtle=$true; spacing='None'; wrap=$true; text=("{0}  |  OP-GL web-server (siem.secureocp.com)  |  informational" -f $Digest.date) })
    $body.Add(@{ type='TextBlock'; weight='Bolder'; size='Medium'; color=$postureColor; spacing='Medium'; wrap=$true; text=("Posture: {0}" -f $postureText) })
    $body.Add(@{ type='ColumnSet'; spacing='Medium'; columns=@(
        (_Tile $nCrit 'CRITICAL' 'Attention'),
        (_Tile $nHigh 'HIGH'     'Warning'),
        (_Tile $nMod  'MODERATE' 'Accent'),
        (_Tile $nLow  'LOW'      'Good')
    ) })

    # Each finding as a compact Who/What/When/Where table (FactSet) + Why/MITRE/Action,
    # with a paste-ready Graylog query below. Same shape every tier; Why justifies the tier.
    foreach ($grp in @(
        @{ key='critical'; label='CRITICAL - corroborated across systems'; col='Attention' },
        @{ key='high';     label='HIGH - multiple signals on one source';  col='Warning' },
        @{ key='moderate'; label='MODERATE - new entity / threshold (under review)'; col='Accent' },
        @{ key='low';      label='LOW - probes that did not succeed';      col='Good' }
    )) {
        $tier  = $Digest[$grp.key]
        $items = @($tier.items)
        if ($items.Count -eq 0) { continue }
        $body.Add(@{ type='TextBlock'; weight='Bolder'; size='Medium'; color=$grp.col; spacing='Medium'; separator=$true; wrap=$true; text=$grp.label })
        foreach ($it in $items) {
            $whatVal  = if ($it.finding) { "{0}: {1}" -f $it.what, $it.finding } else { [string]$it.what }
            $whereVal = if ($it.host -and $it.host -ne '-') { [string]$it.host } else { '-' }
            $whenVal  = '-'
            if ($it.when) { try { $whenVal = ([datetime]$it.when).ToUniversalTime().ToString('MM-dd HH:mm') + ' UTC' } catch { $whenVal = [string]$it.when } }
            # who / what / when / where (+ why / MITRE / action) as a compact table; query below.
            $line = New-Object System.Collections.Generic.List[object]
            $line.Add(@{ type='FactSet'; facts=@(
                @{ title='Who';    value=[string]$it.ip },
                @{ title='What';   value=$whatVal },
                @{ title='When';   value=$whenVal },
                @{ title='Where';  value=$whereVal },
                @{ title='Why';    value=[string]$it.why },
                @{ title='MITRE';  value=[string]$it.mitre },
                @{ title='Action'; value=[string]$it.action }
            ) })
            if ($it.query) { $line.Add(@{ type='TextBlock'; wrap=$true; spacing='None'; isSubtle=$true; fontType='Monospace'; text=("Query: {0}" -f [string]$it.query) }) }
            $body.Add(@{ type='Container'; spacing='Small'; style='emphasis'; items=$line.ToArray() })
        }
        if ([int]$tier.total -gt $items.Count) {
            $body.Add(@{ type='TextBlock'; wrap=$true; spacing='Small'; isSubtle=$true; text=("+ {0} more - see Open in Graylog" -f ([int]$tier.total - $items.Count)) })
        }
    }
    if ($Digest.suggestions -and @($Digest.suggestions).Count -gt 0) {
        $body.Add(@{ type='TextBlock'; weight='Bolder'; size='Medium'; color='Accent'; spacing='Medium'; separator=$true; wrap=$true; text='Suggestions to improve detection (auto - learned from recurrence)' })
        foreach ($s in $Digest.suggestions) {
            $body.Add(@{ type='TextBlock'; wrap=$true; spacing='Small'; text=("- {0}" -f [string]$s) })
        }
    }
    $body.Add(@{ type='TextBlock'; isSubtle=$true; spacing='Medium'; separator=$true; wrap=$true; text='Detection runs every 30 min (0 AI tokens); CRITICAL/HIGH (corroborated) are also alerted live. Tiers - CRITICAL: corroborated across >=2 systems; HIGH: multiple signals on one source; MODERATE: new entity / threshold; LOW: recorded probe that did not succeed.' })

    $actions = New-Object System.Collections.Generic.List[object]
    if ($Digest.graylog_link) { $actions.Add(@{ type='Action.OpenUrl'; title='Open in Graylog'; url=[string]$Digest.graylog_link }) }

    $card = [ordered]@{
        '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
        type      = 'AdaptiveCard'
        version   = '1.4'
        body      = $body.ToArray()
        actions   = $actions.ToArray()
    }
    return @{
        type        = 'message'
        attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
    }
}
