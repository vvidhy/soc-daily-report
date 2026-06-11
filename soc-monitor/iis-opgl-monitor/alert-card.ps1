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

    $high = [int]$Digest.high; $cc = [int]$Digest.confirmed_count; $rc = [int]$Digest.review_count
    $postureColor = if ($high -gt 0) { 'Attention' } elseif ($cc -gt 0) { 'Warning' } else { 'Good' }
    $postureText = if ($high -gt 0) { "ACTION - $high high-severity alert(s) raised today" } elseif ($cc -gt 0) { "$cc confirmed item(s) for analyst review" } else { "NOMINAL - no corroborated threats today" }
    $plain = if ($high -gt 0) { "$high corroborated HIGH alert(s) were raised today and sent to this channel in real time. Below: $cc confirmed item(s) and $rc item(s) under review." } else { "No corroborated breach today (HIGH alerts = 0). The web-attack monitor flagged $cc confirmed item(s) for analyst follow-up and $rc item(s) under review. Items below; everything else is routine external scanning." }

    $body = New-Object System.Collections.Generic.List[object]
    $body.Add(@{ type='TextBlock'; size='Large'; weight='Bolder'; color='Accent'; wrap=$true; text='IIS OP-GL - Daily Activity Digest' })
    $body.Add(@{ type='TextBlock'; isSubtle=$true; spacing='None'; wrap=$true; text=("{0} | informational | public web-server monitoring" -f $Digest.date) })
    $body.Add(@{ type='TextBlock'; weight='Bolder'; size='Medium'; color=$postureColor; spacing='Medium'; wrap=$true; text=("Posture: {0}" -f $postureText) })
    $body.Add(@{ type='FactSet'; facts=@(
        @{ title='HIGH alerts';  value=[string]$high },
        @{ title='Confirmed';    value=[string]$cc },
        @{ title='Under review'; value=[string]$rc }
    ) })
    $body.Add(@{ type='TextBlock'; wrap=$true; spacing='Small'; text=$plain })

    if (@($Digest.confirmed).Count -gt 0) {
        $body.Add(@{ type='TextBlock'; weight='Bolder'; spacing='Medium'; separator=$true; text='Confirmed - worth an analyst look' })
        foreach ($it in $Digest.confirmed) {
            $h = if ($it.host -and $it.host -ne '-') { " ($($it.host))" } else { '' }
            $body.Add(@{ type='TextBlock'; wrap=$true; spacing='None'; text=("- **{0}**: {1}{2}" -f $it.ip, $it.what, $h) })
        }
    }
    if (@($Digest.review_cats).Count -gt 0) {
        $body.Add(@{ type='TextBlock'; weight='Bolder'; spacing='Medium'; separator=$true; text='Under review - by type' })
        foreach ($c in $Digest.review_cats) {
            $eg = if ($c.ip) { "  (e.g. $($c.ip))" } else { '' }
            $body.Add(@{ type='TextBlock'; wrap=$true; spacing='None'; isSubtle=$true; text=("- {0}: **{1}**{2}" -f $c.name, $c.count, $eg) })
        }
    }
    $body.Add(@{ type='TextBlock'; isSubtle=$true; spacing='Medium'; wrap=$true; text='Informational summary. Corroborated HIGH threats are alerted separately, in real time. REVIEW = recorded for awareness; CONFIRMED = multiple signals on one source.' })

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
