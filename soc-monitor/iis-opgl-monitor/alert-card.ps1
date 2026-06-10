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
        $body.Add(@{ type='TextBlock'; weight='Bolder'; spacing='Medium'; text='AI investigation (opus)' })
        $body.Add(@{ type='TextBlock'; wrap=$true; text=[string]$Finding.deep_analysis })
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
