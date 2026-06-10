# alert-html.ps1 — HTML alert presentation for the IIS OP-GL monitor.
#
# Teams renders a subset of HTML in channel messages (h1-h3, b/i/u, p, br,
# ul/ol/li, a, table/tr/td/th, blockquote, pre, code). We build a finding into
# that subset and hand it back as a string. The orchestrator attaches it to the
# finding payload as an `html` field; post-to-teams.ps1 ships the whole object
# to Power Automate, whose "Post message in a chat or channel" action drops the
# `html` field straight into the channel as a formatted message (no card).
#
# Dot-source to use:
#   . .\alert-html.ps1
#   $html = Build-FindingHtml -Finding $finding
#
# Note: all literal entities are NUMERIC (&#8212; &#8594; &#128308;) so the
# output is valid XML as well as HTML — keeps it portable across renderers and
# lets a [xml] well-formedness assertion pass in tests.

$script:DeepInvestUrl = 'https://github.com/mukul975/Anthropic-Cybersecurity-Skills'
$script:EmDash  = '&#8212;'   # —
$script:RArrow  = '&#8594;'   # →

# Severity → leading marker. Only HIGH is alerted today, but map the ladder so
# the same builder works if a lower tier is ever rendered for review.
$script:SeverityMarker = @{
    HIGH      = '&#128308; HIGH'       # red circle
    CONFIRMED = '&#128992; CONFIRMED'  # orange circle
    REVIEW    = '&#128993; REVIEW'     # yellow circle
    LOGGED    = '&#9899; LOGGED'       # black circle
}

function Convert-HtmlText {
    # HTML-encode a scalar for safe placement in element/href context. URI_Query
    # and User-Agent values routinely contain < > & " which would otherwise break
    # the markup or enable injection into the Teams message body.
    param([Parameter(ValueFromPipeline = $true)] $Value)
    process {
        if ($null -eq $Value) { return '' }
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }
}

function Format-HtmlList {
    # Render a string[] as <ul>; returns an em dash when empty so the row never
    # collapses to blank.
    param([object[]] $Items)
    if (-not $Items -or $Items.Count -eq 0) { return $script:EmDash }
    $li = foreach ($i in $Items) { '<li>{0}</li>' -f (Convert-HtmlText $i) }
    return ('<ul>{0}</ul>' -f ($li -join ''))
}

function Build-FindingHtml {
    <#
      .SYNOPSIS
        Render one FindingObject as a Teams-compatible HTML block.
      .OUTPUTS
        [string] HTML fragment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject] $Finding
    )

    $sev = if ($Finding.severity) { [string]$Finding.severity } else { 'REVIEW' }
    $marker = if ($script:SeverityMarker.ContainsKey($sev)) { $script:SeverityMarker[$sev] } else { (Convert-HtmlText $sev) }

    $confidencePct = ''
    if ($null -ne $Finding.confidence_score) {
        try { $confidencePct = '{0}%' -f [Math]::Round([double]$Finding.confidence_score * 100) } catch { $confidencePct = '' }
    }

    if ($Finding.kill_chain_stages -and $Finding.kill_chain_stages.Count -gt 0) {
        $encoded = foreach ($s in $Finding.kill_chain_stages) { Convert-HtmlText $s }
        $killChain = $encoded -join (' {0} ' -f $script:RArrow)
    } else {
        $killChain = $script:EmDash
    }

    # Graylog link: encode for href; only emit an anchor if a link is present.
    $graylog = $script:EmDash
    if ($Finding.graylog_link) {
        $graylog = '<a href="{0}">Open in Graylog</a>' -f (Convert-HtmlText $Finding.graylog_link)
    }

    # Each -f expression is wrapped in its own parens so the comma in a
    # multi-arg format binds to -f, not to the enclosing .Append() method call.
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(('<h3>{0} {1} {2}</h3>' -f $marker, $script:EmDash, (Convert-HtmlText $Finding.title)))
    [void]$sb.Append(('<p>{0}</p>' -f (Convert-HtmlText $Finding.summary)))

    [void]$sb.Append('<table border="1" cellpadding="6" cellspacing="0">')
    $rows = [ordered]@{
        'Finding ID'      = (Convert-HtmlText $Finding.finding_id)
        'MITRE Technique' = (Convert-HtmlText $Finding.technique)
        'Detection Class' = ('Class {0}' -f (Convert-HtmlText $Finding.detection_class))
        'Environment'     = (Convert-HtmlText $Finding.environment)
        'Anchor IP'       = (Convert-HtmlText $Finding.anchor_ip)
        'Anchor User'     = (Convert-HtmlText $Finding.anchor_user)
        'Anchor Host'     = (Convert-HtmlText $Finding.anchor_host)
        'Time (UTC)'      = (Convert-HtmlText $Finding.anchor_time)
        'Confidence'      = (Convert-HtmlText $confidencePct)
    }
    foreach ($k in $rows.Keys) {
        [void]$sb.Append(('<tr><td><b>{0}</b></td><td>{1}</td></tr>' -f (Convert-HtmlText $k), $rows[$k]))
    }
    [void]$sb.Append('</table>')

    [void]$sb.Append('<p><b>Corroboration</b></p>')
    [void]$sb.Append((Format-HtmlList -Items $Finding.corroboration_sources))

    [void]$sb.Append(('<p><b>Kill chain:</b> {0}</p>' -f $killChain))
    [void]$sb.Append(('<p><b>Graylog:</b> {0}</p>' -f $graylog))

    if ($Finding.investigate) {
        [void]$sb.Append(('<p><b>Investigate:</b> <code>{0}</code></p>' -f (Convert-HtmlText $Finding.investigate)))
    }

    [void]$sb.Append(('<p><b>Deep investigation:</b> <a href="{0}">Anthropic Cybersecurity Skills</a></p>' -f $script:DeepInvestUrl))

    return $sb.ToString()
}

function Build-AlertHtml {
    <#
      .SYNOPSIS
        Render multiple findings into one HTML body, separated by <hr>. The
        per-finding posting path uses Build-FindingHtml directly; this exists for
        digest-style messages that batch several findings into one channel post.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject[]] $Findings
    )
    $blocks = foreach ($f in $Findings) { Build-FindingHtml -Finding $f }
    return ($blocks -join '<hr>')
}
