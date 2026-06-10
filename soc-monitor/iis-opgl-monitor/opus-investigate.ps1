<#
  opus-investigate.ps1 - Tier 2 & Tier 3 AI hooks for the IIS OP-GL monitor.

  DESIGN PRINCIPLES (token-optimization + data-integrity are hard constraints):
   * The hourly/30-min detection engine calls NO model (0 tokens). opus is used
     ONLY here, in two surgical, rare, bounded places:
       Tier 2  Invoke-OpusDeepDive  - per HIGH finding (rare), enriches the alert.
       Tier 3  Invoke-OpusDailySweep - once per day, catches novel attacks that
               signature rules miss (the "novel-from-known-entity" gap).
   * TOKEN CAPS: opus only (no per-row sonnet); inputs are hard-capped row counts;
     deep-dives are capped per run; sweep runs 1x/day over a bounded candidate set.
   * DATA INTEGRITY: every prompt forbids fabrication ("analyze ONLY provided data").
     AI output is ADVISORY: it is attached as context (deep_analysis) and NEVER
     changes a finding's deterministic severity, and sweep output is emitted at
     REVIEW only (it cannot auto-escalate to HIGH; only the existing cross-source
     correlation can). If opus fails/times out, detection is unaffected.

  Evidence is gathered by the FREE Graylog REST layer (graylog-api.ps1), so these
  hooks need no MCP. Dot-source graylog-api.ps1 before using these functions.
#>

# Resolve the Claude binary once. Prefer bin\claude.exe (no cmd.exe length limit);
# fall back to whatever 'claude' resolves to on PATH.
$script:ClaudeCmd = $null
$null = foreach ($c in @(
        "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
        "$env:USERPROFILE\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe"
    )) { if ((-not $script:ClaudeCmd) -and (Test-Path $c)) { $script:ClaudeCmd = $c } }
if (-not $script:ClaudeCmd) {
    $g = Get-Command claude -ErrorAction SilentlyContinue
    if ($g) { $script:ClaudeCmd = $g.Source }
}

function _Invoke-Opus {
    <#
      Run one bounded opus turn headlessly. Prompt via redirected stdin (no
      cmd-length limit), hard wall-clock timeout so a hung call never stalls the
      run. Returns the text, or $null on any failure/timeout (caller treats AI as
      optional enrichment).
    #>
    param([string] $Prompt, [int] $TimeoutSec = 150)
    if (-not $script:ClaudeCmd) { return $null }
    $inF  = [System.IO.Path]::GetTempFileName()
    $outF = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($inF, $Prompt, [System.Text.UTF8Encoding]::new($false))
        $p = Start-Process -FilePath $script:ClaudeCmd -ArgumentList '-p','--model','opus' `
                -RedirectStandardInput $inF -RedirectStandardOutput $outF `
                -NoNewWindow -PassThru
        if ($p.WaitForExit($TimeoutSec * 1000)) {
            $txt = [System.IO.File]::ReadAllText($outF)
            return $txt.Trim()
        } else {
            try { $p.Kill() } catch {}
            return $null
        }
    } catch {
        return $null
    } finally {
        Remove-Item $inF, $outF -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-OpusDeepDive {
    <#
      TIER 2 - deep investigation of ONE confirmed HIGH finding. Returns an
      analysis string to attach to the alert (or $null). Does NOT change severity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject] $Finding,
        [Parameter(Mandatory)][psobject] $Config
    )
    $ip  = $Finding.anchor_ip
    $sid = $Config.iis_streams.prod

    # Bounded evidence: up to 15 of the anchor IP's recent IIS requests.
    $rows = @()
    if ($ip -and $ip -ne '-' -and (Get-Command mcp__OP-GL__search_logs_relative -ErrorAction SilentlyContinue)) {
        try {
            $r = mcp__OP-GL__search_logs_relative -streamId $sid `
                    -query "Client_ip:$ip AND filebeat_log_file_path:*inetpub*" `
                    -rangeSeconds 3600 -fields 'Method,Status,URI_Stream,URI_Query,Host,UserAgent,Time_Taken' -limit 15
            $rows = @($r.messages)
        } catch {}
    }
    $evidence = ($rows | Select-Object Method,Status,URI_Stream,URI_Query,Host,UserAgent,Time_Taken | ConvertTo-Json -Compress)
    if (-not $evidence) { $evidence = '(no additional rows retrieved)' }

    $prompt = @"
You are a senior SOC analyst investigating a CONFIRMED high-severity IIS finding.
Base your analysis ONLY on the data below. Do NOT invent any IP, path, user, or
event that is not present. If evidence is insufficient, say so plainly.
Use PLAIN TEXT only - no markdown, asterisks, headers, or backticks (it renders in
an HTML card). Be concise (<200 words). Cover: (1) what happened, (2) likely intent
& MITRE stage, (3) blast radius / what to check next, (4) recommended containment.

FINDING:
  technique: $($Finding.technique)
  anchor_ip: $($Finding.anchor_ip)   anchor_user: $($Finding.anchor_user)   host: $($Finding.anchor_host)
  summary: $($Finding.summary)
  corroboration: $((@($Finding.corroboration_sources)) -join '; ')

ANCHOR IP's RECENT IIS REQUESTS (up to 15):
$evidence
"@
    return (_Invoke-Opus -Prompt $prompt -TimeoutSec 150)
}

function Invoke-OpusDailySweep {
    <#
      TIER 3 - once-daily completeness sweep. Gathers a bounded set of the most
      unusual IIS requests (server errors, rare methods, recent probe hits) via the
      free REST layer and asks opus to surface novel attacks signature rules would
      miss. Returns an analysis string (advisory). Does NOT post HIGH alerts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject] $Config,
        [int] $WindowHours = 24
    )
    $sid = $Config.iis_streams.prod
    $rangeSeconds = $WindowHours * 3600
    if (-not (Get-Command mcp__OP-GL__search_logs_relative -ErrorAction SilentlyContinue)) { return $null }

    $flds = 'Client_ip,Method,Status,URI_Stream,URI_Query,Host,UserAgent'
    $cand = @()
    foreach ($slice in @(
            'Status:500 AND filebeat_log_file_path:*inetpub*',
            '(Method:PUT OR Method:DELETE OR Method:PATCH OR Method:TRACE OR Method:CONNECT) AND filebeat_log_file_path:*inetpub*',
            'Status:403 AND filebeat_log_file_path:*inetpub*'
        )) {
        try {
            $r = mcp__OP-GL__search_logs_relative -streamId $sid -query $slice -rangeSeconds $rangeSeconds -fields $flds -limit 12
            $cand += @($r.messages)
        } catch {}
    }
    # Hard cap the candidate set (token bound).
    $cand = @($cand | Select-Object -First 40 Client_ip,Method,Status,URI_Stream,URI_Query,Host,UserAgent)
    if ($cand.Count -eq 0) { return "Daily sweep: no candidate anomalies (500/403/rare-method) in the last $WindowHours h." }

    $json = $cand | ConvertTo-Json -Compress
    $prompt = @"
You are a senior SOC analyst running a daily completeness sweep over the most
UNUSUAL IIS requests from the last $WindowHours hours. Signature rules already
cover obvious SQLi/XSS/path-traversal/webshell/CVE-probe/auth-storm. Your job is
to find anything SUBTLE those rules miss: business-logic abuse, novel exploitation,
slow recon, suspicious sequences. Base your analysis ONLY on the rows below - do
NOT invent anything. List at most 5 items, each: IP, why suspicious, confidence
(low/med/high), recommended action. If nothing is genuinely suspicious, say
"No novel patterns - routine error/method noise." Be concise. Plain text only -
no markdown, asterisks, or backticks.

CANDIDATE ROWS ($($cand.Count)):
$json
"@
    return (_Invoke-Opus -Prompt $prompt -TimeoutSec 180)
}
