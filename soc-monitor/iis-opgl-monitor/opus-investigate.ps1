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

# ── Cybersecurity-skill mapping (mukul975/Anthropic-Cybersecurity-Skills) ──
# On a HIGH finding the deep-dive APPLIES the matching repo skill's methodology
# (the skills themselves query Graylog via MCP, which an unattended run can't reach,
# so we feed the skill REST-gathered evidence and have opus apply its method).
$script:SkillsRepo = 'C:\Users\VidhyaV\.claude\agents\Anthropic-Cybersecurity-Skills\skills'
$script:ClassSkill = @{
    1='detecting-sql-injection-via-waf-logs';            2='analyzing-web-server-logs-for-intrusion'
    3='analyzing-web-server-logs-for-intrusion';         4='analyzing-web-server-logs-for-intrusion'
    5='exploiting-server-side-request-forgery';          6='analyzing-web-server-logs-for-intrusion'
    7='hunting-for-webshell-activity';                   8='hunting-credential-stuffing-attacks'
    9='analyzing-web-server-logs-for-intrusion';        10='analyzing-web-server-logs-for-intrusion'
    11='analyzing-web-server-logs-for-intrusion';       12='analyzing-web-server-logs-for-intrusion'
    13='hunting-for-data-exfiltration-indicators';      14='hunting-for-command-and-control-beaconing'
    15='hunting-for-unusual-network-connections';       16='analyzing-web-server-logs-for-intrusion'
    17='analyzing-web-server-logs-for-intrusion'
}

function _Resolve-DeepSkill {
    param([int] $ClassId)
    $name = if ($script:ClassSkill.ContainsKey($ClassId)) { $script:ClassSkill[$ClassId] } else { 'analyzing-web-server-logs-for-intrusion' }
    $path = Join-Path $script:SkillsRepo "$name\SKILL.md"
    if (-not (Test-Path $path)) { $name = 'analyzing-web-server-logs-for-intrusion'; $path = Join-Path $script:SkillsRepo "$name\SKILL.md" }
    return @{ name = $name; path = $path }
}

function _Skill-KeySections {
    # Token control: feed opus only the skill's PURPOSE + the top of the body
    # (these skills front-load methodology/principles; detailed examples sit lower),
    # not the whole SKILL.md. ~half the tokens of the full file.
    param([string] $Path, [int] $MaxChars = 4000)
    if (-not (Test-Path $Path)) { return '' }
    $raw  = Get-Content $Path -Raw -Encoding utf8
    $desc = ''
    $body = $raw
    if ($raw -match '(?s)^---\s*(.*?)\s*---\s*(.*)$') {
        $fm = $matches[1]; $body = $matches[2]
        $m = [regex]::Match($fm, '(?m)^description:\s*(.+)$')
        if ($m.Success) { $desc = ($m.Groups[1].Value.Trim() -replace '^["'']|["'']$','') }
    }
    if ($body.Length -gt $MaxChars) { $body = $body.Substring(0, $MaxChars) }
    if ($desc) { return ("Purpose: {0}`r`n`r`n{1}" -f $desc, $body) }
    return $body
}

function _OPGL-CrossStream {
    # Correlation hunt: pull the anchor's activity across all OP-GL streams (REST).
    param([psobject] $Config, [string] $Ip, [string] $User)
    $cs = $Config.correlation_streams
    $flds = 'source_ip,src_ip,dst_ip,client_ip,account_name,action,policy_name,username,auth_result,filename,alert_name,threat_name,EventID,event_description,from_address,to_address,subject,timestamp'
    $out = [ordered]@{}
    $pivots = @(
        @{ k='Winlog_beat';   sid=$cs.winlog_beat;   q=$(if($Ip -and $Ip -ne '-'){"source_ip:$Ip"}) },
        @{ k='FortiGate';     sid=$cs.fortigate;     q=$(if($Ip -and $Ip -ne '-'){"src_ip:$Ip OR dst_ip:$Ip"}) },
        @{ k='Securenvoy';    sid=$cs.securenvoy;    q=$(if($User -and $User -ne '-'){"username:$User"}) },
        @{ k='External_SFTP'; sid=$cs.external_sftp; q=$(if($Ip -and $Ip -ne '-'){"client_ip:$Ip"}) },
        @{ k='ESET';          sid=$cs.eset_syslog;   q=$(if($Ip -and $Ip -ne '-'){"source_ip:$Ip"}) },
        @{ k='Hmailer';       sid=$cs.hmailer;       q=$(if($Ip -and $Ip -ne '-'){"src_ip:$Ip"}) }
    )
    foreach ($p in $pivots) {
        if (-not $p.q -or -not $p.sid) { continue }
        $rows = @()
        try { $rows = @((mcp__OP-GL__search_logs_relative -streamId $p.sid -query $p.q -rangeSeconds 3600 -fields $flds -limit 6).messages) } catch {}
        if ($rows.Count -gt 0) { $out[$p.k] = $rows }
    }
    return $out
}

function Invoke-OpusDeepDive {
    <#
      TIER 2 - deep, SKILL-DRIVEN investigation of ONE confirmed HIGH finding:
        1. cross-stream correlation hunt (REST) across all OP-GL log sources,
        2. load the matching Anthropic-Cybersecurity-Skills methodology,
        3. opus applies that method to the evidence.
      Returns the analysis (prefixed with the skill used) or $null. Never changes
      severity; failure/timeout is a no-op (alert still fires on deterministic data).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject] $Finding,
        [Parameter(Mandatory)][psobject] $Config
    )
    if (-not (Get-Command mcp__OP-GL__search_logs_relative -ErrorAction SilentlyContinue)) { return $null }
    $ip  = $Finding.anchor_ip
    $sid = $Config.iis_streams.prod

    # Anchor's IIS activity
    $iisRows = @()
    if ($ip -and $ip -ne '-') {
        try { $iisRows = @((mcp__OP-GL__search_logs_relative -streamId $sid -query "Client_ip:$ip AND filebeat_log_file_path:*inetpub*" -rangeSeconds 3600 -fields 'Method,Status,URI_Stream,URI_Query,Host,UserAgent,Time_Taken' -limit 15).messages) } catch {}
    }
    $iisJson = if ($iisRows.Count) { ($iisRows | ConvertTo-Json -Compress -Depth 4) } else { '(none)' }

    # Cross-stream correlation hunt
    $cross = _OPGL-CrossStream -Config $Config -Ip $ip -User $Finding.anchor_user
    $crossJson = if (@($cross.Keys).Count) { ($cross | ConvertTo-Json -Compress -Depth 5) } else { '(no hits for this anchor in Windows/FortiGate/MFA/SFTP/AV/email)' }

    # Matched cybersecurity skill (methodology, token-bounded)
    $skill = _Resolve-DeepSkill -ClassId ([int]$Finding.detection_class)
    $skillText = _Skill-KeySections -Path $skill.path -MaxChars 4000   # key sections only (~half the tokens)

    $prompt = @"
You are a SOC analyst writing a deep investigation of a CONFIRMED high-severity IIS finding
for a Microsoft Teams card that analysts of ALL levels will read and act on. APPLY THE
METHODOLOGY of the cybersecurity skill below. Use ONLY the provided data - never invent an
IP, path, user, count, or event; if something is not in the data write "unknown from current data".

WRITE FOR CLARITY so anyone can understand and act:
- Plain language, short lines, no jargon walls.
- Use light markdown that Teams renders: **bold** labels, "- " bullets, "1." numbered steps.
- Do NOT use backticks, code fences, or "#" headings.
- Keep the whole write-up under ~230 words.
- In any query you write, use the REAL OP-GL IIS field names so it pastes and runs:
  Client_ip, URI_Stream, URI_Query, Method, Status, Host, UserAgent, Server_Bytes, Time_Taken
  (do NOT use IIS W3C names like cs-uri-stem, c-ip, sc-status).

Use THIS EXACT structure and these bold labels:

**Verdict:** one plain sentence - what this is and how serious, so anyone gets it instantly.

**What happened**
1-2 short sentences, plain English.

**Correlation (other security systems)**
- Windows: hit or none + what it means in a few words
- FortiGate: hit or none + meaning
- MFA / SFTP / Antivirus / Email: combine; list only what matters

**Kill chain:** Stage (Txxxx) -> Stage (Txxxx)   (label any unconfirmed stage "potential")

**Risk & scope**
1-2 short lines: how far it got; what is confirmed vs unknown.

**Do now**
1. concrete containment / response action
2. concrete action

**Investigate further**
- plain step - query: a Graylog query an analyst can paste as-is
- plain step - query: ...

== APPLIED SKILL METHODOLOGY: $($skill.name) ==
$skillText

== FINDING ==
technique: $($Finding.technique)
anchor_ip: $($Finding.anchor_ip)   anchor_user: $($Finding.anchor_user)   host: $($Finding.anchor_host)
summary: $($Finding.summary)
correlation seen at detection: $((@($Finding.corroboration_sources)) -join '; ')

== CROSS-STREAM CORRELATION EVIDENCE (OP-GL, anchor $ip, last 1h) ==
$crossJson

== ANCHOR IIS REQUESTS (last 1h, up to 15) ==
$iisJson
"@
    $result = _Invoke-Opus -Prompt $prompt -TimeoutSec 200
    if ($result) { return ("[skill applied: {0}]`r`n{1}" -f $skill.name, $result) }
    return $null
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
    if ($cand.Count -eq 0) { return "**Sweep verdict:** No candidate anomalies (500/403/rare-method) in the last $WindowHours h - clean." }

    $json = $cand | ConvertTo-Json -Compress
    $prompt = @"
You are a senior SOC analyst running a daily completeness sweep over the most UNUSUAL
IIS requests from the last $WindowHours hours. Signature rules already cover obvious
SQLi/XSS/path-traversal/webshell/CVE-probe/auth-storm. Find anything SUBTLE those rules
miss: business-logic abuse, novel exploitation, slow recon, suspicious sequences. Base
your analysis ONLY on the rows below - invent nothing.

WRITE FOR CLARITY for a Teams card that analysts of all levels read:
- Light markdown: **bold** labels and "- " bullets. No backticks, code fences, or "#" headings.
- First line EXACTLY: **Sweep verdict:** then either "No novel patterns - routine error/method noise" or "<N> item(s) to review".
- Then at most 5 items, one bullet each, in this shape:
  - **<IP>** - why suspicious (one phrase) - confidence: low/med/high - action - query: <paste-ready Graylog query>
- In any query use REAL OP-GL fields: Client_ip, URI_Stream, URI_Query, Method, Status, Host, UserAgent.
- Keep the whole thing under ~200 words.

CANDIDATE ROWS ($($cand.Count)):
$json
"@
    return (_Invoke-Opus -Prompt $prompt -TimeoutSec 180)
}
