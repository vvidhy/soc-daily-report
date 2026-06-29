# Runs ONE no-skill hunt by key, sourcing its prompt + model from noskill-hunts.json.
# Used by both the first pass (daily-report-noskill.cmd) and the retry pass
# (retry-stale-noskill.ps1) - single source of truth for each prompt.
#
# LOGGING: this script writes ONLY to stdout/stderr (claude's output flows straight
# through). The CALLER owns the log file via a `>> daily.log 2>&1` redirect. Do NOT
# Add-Content to daily.log here - the caller's redirect already holds that handle, and a
# second writer causes "file in use by another process" IOExceptions (the 2026-06-02 bug).
# The azure print-instead-of-write fallback lives as its own step in daily-report-noskill.cmd.
param([Parameter(Mandatory=$true)][string]$Key)
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$claude='C:\Users\VidhyaV\AppData\Roaming\npm\claude.cmd'
Set-Location $proj   # claude inherits this cwd; prompts use relative paths (reports-noskill\...) so it MUST resolve against the project, not the caller's cwd

# Decode the claude CLI's UTF-8 output correctly. Without this, PowerShell 5.1
# decodes native-command stdout as the OEM codepage and mangles unicode (â€" instead of —).
# [Console]::OutputEncoding controls how PS reads bytes from native command stdout.
# $OutputEncoding controls how PS writes to outbound pipes.
# Both must be UTF-8. Restore on exit so callers aren't affected.
$_prevConsoleEnc = [Console]::OutputEncoding
$_prevOutputEnc  = $OutputEncoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding            = [System.Text.Encoding]::UTF8
try {

try {
  $manifest = Get-Content "$proj\noskill-hunts.json" -Raw | ConvertFrom-Json
} catch { Write-Output "run-noskill-hunt: cannot read noskill-hunts.json - $($_.Exception.Message)"; exit 2 }

$h = $manifest | Where-Object { $_.key -eq $Key } | Select-Object -First 1
if(-not $h){ Write-Output "run-noskill-hunt: unknown key '$Key'"; exit 2 }

# Weekly session budget guard — raised to 85 to support re-run after budget exhaustion
$rlResult = & powershell -NoProfile -ExecutionPolicy Bypass -File "$proj\rate-limit-check.ps1" -Key $Key -WeeklyLimit 85 2>&1
Write-Output $rlResult
if ($LASTEXITCODE -eq 1) { exit 3 }  # exit 3 = rate-limited (caller can detect)

$promptPath = Join-Path $proj $h.prompt
if(-not (Test-Path $promptPath)){ Write-Output "run-noskill-hunt: missing prompt file $promptPath"; exit 2 }
$prompt = Get-Content $promptPath -Raw

Write-Output "==== NOSKILL HUNT [$Key] model=$($h.model) $(Get-Date -Format o) ===="
if($Key -eq 'azure'){ Write-Output "===AZURE-OUTPUT-START===" }

# Per-hunt MCP scope + turn ceiling (from noskill-hunts.json). Defaults preserve old
# behavior: a hunt with no "mcp"/"maxTurns" field falls back to the full .mcp.json / 200.
# COUPLING: if a prompt is later changed to query a new Graylog, widen its "mcp" entry to
# match or that GL's tools will be absent (--strict-mcp-config). See TOKEN-REDESIGN-PLAN.md.
$mcpName = if($h.mcp){ $h.mcp } else { '.mcp.json' }
$mcp = Join-Path $proj $mcpName
if(-not (Test-Path $mcp)){ Write-Output "run-noskill-hunt [$Key]: missing mcp config $mcp - falling back to .mcp.json"; $mcp = Join-Path $proj '.mcp.json'; $mcpName = '.mcp.json' }
$turns = if($h.maxTurns){ [string]$h.maxTurns } else { '200' }
Write-Output "run-noskill-hunt [$Key]: mcp=$mcpName maxTurns=$turns"

$baseArgs = @(
  '--model', $h.model,
  '--permission-mode','bypassPermissions',
  '--disallowed-tools','Skill',
  '--mcp-config', $mcp,
  '--strict-mcp-config',
  '--max-turns', $turns
)

# Windows cmd.exe hard-caps command lines at 8191 chars. When a prompt is long
# (e.g. IIS at ~11k chars), passing it via -p overflows and the hunt silently
# fails. Strategy: try -p first; if the combined length would exceed 7800 chars,
# write the prompt to a temp file and pipe it via stdin instead so the hunt
# continues uninterrupted.
$cmdLineEst = ($baseArgs -join ' ').Length + $prompt.Length + 4  # 4 = " -p "
if($cmdLineEst -le 7800){
  # Normal path: pass prompt as -p argument
  Write-Output "run-noskill-hunt [$Key]: using -p arg (cmdline est $cmdLineEst chars)"
  $claudeArgs = @('-p', $prompt) + $baseArgs
  $null | & $claude @claudeArgs
} else {
  # Long-prompt path: write to temp file, pipe via stdin to bypass the limit
  $tmpFile = [IO.Path]::GetTempFileName()
  Write-Output "run-noskill-hunt [$Key]: prompt too long ($cmdLineEst chars est > 7800) - using temp-file stdin path ($tmpFile)"
  try {
    [IO.File]::WriteAllText($tmpFile, $prompt, [Text.Encoding]::UTF8)
    Get-Content $tmpFile -Raw -Encoding UTF8 | & $claude @baseArgs
  } finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
  }
}
} finally {
  # Restore console encoding so callers aren't affected
  [Console]::OutputEncoding = $_prevConsoleEnc
  $OutputEncoding            = $_prevOutputEnc
}
