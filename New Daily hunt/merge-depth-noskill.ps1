# merge-depth-noskill.ps1
param([string]$DepthFile = '')
# Folds the DEPTH PASS output (reports-noskill\depth-findings.json) into
# daily-latest.md's findings-json block - the same proven path merge-correlation
# uses - so depth findings appear in the PDF, CSV/workbook and Teams.
#
# ADD-ON / MONOTONIC: this only APPENDS depth findings (change = added | escalated |
# known-gap | fp-cleared-with-evidence). Pure 'confirmed' restatements are dropped so
# they do not duplicate the breadth row they confirm. It never edits or removes a breadth
# finding. If depth-findings.json is missing / empty / unparseable, the breadth report is
# left EXACTLY as-is (depth is a no-harm add-on). Plumbing only - no detection signatures.
$ErrorActionPreference = 'Continue'
$proj      = 'D:\Vidhya\New Daily hunt'
$mainFile  = "$proj\reports-noskill\daily-latest.md"
$depthFile = if ($DepthFile) { $DepthFile } else { "$proj\reports-noskill\depth-findings.json" }

if (-not (Test-Path $depthFile)) { Write-Output 'merge-depth: no depth-findings.json - breadth report unchanged.'; exit 0 }
if (-not (Test-Path $mainFile))  { Write-Output 'merge-depth: no daily-latest.md - cannot merge.'; exit 0 }

$clean = { param($s) ($s -replace '[^\x20-\x7E\r\n]', '') }

# --- existing breadth + correlation findings from the daily-latest.md block ---
$mainRaw = & $clean (Get-Content $mainFile -Raw)
$mm = [regex]::Match($mainRaw, '(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
if (-not $mm.Success) { Write-Output 'merge-depth: no findings-json block in daily-latest.md - aborting, breadth unchanged.'; exit 0 }
$mainF = @()
try { $mainF = @($mm.Groups[1].Value | ConvertFrom-Json) }
catch { Write-Output "merge-depth: cannot parse daily-latest.md findings block ($_) - aborting, breadth unchanged."; exit 0 }
# flatten any {value:[...]} breadth wrapper (breadth pipeline can emit [{value:[...35...]}])
$mainFlat = @()
foreach ($it in @($mainF)) {
  if ($null -ne $it -and $it.PSObject.Properties.Name -contains 'value' -and $it.PSObject.Properties.Name -notcontains 'sev') {
    foreach ($s in @($it.value)) { if ($null -ne $s) { $mainFlat += $s } }
  } else { $mainFlat += $it }
}
$mainF = $mainFlat

# --- depth findings (own file; tolerate raw JSON, code fences, or {value:[...]} wrappers) ---
$depthRaw = & $clean (Get-Content $depthFile -Raw)
if ([string]::IsNullOrWhiteSpace($depthRaw)) { Write-Output 'merge-depth: depth-findings.json empty - breadth report unchanged.'; exit 0 }

$candidates = @()
$fb = [regex]::Match($depthRaw, '(?ms)```(?:findings-json|json)?\s*[\r\n]+(.*?)[\r\n]+```')
if ($fb.Success) { $candidates += $fb.Groups[1].Value }
$candidates += $depthRaw
$jb = [regex]::Match($depthRaw, '(?ms)(\[.*\]|\{.*\})')
if ($jb.Success) { $candidates += $jb.Groups[1].Value }

$depthParsed = $null
foreach ($c in $candidates) {
  try { $depthParsed = $c | ConvertFrom-Json -ErrorAction Stop; break } catch { continue }
}
if ($null -eq $depthParsed) { Write-Output 'merge-depth: could not parse depth-findings.json - breadth report unchanged.'; exit 0 }

# flatten any {value:[...]} / {value:[...],Count:N} wrappers (the shape MCP/agent output can take)
$depthFlat = @()
foreach ($it in @($depthParsed)) {
  if ($null -ne $it -and ($it.PSObject.Properties.Name -contains 'value')) { $depthFlat += @($it.value) }
  else { $depthFlat += $it }
}

# keep real, non-duplicate depth results: drop CLEAN and pure 'confirmed' restatements
$depthF = @($depthFlat | Where-Object {
    $_ -ne $null -and
    [string]$_.sev -ne '' -and [string]$_.sev -ne 'CLEAN' -and
    [string]$_.change -ne 'confirmed'
  })
if ($depthF.Count -eq 0) { Write-Output 'merge-depth: no new/escalated depth findings to add - breadth report unchanged.'; exit 0 }

$merged   = @($mainF) + @($depthF)
$newJson  = $merged | ConvertTo-Json -Depth 12 -Compress
$newBlock = '```findings-json' + "`n$newJson`n" + '```'
$newMain  = [regex]::Replace($mainRaw, '(?ms)```findings-json[\r\n]+.*?[\r\n]+```', $newBlock)
[System.IO.File]::WriteAllText($mainFile, $newMain, [System.Text.UTF8Encoding]::new($false))
Write-Output "merge-depth: added $($depthF.Count) depth finding(s) to daily-latest.md ($($merged.Count) total)."
