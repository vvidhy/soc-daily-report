# rate-limit-check.ps1 — weekly session budget guard
# Usage: rate-limit-check.ps1 -Key <hunt-key> [-WeeklyLimit <N>]
# Exit 0 = OK to run (budget available)
# Exit 1 = budget exceeded (caller should skip this hunt)
#
# Tracks sessions in logs-noskill\session-budget.json:
#   { "week": "2026-W25", "count": 12, "limit": 30, "log": [...] }
# Resets automatically on new ISO week.

param(
    [Parameter(Mandatory=$true)][string]$Key,
    [int]$WeeklyLimit = 30
)

$proj   = 'D:\Vidhya\New Daily hunt'
$budgetFile = Join-Path $proj 'logs-noskill\session-budget.json'

# ISO week string e.g. "2026-W25"
$now   = Get-Date
$week  = "$(Get-Date -Format yyyy)-W$((Get-Date -UFormat '%V'))"

# Load or init budget
$budget = $null
if (Test-Path $budgetFile) {
    try { $budget = Get-Content $budgetFile -Raw | ConvertFrom-Json } catch {}
}
if (-not $budget -or $budget.week -ne $week) {
    # New week — reset
    $budget = [PSCustomObject]@{ week = $week; count = 0; limit = $WeeklyLimit; log = @() }
}

# Always honour the passed-in limit (allows override)
$budget.limit = $WeeklyLimit

if ($budget.count -ge $budget.limit) {
    Write-Output "RATE-LIMIT: weekly session budget exhausted ($($budget.count)/$($budget.limit)) for week $week - skipping [$Key]"
    exit 1
}

# Increment and save
$budget.count++
$budget.log += "$($now.ToString('o')) [$Key]"
$budget | ConvertTo-Json -Depth 5 | Set-Content $budgetFile -Encoding UTF8

$remaining = $budget.limit - $budget.count
Write-Output "RATE-LIMIT: session $($budget.count)/$($budget.limit) used (week $week, $remaining remaining) - running [$Key]"
exit 0
