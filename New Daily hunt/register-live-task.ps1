<#
  register-live-task.ps1 - register the hourly LIVE hunt as an S4U scheduled task.

  RUN ONCE in an ELEVATED (Run as Administrator) PowerShell. S4U = runs unattended,
  no logged-in session required, as the current user (so claude.cmd + the webhook
  config resolve). Mirrors the register-watchdog / register-tasks S4U pattern.

  The task runs live-report-noskill.cmd every hour: lean MITRE+UEBA sweep of the
  last ~65 min across all 4 GLs -> IIS-OPGL Teams channel. ExecutionTimeLimit caps
  a run at 50 min so a hung run is killed before the next hour; MultipleInstances
  IgnoreNew prevents overlap.

  Validate without scheduling:  Start the task once and read the log -
    Start-ScheduledTask -TaskName 'SOC-Live-Hourly'
    Get-Content 'D:\Vidhya\New Daily hunt\logs-noskill\live.log' -Tail 40
#>
[CmdletBinding()]
param(
    [string] $TaskName = 'SOC-Live-Hourly',
    [int]    $EveryMinutes = 60
)
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { Write-Warning 'Not elevated. Re-run in a PowerShell started with "Run as Administrator".'; return }

$cmd = 'D:\Vidhya\New Daily hunt\live-report-noskill.cmd'
if (-not (Test-Path $cmd)) { throw "live-report-noskill.cmd not found at $cmd" }

$userId    = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType S4U -RunLevel Limited
$action    = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c "{0}"' -f $cmd)

# Hourly forever: a single trigger that repeats every $EveryMinutes from now.
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes)

$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 50)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force `
    -Description ("Hourly LIVE SOC hunt (MITRE + UEBA, last ~65 min, all 4 GLs) -> IIS-OPGL Teams channel. Runs live-report-noskill.cmd. Separate from the daily pipeline.") | Out-Null

Write-Host ("{0}: registered (every {1} min, S4U)." -f $TaskName, $EveryMinutes)
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize
Write-Host 'Validate:  Start-ScheduledTask -TaskName ''SOC-Live-Hourly''  ;  Get-Content ''D:\Vidhya\New Daily hunt\logs-noskill\live.log'' -Tail 40'
