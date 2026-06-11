<#
  register-tasks.ps1 - one-time enablement of the IIS OP-GL monitor scheduled tasks.

  RUN ONCE IN AN ELEVATED (Run as Administrator) PowerShell. Registering S4U tasks
  requires admin rights; everything else (code, REST data layer, opus tiers) is
  already in place and live-validated.

  Creates three S4U tasks (run unattended, no logged-in session, as the current user
  so 'claude' finds its auth for the opus tiers):
    SOC-IIS-OPGL-Monitor     - every 30 min (Tier 1 detection; 0 tokens/run)
    SOC-IIS-OPGL-DailySweep  - daily 06:30 (Tier 3 opus completeness sweep; advisory)
    SOC-IIS-OPGL-Digest      - daily 17:00 (REVIEW/CONFIRMED activity digest; 0 tokens)
#>

$ErrorActionPreference = 'Stop'

# Elevation guard
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not elevated. Re-run this script in a PowerShell started with "Run as Administrator".'
    return
}

$userId    = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name   # e.g. AzureAD\VidhyaV
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType S4U -RunLevel Limited
$module    = 'D:\Vidhya\soc-monitor\iis-opgl-monitor'

# --- Tier 1: 30-minute detection engine (REST; 0 tokens/run) ---
$a1 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NonInteractive -WindowStyle Hidden -File "{0}\iis-opgl-monitor.ps1"' -f $module)
$t1 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 30)
$s1 = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName 'SOC-IIS-OPGL-Monitor' -Action $a1 -Trigger $t1 -Settings $s1 -Principal $principal -Force `
    -Description 'IIS OP-GL behavioral monitor every 30 min (60-min lookback, deduped). REST data layer = 0 tokens/run; opus only on HIGH.' | Out-Null
Write-Host 'SOC-IIS-OPGL-Monitor: registered (every 30 min, S4U).'

# --- Tier 3: daily opus completeness sweep (advisory) ---
$a2 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NonInteractive -WindowStyle Hidden -File "{0}\iis-opgl-daily-sweep.ps1"' -f $module)
$t2 = New-ScheduledTaskTrigger -Daily -At '6:30AM'
$s2 = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'SOC-IIS-OPGL-DailySweep' -Action $a2 -Trigger $t2 -Settings $s2 -Principal $principal -Force `
    -Description 'Tier 3 daily opus completeness sweep for the IIS OP-GL monitor (advisory report; bounded token cost).' | Out-Null
Write-Host 'SOC-IIS-OPGL-DailySweep: registered (daily 06:30, S4U).'

# --- Daily activity digest (REVIEW/CONFIRMED visibility -> Teams; 0 tokens, file+REST) ---
$a3 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NonInteractive -WindowStyle Hidden -File "{0}\iis-opgl-digest.ps1"' -f $module)
$t3 = New-ScheduledTaskTrigger -Daily -At '5:00PM'
$s3 = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'SOC-IIS-OPGL-Digest' -Action $a3 -Trigger $t3 -Settings $s3 -Principal $principal -Force `
    -Description 'Daily IIS OP-GL activity digest -- REVIEW/CONFIRMED visibility to Teams (0 tokens, pure file+REST).' | Out-Null
Write-Host 'SOC-IIS-OPGL-Digest: registered (daily 17:00, S4U).'

Write-Host ''
Get-ScheduledTask -TaskName 'SOC-IIS-OPGL-*' | Select-Object TaskName, State | Format-Table -AutoSize
Write-Host 'Done. To validate the S4U context safely (no Teams post), run:'
Write-Host '  Start-ScheduledTask -TaskName "SOC-IIS-OPGL-DailySweep"'
Write-Host '  then check D:\Vidhya\soc-monitor\iis-opgl-monitor\logs\daily-sweep-*.md'
