# Deployment & Task Import Guide

How to restore SOC scheduled tasks from this repository on a new system.

## Prerequisites

- Windows Server 2016+
- PowerShell 5.1+ (as Administrator)
- `claude` CLI installed and in PATH
- Network access to Graylogs

## Step 1: Prepare Scripts

```powershell
# Copy scripts to system
Copy-Item -Path "D:\Vidhya\soc-monitor" -Destination "C:\Users\<username>\soc-monitor" -Recurse -Force

# Update paths in scripts if needed (search & replace C:\Users\VidhyaV with your user path)
```

## Step 2: Configure Secrets

Create `C:\Users\<username>\soc-monitor\config\secrets.local.ps1`:

```powershell
# Teams Webhook
$env:TEAMS_WEBHOOK = "https://outlook.webhook.office.com/webhookb2/..."

# SharePoint path for reports
$env:SHAREPOINT_PATH = "\\sharepoint.company.com\teams\SOC-Reports"

# Optional: Claude config path
$env:CLAUDE_CONFIG = "$HOME\.claude"
```

## Step 3: Import Task Definitions

Run as Administrator:

```powershell
# Navigate to repo
cd D:\Vidhya

# Import each task from XML
$tasks = @(
    "SOC-DailyReport",
    "SOC-DailyReport-NoSkill", 
    "SOC-DailyReport-Deliver",
    "SOC-Monitor-Sweep"
)

foreach ($task in $tasks) {
    $xml = Get-Content "$task.xml" -Raw
    Register-ScheduledTask -Xml $xml -TaskName $task -Force
    Write-Host "✓ Imported: $task"
}
```

## Step 4: Verify Import

```powershell
# List all imported tasks
Get-ScheduledTask -TaskName "SOC-*" | Select-Object TaskName, State

# Check a specific task
Get-ScheduledTask -TaskName "SOC-DailyReport" | Select-Object -ExpandProperty Actions
```

## Step 5: Adjust Paths (if needed)

If scripts are in a different location, update task actions:

```powershell
$task = Get-ScheduledTask -TaskName "SOC-DailyReport"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File 'C:\Users\<YourUser>\soc-monitor\daily-report-guarded.cmd'"
Set-ScheduledTask -TaskName "SOC-DailyReport" -Action $action
```

## Step 6: Enable Tasks

```powershell
# Enable each task
$tasks | ForEach-Object { 
    Enable-ScheduledTask -TaskName $_
    Write-Host "✓ Enabled: $_"
}

# Verify enabled
Get-ScheduledTask -TaskName "SOC-*" | Select-Object TaskName, State
```

## Step 7: Test Run

```powershell
# Test one task manually
Start-ScheduledTask -TaskName "SOC-Monitor-Sweep"

# Check if it completes
Get-ScheduledTaskInfo -TaskName "SOC-Monitor-Sweep"

# View logs
Get-Content "C:\Users\<username>\soc-monitor\logs\*.log" -Tail 50
```

## Troubleshooting

### Task won't start
- Check PowerShell execution policy: `Get-ExecutionPolicy`
- Verify script paths exist and are accessible
- Check Task Scheduler event log: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'} -Tail 20`

### Scripts fail with permission errors
- Ensure PowerShell runs as Administrator
- Check file permissions on `C:\Users\<username>\soc-monitor`

### Claude CLI not found
- Verify `claude` is in PATH: `Where.exe claude`
- Install: `npm install -g @anthropic-ai/claude-cli` or use provided binary

### Teams webhook fails
- Verify webhook URL in `secrets.local.ps1`
- Test webhook: `Invoke-WebRequest -Uri $env:TEAMS_WEBHOOK -Method Post -Body '{...}'`

---

## Rollback

To remove tasks:

```powershell
$tasks | ForEach-Object {
    Unregister-ScheduledTask -TaskName $_ -Confirm:$false
}
```

---

**Last Updated**: 2026-06-04
