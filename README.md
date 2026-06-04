# SOC Daily Report System

Automated security operations center (SOC) daily threat hunting and reporting system using Graylog and Claude AI.

## Overview

This repository contains:
- **Scheduled Tasks**: 4 Windows scheduled tasks for automated SOC reporting (task definitions as XML)
- **PowerShell Scripts**: 35+ scripts that execute daily threat hunts across multiple Graylogs
- **Hunt Pipelines**: Multi-stage hunting workflows covering IIS, RDP, Azure, Linux, SFTP, and correlation analysis
- **Reporting**: Automated PDF generation and delivery to Teams/SharePoint

## Scheduled Tasks

| Task | Schedule | Status | Purpose |
|------|----------|--------|---------|
| `SOC-DailyReport-NoSkill` | 02:30 AM | Disabled | No-skill MCP pipeline (parallel hunts) |
| `SOC-DailyReport` | 08:00 AM | Disabled | Full skill-based hunting pipeline |
| `SOC-DailyReport-Deliver` | 09:30 AM | Disabled | Deliver reports to Teams & SharePoint |
| `SOC-Monitor-Sweep` | Every 4 hours | Disabled | Real-time threat monitoring |

### Task Definitions
- `SOC-DailyReport.xml` - Main daily report (08:00)
- `SOC-DailyReport-NoSkill.xml` - No-skill pipeline (02:30)
- `SOC-DailyReport-Deliver.xml` - Report delivery (09:30)
- `SOC-Monitor-Sweep.xml` - Continuous monitoring

## Scripts & Modules

### Core Hunting Pipelines
- `run-hunt-file.ps1` - Main hunt executor
- `run-noskill-hunt.ps1` - No-skill variant
- `check-iis-fresh.ps1` - IIS log freshness check
- `check-noskill.ps1` - Validation checks

### Hunt Types
- **IIS**: `hunt4h/` directory contains IIS-specific logic
- **Correlation**: `prep-correlation.ps1`, `gen-correlation-queries.ps1`
- **Delivery**: `send-report.ps1`, `send-report-noskill.ps1`
- **Safety**: `deliver-safety-net.ps1`, `send-alert.ps1`

### Configuration
- `config/secrets.local.ps1` - **NOT COMMITTED** - contains API keys & webhooks

## Directory Structure

```
D:\Vidhya/
├── soc-monitor/              # Main SOC system
│   ├── *.cmd                 # Batch entry points
│   ├── *.ps1                 # PowerShell scripts
│   ├── hunt4h/               # Hunt4h pipeline
│   ├── config/               # Configuration
│   ├── logs/                 # Execution logs
│   ├── state/                # State tracking (NOT COMMITTED)
│   └── findings/             # Sample findings
├── report-preview/           # PDF generation scripts
├── [Task XMLs]               # Task definitions
└── [This README]
```

## Setup & Deployment

### Prerequisites
- Windows Server with Task Scheduler
- PowerShell 5.1+
- Claude AI SDK (`claude.exe`)
- Network access to 4 Graylogs (AZ-GL, PROD-GL, DEV-GL, OP-GL)
- Teams webhook for notifications

### Installation

1. **Clone or download** this repository
2. **Copy to system**: `D:\Users\VidhyaV\soc-monitor\`
3. **Configure secrets**: Create `config/secrets.local.ps1` with:
   ```powershell
   $env:TEAMS_WEBHOOK = "https://outlook.webhook.office.com/..."
   $env:SHAREPOINT_PATH = "\\sharepoint\SOC-Reports"
   ```
4. **Import tasks**: For each XML file:
   ```powershell
   Register-ScheduledTask -Xml (Get-Content "SOC-DailyReport.xml" | Out-String) -TaskName "SOC-DailyReport"
   ```

### Enable Tasks
```powershell
Enable-ScheduledTask -TaskName "SOC-DailyReport-NoSkill"
Enable-ScheduledTask -TaskName "SOC-DailyReport"
Enable-ScheduledTask -TaskName "SOC-DailyReport-Deliver"
```

## Known Issues & Notes

- **IIS Parser Blind Spot**: 3 of 4 Graylogs mis-parse IIS fields; using raw-message fallback
- **Tasks Currently Disabled**: As of 2026-06-03, all tasks are paused
- **Command-line Length**: Fixed via direct `bin\claude.exe` calls (bypasses cmd.exe 8191-char limit)

## Status & Monitoring

Check task history:
```powershell
Get-ScheduledTaskInfo -TaskName "SOC-DailyReport"
Get-EventLog -LogName System -Source "TaskScheduler" -Newest 20
```

View logs:
```powershell
Get-Content "D:\Vidhya\soc-monitor\logs\*.log" -Tail 50
```

## Contributing

Document changes in task definitions or script updates. Update task XMLs before pushing changes.

## Related Documents

- [Daily Hunt Design](soc-monitor/README.md)
- [IIS Extractor Fix](iis-extractor-fix.md)

---

**Last Updated**: 2026-06-04  
**Maintainer**: Vidhya (vidhyavenkatraghavan@gmail.com)
