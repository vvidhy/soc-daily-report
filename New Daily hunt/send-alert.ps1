$ErrorActionPreference='Continue'
$webhookFile='D:\Vidhya\New Daily hunt\.webhook-alerts'
$tick='D:\Vidhya\New Daily hunt\logs\last-tick.txt'
if(-not (Test-Path $webhookFile)){ Write-Output 'ALERT: webhook file missing'; exit 0 }
if(-not (Test-Path $tick)){ Write-Output 'ALERT: no tick output'; exit 0 }
$url=(Get-Content $webhookFile -Raw).Trim()
$lines = Get-Content $tick | Where-Object { $_ -match '^\s*ALERT:' }
if(-not $lines){ Write-Output 'No ALERT lines this tick'; exit 0 }
function Clean([string]$s){ ($s -replace '[^\x20-\x7E\r\n]','') }
$text = ($lines | ForEach-Object { '- ' + (Clean ($_ -replace '^\s*ALERT:\s*','')) }) -join "`n"
$title = 'SOC Alert - ' + (Get-Date).ToString('yyyy-MM-dd HH:mm') + ' (' + $env:COMPUTERNAME + ')'
$p=@{ type='message'; attachments=@(@{
  contentType='application/vnd.microsoft.card.adaptive'
  content=@{ type='AdaptiveCard'; '$schema'='http://adaptivecards.io/schemas/adaptive-card.json'; version='1.4'
    body=@(@{type='TextBlock';text=$title;weight='Bolder';size='Medium';wrap=$true}
           @{type='TextBlock';text=$text;wrap=$true}) }
}) } | ConvertTo-Json -Depth 12 -Compress
try { Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' -Body $p -ErrorAction Stop | Out-Null; Write-Output "Alert posted ($($lines.Count) line(s))" }
catch { Write-Output "Alert POST FAILED: $($_.Exception.Message)" }
