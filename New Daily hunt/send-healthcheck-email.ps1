# send-healthcheck-email.ps1
# One-off: emails the daily-hunt health-check report to a single recipient.
# Benign email plumbing only. Relay -> MX fallback (matches send-csv-noskill.ps1).

$ErrorActionPreference = 'Continue'
$smtpHost = '10.102.100.112'
$smtpPort = 25
$fromAddr = 'soc-noskill@casepoint.in'
$toAddr   = 'vidhya.v@casepoint.in'
$dateStr  = (Get-Date).ToString('yyyy-MM-dd HH:mm')

$body = @"
<div style="font-family:Arial,Helvetica,sans-serif;color:#2C2C2A;max-width:720px;">
<table style="width:100%;border-collapse:collapse;"><tr>
<td style="font-size:17px;font-weight:bold;">SOC Daily Hunt &mdash; Health Check</td>
<td style="text-align:right;"><span style="font-size:12px;font-weight:bold;background:#F7C1C1;color:#791F1F;padding:4px 10px;">ACTION REQUIRED</span></td>
</tr></table>
<p style="font-size:12px;color:#5F5E5A;margin:4px 0 16px;">Generated $dateStr &middot; task SOC-DailyReport-NoSkill</p>

<p style="font-size:13px;"><b>Verdict:</b> The pipeline code is healthy, but the hunt has <b>not delivered an automated report since 2026-06-20</b> (4 days). The cause is environmental, not a regression from the recent changes: an interactive-logon dependency plus the Claude subscription session cap. One stale data artifact was found and fixed.</p>

<h3 style="font-size:14px;margin:18px 0 6px;color:#444441;">Findings</h3>
<table style="width:100%;border-collapse:collapse;font-size:12.5px;">
<tr>
<th style="text-align:left;background:#F1EFE8;border:1px solid #D3D1C7;padding:7px 9px;">#</th>
<th style="text-align:left;background:#F1EFE8;border:1px solid #D3D1C7;padding:7px 9px;">Issue</th>
<th style="text-align:left;background:#F1EFE8;border:1px solid #D3D1C7;padding:7px 9px;">Evidence</th>
<th style="text-align:left;background:#F1EFE8;border:1px solid #D3D1C7;padding:7px 9px;">Severity</th>
</tr>
<tr>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;">1</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;"><b>Interruption (structural):</b> task runs as <b>Interactive</b> logon, so the 03:00 daily trigger only fires while VidhyaV is logged on. WakeToRun / StartWhenAvailable cannot run an Interactive task while logged off.</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;">Today's 03:00 run was missed (Next run = 25-06 03:00; Last run = 23-06 14:12, a catch-up the 06:55 deadline guard skipped). No delivered marker since 06-19/06-20.</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;color:#791F1F;"><b>HIGH</b></td>
</tr>
<tr>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;">2</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;"><b>Stale (quota):</b> manual evening re-runs hit the Claude subscription 5-hour session cap. When hit mid-pipeline, each sub-hunt is marked a gap and the run never reaches merge/PDF/email &mdash; so the previous report stays as the latest.</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;">session log: runs 06-21 17:30-18:05 and 06-22 20:10-20:40 all returned &quot;You&#39;ve hit your session limit&quot;. Internal weekly budget is fine (26/50) &mdash; not the blocker.</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;color:#791F1F;"><b>HIGH</b></td>
</tr>
<tr>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;">3</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;"><b>Stale data bug (fixed):</b> coverage-gaps.json held a malformed entry &quot;iis rdp&quot; (two surface keys joined by a space). Not a valid hunt key, so targeted stale-retry could never clear it &mdash; a phantom permanent gap.</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;">Was [&quot;azure&quot;,&quot;iis rdp&quot;]; corrected to [&quot;azure&quot;,&quot;iis&quot;,&quot;rdp&quot;] (backup kept). The next full run rebuilds this file authoritatively.</td>
<td style="border:1px solid #D3D1C7;padding:7px 9px;vertical-align:top;color:#633806;"><b>FIXED</b></td>
</tr>
</table>

<h3 style="font-size:14px;margin:18px 0 6px;color:#444441;">What is fine</h3>
<ul style="font-size:12.5px;margin:0 0 8px;">
<li>Task is <b>enabled</b> (Ready). Guard / resume / stale-retry / deadline logic is sound and non-fatal by design.</li>
<li>Email path is correctly scoped to a single recipient (vidhya.v@casepoint.in).</li>
<li>Non-delivery is environmental (logon + session cap), <b>not</b> a code regression from the recent split-by-model / digest changes.</li>
</ul>

<h3 style="font-size:14px;margin:18px 0 6px;color:#444441;">Recommended fixes (priority order)</h3>
<ol style="font-size:12.5px;margin:0;">
<li><b>Re-register the task as S4U</b> (run whether logged on or not) via register-live-task.ps1 elevated. Removes the Interactive dependency &mdash; the single biggest no-miss fix.</li>
<li>Until then, keep the machine awake and logged on at 03:00 (WakeToRun is set but is a no-op for an Interactive task).</li>
<li>Avoid manual mid-day re-runs that burn the 5-hour session cap; the 03:00 schedule was chosen so the cap resets overnight.</li>
<li>Done: malformed coverage-gaps.json cleared so the next run starts clean.</li>
</ol>

<p style="font-size:11px;color:#888780;margin:16px 0 0;">Casepoint SOC &middot; daily-hunt health check (automated diagnostic)</p>
</div>
"@

$subject = "SOC Daily Hunt - Health Check ($dateStr) - ACTION REQUIRED: no auto-delivery since 06-20"

$mailParams = @{
  From = $fromAddr; To = $toAddr; Subject = $subject
  Body = $body; BodyAsHtml = $true; SmtpServer = $smtpHost; Port = $smtpPort
}

try {
  Send-MailMessage @mailParams -ErrorAction Stop
  Write-Output "SENT via relay $smtpHost`:$smtpPort -> $toAddr"
} catch {
  Write-Output "Relay failed: $($_.Exception.Message) - trying MX fallback"
  try {
    $mailParams['SmtpServer'] = 'casepoint-in.mail.protection.outlook.com'
    Send-MailMessage @mailParams -ErrorAction Stop
    Write-Output "SENT via MX fallback -> $toAddr"
  } catch {
    Write-Output "MX fallback failed: $($_.Exception.Message)"
  }
}
