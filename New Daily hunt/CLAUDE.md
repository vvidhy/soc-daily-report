# SOC Daily Hunt — Architecture Reference

This file is the single source of truth for the SOC daily hunt pipeline.
**Read this before creating any new file, script, or scheduled task.**

---

## Scheduled Tasks (canonical set — 3 only)

| Task Name | State | Schedule | Entry Point | Purpose |
|-----------|-------|----------|-------------|---------|
| **SOC-DailyReport-NoSkill** | Disabled | 04:00 daily, retry every 1h for 8h | `daily-report-noskill-guarded.cmd` | Full daily hunt — all surfaces, depth, correlation, PDF + email delivery |
| **SOC-Live-Hourly** | Disabled | Every 1h (00:00 start) | `live-report-noskill.cmd` | Near-real-time MITRE+UEBA sweep of last 65 min → IIS-OPGL Teams channel |
| **SOC-NoSkill-FreshNow** | Disabled | Manual trigger | `run-fresh-now.cmd` | On-demand full daily pipeline run |

**Do not create new scheduled tasks.** If a new hunt stage is needed, add it as a step inside `daily-report-noskill.cmd`.

---

## Daily Hunt Pipeline (`daily-report-noskill.cmd`)

All stages are wired inside this single `.cmd` — in this order:

```
1. FRESH START     11 focused sub-hunts via run-sub-hunt.ps1 (see Sub-Hunt table below)
                   Each sub-hunt: Sonnet, MCP-scoped config, 20-50 turns
                   Token exhaustion on one surface → marks gap, continues next surface
2. MERGE           merge-all-noskill.ps1  → assembles daily-latest.md from all *-latest.md files
                                            rebuilds coverage-gaps.json authoritatively
3. STALE RETRY     retry-targeted-noskill.ps1  up to 2 passes, retries only the specific
                                               surface key that failed (not all surfaces)
4. AZURE FLOOR     azure-floor.ps1             0 tokens, deterministic failed-auth
5. CORRELATION     run-noskill-hunt.ps1 -Key correlation   Opus, 20 turns, HIGH/CRITICAL only
   CORR QUERIES    build-correlation-queries.ps1           0 tokens, MEDIUM/LOW → Graylog pivots
6. DEPTH PASS      run-noskill-hunt.ps1 -Key depth          Sonnet, 60 turns
7. DEPTH CATCHUP   run-noskill-hunt.ps1 -Key depth-catchup  Sonnet, 40 turns
8. DELIVER         generate-pdf-noskill.ps1
                   send-report-noskill.ps1
                   send-csv-noskill.ps1   (email with CSV + PDF)
```

All stages are **non-fatal** — token exhaustion on any stage skips it and delivers what was collected.

### Sub-Hunt Schedule (Step 1 breakdown)

| # | Key | Surfaces | MCP Config | Turns | GLs |
|---|-----|----------|------------|-------|-----|
| 1 | `iis` | iis + user-behavior (geo-ACL/exfil/admin) | mcp-3gl | 30 | OP+PROD+AZ |
| 2 | `rdp` | rdp | mcp-3gl | 20 | AZ+PROD+OP |
| 3 | `azure` | azure | mcp-azprod | 18 | AZ+PROD |
| 4 | `linux` | linux | mcp-3gl | 18 | AZ+PROD+OP |
| 5 | `sftp` | sftp,dtc | mcp-3gl | 18 | AZ(dtc)+PROD+OP |
| 6 | `network` | network(fortigate,switch,kemp) | mcp-3gl | 20 | AZ+PROD+OP |
| 7 | `db` | db | .mcp.json | 15 | all 4 GLs |
| 8 | `infra` | eset,securenvoy,virt,hw | .mcp.json | 16 | all 4 GLs |
| 9 | `dev` | linux,rdp,iis,sftp,dtc,azure,firewall | mcp-dev | 12 | DEV (incl Azure Event Hub casepoint.in) |

`app` and `app-pt` retired 2026-06-22: all their streams are IIS logs (inetpub). User-behavior checks folded into `iis` STEP 3.

---

## Hunt Keys (`noskill-hunts.json`)

Each key maps to: prompt file + model + MCP config + turn ceiling.
**To add a new surface: add one entry here + one prompt in `noskill-prompts/`. No new task needed.**

| Key | Model | Prompt | MCP | MaxTurns |
|-----|-------|--------|-----|----------|
| `daily` | Sonnet | `noskill-prompts/daily-single.txt` | `.mcp.json` (all 4 GLs) | 200 |
| `daily-stale` | Sonnet | `noskill-prompts/daily-stale.txt` | `.mcp.json` | 50 |
| `iis` | Sonnet | `noskill-prompts/iis.txt` | `mcp-3gl.json` | 30 |
| `rdp` | Sonnet | `noskill-prompts/rdp.txt` | `mcp-3gl.json` | 20 |
| `azure` | Sonnet | `noskill-prompts/azure.txt` | `mcp-azprod.json` | 18 |
| `linux` | Sonnet | `noskill-prompts/linux.txt` | `mcp-3gl.json` | 18 |
| `sftp` | Sonnet | `noskill-prompts/sftp.txt` | `mcp-3gl.json` | 18 |
| `network` | Sonnet | `noskill-prompts/network.txt` | `mcp-3gl.json` | 20 |
| `db` | Sonnet | `noskill-prompts/db.txt` | `.mcp.json` | 15 |
| `infra` | Sonnet | `noskill-prompts/infra.txt` | `.mcp.json` | 16 |
| ~~`app`~~ | retired | all streams were IIS logs — folded into `iis` STEP 3 | — | — |
| ~~`app-pt`~~ | retired | OpexusPT + all streams confirmed IIS — folded into `iis` | — | — |
| `dev` | Sonnet | `noskill-prompts/dev.txt` | `mcp-dev.json` | 12 |
| `correlation` | **Opus** | `noskill-prompts/correlation.txt` | `mcp-3gl.json` | 8 |
| `depth` | Sonnet | `noskill-prompts/depth-pass.txt` | `.mcp.json` | 15 |
| ~~`depth-catchup`~~ | retired | eliminated 2026-06-22 — token budget reduction to 43% | — | — |
| `live` | Sonnet | `noskill-prompts/live.txt` | `.mcp.json` | 35 |

---

## Key Scripts

| Script | Purpose |
|--------|---------|
| `run-noskill-hunt.ps1` | Single executor — reads `noskill-hunts.json`, calls claude with right model/MCP/turns |
| `run-sub-hunt.ps1` | Non-fatal wrapper around run-noskill-hunt.ps1 — adds surface to coverage-gaps on token exhaustion, always exits 0 |
| `merge-all-noskill.ps1` | Combines all surface *-latest.md into daily-latest.md; rebuilds coverage-gaps.json |
| `retry-targeted-noskill.ps1` | Targeted stale retry — runs specific surface hunt key for each gap (not the generic daily-stale) |
| `retry-stale-noskill.ps1` | Legacy generic retry (kept for reference; no longer called by pipeline) |
| `build-correlation-queries.ps1` | 0-token: extracts IPs/users from HIGH/CRITICAL findings → paste-ready Graylog queries appended to `daily-latest.md` |
| `merge-correlation-noskill.ps1` | (legacy) Folds old AI correlation findings into `daily-latest.md` — not called by pipeline |
| `merge-depth-noskill.ps1` | Folds depth findings into `daily-latest.md` (non-fatal) |
| `merge-iis-deep-noskill.ps1` | Replaces daily IIS section with deep IIS output |
| `azure-floor.ps1` | Deterministic failed-auth floor (0 tokens) |
| `generate-pdf-noskill.ps1` | Renders `daily-latest.md` → PDF via Edge headless |
| `send-report-noskill.ps1` | Posts Teams Adaptive Cards per finding |
| `send-csv-noskill.ps1` | Emails CSV + PDF to SOC inbox |
| `alert-hunt-status-noskill.ps1` | Teams alert on pipeline errors (token-exhausted, PDF-missing) |
| `extract-queries-noskill.ps1` | After delivery: extracts every Graylog query from alert-*.json + daily-latest.md → `reports-noskill/query-cache.json` |
| `check-iis-fresh.ps1` | IIS freshness check — validates `iis-latest.md` was written THIS run (newer than run-start.flag) and contains a findings-json block. Exit 0 = stale/retry needed, Exit 1 = fresh. Called after the deep IIS hunt step. |
| `generate-pdf-noskill.ps1` | Report generation — reads `daily-latest.md`, builds styled HTML from findings-json, renders to `daily-SOC-noskill-YYYY-MM-DD.pdf` using **Edge headless** (`msedge.exe --headless --print-to-pdf`). Embeds Casepoint logo from `assets/casepoint-logo.png`. |
| `generate-live-pdf.ps1` | Same as above but for the hourly live hunt — reads `reports-live/live-latest.md` → `reports-live/live-SOC-YYYY-MM-DD-HHmm.pdf` |
| `build-report-workbook.ps1` | Builds a single multi-tab Excel workbook (`reports-noskill/SOC-noskill-report.xlsx`) — one worksheet per day from every `daily-SOC-noskill-YYYY-MM-DD.csv`. Pure .NET OpenXML (no Excel required). Run manually to consolidate history. |
| `iis-preparse.ps1` | Zero-token STEP 0: aggregates IIS status buckets per GL via REST → `reports-noskill/iis-preparse.json`; run before `iis` sub-hunt so Claude skips STEP 0 and goes straight to STEP 1 URI drills |
| `depth-catchup-rest.ps1` | Zero-token depth catchup: reads `depth-coverage.json` for modules with status "budget", runs each module's primary detection query via REST, writes `depth-catchup.json` (REVIEW if count>0 with paste-ready query, CLEAN if 0); replaces the old AI depth-catchup pass |
| `graylog-rest-query.ps1` | REST fallback when MCP is flaky |

---

## Output Directories & Report Files

| Path | File | Description |
|------|------|-------------|
| `reports-noskill/` | `daily-latest.md` | Master findings document — source for PDF, CSV, Teams cards |
| `reports-noskill/` | `daily-SOC-noskill-YYYY-MM-DD.pdf` | Daily PDF report (Edge headless render) |
| `reports-noskill/` | `daily-SOC-noskill-YYYY-MM-DD.csv` | CSV export of all findings |
| `reports-noskill/` | `query-cache.json` | Every Graylog query that ran, by surface + severity |
| `reports-noskill/` | `alert-*.json` | One file per CRITICAL/HIGH finding |
| `reports-noskill/` | `coverage-gaps.json` | Surfaces not yet covered (empty = full coverage) |
| `reports-live/` | `live-latest.md` | Hourly live hunt output |
| `reports-live/` | `live-SOC-YYYY-MM-DD-HHmm.pdf` | Hourly live PDF |
| `logs-noskill/` | `daily.log` | Full pipeline run log |
| `logs-noskill/` | `live.log` | Hourly live hunt log |

---

## Delivery

### Teams (Adaptive Cards)
- **Script:** `send-report-noskill.ps1`
- **Webhook config:** `.webhook-noskill` (URL file in project root)
- **What posts:** One Adaptive Card per finding (severity + surface + evidence + action) + a summary card with PDF link
- **Live hunt channel:** `.webhook-live` → `send-live-noskill.ps1` → IIS-OPGL Teams channel

### Email (CSV + PDF)
- **Script:** `send-csv-noskill.ps1`
- **SMTP relay:** `10.102.100.112` (MTSMTP01), port 25, no auth, internal only
- **From:** `soc-noskill@casepoint.in`
- **To:** `vidhya.v@casepoint.in`
- **Attachments:** `daily-SOC-noskill-YYYY-MM-DD.csv` + `daily-SOC-noskill-YYYY-MM-DD.pdf`
- **Suppress email (Teams-only test):** set env var `SOC_SKIP_EMAIL=1`

### OneDrive / SharePoint
- **OneDrive folder URL:** `.onedrive-folder-url` (file in project root)
- **SharePoint PDF base URL:** `.sharepoint-pdf-url-base` (file in project root)
- PDF is copied to OneDrive SOC-Reports folder; Power Automate picks it up and posts the link in Teams summary card

---

## MCP Config Files

| File | Graylogs |
|------|---------|
| `.mcp.json` | All 4 (OP, PROD, AZ, DEV) |
| `mcp-3gl.json` | OP, PROD, AZ |
| `mcp-azprod.json` | AZ + PROD |
| `mcp-prodop.json` | PROD + OP |
| `mcp-prod.json` | PROD only |
| `mcp-dev.json` | DEV only |

---

## IIS Log Parsing

### Mandatory IIS Hunt Order (NEVER deviate from this)

```
STEP 1 — CONTENT (what was requested):
  Aggregate URI_Query   → read every distinct query string for attack tokens
  Aggregate URI_Stream  → read every distinct URI path for suspicious patterns

STEP 2 — CONFIRMATION (did it succeed):
  Filter by Status code ONLY after a suspicious URI is found
  200 on an attack URI = compromise (HIGH/CRITICAL)
  403/404 on an attack URI = attack attempt (MEDIUM minimum, still reported)

NEVER lead with Status. A Status-only IIS pass = FAILED hunt.
"All 403s = clean" is WRONG — a 403 on a SQLi string is still a logged attack.
```

### Parser Reality per Graylog

| Graylog | URI_Query / URI_Stream | Status / Client_ip | Fallback |
|---------|----------------------|-------------------|---------|
| **OP-GL** | ✅ Fully parsed — aggregate directly | ✅ Parsed | Named fields usable |
| **PROD-GL** | ❌ Frequently NULL | ❌ Frequently NULL | Hunt raw `message` field + `filebeat_log_file_path:*inetpub*` |
| **AZ-GL** | ❌ Frequently NULL | ❌ Frequently NULL | Hunt raw `message` field |
| **DEV-GL** | ❌ Frequently NULL | ❌ Frequently NULL | Hunt raw `message` field |

### Unparsed Log Fallback (no logs skipped)

When named fields are NULL the hunt **does not skip** — it falls back to raw message:

```
# Coverage sweep for unextracted/unrouted events
NOT _exists_:Status
NOT _exists_:URI_Stream

# Then hunt the raw message body with the same attack signatures
message:*UNION+SELECT* OR message:*../../../* OR message:*cmd.exe* ...
```

Rule: **A named-field zero is NEVER a clean verdict.** Raw message must also be searched before any surface is declared clean. When parsed field and raw message disagree — trust the raw message.

### Pre-built IIS Query Files

IIS queries are pre-built Lucene queries stored as `q_*.txt` files — used by `graylog-rest-query.ps1` as REST fallback when MCP is flaky, and can be pasted directly into the Graylog search bar for manual investigation.

| File | Detects |
|------|---------|
| `q_iis_sqli.txt` | SQL injection patterns in URI |
| `q_iis_scanner.txt` | Scanner/fuzzer signatures |
| `q_iis_traversal.txt` | Path traversal attempts |
| `q_4625burst.txt` | Windows failed logon bursts |
| `q_4688.txt` | Process creation (commandline) |
| `q_1102.txt` | Audit log cleared (Event 1102) |
| `q_7045.txt` | New service installed |
| `q_azure_fail.txt` | Azure failed auth |
| `q_azure_legacy.txt` | Azure legacy auth (SMTP/ROPC) |
| `q_eset.txt` | ESET threat detections |
| `q_forti_deny.txt` | FortiGate denied connections |
| `q_forti_ips.txt` | FortiGate IPS alerts |
| `q_linux_sshfail.txt` | SSH brute force |
| `q_linux_miner.txt` | Cryptominer signatures |
| `q_linux_revsh.txt` | Reverse shell indicators |
| `q_privgrp.txt` | Privileged group changes |

These are **detection queries only** — the hunt generates its own dynamic queries. The `q_*.txt` files are the REST fallback and manual reference set.

---

## REVIEW Finding Rule (applies to ALL hunts)

When any check is skipped due to turn budget, emit a REVIEW finding that includes:
- `query` = exact paste-ready Graylog query the analyst can copy into the search bar
- `action` = "Run manually in [GL]: [one-line description of what to look for]"
- `investigate` = follow-up query if the first one returns results

A REVIEW with no runnable query is useless — it tells an analyst something was missed but gives them nothing to act on. Every skipped check must leave a query behind.

---

## Rules — follow these in every session

1. **3 scheduled tasks only** — never create a new one. Test runs use `SOC-NoSkill-FreshNow`.
2. **Add hunts via `noskill-hunts.json`** — never hardcode a `claude` call outside `run-noskill-hunt.ps1`.
3. **No `.bak` files** — use git for versioning.
4. **Cortex XDR blocks PowerShell with attack-signature literals** — keep threat keywords in `.json`/`.txt` data files, never in `.ps1` bodies.
5. **All tasks run Interactive** (logged-in session). For 24/7 unattended, re-register with S4U via `register-live-task.ps1` elevated.
6. **Don't delete `reports-noskill/` or `logs-noskill/`** — active pipeline state lives there.
