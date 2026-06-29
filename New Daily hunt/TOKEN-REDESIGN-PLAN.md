# Daily Hunt — Token Redesign Plan (proposal, nothing changed yet)

**Date:** 2026-06-12
**Target:** the 02:30 `SOC-DailyReport-NoSkill` pipeline (currently **Disabled** — redesign before re-enabling).
**Goal:** cut token consumption materially **without** (a) dropping any finding, (b) changing *what* is hunted, or (c) abandoning AI-hunts-via-MCP (per the 2026-06-11 directive in `daily-sweep-spec`).

This plan is **structural only**. No model changes, no hunt consolidation, no REST layer, no schedule re-enable — those are listed under "Explicitly OUT" so they don't creep in.

---

## Diagnosis — where the tokens go

12 sequential `claude -p` processes (`daily-report-noskill.cmd`); 11 Sonnet surface hunts + 1 Opus correlation that is already gated to ~0 tokens on quiet days (`correlation-gate-noskill.ps1`). The burn is structural:

1. **Every hunt loads all 4 Graylog MCP servers** (`run-noskill-hunt.ps1` passes the single `.mcp.json` to every hunt) = ~32 tool schemas resident in each process's prompt prefix and re-billed (cached rate) on every turn — even hunts that touch 1 GL.
2. **`--max-turns 200` on every hunt** — no per-hunt ceiling. A hunt that wanders to 80–150 turns pays a near-quadratic context cost. The 2026-06-03 blowout (hit the 5h budget block ~04:00) was this.
3. **`iis` is explicitly uncapped** — "NO per-category aggregate cap … run as many aggregate_logs as coverage requires," 14 attack-classes × 3 GLs, raw-message hunting on the blind-spot GLs, and it can **double-run** (inline freshness retry + retry-stale pass).
4. **`rdp`, `azure`, `linux`, `sftp` say only "Aggregate first"** — no hard per-query cap, unlike the newer prompts.

The newer prompts (`dev`/`app`/`app-pt`/`db`/`network`/`infra`) are already well-disciplined ("ONE aggregate per stream/category + ≤10-row drill on confirmed HIGH + REVIEW-coverage-gap on timeout"). The redesign **propagates that existing, proven discipline to the laggards** and bounds the fleet structurally.

---

## Change A — Per-hunt MCP scoping  *(zero recall risk)*

Give each hunt only the Graylog servers its prompt actually queries. Derived directly from each prompt's own scope clause, so nothing it queries is removed.

| Hunt | GLs the prompt queries | MCP config | tools (was 32) |
|------|------------------------|------------|----------------|
| `iis` | OP, PROD, AZ (DEV skipped) | `mcp-3gl.json` | 24 |
| `rdp` | AZ, PROD, OP | `mcp-3gl.json` | 24 |
| `linux` | AZ, PROD, OP | `mcp-3gl.json` | 24 |
| `network` | AZ, PROD, OP | `mcp-3gl.json` | 24 |
| `correlation` | AZ, PROD, OP (DEV forbidden) | `mcp-3gl.json` | 24 |
| `azure` | AZ + PROD (OP none, DEV skip) | `mcp-azprod.json` | 16 |
| `app` | AZ + PROD (OP N/A, DEV skip) | `mcp-azprod.json` | 16 |
| `sftp` | PROD + OP (AZ none, DEV skip) | `mcp-prodop.json` | 16 |
| `app-pt` | PROD only | `mcp-prod.json` | 8 |
| `dev` | DEV only | `mcp-dev.json` | 8 |
| `db` | all 4 | `.mcp.json` (unchanged) | 32 |
| `infra` | all 4 | `.mcp.json` (unchanged) | 32 |

**Biggest wins:** `dev` and `app-pt` currently haul 4× the schema they use (32→8).

**New files** (5 subsets of the existing `.mcp.json`, same tokens/URLs, fewer servers):
- `mcp-3gl.json` — PROD-GL, OP-GL, AZ-GL
- `mcp-azprod.json` — AZ-GL, PROD-GL
- `mcp-prodop.json` — PROD-GL, OP-GL
- `mcp-prod.json` — PROD-GL
- `mcp-dev.json` — DEV-GL

**Coupling note:** if a prompt is later changed to query a new GL, its `mcp` entry must be widened to match, or that GL returns "tool not available." I'll add a one-line comment to `noskill-hunts.json` flagging this.

---

## Change B — Per-hunt turn caps  *(low risk, paired with graceful truncation)*

Replace the blanket `--max-turns 200` with a per-hunt ceiling. **The cap is a token safety-ceiling, not the expected turn count** — it catches runaway/looping query behavior. (Slow-but-progressing hunts are handled separately by the 25-min `hunt-watchdog-noskill.ps1`; turns ≠ time.)

| Hunt | maxTurns | rationale (typical work) |
|------|----------|--------------------------|
| `iis` | 70 | 14 classes × 3 GLs + raw sweeps + drills (heaviest; also de-uncapped in Change C) |
| `rdp` | 60 | B1–B4 + 6 host-wide categories × 3 GLs |
| `infra` | 50 | 4 categories × ≤4 GLs, virt up to 3 |
| `app` | 45 | crown-jewel streams across AZ+PROD + drills |
| `db` | 45 | per-stream × 4 GLs, Redis 5 split-queries |
| `network` | 45 | 3 categories × 3 GLs, firewall/LB up to 3 each |
| `azure` | 35 | identity checks across 2 GLs |
| `linux` | 35 | signature sweeps across 3 GLs |
| `sftp` | 35 | blocked-source + TLS-recon + transfer across 2 GLs |
| `dev` | 30 | 7 source-types, one aggregate each |
| `app-pt` | 25 | 3 streams × few filters |
| `correlation` | 25 | reads merged JSON + ≤5 confirm aggregates |

**Graceful-truncation rule (added to every prompt that lacks it):** *"If you approach your turn budget, STOP querying, write the report with what you have, and emit a REVIEW 'coverage-gap' finding naming each unassessed surface/stream."* The disciplined prompts already do this per-stream; this ties it to the turn budget so a capped hunt is **loud, never silently clean** — preserving the no-miss contract.

---

## Change C — Prompt token-discipline deltas

| Hunt | Edit | Size |
|------|------|------|
| `iis` | **Remove** "there is NO per-category aggregate cap … run as many aggregate_logs calls as coverage requires." **Replace** with: ONE aggregate per attack-class per GL; on the blind-spot GLs (PROD/AZ) batch each class's tokens into a **single raw-message OR-query** + ONE `NOT _exists_:Status` coverage sweep per GL; ≤10 raw rows only to confirm a candidate; turn-budget → write report + REVIEW coverage-gap. **Preserves full coverage** (every class, every GL, raw-message hunting on blind-spot GLs) — only removes the "unbounded" license. | large |
| `rdp` | Add HARD CAP: aggregate-first, ONE aggregate per behavioral trigger (B1–B4) and ONE per host-wide category (the 6) per GL; ≤10-row drill on confirmed anomalies only; turn-budget → report + REVIEW coverage-gap. | medium |
| `azure` | Upgrade "Aggregate first" → the explicit "ONE aggregate per check, ≤10 raw rows on confirmed HIGH only, REVIEW-coverage-gap on timeout/turn-budget" pattern (copied verbatim from the disciplined prompts). | small |
| `linux` | Same upgrade as `azure`. | small |
| `sftp` | Same upgrade as `azure` (it already says "do not pull millions of rows"; make the per-query cap explicit). | small |
| `dev`, `app`, `app-pt`, `db`, `network`, `infra` | Already disciplined. **Only** add the one-sentence turn-budget tie-in so the new cap can't truncate them silently. | 1 line each |
| `correlation` | Already bounded (≤5 confirm aggregates, no raw, merged-JSON input). **No change.** | none |

---

## Change D — Runner + manifest wiring

**`noskill-hunts.json`** — add two fields per hunt:
```json
{ "key": "iis", "model": "sonnet", "prompt": "noskill-prompts\\iis.txt", "mcp": "mcp-3gl.json", "maxTurns": 70 }
```
(`db`/`infra` get `"mcp": ".mcp.json"`. Missing fields default to `.mcp.json` / `200` for safety.)

**`run-noskill-hunt.ps1`** — two minimal edits:
- `$mcp = Join-Path $proj ($h.mcp ? $h.mcp : '.mcp.json')` (PS 5.1: use `if`/`else`, no ternary)
- `--max-turns ($h.maxTurns ? $h.maxTurns : 200)` → likewise via a `$turns` variable.

Both already flow into `$baseArgs`; this just makes them per-hunt. The temp-file/stdin long-prompt path is unaffected.

---

## Files touched + rollback

- **New:** `mcp-3gl.json`, `mcp-azprod.json`, `mcp-prodop.json`, `mcp-prod.json`, `mcp-dev.json`, this plan.
- **Edited:** `noskill-hunts.json`, `run-noskill-hunt.ps1`, prompts `iis/rdp/azure/linux/sftp` (real edits) + `dev/app/app-pt/db/network/infra` (1-line each). `correlation.txt` untouched.
- **Backups:** every edited file copied to `*.bak-20260612-tokenredesign` before edit (matches the project's existing `.bak-*` convention).
- **Rollback:** restore the `.bak-20260612-tokenredesign` files + delete the 5 `mcp-*.json`. The manifest defaults (missing `mcp`/`maxTurns` → `.mcp.json`/`200`) mean even a partial revert is safe.

## Validation before re-enabling

1. **Static:** `noskill-hunts.json` parses; each referenced `mcp-*.json` exists and parses; each `prompt` file exists; `run-noskill-hunt.ps1` syntax-OK.
2. **Per-config sanity:** each `mcp-*.json` lists exactly the intended servers.
3. **One live dry-run of the heaviest hunt** (`iis`) via `run-noskill-hunt.ps1 -Key iis` (Task-Scheduler context per the Cortex constraint), confirm: fresh `iis-latest.md` with `findings-json`, all 14 classes covered per env, no `command line too long`, turn count well under 70.
4. Only then `Enable-ScheduledTask -TaskName SOC-DailyReport-NoSkill` (separate, explicit step — not part of this change).

## Explicitly OUT of this plan (available if you want them later)

- **Model changes** — already Sonnet-everywhere + gated Opus; no further tiering.
- **Hunt consolidation** (e.g. `app-pt`→`app`, `db`→`infra`) — would cut fixed reloads further but reverses splits you made deliberately.
- **REST 0-token pre-pass** — precompute the deterministic signature counts (the 40+ IIS aggregates) via the archived `graylog-rest.ps1` and feed Sonnet a pre-surfaced table. Biggest possible cut, but reintroduces the layer you archived for hunting on 06-11. Out unless you ask.
- **Re-enabling the task** — separate step after validation.
