# Depth-module library — schema & handoff

A **depth module** is a self-contained, reproducible deep-investigation method for ONE
technique. It is the rigour the skills encode and the breadth sweep only approximates.
Data-file only (Cortex-clean: signatures/methods live here in .json, .ps1 stays benign plumbing).

## How it plugs in (deployment-agnostic)

```
Layer 1 BREADTH (Sonnet, every surface/GL)  --emits-->  leads-queue.json
Layer 2 TRIAGE   (dedup by entity, rank)
Layer 3 DEPTH    (Opus inline  OR  colleague's hunt on diff machine)
                  reads leads-queue.json, runs the module whose `trigger` matches each lead
```

The queue is the contract. A lead is `{surface, entity, technique, prelim_sev, module}`.
Depth NEVER runs on its own coverage — it runs on what breadth flagged. Same artifact
whether depth is an inline Opus pass or a second machine.

## Module fields

| field | meaning |
|---|---|
| `module` / `version` | id + version |
| `technique` / `mitre` / `tactic` | what it detects + ATT&CK mapping |
| `surface` / `applies_to_gl` | where it runs |
| `trigger` | the breadth lead-type that invokes it + the entity it keys on |
| `telemetry_required` | fields/streams that must exist |
| `telemetry_gap_behavior` | what to do if that data is absent — **KNOWN-GAP, never "clean"** |
| `inputs` | entity + window pulled from the lead |
| `method` | ordered deep steps: goal + Cortex-clean Lucene query + compute + threshold |
| `decision` | evidence -> severity + confidence rubric |
| `false_positive_checks` | known-benign patterns + suppression-ledger entries to rule out |
| `evidence_capture` | fields to record on the finding |
| `output_findings_json` | maps to the existing findings-json keys |

## Rules every module obeys
1. **Targeted, exact-count queries on ONE entity** — never top-N aggregates (truncation-proof).
2. **Absent telemetry = KNOWN-GAP note + pivot**, never a clean verdict.
3. **Bake in the environment** — field-name twins (`azure_prop_*`/`properties_*`), the
   allow-lists (Cato, Zscaler, Nessus), and the suppression ledger.
4. Output the same findings-json keys breadth uses, so one report reconciles both phases.

## Library coverage (target set)
Drafted now: `credential-stuffing-pivot`, `beaconing-c2`, `dcsync-replication`.
To add: `impossible-travel`, `oauth-consent-grant`, `webshell-upload-exec`, `aitm-token-replay`,
`legacy-auth-success`, `rdp-bruteforce-success`, `sftp-exfil`, `service-install-persistence`,
`scheduled-task-persistence`, `mfa-fatigue`, `data-exfil-volumetric`, `password-spray-origin`.
KNOWN-GAP stubs (telemetry-blind, ship as recommendations not detections):
`kerberoasting`, `smb-lateral`, `lsass-dump`, `bec-mailbox-rule`.
