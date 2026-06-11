# IIS OP-GL Security Monitor — How It Works

**In one line:** an always-on, automated system that watches the OPEXUS web-server
(IIS) logs and alerts the SOC — with high confidence — only when a real attack is
corroborated across multiple independent security systems.

- **Where:** OP-GL Graylog (`siem.secureocp.com`) — IIS web traffic for eCase/FOIA/PAL.
- **How often:** every **30 minutes**, fully automated, unattended.
- **Cost:** routine detection uses **no AI / ~zero cost**; AI is used only on rare,
  high-value events.

---

## The detection flow (runs every 30 minutes)

```
        OP-GL Graylog  —  IIS web logs  (~1,000,000 requests/hour)
                              │   read-only query
                              ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │ 1. LEARN   Verify the log feed is complete and correctly parsed   │
   │            (catch any ingestion gaps before analysing)            │
   ├─────────────────────────────────────────────────────────────────┤
   │ 2. OBSERVE Load the "known entities" baseline — every IP, user,   │
   │            URL and host seen before. Anything NEW is flagged from  │
   │            its first appearance (no blind learning period)         │
   ├─────────────────────────────────────────────────────────────────┤
   │ 3. CHECK   Run 18 attack-pattern detections: SQL injection, XSS,  │
   │            remote-code-exec, path traversal, SSRF, web shells,     │
   │            brute-force / credential stuffing, enumeration,         │
   │            scanners, CVE/CMS probing, protocol abuse, data         │
   │            exfiltration, C2 beaconing, + anomaly catch-alls        │
   ├─────────────────────────────────────────────────────────────────┤
   │ 4. KEEP    Cross-check every suspect against ALL other OP-GL       │
   │            security logs — Windows, FortiGate firewall, MFA,       │
   │            file-transfer (SFTP), antivirus, email — for the same   │
   │            attacker. Only corroborated threats become alerts.      │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        Microsoft Teams alert (rich card) — HIGH-confidence only
              + an AI (Claude Opus) investigation attached
```

*(The four stages follow our "LOCK" hunting framework: **L**earn, **O**bserve,
**C**heck, **K**eep.)*

---

## How we keep confidence high (and avoid alert fatigue)

Every finding climbs a four-step ladder — an alert fires **only at the top**:

| Tier | Meaning | Action |
|------|---------|--------|
| **LOGGED** | Known and normal | Recorded, no alert |
| **REVIEW** | Something new, or a rate threshold breached | Queued for correlation |
| **CONFIRMED** | Multiple detections agree on the same actor | Held |
| **HIGH** | Independently corroborated by another security system | **Teams alert + AI deep-dive** |

> An alert requires evidence from **two or more independent sources** (e.g. a web
> brute-force *and* matching Windows failed-logons / MFA denials). This is why the
> SOC gets signal, not noise.

---

## How we make sure threats aren't missed

- **First-occurrence net:** any never-before-seen IP/user/URL is reviewed from its
  very first request — there is no "warm-up" window where new attackers slip by.
- **18 behavioural detections** (including CVE / admin-API probing and API-object
  / IDOR enumeration) plus structural-anomaly and catch-all classes.
- **Daily AI completeness sweep:** once a day, Claude Opus reviews the day's most
  unusual traffic to catch subtle, slow, or novel attacks that fixed rules miss.

---

## How it stays cost-efficient

- **Routine detection = direct database queries, no AI** → effectively free, 48×/day.
- **AI (Claude Opus) is used surgically:** only to investigate a confirmed HIGH
  alert (rare) and once daily for the sweep.
- Net effect: thorough 24/7 coverage at minimal, predictable cost.

---

## Current status (live)

- Running every 30 minutes; last cycle **succeeded** — ~960,000 requests analysed,
  feed health 99.9%.
- Baseline is **learning** (entities tracked and growing → fewer manual reviews
  over time).
- **Zero false high-severity alerts** to date (correctly silent when nothing is
  corroborated).
- Alerts route to a dedicated **Microsoft Teams** channel as formatted cards.

---

*Built on the SOC's existing Graylog SIEM and Teams workflow; no new infrastructure.*
