# IIS Graylog Extractor Fix — field misalignment across GLs

**Author:** SOC (is@casepoint.com)
**Date:** 2026-06-01
**Audience:** Graylog pipeline / extractor owner
**Severity of impact:** High — IIS threat-hunting is blind to 15–60% of web traffic in 3 of 4 Graylogs.

---

## 1. Symptom

The daily IIS hunt (`iis-log-hunt`) queries the named IIS schema
(`Status`, `Method`, `URI_Stream`, `Client_ip`, `UserAgent`, `Host`, …).
On three of the four Graylogs a large fraction of `inetpub` events either have
**no named fields at all** or have the **wrong values** in them, so every
hypothesis query returns 0 and the hunt reports "clean / disproved" while real
attacks pass through uninspected.

Measured 2026-06-01 (1-hour sample, `filebeat_log_file_path:*inetpub*`):

| GL | Mis-parsed share | Failure mode |
|---|---|---|
| **OP-GL** | 0% (`missing:0`) | none — reference-correct |
| **PROD-GL** | ~15% | column shift (`Status:0`, real status in `Host`) + total miss |
| **DEV-GL** | high (~90k/hr `NOT _exists_:Status`) | same as PROD |
| **AZ-GL** | ~60% | column shift on gov W3SVC2 logs |

A live path-traversal + SQLi + command-injection scan against
`fxpt.casepoint.com` (FOIAXpress, `LDPTOPEXUS01`) from XFF `38.101.76.200` was
**invisible to the normal hunt** purely because of this defect.

---

## 2. Root cause

The IIS sites emit **more W3C columns than the deployed extractor pattern was
written for.** The extra columns shift every field to the right of the
insertion point. Two distinct real layouts exist beyond the one OP-GL parses:

### Layout A — full extended (cs-host + X-Forwarded-For + cs-username)

Emitted by FOIAXpress, ARA/ATIPXpress, AZ gov (W3SVC2) sites. 17 fields:

```
date time s-sitename s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip
cs-version cs(User-Agent) cs(Referer) cs-host sc-status sc-substatus
sc-win32-status time-taken X-Forwarded-For cs-username
```

Real line (PROD, fxpt.casepoint.com):
```
2026-06-01 09:44:04 W3SVC1 10.101.245.12 GET /FOIAXpress/WebResource.axd d=…&t=… 443 \
10.101.100.253 HTTP/1.1 Mozilla/5.0+… https://fxpt.casepoint.com/… \
fxpt.casepoint.com 304 0 0 2 123.253.153.138,+fxpt.casepoint.com sahil
                   └cs-host┘ └status      └─── X-Forwarded-For ───┘  └username┘
```
PROD/DEV/AZ extractor (which has no `cs-host` column) mis-maps:
`Status="0"`, `Host="304"`, `Client_ip=".153.138"` (truncated).

### Layout B — reduced (no s-sitename)

Emitted by FOIA-API hosts (`LDPTFOAPI01`, `DRMTFOAPI01`, …). No `W3SVC#` token:

```
2026-06-01 09:44:14 10.101.235.80 POST /Identity/connect/token - 443 \
10.101.213.11 - - 200 0 0 61 -
```
The extractor expects `… s-sitename s-ip …`; with the sitename missing the
whole pattern fails to match → **zero named fields** (`NOT _exists_:Status`).

OP-GL parses correctly because its hosts/extractor already align to Layout A
(its `-` placeholders fill cs-host/XFF/username). PROD, DEV, AZ run an older
pattern that predates the `cs-host` column.

---

## 3. Fix — apply on PROD-GL, DEV-GL, AZ-GL

Standardize all four GLs on a `cs-host`-aware grok with a reduced-format
fallback. Recommended: a Graylog **pipeline rule** that tries Layout A, then
Layout B.

### Grok pattern — Layout A (primary)

```
%{TIMESTAMP_ISO8601:iis_ts} %{NOTSPACE:s_sitename} %{IPORHOST:s_ip} %{WORD:Method} %{NOTSPACE:URI_Stream} %{NOTSPACE:URI_Query} %{NUMBER:Port} %{IPORHOST:c_ip} %{NOTSPACE:cs_version} %{NOTSPACE:UserAgent} %{NOTSPACE:Referer} %{NOTSPACE:cs_host} %{NUMBER:Status} %{NUMBER:sc_substatus} %{NUMBER:sc_win32} %{NUMBER:Time_Taken} %{NOTSPACE:x_forwarded_for} %{GREEDYDATA:cs_username}
```

### Grok pattern — Layout B (fallback, no s-sitename)

```
%{TIMESTAMP_ISO8601:iis_ts} %{IPORHOST:s_ip} %{WORD:Method} %{NOTSPACE:URI_Stream} %{NOTSPACE:URI_Query} %{NUMBER:Port} %{IPORHOST:c_ip} %{NOTSPACE:UserAgent} %{NOTSPACE:Referer} %{NUMBER:Status} %{NUMBER:sc_substatus} %{NUMBER:sc_win32} %{NUMBER:Time_Taken} %{GREEDYDATA:cs_username}
```

### Field mapping (must match what the hunt queries)

| Grok capture | Graylog field |
|---|---|
| `cs_host` | **`Host`** (the HTTP host header — not the status!) |
| `Status` | `Status` |
| `Method` | `Method` |
| `URI_Stream` | `URI_Stream` |
| `URI_Query` | `URI_Query` |
| `UserAgent` | `UserAgent` |
| `Time_Taken` | `Time_Taken` |

### Client_ip — derive from X-Forwarded-For, not c-ip

`c-ip` is always the internal KEMP/load-balancer address (`10.x`). The true
client is the **first** token of `X-Forwarded-For`. In the pipeline:

```
let xff_parts = split(to_string($message.x_forwarded_for), ",");
set_field("Client_ip", to_string(xff_parts[0]));
```

This matters: geo-fence checks (`config/geo-blocks.md`), per-IP rate
aggregations, and IOC correlation all key on `Client_ip`. Without this they
either see `10.x` or a mangled fragment.

---

## 4. Best-practice hardening (recommended)

IIS writes a `#Fields:` directive at the top of every log file listing the
exact columns. The most robust long-term fix is to **key extraction off the
`#Fields:` header** rather than positional grok, so future column changes
(adding `cs(Cookie)`, `crypt-protocol`, etc.) don't silently break parsing again.
At minimum, standardize the IIS site logging config so every site emits the
**same** W3C field set.

---

## 5. Validation queries (run after the fix on each GL)

```
# Should trend to ~0 on every GL:
filebeat_log_file_path:*inetpub* AND NOT _exists_:Status

# Status field should contain only HTTP codes (no hostnames, no "0" floods):
aggregate Status over filebeat_log_file_path:*inetpub*

# Host field should contain only hostnames (no "200"/"304"):
aggregate Host over filebeat_log_file_path:*inetpub*

# Client_ip should be public client IPs, not 10.x LB addresses:
aggregate Client_ip over filebeat_log_file_path:*inetpub*
```

Sign-off when all four GLs match OP-GL's clean baseline.
