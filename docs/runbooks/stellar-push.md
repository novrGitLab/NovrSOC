# Stellar Cyber push — runbook

NovrSOC pushes each stored alert to Stellar Cyber's webhook ingest as one JSON `POST`, about a minute after it is stored (`backend/src/jobs/stellarPush.ts`). It uses the same ordering and redaction as the pull export.

## What is forwarded

**Source:** every Wazuh alert stored in NovrSOC's `alerts` table. The path is: Wazuh indexer → `soar.py --forward` → `POST /api/ingest/alerts` → `alerts`. All rule levels are included by default (`SOAR_FORWARD_MIN_LEVEL=0`), for agents whose Wazuh group is mapped to an org.

**So it covers** what Wazuh raises alerts on:
- agent-collected events (Linux auth/syslog, Windows Event Log, Sysmon, file integrity, rootcheck, vulnerability detector)
- syslog that network devices and firewalls send to the Wazuh manager, **when** a Wazuh rule fires on it

**Not covered** (none of these is collected as alerts today):
- Wazuh archive events that triggered no rule
- OPNsense (not connected)
- email-security, CNII-scan, case/SOAR and audit-log events

## 1. Database (once)

Run `backend/sql/2026-10-11_push_state.sql` in the Supabase SQL editor. It creates `push_state` and `push_dead_letters`, and needs `alerts.ingest_seq` (`2026-10-09_alerts_ingest_seq.sql`).

## 2. Railway variables

| Variable | Value |
|---|---|
| `STELLAR_PUSH_URL` | The full webhook URL Stellar issued: `https://poc-eu.stellarcyber.cloud/webhook/<tenant>/<id>` |
| `STELLAR_PUSH_API_KEY` | The API key Stellar issued. Railway only: never in the repo, a ticket or chat. |
| `STELLAR_PUSH_ORG_IDS` | The org slug(s) whose alerts Stellar may receive, comma-separated. Nothing else is sent. |
| `STELLAR_PUSH_AUTH_HEADER` / `STELLAR_PUSH_AUTH_SCHEME` | Default `Authorization: Bearer <key>`. **Confirm with Stellar** (or match the NovrGRC sender). Scheme `none` sends the bare key. |
| `STELLAR_PUSH_START` | First run only. `latest` (default: only new alerts), `hours:N` (alerts stored in the last N hours) or `beginning` (all retained, up to 90 days). Start with `latest` and confirm receipt before any backfill. |
| `STELLAR_PUSH_MAX_PER_MIN` | Send rate cap, default 600. It bounds a backfill. |
| `STELLAR_PUSH_TIMEOUT_MS` | Per request, default 10000 |
| `STELLAR_PUSH_PROFILE` | `standard` (default: includes the redacted original alert as `raw`) or `no_raw` |
| `STELLAR_PUSH_ENABLED` | `true`, set **last**. This is the kill switch. |

The job runs only in the production Railway environment (`lib/runtimeEnv.ts`). A local run never pushes.

## 3. Check it

- **Admin → Settings → Export Clients → "Stellar Cyber push"** (super_admin) shows: status, delivered, backlog, transient retries, refused (dead letters), last success, last error and next attempt. The same data is at `GET /api/admin/push-status`.
- **Railway logs:** `[stellar-push] pushing orgs … to poc-eu.stellarcyber.cloud`, then `sent N, refused 0, …`.
- **In Stellar:** search for `event_type: security.alert`. A 2xx response only means the webhook accepted the event. Ask Stellar to confirm the events are searchable.

## 4. Failures

| Shown as | Meaning and what happens |
|---|---|
| `401 / 403 (check STELLAR_PUSH_API_KEY / auth header)` | Wrong key, or the receiver expects a different header. The position is kept, nothing is lost. Fix the variable and redeploy. |
| `network error or timeout`, `404`, `429 rate limited`, `5xx` | Retried with exponential backoff and jitter (30 s doubling to 10 min; `Retry-After` honoured). The position is kept, nothing is lost. |
| Refused (dead letters), from `400` / `413` / `422` | Stellar rejected that event's content (a `413` is first re-sent without `raw`). The event is recorded in `push_dead_letters` and the feed moves on. After Stellar fixes their side, click **Retry refused alerts**. |

- **Stop:** unset `STELLAR_PUSH_ENABLED` and redeploy.
- **Re-send from a point:** set `push_state.last_seq` to the `ingest_seq` just before it. Receivers de-duplicate on `event_id`.
- **Delivery is at least once, in order.** A crash mid-batch can re-send at most that batch.

## 5. Event fields

| Field | Content |
|---|---|
| `event_id`, `event_type` (`security.alert`), `occurred_at`, `received_at`, `tenant_ref` (org), `source` (`NovrSOC`), `sensor` (`wazuh`), `schema_version` | Identity and timing. De-duplicate on `event_id`. |
| `srcip`, `dstip`, `srcport`, `dstport`, `proto`, `proto_num` | 5-tuple, flat. Also nested in `network`. From Wazuh's decoded `data.srcip/srcport/dstip/dstport/protocol`, falling back per field to Sysmon's `sourceIp/sourcePort/destinationIp/destinationPort/protocol`. `null` when the event has none (e.g. file integrity). |
| `severity`, `rule` (id, level, description), `rule_groups` | Detection |
| `mitre_ids`, `mitre_tactics`, `mitre_techniques` | ATT&CK mapping |
| `agent` (id, name, ip), `manager`, `decoder`, `location` | Source metadata: which sensor, which decoder, which log |
| `user` (src, dst), `action`, `url` | Who and what |
| `process` (name, command_line, parent_name, parent_command_line, pid, md5, sha1, sha256) | Sysmon process context |
| `file` (path, change, md5, sha1, sha256) | File integrity (syscheck) |
| `full_log` (up to 8 KB) | The original log line |
| `raw`, `raw_truncated` | **The original Wazuh alert with its own field names**, for building a parser. Alerts over 32 KB were stored as a preview (`raw_truncated: true`). |

- **Nothing is invented:** anything the alert doesn't carry is `null`.
- **Redaction:** every string, including inside `raw`, is redacted before it leaves NovrSOC. That covers passwords, tokens, API keys, Authorization headers and private keys.
