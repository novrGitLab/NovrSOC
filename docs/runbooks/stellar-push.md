# Stellar Cyber push — runbook

NovrSOC pushes each stored alert to Stellar Cyber's webhook ingest as one JSON `POST`, about a minute after it is stored (`jobs/stellarPush.ts`). It needs the alert pipeline (R2) to be running, and it uses the same ordering and redaction as the pull export.

## 1. Database (once)

Run `backend/sql/2026-10-11_push_state.sql` in the Supabase SQL editor. It needs `alerts.ingest_seq` (`2026-10-09_alerts_ingest_seq.sql`).

## 2. Railway variables

| Variable | Value |
|---|---|
| `STELLAR_PUSH_URL` | The full webhook URL from Stellar: `https://poc-eu.stellarcyber.cloud/webhook/<tenant>/<id>` |
| `STELLAR_PUSH_API_KEY` | The API key Stellar issued. Paste it into Railway only. Never put it in the repo, a ticket or chat. |
| `STELLAR_PUSH_ORG_IDS` | The org slug(s) whose alerts Stellar may receive, comma-separated. Nothing else is sent. |
| `STELLAR_PUSH_AUTH_HEADER` / `STELLAR_PUSH_AUTH_SCHEME` | Default `Authorization: Bearer <key>`. If the NovrGRC integration sent the key differently, match it (scheme `none` sends the bare key). |
| `STELLAR_PUSH_PROFILE` | `standard` (default: includes the redacted original alert as `raw`) or `no_raw` |
| `STELLAR_PUSH_START` | `latest` (default: only alerts stored from now on) or `beginning` (everything retained, up to 90 days). Read on first run only. |
| `STELLAR_PUSH_ENABLED` | Set to `true` last. This is the kill switch. |

The job runs only in the production Railway environment (see `lib/runtimeEnv.ts`). A local run never pushes.

## 3. Check it

- Railway logs show `[stellar-push] pushing orgs … to poc-eu.stellarcyber.cloud`, then `sent N, skipped 0` as alerts arrive.
- `SELECT * FROM push_state;` shows `last_seq`, `sent_count`, `skipped_count`, `last_success_at` and `last_error`.
- In Stellar, search for `event_type: security.alert`. Each event has the 5-tuple as top-level `srcip`, `dstip`, `srcport`, `dstport` and `proto`.

## 4. Failures

| Log / `last_error` | Meaning |
|---|---|
| `401 (check STELLAR_PUSH_API_KEY / auth header)` | Wrong key, or the receiver expects a different header. Fix the variable and redeploy. The position is kept, so nothing is lost. |
| `network error or timeout`, `5xx`, `429` | Retried automatically with backoff (30 s doubling to 10 min). Nothing is lost. |
| `skipped <id>: 400` | Stellar rejected that one event's content. It is skipped so the feed keeps moving. |

**Stop:** unset `STELLAR_PUSH_ENABLED` and redeploy. **Re-send from a point:** set `push_state.last_seq` to the `ingest_seq` just before it.

## 5. Event fields

| Field | Content |
|---|---|
| `event_id`, `event_type` (`security.alert`), `occurred_at`, `received_at`, `tenant_ref` (org), `source` (`NovrSOC`), `sensor` (`wazuh`) | Identity and timing. De-duplicate on `event_id`. |
| `srcip`, `dstip`, `srcport`, `dstport`, `proto`, `proto_num` | The 5-tuple, flat. Also nested in `network`. From the decoded Wazuh fields, falling back to Sysmon. |
| `severity`, `rule` (id, level, description), `rule_groups` | Detection |
| `mitre_ids`, `mitre_tactics`, `mitre_techniques` | ATT&CK mapping |
| `agent` (id, name, ip), `manager`, `decoder`, `location` | Where it was seen |
| `user` (src, dst), `action`, `url` | Who and what |
| `process` (name, command_line, parent_name, parent_command_line, pid, md5, sha1, sha256) | Sysmon process context |
| `file` (path, change, md5, sha1, sha256) | File integrity (syscheck) |
| `full_log` (up to 8 KB), `raw` | Original log, redacted |

Anything the alert doesn't carry is `null`. Every free-text field is redacted (passwords, tokens, API keys, Authorization headers, private keys) before it leaves NovrSOC.
