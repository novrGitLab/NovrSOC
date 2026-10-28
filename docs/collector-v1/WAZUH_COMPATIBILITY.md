# Collector V1 and Wazuh — compatibility notes

## What NovrSOC's existing Wazuh integration actually is

NovrSOC only **reads** from Wazuh. `backend/src/lib/wazuh.ts` / `backend/src/services/wazuh.ts`
call the Wazuh Manager REST API (port 55000); `backend/src/lib/wazuh-indexer.ts` queries the
indexer directly (`wazuh-alerts-4.x-*`, `wazuh-states-vulnerabilities-*` — confirming the targeted
major version line is **4.8+**, from the index naming convention already relied on throughout the
codebase). Nothing in NovrSOC writes into Wazuh's configuration, decoders, or rules, and this
release changes nothing about that.

Alert *generation* (which rule fired, at what level) happens entirely inside Wazuh. NovrSOC's own
`alerts` table is a downstream copy, populated by `infra/soar/soar.py --forward` polling the
indexer and POSTing to `/api/ingest/alerts` with the shared `ALERT_INGEST_TOKEN`
(`backend/src/routes/ingest.ts`). Tenant ownership for that path already has two resolvers:
`wazuh_group_org_map` (an enrolled agent's groups → organisation) and `wazuh_source_org_map` (an
agentless syslog sender's address, for alerts the manager itself received on port 514 — agent
`000` — from devices like the OPNsense firewall already deployed, per
`docs/runbooks/deploy-p24-wazuh-tenancy.md`).

## Where Collector V1 sits relative to that

**Collector V1 does not touch any of the above.** It is a second, independent path:

```
Client log sources → Vector collector → NovrSOC collector gateway → collector_log_events (NovrSOC's own table)
```

versus the existing, unchanged path:

```
Client log sources → Wazuh manager (syslog 514 or an enrolled agent) → Wazuh decodes/scores → indexer
                                                                              |
                                                            soar.py --forward polls it
                                                                              v
                                                              /api/ingest/alerts → `alerts` table
```

This is a deliberate design choice, not an oversight: the brief for this release explicitly says
"keep ingestion identity and routing separate from Wazuh's alert-generation logic" and "do not
send arbitrary unvalidated events into the Wazuh management API." A collector-forwarded syslog
line has had **no detection logic applied to it** — no Wazuh rule, no severity level. Writing it
into the `alerts` table (which exists specifically to hold Wazuh's own scored output) or pushing
it into the Wazuh Manager API would either fabricate a severity nothing actually assigned, or
hand raw, less-trusted client-site input straight to Wazuh's own management surface. Neither is
acceptable, so `collector_log_events` is its own table, labelled honestly as unscored logs — see
`backend/sql/2026-11-12_p31_collector_v1.sql`'s header comment.

## What this means operationally

- A site using **only** Collector V1 (no Wazuh agent, no OPNsense-style syslog-to-Wazuh-manager
  setup) gets raw log storage and search in NovrSOC — not Wazuh-grade detection. This is the
  explicit limitation the brief requires stating: *"do not claim full endpoint detection and
  response from agentless log collection."* Collector V1 does not claim it.
- A site that **also** runs Wazuh (agents, or its own manager-side syslog listener per the P24
  pattern) keeps that path entirely as-is. The two are independent and can run side by side at
  the same organisation without interfering — they write to different tables and use different
  authentication. There is no reason a client couldn't have both a Wazuh agent AND a Collector V1
  appliance forwarding, say, a firewall's syslog that the agent fleet doesn't cover.
- If a future release wants Collector V1's logs to also reach Wazuh's own detection engine (so
  Wazuh's rules evaluate them, not just NovrSOC's raw storage), the correct integration point is
  pointing the **Wazuh manager's own syslog listener** at the same devices — i.e. extending the
  existing P24 pattern (`wazuh_source_org_map`) to more senders — not routing Collector V1's
  already-collected events into Wazuh after the fact. That is a Wazuh-side configuration change on
  the manager, explicitly out of scope for this release ("do not alter production Wazuh decoders,
  rules, or manager configuration during this task").

## Verified vs. assumed

- **Verified in this codebase**: the 4.8+ index naming convention, the existing tenancy resolvers,
  the `soar.py`/`ALERT_INGEST_TOKEN` forwarder, and that no prior code writes logs or events into
  Wazuh.
- **Not verified**: the exact Wazuh manager/indexer version running in any specific client
  deployment — `docs/runbooks/deploy-p13-p14-vms-platform.md` notes elsewhere that this is only
  ever confirmed live, post-deploy, never pinned in code. Collector V1 has no dependency on that
  number either way, since it never talks to Wazuh at all.
