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
## Reaching Wazuh detection too (Sprint 3, optional — two ways, pick one per device)

A site that wants a device's logs BOTH stored in NovrSOC (Collector V1) AND actually evaluated by
Wazuh's own rules has two options. Neither alters live Wazuh infrastructure; neither is required
— without either, Collector V1 works exactly as described above, honestly storing unscored logs.

### Option A (recommended): point the device at both destinations directly

The device itself (firewall, switch, etc.) sends syslog to **two** destinations: the Collector V1
appliance (as already documented in `docs/collector-v1/LINUX_SYSLOG_ONBOARDING.md`) and the Wazuh
manager's existing syslog listener (the P24 pattern — `docs/runbooks/deploy-p24-wazuh-tenancy.md`'s
"Syslog listener" section), independently and in parallel. Most syslog clients support more than
one destination natively (e.g. multiple `<remote>`/`syslog server` entries); where a device truly
cannot, a local `socat`/firewall port-mirror rule at the device's own network edge duplicates the
UDP stream to both addresses — outside NovrSOC entirely, nothing in this repository changes.

This is the recommended option because it needs **zero new code and nothing newly unverified**:
Wazuh receives the exact original wire-format syslog packet, byte for byte, through the identical
path P24 already proved; Collector V1 receives its own independent copy through its own already-
tested gateway. Source identity and tenant attribution are preserved because each path keeps its
own existing resolution (`wazuh_source_org_map` for Wazuh's copy, the collector's bound
organisation for NovrSOC's copy) — neither path's logic changes to make this work.

### Option B: an optional Vector-side relay, for a device that genuinely cannot send twice

`infra/novrsoc-collector/config/vector.toml` includes a **disabled-by-default**, commented-out
`[sinks.wazuh_relay]` block that re-emits received syslog to the Wazuh manager's syslog port as a
second Vector sink, for the rare device that cannot be configured with two destinations itself.
Enabling it needs no Wazuh-side change (it sends to the same already-open syslog listener P24
documents) and no NovrSOC backend change — it is pure appliance-side Vector configuration.

**Explicitly unverified, stated rather than hidden**: the relay reconstructs an RFC 3164-shaped
syslog line from Vector's already-parsed fields (priority, timestamp, hostname, message) in VRL,
because Vector's `syslog` source does not retain the original raw wire bytes once parsed. This
reconstruction has not been validated against a live Wazuh decoder in the environment this was
built in (no Docker/Vector/Wazuh available — see the appliance README's "Known limitations").
Before relying on it: enable it, send one test event, and check the indexer
(`GET wazuh-alerts-4.x-*/_search?q=agent.id:000`) decodes it as cleanly as a directly-sent event —
the exact same live-verification step `deploy-p24-wazuh-tenancy.md` already asks for its own
decoder. If the reconstruction doesn't decode cleanly, use Option A instead — it has no such risk.

## Verified vs. assumed

- **Verified in this codebase**: the 4.8+ index naming convention, the existing tenancy resolvers,
  the `soar.py`/`ALERT_INGEST_TOKEN` forwarder, and that no prior code writes logs or events into
  Wazuh.
- **Not verified**: the exact Wazuh manager/indexer version running in any specific client
  deployment — `docs/runbooks/deploy-p13-p14-vms-platform.md` notes elsewhere that this is only
  ever confirmed live, post-deploy, never pinned in code. Collector V1 has no dependency on that
  number either way, since it never talks to Wazuh at all. Option B's VRL syslog reconstruction
  (above) is separately, explicitly unverified against a live decoder — Option A carries no such
  risk, which is why it's the recommended path.
