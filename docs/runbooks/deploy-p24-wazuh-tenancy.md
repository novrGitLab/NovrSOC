# Deploying P24: Wazuh tenancy, OPNsense syslog sources and firewall fields

**Status:** implemented and tested locally. **Not deployed.** Nothing here has run against Supabase, Railway, Vercel, the Wazuh manager or the indexer. Each stage needs approval.

## What this release does

| Area | Change |
|---|---|
| Tenancy (security) | Every route that reads the Wazuh indexer or Manager API directly is limited to the request organisation (`backend/src/lib/orgScope.ts`): agents whose groups map to it in `wazuh_group_org_map`, plus syslog senders mapped to it in `wazuh_source_org_map`. An agent whose groups map to two organisations belongs to neither; agent 000 (the manager) is nobody's endpoint. With ownership unresolvable the routes answer 503 and send no query. Covers `/api/wazuh/*`, `/api/threats/*`, `/api/mitre/*`, `/api/search`, `/api/notifications`, `/api/assets`, `/api/org-cti/*`, NovrAI telemetry, email-security "related SOC alerts", and the hourly MITRE job |
| Threat Management | No shared in-process alert list: look-up, triage and "create incident" re-read the alert inside the caller's scope, so one organisation can no longer act on another's alert |
| Response | Isolation is requested only for an agent the organisation owns, and is checked again when an approved isolation runs |
| OPNsense / agentless syslog | An agent-000 alert resolves to the organisation its sender address (`location`) is mapped to. Unmapped senders are quarantined as `unmapped_source` and replayed when a super_admin maps the address (Settings → Wazuh Groups → Syslog sources). Only IP addresses can be mapped |
| Firewall fields | Stored alerts gain `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `net_action`, `net_direction`, `net_interface`, `decoder_name`, `device_hostname`, extracted at ingest from the alert itself (before the 32 KB raw cap). `/api/alerts` filters by `action`, `ip`, `protocol`, `port`, `firewall=1` |
| Client portal | New `/api/client/secops/{summary,alerts,agents}` (permission `secops:client`, portal_user), used by the client Dashboard, Security Alerts and Digital Assets pages, which used to get 403 |
| Frontend | Alert Queue shows network fields and firewall filters; Alert Queue, SOC Overview and client Dashboard refresh while visible (30 s / 60 s); stale banner uses the backend's `ALERT_STALE_MINUTES`; fabricated values removed (manager agent `000` with invented status/OS, "default" group fallback, customer counts of 0, the portal's threat level, "Intelligence Feed: Active" and stale install commands) |

**Unchanged:** the forwarder (`infra/soar/soar.py`), the ingest token, authentication, and every existing permission. One permission is added (`secops:client`, portal_user only).

## Order

1. Supabase SQL → 2. backend (Railway) → 3. frontend (Vercel) → 4. map the OPNsense sender → 5. checks.

The backend works before the SQL (no source mappings, no network columns — OPNsense alerts stay quarantined), but run the SQL first.

### What this release ships (checked 2026-10-22)

Production runs `c0fa465` (P19; `/health` reports it). P24 is written on top of `main` (`adc82f3`), so the backend release is **`adc82f3` + the P24 commit** and also carries P20, P21, P22 (OpenVAS policy, off by default) and P23 (CNII National), none of which is deployed yet. It supersedes the separate `deploy/openvas-policy` branch.

| Migration | Production state (read-only probe, 2026-10-22) |
|---|---|
| P20 `2026-10-26_p20_vms_insights.sql` | applied (`vms_risk_snapshots.risk_mean` present) |
| P21 `2026-10-27_p21_staff_org_assignments.sql` | **not applied** (`staff_org_assignments` missing). Run it before the backend. Without it analysts are limited to their own organisation (fail closed) |
| P24 `2026-10-29_p24_wazuh_sources.sql` | applied (all columns and `wazuh_source_org_map` present). Confirm the quarantine reason check in the SQL editor (query below) |

### Live data state (2026-10-22, counts only)

- **Ingestion has stopped:** the newest stored alert was received 2026-10-16 07:21 UTC, and nothing has been quarantined since either. Fix the forwarder or ingest path first (see "Restore ingestion"); no deployment makes alerts appear while it is stopped.
- 1 group mapping (`cybernovr` → `cybernovr`), 0 sender mappings, 1 organisation.
- 282 quarantined: 278 from agents only in Wazuh's catch-all `default` group, 4 manager-internal (`netstat listening ports`, `rootcheck`; correctly unmappable). No OPNsense alert has reached NovrSOC yet.

### Restore ingestion (on the Wazuh manager)

```bash
systemctl status novrsoc-forwarder --no-pager
journalctl -u novrsoc-forwarder --since "2026-10-16" --no-pager | tail -50   # 401 = ALERT_INGEST_TOKEN mismatch; indexer errors = WAZUH_INDEXER_*; network = NOVRSOC_BACKEND
cat /var/lib/novrsoc/ingest_cursor.json
```

### The 278 `default`-group alerts

Do **not** map `default` to an organisation: every newly enrolled agent joins `default`, so a future client's agents would land in Cybernovr. Put Cybernovr's agents in the `cybernovr` group instead (`/var/ossec/bin/agent_groups -a -i <agent id> -g cybernovr -q`), then replay the quarantine (Settings → Wazuh Groups → Replay now). Quarantine holds alerts 14 days.

### Syslog listener

The sender address decides ownership, so the manager must accept syslog only from the firewall over WireGuard. In `/var/ossec/etc/ossec.conf`: a `<remote>` block with `<connection>syslog</connection>`, `<protocol>udp</protocol>`, `<port>514</port>`, `<allowed-ips>10.0.0.4</allowed-ips>` and `<local_ip>` set to the manager's WireGuard address.

## 1. Supabase

Run `backend/sql/2026-10-29_p24_wazuh_sources.sql` in the SQL editor (production project). Additive and idempotent. It was applied twice to a throwaway Postgres built from the alert-store migrations: it applies, the second run changes nothing, existing quarantine rows are kept, and the backfill fills a pre-P24 OPNsense row correctly and leaves invalid values NULL. Check:

```sql
SELECT count(*) FROM information_schema.columns WHERE table_name = 'alerts'
  AND column_name IN ('src_ip','src_port','dst_ip','dst_port','protocol','net_action','net_direction','net_interface','decoder_name','device_hostname');  -- 10
SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'public.alert_quarantine'::regclass AND contype = 'c';  -- lists unmapped_source
SELECT relrowsecurity FROM pg_class WHERE relname = 'wazuh_source_org_map';  -- true
```

Optional, off-peak: `SELECT public.backfill_alert_network();` fills the new columns for alerts stored before this release.

## 2. Backend (Railway)

No new environment variables. `WAZUH_PASSWORD` (the name in `.env.example`) is now accepted everywhere alongside `WAZUH_API_PASSWORD`. The backend needs, as before:

- `WAZUH_HOST`, `WAZUH_PASSWORD` — Manager API; agent groups for ownership come from `GET /agents`. Without it, ownership falls back to the indexer's `wazuh-monitoring-*` snapshot.
- `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`.
- `ALERT_INGEST_TOKEN` (forwarder).

## 3. Frontend (Vercel)

No new variables.

## 4. Map the OPNsense sender

1. Confirm the address Wazuh records for the firewall: in the indexer, `GET wazuh-alerts-4.x-*/_search?q=agent.id:000 AND decoder.name:<your decoder>&size=1` → `_source.location` (expected `10.0.0.4`, the firewall's WireGuard address).
2. Settings → Wazuh Groups → Syslog sources: enter that address, the device name and the organisation → **Map sender**. Quarantined alerts from it are replayed at once (the page reports how many).
3. UDP 514 must be reachable only through WireGuard, with the firewall as the only peer allowed that address — the sender address is the ownership key.

## 5. Checks

- Platform Health: "Alert ingestion" up; "Alert quarantine" no longer lists the sender.
- Alerts page, filter **Firewall**: OPNsense events with action, direction, interface, source/destination and protocol.
- As an analyst not assigned to another organisation: `X-Org-Id` for it → 403 on `/api/wazuh/alerts`.
- Client portal (portal_user): Dashboard, Security Alerts and Digital Assets load with the organisation's own data.

## Needs live verification

- The custom OPNsense decoder's field names. The extractor (`backend/src/lib/alertNetwork.ts`) reads `data.action`, `data.direction|dir`, `data.interface|iface|ifname|real_interface`, `data.protocol|proto`, `data.srcip/dstip/srcport/dstport`. Compare with one real alert; add a name to the candidate list if different.
- Field types in the indexer template (`data.srcip` keyword vs ip), which the network-connections and attack-origins prefix queries rely on.
- Whether `wazuh-monitoring-*` is populated (only used when the Manager API is unreachable).

## Rollback

Redeploy the previous backend and frontend. The SQL needs no rollback: its columns and table are unused by the previous code. To undo a sender mapping, Unmap it on the same page.
