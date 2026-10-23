# Quarantine recovery and future mapping for agents 000, 011–014

**Status:** prepared, not run. Every step below needs approval. Nothing here has been run against production.

## Why these alerts are quarantined

The backend stores an alert only when the agent's Wazuh groups map to exactly one organisation (`wazuh_group_org_map`). The only mapping is `cybernovr` → `cybernovr`. As of 2026-10-23, the agents below were only in Wazuh's catch-all `default` group, or had no group at all (the manager). Their alerts are therefore quarantined as `unmapped_group`, with their full original rows kept.

| Agent | Name | Groups | Quarantined (2026-10-23) |
|---|---|---|---|
| 011 | DESKTOP-FBC0TFT | default | 299 |
| 012 | PARTYJOLLOF | default | 393 |
| 013 | Aliyat | default | 304 |
| 014 | Mac.lan | default | 22 |
| 000 | novrsoc-security (manager) | none | 144 |

Replay (`services/alertQuarantine.ts`) resolves ownership from the groups stored with each row (`['default']`). Moving the agents into a mapped group fixes future alerts, but releases none of the existing rows. That is what `sql/quarantine-recover-by-agent.sql` is for.

**Ownership is provisional (all five → `cybernovr`) until it is verified independently.** Confirm each host belongs to Cybernovr before step 4. The names PARTYJOLLOF, Aliyat and Mac.lan don't identify an owner by themselves.

## Files

| File | What it does |
|---|---|
| `sql/quarantine-preflight.sql` | Read only: counts by agent, reason and groups; names per agent id; manager-local vs syslog rows; organisations and group map; conflicts; whether the purge is scheduled; earliest purge risk; the exact expected counts for a cutoff |
| `sql/quarantine-recover-by-agent.sql` | One transaction, dry run by default. Releases the named agents' rows (received at or before a cutoff) into one organisation, writes a recovery log, then removes the released quarantine rows |
| `sql/quarantine-recovery-rollback.sql` | One transaction, dry run by default. Restores one recovery run from its log and removes only the alerts that run inserted |
| `sql/verify-quarantine-recovery.mjs` | Staging test of both scripts on a throwaway Postgres built from `backend/sql` |

## Retention: the deadline

`public.purge_alert_quarantine(14)` deletes quarantined rows received more than 14 days before it runs. The migration defines it, but schedules it only in a commented-out line (`30 3 * * *`, daily at 03:30 UTC). Preflight query 7 shows whether production has scheduled it.

- **Oldest row received:** 2026-10-15 14:36 UTC (agent 011).
- **Eligible for deletion from:** 2026-10-29 14:36 UTC.
- **If scheduled as in the migration's comment (03:30 UTC daily):** the first deletion is 2026-10-30 03:30 UTC. Later rows follow day by day.
- **If not scheduled:** nothing is deleted automatically.

## Future mapping (Wazuh manager — commands prepared, not run)

Use a dedicated group, so agents don't silently receive another group's shared agent configuration. Never map `default`: every newly enrolled agent joins it.

```bash
# Inspect (read only)
/var/ossec/bin/agent_groups -l                                  # groups and agent counts
for a in 011 012 013 014; do /var/ossec/bin/agent_groups -s -i $a; done
ls /var/ossec/etc/shared/                                        # what each group pushes to its agents

# 1. Create the group (empty agent.conf: it pushes nothing new)
/var/ossec/bin/agent_groups -a -g cybernovr-endpoints -q
cat /var/ossec/etc/shared/cybernovr-endpoints/agent.conf        # confirm empty <agent_config></agent_config>
```

2. Map the group **before** adding agents, so their new alerts are stored as soon as they move. In Settings → Wazuh Groups (super_admin), map `cybernovr-endpoints` to Cybernovr. Or:
   `PUT /api/admin/wazuh-group-map {"mappings":[{"wazuh_group":"cybernovr-endpoints","org_id":"cybernovr"}]}`

```bash
# 3. Add each agent. It keeps `default` (unmapped, so harmless); `default` + `cybernovr-endpoints` resolves to exactly one organisation.
for a in 011 012 013 014; do /var/ossec/bin/agent_groups -a -i $a -g cybernovr-endpoints -q; done
for a in 011 012 013 014; do /var/ossec/bin/agent_groups -s -i $a; done
```

4. Wait at least 5 minutes: the forwarder caches agent groups for 300 s.

**Reverse:** `/var/ossec/bin/agent_groups -r -i <id> -g cybernovr-endpoints -q` for each agent, then remove the mapping (`org_id: null`). The group can then be deleted with `agent_groups -r -g cybernovr-endpoints -q`.

## Manager (agent 000) ownership — proposed design (not implemented)

The manager has no group, so no group mapping can ever place its own events: syscheck, rootcheck, netstat and the like. With P24, syslog the manager receives from other devices is placed by sender IP (`wazuh_source_org_map`); manager-local events are still quarantined.

**Proposal:** an explicit, audited, single-row setting `wazuh_manager_owner (org_id, manager_name, set_by, set_at)`, managed only by super_admin at `/api/admin/wazuh-group-map/manager`.
- Ingest places an alert there only if **all** of these hold:
  - `agent.id = '000'`;
  - `location` is **not** an IP address (manager-local, never syslog);
  - `agent.name` equals `manager_name`, so a second manager or a cluster node can't inherit it.
- Replay applies the same rule. Unset means quarantined (fail closed). Clearing the setting is the reverse. Every change is audited.
- Not an environment variable: it needs an audit trail, has to be the same on every backend host, and should be reversible without a redeploy.

Until that exists, the manager's existing rows can be released with the recovery script, which already applies the same rule. New manager events will keep accumulating in quarantine.

## Production execution order

1. **Approve ownership** of 011–014 and 000, after independent verification.
2. **Preflight:** run `sql/quarantine-preflight.sql` in the Supabase SQL editor and save the output. Confirm:
   - query 2 shows one name per agent id;
   - query 3 shows no syslog (IP) rows for agent 000 that should go elsewhere;
   - query 5 shows no conflicts under another organisation;
   - query 7 shows the purge schedule.
3. **Backend:** deploy the 503 fix (`fix/ingest-quarantine-persistence`, on top of `9cda076`) to Render. It touches no schema. Confirm `/health` reports the new commit.
4. **Future mapping:** "Future mapping" steps 1–4 above. Then check that new alerts from 011–014 are stored, not quarantined: `SELECT agent_id, count(*) FROM alerts WHERE agent_id IN ('011','012','013','014') AND received_at > now() - interval '15 minutes' GROUP BY 1;`
5. **Recovery, dry run:** choose `cutoff` = the time step 4 completed. Run preflight query 9 with that cutoff, and put its counts into `expected`. Set the same cutoff in the script and run it with `dry_run` true. Expect `DRY RUN OK — rolled back. Would release N alert(s) …`, with the per-agent counts.
6. **Recovery, approved run:** set `dry_run` false and run it again. **Record the printed run id.**
7. **Optional:** `SELECT public.backfill_alert_network();` fills the P24 network columns for the recovered rows. It is safe to re-run.

## Rollback

| Step | Rollback |
|---|---|
| 3 (backend) | Render → the `9cda076` deploy → Rollback; `/health` shows `9cda0760e81e` |
| 4 (mapping) | Remove the agents from `cybernovr-endpoints`, and unmap the group |
| 6 (recovery) | `sql/quarantine-recovery-rollback.sql` with the run id: dry run first, then for real. It refuses if any recovered alert has since been triaged, assigned, noted or put in a case, because deleting the alert would cascade-delete its triage history. Handle those first |

Recovered alerts that the vendor export or Stellar push has already sent cannot be recalled by rollback.

## Post-deployment verification

- **Ingest:** forwarder log batches show `quarantined 0` for 011–014. `alert_ingest_rejects` gets no new `unmapped_group` rows for them.
- **Recovery:** the `cybernovr` alert count rises by the released count. Preflight query 1 shows no rows for 011–014 received before the cutoff. For 000, only syslog rows (if any) and events after the cutoff remain.
- **Spot check:** compare one recovered alert's `wazuh_alert_id`, `event_time` and `raw` with the same entry in `alert_quarantine_recovery_log.quarantine_row`.
- **Alerts page (Cybernovr):** the agents' alerts appear at their original times.
- **Persistence fix:** in staging, make `alert_quarantine` unavailable. An unmapped batch must get 503, and the forwarder's cursor must not move.

## Staging test

```bash
mkdir -p /tmp/pglite && (cd /tmp/pglite && npm init -y >/dev/null && npm i @electric-sql/pglite@0.2.17)
git show release/p24-wazuh:backend/sql/2026-10-29_p24_wazuh_sources.sql > /tmp/p24.sql   # production has P24 applied
node docs/runbooks/sql/verify-quarantine-recovery.mjs /tmp/pglite backend/sql /tmp/p24.sql
```

It covers dry run; the approved run (timestamps, ids, payload, organisation, an alert already stored); repeat runs; rollback (exact restore, removing only inserted alerts, no second rollback, refusal after triage, assignment, history or a case); and every abort condition (unknown or second organisation, count, name, ambiguous reason, mapped group, cross-organisation conflict, future cutoff, an insert failing mid-transaction).
