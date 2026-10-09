# NovrSOC SOAR engine: deployment

The engine runs on the Wazuh manager (VPS 8). Wazuh's integratord calls it once for each alert at level 7 or above. It writes a case to Supabase and runs the response for the alert's tier. The platform's Cases and SOAR Automation pages read the results.

## 1. Database (once)

Run `backend/sql/2026-09-cases-soar.sql` in the Supabase SQL editor. **Do not use the SQL from the spec.** `public.playbooks` already exists, so the spec's seed insert fails, and that failure rolls back every table the script created.

## 2. Backend (Railway)

Set `SOAR_ENGINE_TOKEN` to a random value (`openssl rand -hex 32`). The engine sends this token when it calls `POST /api/soar/enrich`. While the variable is unset, the endpoint refuses every request.

## 3. Wazuh manager

```bash
pip3 install requests --break-system-packages

mkdir -p /opt/novrsoc
cp soar.py /opt/novrsoc/soar.py
cp soar.env.example /opt/novrsoc/soar.env      # then fill it in
chown root:wazuh /opt/novrsoc/soar.py /opt/novrsoc/soar.env
chmod 750 /opt/novrsoc/soar.py
chmod 640 /opt/novrsoc/soar.env

cp custom-novrsoc-soar /var/ossec/integrations/custom-novrsoc-soar
chown root:wazuh /var/ossec/integrations/custom-novrsoc-soar
chmod 750 /var/ossec/integrations/custom-novrsoc-soar

# integratord runs as `wazuh`, which cannot create files in /var/log
touch /var/log/novrsoc-soar.log
chown wazuh:wazuh /var/log/novrsoc-soar.log
```

Add this block to `/var/ossec/etc/ossec.conf` inside `<ossec_config>`:

```xml
<integration>
  <name>custom-novrsoc-soar</name>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Then restart the manager with `systemctl restart wazuh-manager`.

If TheHive's `custom-thehive` integration block is still in `ossec.conf`, remove it. Otherwise every alert is sent to both systems.

## 4. Test

```bash
set -a; . /opt/novrsoc/soar.env; set +a
echo '{"id":"manual-test-1","rule":{"level":10,"id":"5710","description":"Test alert","groups":["ssh"],"mitre":{"id":["T1110"],"tactic":["Credential Access"]}},"agent":{"id":"001","name":"RayneOps"},"data":{"srcip":"185.220.101.47"}}' \
  | sudo -u wazuh -E python3 /opt/novrsoc/soar.py
tail -n 20 /var/log/novrsoc-soar.log
```

The test creates a tier-2 case. It appears on **Cases**. Its actions are listed under **SOAR Automation → Tier 2**, and each shows SUCCESS, SKIPPED (with the reason) or FAILED. If you run the same test again, the engine logs "already has case" and does not create a duplicate. Change `"id"` to create a new test case.

## What each tier does

| Tier | Level | Actions |
| --- | --- | --- |
| 1 | 7–9 | Enrich IOC, then auto-close |
| 2 | 10–12 | Enrich IOC, block source IP (OPNsense), email the SOC mailbox. An analyst then reviews the case |
| 3 | 13+ | Enrich IOC, block IP, isolate agent (T1486/T1021/T1055/T1210 only), CISO email (plus a SOC email if `SOC_EMAIL` is a different inbox) |

Each action whose configuration is missing is skipped and logged with the reason. An action is logged as SUCCESS only when the remote system accepted it. Isolation is logged as REQUESTED, because the Wazuh manager accepting the command does not confirm that it ran on the endpoint.

## Alert forwarder (durable alert store)

The integration above only sees one alert at a time and keeps no state. The forwarder is a separate service that copies every alert into the NovrSOC alert store (`POST /api/ingest/alerts`), which feeds the Overview and Alerts pages. It runs `soar.py --forward`. It shares no code path with the response actions, so if forwarding fails, responses still run, and if a response fails, forwarding still runs.

How it works:

1. It reads alerts from the Wazuh Indexer (`WAZUH_ALERTS_INDEX`, default `wazuh-alerts-4.x-*`), oldest first, starting from its cursor.
2. It looks up each agent's groups through the Wazuh API (`GET /agents`, cached for 5 minutes). The backend uses the groups to decide which organisation owns the alert, using the map at `/api/admin/wazuh-group-map`. If an agent is in no mapped group, its alerts are rejected and recorded, not stored.
3. It sends alerts in batches of up to 100 with `ALERT_INGEST_TOKEN`. Network errors, 429 and 5xx responses are retried with backoff (2, 4, 8, 16 and 32 seconds). If a batch is still refused, the cursor does not move, and the next cycle replays from the same point.
4. The cursor (`SOAR_CURSOR_FILE`, default `/var/lib/novrsoc/ingest_cursor.json`) records the timestamp of the last alert the backend took. Each cycle also re-reads the last `SOAR_FORWARD_OVERLAP_SECONDS` (default 120), to catch alerts the indexer stored late. Resending is harmless because the backend ignores duplicates.
5. On its first run, with no cursor, it backfills the last `SOAR_BACKFILL_HOURS` (default 24).

Setup:

1. Set `ALERT_INGEST_TOKEN` to the same random value on Railway and in `/opt/novrsoc/soar.env` (`openssl rand -hex 32`). It must be different from `SOAR_ENGINE_TOKEN`.
2. In `soar.env`, also set `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASSWORD`. `WAZUH_VERIFY_TLS` applies to the indexer as well as the Wazuh API.
3. Install and start the service:

```bash
cp soar.py /opt/novrsoc/soar.py
cp novrsoc-forwarder.service /etc/systemd/system/
touch /var/log/novrsoc-forwarder.log && chown wazuh:wazuh /var/log/novrsoc-forwarder.log
systemctl daemon-reload && systemctl enable --now novrsoc-forwarder
journalctl -u novrsoc-forwarder -f
```

To replay a time range, for example after mapping a group whose alerts were rejected, stop the service, edit `last_forwarded_timestamp` in the cursor file (or delete the file to backfill again), and start it.

Unit tests (no network): `cd infra/soar && python -m unittest test_forwarder -v`.
