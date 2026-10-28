# Collector V1 — Docker runtime & end-to-end validation runbook

**Status: not yet executed.** This session has neither a Docker engine nor production NovrSOC
credentials, so nothing in this document has been run — see the final report in
`docs/collector-v1/DOCKER_VALIDATION_RESULTS_TEMPLATE.md`'s header for exactly what WAS verified
instead (config review, syntax validation, the fake-database test suite). This runbook is the
exact procedure for whoever runs it next, with a dedicated organisation, a disposable test
collector, and synthetic events that are unmistakably test data throughout.

**Never print, log, or commit the real enrollment token.** It goes in `.env` only (already
gitignored — confirmed by `infra/novrsoc-collector/.gitignore`). If it appears in a terminal
scrollback you plan to share, redact it first.

## 1. Provision an Ubuntu test VM

Ubuntu 22.04 LTS, 2 vCPU / 2 GB RAM is enough (Vector itself is light; this is a short-lived test
box, not a production appliance host). Outbound HTTPS to the NovrSOC backend; nothing needs to be
reachable from the internet.

```bash
sudo apt-get update && sudo apt-get upgrade -y

# Docker Engine + Compose plugin (official repo, not the distro's often-outdated docker.io package)
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Run docker without sudo (log out/in once after this)
sudo usermod -aG docker "$USER"

docker --version          # expect: Docker version 2x.x.x
docker compose version    # expect: Docker Compose version v2.x.x

# Tools used later in this runbook to send and inspect syslog
sudo apt-get install -y netcat-openbsd jq
```

Clone the repo (or copy just `infra/novrsoc-collector/`) onto the VM:

```bash
git clone https://github.com/novrGitLab/NovrSOC.git
cd NovrSOC/infra/novrsoc-collector
```

## 2. Enroll a dedicated, disposable test collector

**Use NovrSOC's own internal organisation (not a real client's), and name the collector so its
purpose and disposability are obvious:**

1. Sign in to NovrSOC as `super_admin` or `soc_manager`.
2. Collector Management → New collector → name it exactly `docker-validation-TEMPORARY-<today's
   date>` (e.g. `docker-validation-TEMPORARY-2026-10-29`).
3. Copy the one-time enrollment token **directly into `.env`** on the test VM — never into a
   terminal command you'll run again, a chat message, a screenshot, or a commit.

```bash
cp .env.example .env
nano .env   # paste NOVRSOC_COLLECTOR_TOKEN and NOVRSOC_BACKEND_URL, save, exit
chmod 600 .env
```

### For step 8 (cross-tenant isolation): a second organisation

Org isolation needs two distinct organisations. If a dedicated sandbox/test organisation already
exists, enroll a **second** test collector there (e.g. `docker-validation-TEMPORARY-org-b`) and
run a second appliance instance (a second `docker compose -p collector-b ...` project, or a second
VM) pointed at it with its own `.env`. If no second test organisation exists, coordinate with
whoever administers organisations to create a short-lived one for this test, and remove it
afterward — do not run this test against a real client's second organisation.

## 3. Validate config, then start — Docker runtime checks

```bash
./scripts/validate-config.sh   # runs `vector validate` inside the pinned image — record its exact output
./scripts/start.sh
docker compose ps              # expect both services "Up"; vector "healthy" within ~10s
docker compose logs vector --tail 50
docker compose logs heartbeat --tail 20
```

**Record for each:**
- Did `validate-config.sh` pass without edits? If not, what did it flag, and what fixed it?
- Did `vector` reach `healthy`? How long did it take?
- Did `heartbeat` log a successful send within the first `HEARTBEAT_INTERVAL_SECONDS` (default 60s)?
- In NovrSOC → Collector Management → the test collector: did its status move from "enrolling" to
  "connected"? How long after `start.sh` did that take?

## 4. Syslog reception (TCP, UDP, TLS) — synthetic, clearly labelled events

Every test message below includes `TEST-EVENT-DOCKER-VALIDATION` and a timestamp, so it is
unmistakable in logs, in `collector_log_events`, and in anyone's search results later.

```bash
TS=$(date -u +%Y%m%dT%H%M%SZ)

# UDP (RFC 3164)
echo "<134>$(date '+%b %d %H:%M:%S') test-host testtool: TEST-EVENT-DOCKER-VALIDATION udp $TS" | nc -u -w1 localhost "${SYSLOG_UDP_PORT:-5514}"

# TCP
echo "<134>$(date '+%b %d %H:%M:%S') test-host testtool: TEST-EVENT-DOCKER-VALIDATION tcp $TS" | nc -w1 localhost "${SYSLOG_TCP_PORT:-6514}"

# TLS (self-signed cert accepted for this test only; real deployments use a real CA-issued one)
mkdir -p tls && openssl req -x509 -newkey rsa:2048 -keyout tls/collector.key -out tls/collector.crt -days 1 -nodes -subj "/CN=docker-validation-test"
cp tls/collector.crt tls/ca.crt
docker compose restart vector   # picks up the new cert files
echo "<134>$(date '+%b %d %H:%M:%S') test-host testtool: TEST-EVENT-DOCKER-VALIDATION tls $TS" | openssl s_client -connect localhost:"${SYSLOG_TLS_PORT:-6515}" -quiet 2>/dev/null
```

**Record:** did `docker compose logs vector` show each event being received and forwarded
(`vector_component_received_events_total` / `...sent_events_total` climbing in
`curl -s http://localhost:9598/metrics | grep novrsoc`, from inside the compose network — e.g.
`docker compose exec heartbeat sh -c "curl -s http://vector:9598/metrics | grep novrsoc"`)?

## 5. Persistent buffering and outbound HTTPS delivery

Already exercised by step 4 if the backend accepted them — confirm durably:

```bash
# A real delivery happened if curl's own metrics/logs show it, not just that Vector accepted the syslog line.
docker compose exec heartbeat sh -c "curl -s http://vector:8686/health"   # expect: a 200/healthy response
```

Then confirm in NovrSOC (see step 6) that the three events actually reached
`collector_log_events` — that is the real proof of "outbound HTTPS delivery," not just that Vector
accepted them locally.

## 6. Confirm correct organisation and visibility

As a staff member of the test collector's organisation:

- Collector Management → the test collector → **Diagnostics**: the three
  `TEST-EVENT-DOCKER-VALIDATION` messages should appear, each tagged `syslog_tcp`/`syslog_udp`/
  `syslog_tls` under **Connected sources**.
- In the Supabase SQL editor (read-only check, no write):
  ```sql
  SELECT org_id, collector_id, source_key, host, message, received_at
  FROM collector_log_events
  WHERE message LIKE '%TEST-EVENT-DOCKER-VALIDATION%'
  ORDER BY received_at DESC;
  ```
  Confirm `org_id` is exactly the organisation the test collector was enrolled under — never a
  different one.

## 7. Network interruption, recovery, duplicates, revocation

**Outage + recovery (persistent buffering under real network loss):**
```bash
docker network disconnect novrsoc-collector_default novrsoc-collector-vector   # or: sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP, then revert later
echo "<134>$(date '+%b %d %H:%M:%S') test-host testtool: TEST-EVENT-DOCKER-VALIDATION outage $(date -u +%Y%m%dT%H%M%SZ)" | nc -u -w1 localhost "${SYSLOG_UDP_PORT:-5514}"
sleep 30
docker compose logs vector --tail 20   # expect retry/backoff log lines, not a dropped event
docker network connect novrsoc-collector_default novrsoc-collector-vector      # or revert the iptables rule
sleep 15
# Then repeat step 6's SQL check — the "outage" event should now be present, received late but not lost.
```

**Duplicate handling (resend the exact same event):**
```bash
MSG="<134>$(date '+%b %d %H:%M:%S') test-host testtool: TEST-EVENT-DOCKER-VALIDATION dup-check fixed-id-1"
echo "$MSG" | nc -u -w1 localhost "${SYSLOG_UDP_PORT:-5514}"
sleep 3
echo "$MSG" | nc -u -w1 localhost "${SYSLOG_UDP_PORT:-5514}"   # byte-for-byte identical
```
Confirm via the SQL query in step 6: exactly **one** row for `fixed-id-1`, not two — the
`UNIQUE (collector_id, dedup_key)` constraint should have absorbed the resend.

**Restart recovery:**
```bash
docker compose restart vector
sleep 10
docker compose ps   # expect "healthy" again
```
Confirm the collector's status in NovrSOC returns to "connected" within one heartbeat interval,
and that no event sent before the restart was lost (re-run step 6's query).

**Revocation:**
1. Collector Management → the test collector → **Revoke**.
2. On the VM: `docker compose logs heartbeat --tail 5` — the next heartbeat attempt should fail.
3. Confirm the backend's response was **401**, not a crash: temporarily run
   `docker compose exec heartbeat sh -c "curl -s -o /dev/null -w '%{http_code}\n' -X POST \"$NOVRSOC_BACKEND_URL/api/collectors/ingest/heartbeat\" -H \"Authorization: Bearer $NOVRSOC_COLLECTOR_TOKEN\""`.

## 8. Cross-tenant isolation

As a staff member of the **second** organisation (or any organisation other than the test
collector's own): confirm `GET /api/collectors` never lists the test collector, and
`GET /api/collectors/<test-collector-id>` returns 404 — this mirrors
`backend/src/routes/__tests__/collectors.test.ts`'s own tenant-isolation tests, now against the
real deployed backend and a real collector instead of a fake database.

## 9. Record results

Fill in `docs/collector-v1/DOCKER_VALIDATION_RESULTS_TEMPLATE.md` (below) with pass/fail, exact
timings (how long to "connected," how long an outage-buffered event took to arrive once the
network came back), and any Vector config changes that were needed to make any of the above work
— those changes should be reflected back into `config/vector.toml` and this runbook, not left as
tribal knowledge on the test VM.

## 10. Afterward

```bash
./scripts/stop.sh --volumes   # discards the disk buffer too — this is a disposable test instance
```
Then in NovrSOC: **Revoke** the test collector if not already done in step 7, and ask whoever
administers organisations to remove the temporary second test organisation from step 2, if one was
created solely for this test.
