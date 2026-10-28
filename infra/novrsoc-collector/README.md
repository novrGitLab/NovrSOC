# NovrSOC Collector V1

A per-organisation log-collection appliance: Vector receives syslog (TCP/UDP/TLS) from client-site
devices, buffers it on disk, and forwards it over authenticated HTTPS to NovrSOC's collector
ingestion gateway. A sidecar reports real throughput/health metrics back as a heartbeat.

**Status: built and unit-tested against a fake backend in this repository. Not deployed to any
client environment, not run against a real Vector/Docker instance (no Docker engine was available
in the environment this was developed in — see "Known limitations" below). Validate locally with
`scripts/validate-config.sh` and a real `docker compose up` before deploying to any client site.**

This does **not** give NovrSOC full endpoint detection and response. It collects and stores raw
logs from whatever sources you point at it; detection logic (rules, correlation, scoring) is not
part of Collector V1 — see the main delivery report's "What this does not do" section.

## What this is not

- **Not a Wazuh agent, and not a Wazuh ingestion path.** Collected logs land in NovrSOC's own
  `collector_log_events` table, never in Wazuh and never scored as a Wazuh-style "alert" — see
  `backend/sql/2026-11-12_p31_collector_v1.sql`'s header for why. If you also run Wazuh agents at
  the same site, that stays entirely separate; this appliance changes nothing about it.
- **Not a Windows Event Forwarding server.** Vector does not implement Microsoft's native WEF
  subscription protocol. See `docs/collector-v1/WINDOWS_EVENT_FORWARDING.md` for how a real
  Windows Event Collector bridges into this appliance (as an ordinary syslog sender).

## 1. Enroll the collector in NovrSOC first

Staff (super_admin or soc_manager) → Collector Management → New collector → name it. The response
shows an enrollment token **exactly once**:

```
NOVRSOC_COLLECTOR_TOKEN=<collector-id>.<secret>
```

There is no way to view it again. If it's lost before you paste it into `.env`, use "Rotate" in
Collector Management to issue a new one (this invalidates the old one immediately).

## 2. Configure

```bash
cp .env.example .env
# Fill in NOVRSOC_COLLECTOR_TOKEN (from step 1) and NOVRSOC_BACKEND_URL.
```

Review `config/vector.toml` — the three syslog sources (TCP 6514, UDP 5514, TLS 6515) are enabled
by default; comment out any you don't need. See `examples/example-syslog-source.toml` for what to
point a sending device at, and when you'd add a device-specific source instead of using the shared
ones.

For TLS syslog, place your certificate and key under `./tls/` (`collector.crt`, `collector.key`,
and `ca.crt` if you'll require client certificates — `NOVRSOC_SYSLOG_TLS_VERIFY_CLIENT=true`).

## 3. Validate, then start

```bash
./scripts/validate-config.sh   # runs `vector validate` inside the pinned image — no listener starts
./scripts/start.sh             # validates again, then docker compose up -d
```

`start.sh` refuses to run if `.env` is missing or `NOVRSOC_COLLECTOR_TOKEN` isn't filled in.

Check it's actually enrolled and connected: NovrSOC → Collector Management → this collector's
status should move from "enrolling" to "connected" within one heartbeat interval (60 s by
default) of the first successful start.

```bash
docker compose logs -f           # both vector and heartbeat
docker compose ps                # vector should show "healthy" after ~10s
```

## 4. Stop

```bash
./scripts/stop.sh                # keeps the disk buffer — anything not yet forwarded resumes on next start
./scripts/stop.sh --volumes       # also deletes the buffer volume (any unforwarded events are lost)
```

## Upgrade

1. Pull this directory's latest `config/vector.toml` and `docker-compose.yml` (the image tag is
   pinned in `docker-compose.yml` — bump it deliberately, never implicitly via `:latest`).
2. `./scripts/validate-config.sh` against the NEW image tag before touching the running appliance.
3. `docker compose pull && docker compose up -d` — the disk buffer volume is untouched by an
   image upgrade, so anything queued survives.
4. Confirm in NovrSOC: Collector Management → this collector's "Version" column should show the
   new Vector version within one heartbeat interval, and "Last heartbeat" should stay current
   through the restart (a few seconds' gap is normal).

## Rollback

1. Edit `docker-compose.yml`'s `image:` line back to the previous tag.
2. `./scripts/validate-config.sh` (confirms the previous image still accepts the current config —
   if you also changed `config/vector.toml` in the same release, revert that file too, in the
   same step, not separately).
3. `docker compose up -d`.
4. Nothing on the NovrSOC side needs rolling back: the backend's ingestion gateway and schema are
   additive (phase P31) and were never version-gated to one Vector release.

## Image provenance

`timberio/vector:0.60.0-debian` was confirmed as Vector's current stable release tag directly
against `vector.dev`'s own installation docs and the `vectordotdev/vector` GitHub releases page at
the time this was written (2026-10-28) — not guessed. Re-confirm against those same two sources
before bumping the version in an upgrade. `curlimages/curl:8.11.1` (the heartbeat sidecar) is the
official, minimal curl image; no Vector-specific reason to use a different tag — bump it on its
own normal release cadence.

## Known limitations (stated, not hidden)

- **Not run against a live Vector instance.** No Docker engine was available in the development
  environment, so `docker compose up`, `vector validate`, and real syslog delivery have not been
  executed here. The end-to-end demonstration in the main delivery report uses the real Express
  gateway code (not a mock) against a fake-but-faithful database, which exercises the backend half
  of this system genuinely — it does not exercise Vector itself. Run `scripts/validate-config.sh`
  and a real local `docker compose up` before any client deployment.
- **Heartbeat metric names are Vector's long-documented `internal_metrics` counters**
  (`vector_component_received_events_total` etc.) but have not been confirmed against a live
  `/metrics` scrape in this environment either — `scripts/heartbeat.sh`'s header says exactly what
  to check if your Vector version reports differently.
- **No TLS client-certificate verification by default** (`NOVRSOC_SYSLOG_TLS_VERIFY_CLIENT=false`)
  because most legacy/agentless syslog senders cannot present one — enable it only once your
  fleet's senders support it.
