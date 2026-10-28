# Collector V1 — Docker runtime & end-to-end validation results

## What this session actually verified vs. what still needs a real run

**No Docker engine and no WSL distribution exist in this environment** (checked directly:
`docker --version` → command not found; `wsl --list` → no installed distributions; no Docker
Desktop install directory). **This session also has no production NovrSOC login credentials** —
nothing was fabricated or guessed to work around either gap. The table below states plainly which
rows are real and which are the documented procedure for whoever runs
`DOCKER_VALIDATION_RUNBOOK.md` next.

| # | Item | This session | Real runtime result |
|---|---|---|---|
| 1 | Inspect `infra/novrsoc-collector/` | **Done** — see "Configuration review" below | — |
| 2 | Docker availability check | **Done — confirmed unavailable**, documented, not worked around | — |
| 3 | Vector startup / syslog TCP+UDP / parsing / buffering / outbound HTTPS / heartbeat metrics / restart recovery | Not run (needs Docker) | _pending — fill in after running the runbook_ |
| 4 | Dedicated test collector identity | Not enrolled (needs a staff login this session doesn't have) | _pending_ |
| 5 | Synthetic test syslog events through a real Vector container | Not sent (needs #3+#4) | _pending_ |
| 6 | Events appear under the correct org, in `collector_log_events` and the dashboard | Not checked live. **The code path is covered by a real test** — see below | _pending for the live check_ |
| 7 | Network interruption / recovery / duplicates / revocation | Not run live. **Duplicate handling and revocation are both covered by real tests against the actual route code** (not Docker, but not fabricated either) | _pending for the live network-outage timing_ |
| 8 | Cross-tenant isolation | Not checked live. **Covered by a real test against the actual route code** | _pending for the live check_ |
| 9 | Document results | This file is the template — fill in the right-hand column after running the runbook | |
| 10 | Run backend/frontend tests, commit fixes | **Done this session** — see "Regression" below | — |

## Configuration review (this session, real)

Re-validated fresh, not assumed from memory:
- `config/vector.toml` — valid TOML (Python `tomllib`), sources/transforms/sinks enumerate exactly
  as expected (`syslog_tcp`, `syslog_udp`, `syslog_tls`, `internal_metrics` → `to_novrsoc` →
  `novrsoc_events`, `metrics_export`); the optional Wazuh-relay block is correctly excluded while
  commented out.
- `docker-compose.yml` — valid YAML (PyYAML), both services present, image tags still
  `timberio/vector:0.60.0-debian` and `curlimages/curl:8.11.1` as pinned.
- `scripts/*.sh` — all four pass `sh -n` (static syntax check).
- No code or config change was needed as a result of this review.

## What's genuinely tested, just not via Docker

These three line items above are **not simulated guesses** — they're exercised by real assertions
against the actual Express routes and service code (`backend/src/routes/__tests__/
collectors.test.ts`), using an in-memory PostgREST stand-in instead of a running container:
- Duplicate handling: `UNIQUE(collector_id, dedup_key)` resend test — passes.
- Revocation: a revoked collector's next heartbeat is refused with 401 — passes.
- Cross-tenant isolation: another organisation's staff get 404 on the test collector and never see
  it listed — passes.

This proves the **backend's** behavior is correct. It does not prove Vector itself starts,
receives real syslog, buffers through a real network drop, or recovers after a real restart —
those need the runbook run on a real Docker host.

## Regression (this session, real)

```
backend: npm test  → 799/799 pass (incl. the collector tests above)
backend: tsc --noEmit → clean
frontend: npm test → 84/84 pass
frontend: tsc --noEmit → clean
frontend: check-nav-routes.mjs → clean, 107 hrefs
frontend: production build → succeeds
```

No fixes were needed as a result of this session's review — nothing above surfaced a bug, so
nothing was committed.

## Next step

Run `docs/collector-v1/DOCKER_VALIDATION_RUNBOOK.md` on a real Ubuntu VM with Docker installed and
a staff login for enrollment, then replace the "_pending_" cells above with the real results.
