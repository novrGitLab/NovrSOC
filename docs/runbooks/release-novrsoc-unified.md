# Release: NovrSOC unified (`release/novrsoc-unified`)

One branch with every completed, tested line of work:

- the Render production release;
- Threat Intelligence V1;
- P24 Wazuh tenancy and OPNsense.

Built in an isolated worktree. Nothing was deployed, no migration was applied, and no other developer's files were changed.

## 1. Branch history

| Commit | What |
|---|---|
| `16b3ffe` (baseline) | `deploy/novrsoc-render` head: production `9cda076` plus the ingest-acknowledgement fix and the quarantine recovery runbook. It is already on GitHub. The brief named `9cda076` as the baseline, but `16b3ffe` contains it and adds a reviewed fix that production needs, so the newer head is used. |
| `6f9916c` | Merge of `feat/ti-v1` (`336589d`): Threat Intelligence V1 (P25). It merged cleanly. |
| `0485195` | Merge of `release/p24-wazuh` (`02fb025` P24, `94c87b6` forwarder checkpoint). Three conflicts were resolved by hand (section 3). |
| this commit | This manifest. |

**Contents by module.** Each row is a feature commit carried in the branch:

| Module | Commits |
|---|---|
| VMS redesign and APIs | P20 `7f5c50b`, `1ea9529`, `cf7f53a`; P21 `c1425f5`, `00e977a` |
| OpenVAS ingestion and authorization policy, off by default | P22 `1b78d58` |
| CNII national drill-down | P23 `e79f382` |
| OpenVAS data-path tests and worker 1.8.1 runbook | `adc82f3` |
| Render deployment config | `9cda076` |
| Ingest acknowledgement and quarantine recovery | `16b3ffe` |
| Threat Intelligence V1 | `336589d` |
| Wazuh tenancy, OPNsense sources, firewall fields, client SecOps | `02fb025` |
| Forwarder checkpoint (`soar.py`) | `94c87b6`. Its forwarder is byte-identical to the one already in `16b3ffe`. |

## 2. Branches reviewed but not merged

| Branch | Why |
|---|---|
| `main` (`adc82f3`) | Fully contained in the baseline. |
| `deploy/openvas-policy` (`eb0aa53`) | Its policy code and `.env.example` lines are identical in the baseline; nothing to add. |
| `backup/wazuh-tenancy-wip` | Same commit as `release/p24-wazuh` (`94c87b6`). |
| `fix/ingest-quarantine-persistence` | Same commit as the baseline (`16b3ffe`). |
| Uncommitted files in the shared checkout | Identical to `release/p24-wazuh` (P24's author). Nothing newer and unreviewed exists. Untouched. |

**Excluded:**

- `worker-1.8.1.py` at the shared checkout root, a local copy;
- `soar-patched.py` and `__pycache__/` in the `novr-render` worktree, which are not mine and untracked.

## 3. Conflict resolution (P24 × production ingest fix)

| File | How it was resolved |
|---|---|
| `backend/src/routes/ingest.ts` | Both behaviours kept:<br>• Production rule: answer 503 unless every quarantined row is confirmed stored.<br>• P24 fallback: before the P24 SQL, store `unmapped_source` as `unmapped_group`.<br>The header keeps both the syslog / network-field notes and the acknowledgement contract. |
| `backend/src/routes/__tests__/alertQuarantine.test.ts` | All production acknowledgement tests and P24's resend test kept. |
| `infra/soar/README.md` | P24's wording, a superset (adds the agentless-syslog paragraph). |

The auto-merged files changed by both lines of work (`backend/src/index.ts`, `frontend/src/config/nav.ts`) were checked:

- `index.ts` has both the `/taxii2` and `/api/client/secops` mounts.
- `nav.ts` has the eight Threat Intelligence pages and P24's client-portal entries.
- No Threat Intelligence code reads the Wazuh indexer or Manager API directly, so P24's organisation scoping is not bypassed.

## 4. Validation (this branch)

| Check | Result |
|---|---|
| Backend `tsc --noEmit`, `npm run build` | pass |
| Backend tests | **640: 637 pass, 0 fail, 3 skipped**. Covers P24 tenancy and OPNsense, TI V1, quarantine acknowledgement, P21 analyst assignment, VMS, CNII, Email Security and auth. |
| Organisation isolation | in the suite above: P24 tenancy, `/api/ti` matches and map, the AI question context, TAXII (no organisation data), P21 |
| STIX: OASIS `stix2-validator` 3.2.0 | pass, 0 errors (only deliberate SHOULD-level warnings) |
| TAXII: OASIS `taxii2-client` 2.3.0 against `/taxii2/` | pass |
| Forwarder unit tests (`infra/soar`) | 23 OK |
| Worker unit tests (`infra/vms-worker`) | 64 OK |
| Frontend `tsc`, tests | pass; 15/15 |
| Navigation check | 97 nav links and 21 VMS pages resolve |
| Frontend production build | pass (125 pages) |
| `NEXT_PUBLIC_BACKEND_URL=https://novrsoc.onrender.com` | inlined; 0 Railway references |
| Frontend lint, whole `src` | 31 problems (18 errors, 13 warnings), the same set as production, all in files unchanged since `9cda076`. P24 and TI add none. |

## 5. Database migrations

Apply in this order, in the Supabase SQL editor, with approval. All are additive and idempotent.

| Migration | Production state (last read-only check, 2026-10-22) | Needed by |
|---|---|---|
| `2026-10-26_p20_vms_insights.sql` | applied | VMS dashboard |
| `2026-10-27_p21_staff_org_assignments.sql` | **not applied** | Analysts' cross-organisation access. Without it analysts are limited to their own organisation (fail closed). |
| `2026-10-29_p24_wazuh_sources.sql` | applied | OPNsense source mapping, firewall fields. Re-running is harmless. |
| `2026-10-30_p25_ti_v1.sql` | **not applied** (new) | Threat Intelligence V1: markings, `stix_uuid`, reports, hosting, TAXII clients. Needs the `uuid-ossp` extension (the file creates it). |

## 6. Environment

`render.yaml` and `backend/.env.example` list every variable.

- **New in this release, all optional:**
  - `MISP_CA_CERT`;
  - `MISP_WRITE_ENABLED`, fixed to `false`;
  - `THREATFOX_API_KEY`;
  - `TI_AI_PROVIDER`, `AI_PROVIDER`;
  - `OLLAMA_URL`, `OLLAMA_API_KEY`, `OLLAMA_CA_CERT`, `OLLAMA_MODEL`;
  - `TI_GEO_BATCH`.
- **Unchanged and required:** `NOVRSOC_ENV=production`, `NOVRSOC_DISABLE_JOBS` (one job owner) and the secrets already on Render.
- **OpenVAS:** active scanning stays off. `VMS_OPENVAS_ENABLED="false"` and `VMS_OPENVAS_SCOPE_IDS=""` are fixed in `render.yaml`, and the code runs OpenVAS only when the value is exactly `true` and the scope is listed.

## 7. Deployment readiness

- **Render (backend):** the image is built from `backend/Dockerfile` (unchanged). `/health` reports the commit. The API stays compatible with workers 1.8.0 and 1.8.1 and the current forwarder.
- **Vercel (frontend):** builds with `NEXT_PUBLIC_BACKEND_URL` set to the Render backend.
- **Order:** P21 and P25 migrations → backend → frontend → map the OPNsense sender (P24 runbook) → TAXII clients and MISP check (TI runbook).

**Rollback.** Redeploy the previous Render deploy (`9cda076` / `16b3ffe`) and the previous Vercel deploy. Every migration is additive and the older code ignores the new columns and tables, so leave them in place.

## 8. Known limitations

- **Not tested against live services:** MISP, Ollama and the Wazuh indexer and manager. Tests used synthetic fixtures. See `ti-v1.md` and `deploy-p24-wazuh-tenancy.md`.
- **Alerts:** whether alerts flow depends on the forwarder on the Wazuh host running the checkpoint fix. The quarantine recovery steps are in `quarantine-recovery.md`.
- **Header breadcrumb:** it shows "Ti" and "Vms" for those sections (shared header, cosmetic).
- **Lint:** existing problems in untouched files remain, as in production.

## 9. GO / NO-GO

- **GO for the code:** every check in section 4 passes, conflicts are resolved with both behaviours preserved, and OpenVAS is off.
- **NO-GO for production until:**
  1. the P21 and P25 migrations are applied (approval needed);
  2. a read-only MISP key is set and the MISP capability check shows it cannot write;
  3. Ollama sits behind its authenticated proxy, or the analyst stays on NVIDIA;
  4. ingestion is confirmed flowing on the Wazuh host.
