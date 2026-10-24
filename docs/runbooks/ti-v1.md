# Threat Intelligence V1 (P25)

Eight pages under `/admin/ti`, the `/api/ti` APIs behind them, a read-only TAXII 2.1 server at
`/taxii2/`, STIX 2.1 export, MISP (read-only) and Ollama integration. Built on the P6 Threat
Information System tables; nothing existing is deleted.

## 1. What is in this release

| Area | What it does |
|---|---|
| **Ingestion** | ThreatFox, URLhaus, Feodo Tracker, CISA KEV and MISP attributes into `ti_indicators`.<br>One row per indicator (`type`, `value`), deduplicated. Every source record is kept in `ti_indicator_sources` with what that source said, its TLP and its MISP distribution.<br>A record repeated within one run counts as a duplicate; re-running a batch creates nothing.<br>`updated_at` (the exported version) moves only when exported content changes. |
| **MISP reports** | New `misp_events` feed: event titles plus the galaxy and taxonomy tags the source attached, stored in `ti_reports`.<br>Targeting counts **only** from `misp-galaxy:target-information` tags. |
| **NVD / EPSS** | Unchanged (`cve_intel`, VMS intel job). Shown with KEV on Vulnerabilities & Advisories; freshness on Sources. |
| **OpenCTI / SpiderFoot** | OpenCTI feed retired: never configured, never run; its stored provenance is kept. SpiderFoot is not used by the TI module. |
| **Hosting location** | `ti_indicator_geo`: the feed's own statement first (Feodo), otherwise GeoIP.<br>A state is recorded only when the provider names a Nigerian state. |
| **Sharing policy** | `services/tiPolicy.ts`, applied to every export (and to the AI):<br>• AMBER+STRICT and RED never leave the platform.<br>• MISP distribution 0, 1, 4 and 5 are never exported.<br>• An unmarked private record counts as AMBER. |
| **STIX 2.1** | `services/tiStix.ts`:<br>• Deterministic UUIDv5 ids, generated in Postgres as `stix_uuid`.<br>• TLP marking definitions.<br>• A NovrSOC property extension.<br>• `indicator` and `vulnerability` objects; bundles add `malware` objects and `indicates` relationships.<br>• Objects built only from records that may be shared. |
| **TAXII 2.1** | `routes/taxii.ts`, read-only:<br>• Discovery, API root, collections, objects, manifest, object, versions.<br>• `added_after`, `limit`, `next`, and `match[id\|type\|version\|spec_version]`.<br>• HTTP Basic per client, with a per-client collection list and TLP ceiling. |
| **AI analyst** | `POST /api/ti/analyst/ask`, plus purposes `indicator_assessment`, `investigation_summary`, `threat_briefing`, `nigeria_briefing` (7d / 30d).<br>Every statement is marked `platform_record`, `source_claim` or `ai_assessment`.<br>Citations to unsent records are removed. The AI never acts. |
| **AI markings** | TLP:RED never enters a prompt.<br>An external provider (NVIDIA) gets CLEAR and GREEN only.<br>Ollama may also read AMBER and AMBER+STRICT. |
| **Pages** | Overview, Nigeria Threat Map, Indicators & Investigation, Threat Actors, Organisation Matches, Vulnerabilities & Advisories, AI Intelligence Analyst, Sources & Exchange.<br>Old `/admin/threat/{nigeria, live-ioc, advisory, actors}` and `/admin/ti/kev` redirect to the new pages.<br>The external lookup and URL scanner are linked from Indicators. |

**Nigeria map rules.** These apply everywhere in the module:

- No attack counts.
- No coordinates.
- Targeting is shown at country level.
- Hosting is labelled as hosting.

The old map's GeoIP-derived "attack" counts (`nigeria_state_threats`) are no longer shown.

## 2. MISP: what it supports, and how to verify

MISP core provides the REST API (`/attributes/restSearch`, `/events/restSearch`) and STIX 2.1 export (`returnFormat: stix2`, via misp-stix). It does **not** serve TAXII 2.1; that needs a separate server. NovrSOC therefore serves TAXII itself and reads MISP over REST.

**The live instance was not contacted during this work** (no credentials were used).

To verify after deployment: Sources → MISP → **Check capabilities**, as a manager. It is read-only:

- `GET /servers/getVersion`: the version.
- `GET /users/view/me`: whether the key's role can write. It must say **no**.
- One `stix2` restSearch limited to a single event.

## 3. Secure connectivity (Render → MISP, Render → Ollama)

Neither service may be publicly reachable without authentication and network controls.

**MISP**
1. Keep it on HTTPS only. MISP authenticates every API call with the key.
2. Use a dedicated **read-only** user. Set `MISP_WRITE_ENABLED` unset or `false`.
3. Pin its self-signed certificate with `MISP_CA_CERT`. Never use `NODE_TLS_REJECT_UNAUTHORIZED=0`.
4. Firewall 443 to the backend's outbound addresses: Render dashboard → service → Connect → Outbound.

**Ollama.** It has no authentication of its own, so it must never be exposed directly.
1. Bind Ollama to `127.0.0.1:11434` (`OLLAMA_HOST=127.0.0.1`).
2. Put a TLS reverse proxy in front (Caddy or nginx) on 443. Its rules:
   - Require `Authorization: Bearer <OLLAMA_API_KEY>`, a 32+ byte random value; reject anything else with 401.
   - Allow only `POST /api/chat`, `GET /api/version` and `GET /api/tags`. Deny `/api/pull`, `/api/delete`, `/api/create`, `/api/push` and everything else.
   - Firewall to Render's outbound addresses.
   - Apply request size and rate limits.
3. Set `OLLAMA_URL=https://<proxy>`, `OLLAMA_API_KEY`, `OLLAMA_CA_CERT` (if the certificate is self-signed), `OLLAMA_MODEL` and `TI_AI_PROVIDER=ollama`.
   - The backend refuses plain `http://` except for localhost.
4. Verify on Sources → AI analyst: the state must be *Reachable* and the detail must read *Model … is available*.

## 4. Deployment steps (each needs approval)

1. **Migration:** run `backend/sql/2026-10-30_p25_ti_v1.sql` in the Supabase SQL editor.
   - It is additive and idempotent: new columns, tables, the `uuid-ossp` extension, and backfills.
   - It needs P6 and P9 applied first.
   - Check it with:
     ```sql
     select stix_uuid, created_at, updated_at from ti_indicators limit 1;
     select count(*) from ti_reports;
     select tlp, count(*) from ti_indicator_sources group by tlp;
     ```
2. **Render variables:** see `render.yaml` and `backend/.env.example`.
   - `MISP_*` with the read-only key, `THREATFOX_API_KEY`, `NVD_API_KEY`.
   - The Ollama variables, if used. `MISP_WRITE_ENABLED=false`.
3. **Deploy** the backend, then the frontend.
4. **Smoke check:**
   - `/api/ti/sources` answers.
   - TAXII discovery without credentials answers 401: `curl -i https://<backend>/taxii2/`.
   - Sources shows feed freshness after the first 6-hour run (90 seconds after start on the job-owning host).
5. **TAXII clients:** create one per partner on Sources (TLP:CLEAR unless agreed otherwise). Hand the credentials over out of band.

**Rollback.** Redeploy the previous commit. The migration only adds, so the old code ignores the new columns and tables; leave them in place.

## 5. TAXII 2.1 for consumers

- **Discovery:** `https://<backend>/taxii2/`. **API root:** `https://<backend>/taxii2/api1/`.
- **Authentication:** HTTP Basic, with the issued username and password.
- **Headers:** send `Accept: application/taxii+json;version=2.1`.
- **Collections:**
  - `4f0b6a3e-6d1c-4c5e-9a6b-2d0c1b7e5a01` (`indicators`): network and file indicators.
  - `4f0b6a3e-6d1c-4c5e-9a6b-2d0c1b7e5a02` (`known-exploited-vulnerabilities`): STIX vulnerability objects.
- **Polling:** use `added_after` set to the last `X-TAXII-Date-Added-Last` you received. A changed object comes back with a new `modified`. Page with `next` while `more` is true; `limit` is at most 1000.
- **Write-protected:** collections are read-only; POST and DELETE return 403.
- **Markings:**
  - `object_marking_refs` use the STIX 2.1 predefined TLP definitions. TLP 2.0 CLEAR is carried as TLP:WHITE.
  - NovrSOC properties sit under the property extension `extension-definition--…` (the definition is included in bundles):
    - `status`;
    - `source_confidence`, the source's claim;
    - `kev`.

## 6. Validation performed (synthetic fixtures; no live intelligence)

| Check | Result |
|---|---|
| Backend `tsc`, `npm run build` | pass |
| Backend tests | 608: 605 pass, 0 fail, 3 skipped. Includes 28 new TI tests: policy, MISP markings and reports, idempotent ingestion, STIX, paging, TAXII, RBAC, viewer markings, map attribution, geo precision, Ollama routing, AI markings, grounding and isolation. |
| OASIS `stix2-validator` 3.2.0 on an exported bundle | pass, 0 errors.<br>Warnings: {103} UUIDv5 ids (deliberate, so re-imports deduplicate) and {302} links without hashes. |
| OASIS `taxii2-client` 2.3.0 against the TAXII server (`scripts/ti/taxii_client_check.py`) | pass: discovery, collections, paging (28 objects over 3 pages), manifest, object, versions, `added_after`, 401 on a bad password, 403 on writes, RED fixture never served, every object valid. |
| Frontend `tsc`, lint (TI files), tests (15) | pass |
| Navigation check | pass |
| Frontend production build | pass |
| Browser walk of all eight pages (synthetic harness) | no page or console errors, no TI API failures, no overflow at 390 px.<br>The map drill-down, indicator drawer, analyst answer and executive view were all checked. |

**Not verified** (needs infrastructure or approval):

- the live MISP version and capabilities;
- a live Ollama server;
- live feed runs against Supabase;
- the migration on the production database.

## 7. GO / NO-GO

- **GO for the code:** every check above passes, and nothing is exported or sent to an AI provider beyond what the markings allow.
- **NO-GO for production until:**
  1. the migration is applied;
  2. a read-only MISP key is set and *Check capabilities* shows `key can write: no`;
  3. the Ollama reverse proxy (or NVIDIA) is in place, if the analyst should work;
  4. MISP and Ollama firewalls are limited to Render's outbound addresses;
  5. the first feed runs show *Current* on Sources.
