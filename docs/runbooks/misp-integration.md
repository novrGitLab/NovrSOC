# MISP integration (P26): Cloudflare Tunnel, read-only ingestion, verification

NovrSOC reads MISP; it never writes to it. The browser never talks to MISP: every request goes from the Render backend to MISP's tunnel hostname.

## 1. What the backend does

- **Feeds.** Both run every 6 hours, only on the host that owns scheduled jobs (`NOVRSOC_DISABLE_JOBS`):
  - `misp`: attributes, `POST /attributes/restSearch`.
  - `misp_events`: event reports, `POST /events/restSearch` with `metadata: true`.
- **Incremental window.** Each run reads records **changed** since the last successful sync, minus one hour of overlap, using MISP's `timestamp` filter.
  - The first run reads `MISP_BACKFILL_DAYS` (default 7).
  - A manager can run a one-time backfill of up to 90 days.
- **Paging.** `limit` is `MISP_PAGE_SIZE` (default 1000) and `page` counts up until a short page, at most `MISP_MAX_PAGES` (default 20), with a `MISP_PAGE_DELAY_MS` pause between pages.
  - A run that reaches the page limit stores what it read, does **not** advance its window, and says so on Sources.
- **Filters.** `deleted: false`, `enforceWarninglist: true` (MISP's known-benign lists), `to_ids: true` for attributes.
- **Stored with each record** (`ti_indicator_sources`):
  - TLP, from attribute and event tags; untagged is AMBER;
  - MISP distribution, with inherit resolved to the event's;
  - event uuid, info and organisation; threat level and analysis;
  - category, type, IDS flag, object relation;
  - first/last seen, modification time;
  - confidence-style taxonomy tags, kept as labels.
  
  No confidence number is invented.
- **Idempotent.** Indicators are unique on `(type, value)` and provenance on `(indicator, feed, source_ref = attribute uuid)`; reports are unique on `(feed, event uuid)`.
- **One run at a time per feed:** a manager's "Run now" while a scheduled run is going gets 409.
- **Read-only, enforced in code:** only `GET`, or `POST` to `/attributes/restSearch` or `/events/restSearch`, can be sent by the ingestion client. The platform's own two write paths stay off unless `MISP_WRITE_ENABLED=true`.
- **Errors.**
  - Network errors, timeouts, 429 and 5xx/Cloudflare 52x–530 are retried up to `MISP_MAX_ATTEMPTS` (default 3) with backoff, honouring `Retry-After`. 401/403 and redirects are not retried.
  - Redirects are never followed: a Cloudflare Access login redirect is reported as "Cloudflare Access redirected…".
  - A tunnel outage (530) is reported as "the Cloudflare Tunnel to MISP is down".
  - An HTML page is reported as "instead of JSON".
  - Messages never contain the key or headers.
- **Status:**
  - Sources → MISP rows show last success, counts, window, pages, truncation and errors. *Check capabilities* shows the version, whether the key can write, and STIX 2 export.
  - The API equivalents are `GET /api/ti/sources` and `POST /api/ti/sources/misp/check` (managers).

## 2. Cloudflare Tunnel (on the MISP host). Needs Cloudflare account access.

Not done from here: it needs your Cloudflare credentials.

```bash
# On the MISP host (Ubuntu). MISP keeps listening locally on 443 (or 80); nothing is opened inbound.
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared

cloudflared tunnel login                         # opens a browser link: pick the zone
cloudflared tunnel create novrsoc-misp
cloudflared tunnel route dns novrsoc-misp misp.<your-domain>

sudo mkdir -p /etc/cloudflared
sudo tee /etc/cloudflared/config.yml >/dev/null <<'EOF'
tunnel: novrsoc-misp
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
ingress:
  - hostname: misp.<your-domain>
    service: https://localhost:443
    originRequest:
      # MISP's own certificate is self-signed: verify it by name instead of disabling checks.
      originServerName: <the CN/SAN on MISP's certificate>
      caPool: /etc/cloudflared/misp-ca.pem       # MISP's certificate (or its CA), copied here
  - service: http_status:404
EOF
sudo cloudflared service install && sudo systemctl enable --now cloudflared
sudo systemctl status cloudflared --no-pager
```

**MISP base URL.** Set it to the tunnel hostname, so browser links resolve:

```bash
sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting "MISP.baseurl" "https://misp.<your-domain>"
```

**Recommended: Cloudflare Access.** Zero Trust → Access → Applications → Self-hosted, for `misp.<your-domain>`.

1. Add a policy with action **Service Auth** that includes the service token `novrsoc-render`.
2. Create the token under Access → Service Auth → Service Tokens.
3. Put its Client ID and Secret into Render as `MISP_CF_ACCESS_CLIENT_ID` and `MISP_CF_ACCESS_CLIENT_SECRET`.
4. Optionally add a second policy for analysts' browsers (SSO).

## 3. Render environment

| Variable | Value |
|---|---|
| `MISP_URL` | `https://misp.<your-domain>`. Cloudflare's certificate is valid, so leave `MISP_CA_CERT` empty. |
| `MISP_API_KEY` | the dedicated **read-only** key |
| `MISP_CF_ACCESS_CLIENT_ID`, `MISP_CF_ACCESS_CLIENT_SECRET` | the Access service token, if Access is used |
| `MISP_WRITE_ENABLED` | `false` (fixed in `render.yaml`) |
| `MISP_NIGERIA_EVENT_ID` | unchanged (the platform's own collection event, excluded from ingestion) |
| Optional | `MISP_BACKFILL_DAYS`, `MISP_PAGE_SIZE`, `MISP_MAX_PAGES`, `MISP_PAGE_DELAY_MS`, `MISP_MAX_ATTEMPTS` |

## 4. Verify with the real instance (after deploy)

1. **Sources → MISP → Check capabilities** (manager). Expect:
   - version `2.5.50`;
   - key can write: **no**;
   - STIX 2 export: supported.
2. **Sources → MISP → Run now** (or *Backfill 30 d*). The row should show:
   - *Current*;
   - fetched/new/updated counts;
   - "backfill since …" with the page count.
3. **Indicators & Investigation:** filter *Source = MISP*.
   - Open one: the MISP source record shows TLP, distribution, event, organisation and category.
   - Check `select feed_id, tlp, count(*) from ti_indicator_sources where feed_id='misp' group by 1,2;` in Supabase.
4. **Idempotency:** run it again. New should be 0 or only genuinely new attributes; updated covers the overlap.
5. **No direct browser access:** the browser's network tab shows only `/api/ti/...` calls to the backend.

**Tunnel outage test.** Stop `cloudflared` for a minute and *Run now*. The row must show "The Cloudflare Tunnel to MISP is down", the rest of the platform must keep working, and after `systemctl start cloudflared` the next run catches up from the last success.
