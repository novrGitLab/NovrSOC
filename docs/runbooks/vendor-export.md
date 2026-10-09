# Runbook: vendor export API

How to deploy, operate and switch off the vendor export (`GET /api/export/v1/events`). A third-party XDR uses it to pull NovrSOC alerts over HTTPS. Background: `backend/src/routes/exportApi.ts` and `backend/src/routes/exportClients.ts`.

This file contains **no secrets**. Everything in `<ANGLE_BRACKETS>` is a placeholder for you to fill in. The only literal addresses are from `192.0.2.0/24` (TEST-NET-1), a range reserved for documentation that is never routed on the internet.

| Placeholder | Meaning |
|---|---|
| `<BACKEND_URL>` | The backend's public base URL (the Railway service), e.g. `https://<your-service>.up.railway.app`. No trailing slash. |
| `<ADMIN_JWT>` | A super_admin session token from step 1 |
| `<EXPORT_TOKEN>` | The vendor's export token, from step 2 or a rotation |
| `<CLIENT_ID>` | The export client's id (a UUID), from step 2 |
| `<ORG_SLUG>` | An organisation slug (`organisations.slug`) the vendor may read |
| `<MY_PUBLIC_IP>` | The public IPv4 address of the machine running these commands |
| `<VENDOR_CIDR>` | The vendor's egress range, e.g. `<a.b.c.d>/29`, provided by the vendor |

Commands are for **Windows PowerShell 5.1 and later**:
- **Use `curl.exe`, not `curl`.** In Windows PowerShell 5.1, `curl` is an alias for `Invoke-WebRequest`.
- **Enable TLS 1.2 first.** Windows PowerShell 5.1 may not use it by default, so run this once per session:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$BACKEND = '<BACKEND_URL>'
```

---

## 0. Deploy order (once)

1. **R2 alert pipeline:**
   - Run `backend/sql/2026-10-09_alerts_pipeline.sql` in the Supabase SQL editor.
   - Deploy the backend.
   - Confirm that alerts are arriving: the Alerts page stops showing "No data".
2. **Export tables:** run `backend/sql/2026-10-09_vendor_export.sql`.
3. **Ingest order:** run `backend/sql/2026-10-09_alerts_ingest_seq.sql`.
   - It numbers existing alerts in one transaction, and **briefly blocks alert ingest** while it runs (the forwarder retries), so run it at a quiet moment.
   - It must run **before** the X1 backend is deployed; otherwise the export returns 502.
4. **Deploy the X1 backend with `EXPORT_API_ENABLED` unset.** The export answers 503; the admin endpoints work.
5. **Do the IP check (section 5) before giving any token to a vendor.**
6. **Turn the export on:** set `EXPORT_API_ENABLED` to exactly `true` on Railway and redeploy (section 7).

**`EXPORT_SETTLE_SECONDS` (optional, default 60):**
- A row is exported only once its `received_at` is at least this many seconds old, and a page stops at the first row that isn't.
- **Why:** sequence numbers are assigned before commit, so two concurrent inserts can become visible out of order. Without the wait, a vendor's cursor could move past a row that was still committing, and that row would never be exported.
- **The trade-off:** vendors see alerts about a minute late.
- **Rules:**
  - Allowed range 0–3600; an invalid value means 60.
  - Don't set it to 0 in production.
  - Raise it only if alert inserts could ever take longer than a minute to commit.

---

## 1. Log in as super_admin and get `<ADMIN_JWT>`

**The endpoint:** `POST /api/auth/signin` with body `{ "email": "...", "password": "..." }`. A successful response is:

```json
{ "token": "<JWT>", "user": { "email": "...", "name": "...", "company": "...", "role": "super_admin" } }
```

**Use `Invoke-RestMethod` here, not `curl.exe`.** The auth routes refuse any request whose User-Agent contains `curl` (bot protection), so `curl.exe` gets 403 on this route.

**Rate limit:** the auth routes allow only 10 failed attempts per 15 minutes per address.

```powershell
$cred = Get-Credential -Message 'NovrSOC super_admin'   # prompts; the password isn't typed into the command line or history
$login = Invoke-RestMethod -Method Post -Uri "$BACKEND/api/auth/signin" -ContentType 'application/json' `
    -Body (@{ email = $cred.UserName; password = $cred.GetNetworkCredential().Password } | ConvertTo-Json)
$login.user.role          # must print: super_admin
$ADMIN_JWT = $login.token
$ADMIN = @{ Authorization = "Bearer $ADMIN_JWT" }
```

**Notes:**
- The token is valid for 24 hours.
- If `role` isn't `super_admin`, the admin calls below return 403.
- Don't paste `$ADMIN_JWT` into tickets or chat.

---

## 2. Create an export client

**Requirements:**
- `org_ids` must be existing organisation slugs and can't be empty.
- `allowed_cidrs` can't be empty; each entry is an IPv4/IPv6 CIDR or a bare address. `/0` is refused.

**Redaction profile:**
- `standard` (the default) includes the raw alert, redacted.
- `no_raw` omits it.

```powershell
$body = @{
    name              = '<VENDOR_NAME>'
    org_ids           = @('<ORG_SLUG>')
    allowed_cidrs     = @('<VENDOR_CIDR>')
    redaction_profile = 'standard'
} | ConvertTo-Json
$created = Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients" -Headers $ADMIN -ContentType 'application/json' -Body $body
$created.client            # id, name, org_ids, allowed_cidrs, enabled, redaction_profile, created_at, ...
$CLIENT_ID = $created.client.id
$EXPORT_TOKEN = $created.token   # shown ONCE; it is never returned again
```

**Handing over the token:**
- Give `$EXPORT_TOKEN` to the vendor through a secure channel (a password manager share or a one-time secret link). Then clear it: `Remove-Variable EXPORT_TOKEN`.
- NovrSOC stores only its SHA-256 hash, so a lost token can't be recovered. Rotate instead.

**Listing clients** (this never shows tokens or hashes):

```powershell
(Invoke-RestMethod -Uri "$BACKEND/api/admin/export-clients" -Headers $ADMIN).clients | Format-Table id, name, enabled, org_ids, allowed_cidrs, last_used_at
```

---

## 3. Rotate, disable, enable

```powershell
# Rotate: a new token is shown once. The old token stops working on the very next request.
$rot = Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients/<CLIENT_ID>/rotate" -Headers $ADMIN
$EXPORT_TOKEN = $rot.token

# Disable: every request with this client's token gets 401 until it is re-enabled.
Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients/<CLIENT_ID>/disable" -Headers $ADMIN

# Enable
Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients/<CLIENT_ID>/enable" -Headers $ADMIN
```

Every create, rotate, disable and enable is written to the audit log.

---

## 4. Call the export

**Parameters:** only `cursor`, `limit` (default 500, maximum 1000), `format` (`json` or `ndjson`) and `org` (a comma-separated subset of the client's orgs) are accepted. Anything else is 400.

**Response:** `{ schema_version, events, next_cursor, has_more }`.

**One page (JSON):**

```powershell
curl.exe -sS -H "Authorization: Bearer <EXPORT_TOKEN>" "$BACKEND/api/export/v1/events?limit=100"
```

**Narrow to one of the client's orgs.** An org outside the client's scope gets 403.

```powershell
curl.exe -sS -H "Authorization: Bearer <EXPORT_TOKEN>" "$BACKEND/api/export/v1/events?limit=100&org=<ORG_SLUG>"
```

**All pages, following the cursor:**

```powershell
$EXPORT = @{ Authorization = 'Bearer <EXPORT_TOKEN>' }
$cursor = $null
$all = @()
do {
    $uri = "$BACKEND/api/export/v1/events?limit=500"
    if ($cursor) { $uri += "&cursor=$cursor" }
    $page = Invoke-RestMethod -Uri $uri -Headers $EXPORT
    $all += $page.events
    $cursor = $page.next_cursor
} while ($page.has_more)
"$($all.Count) events; resume later from cursor: $cursor"
```

**About the cursor:**
- Keep the last `next_cursor` and pass it on the next poll. Each event is delivered once, in the order NovrSOC stored it, including alerts that arrive late with an old `event_time`.
- At the end of the data, `has_more` is `false` and `next_cursor` stays the same, so polling resumes from there.
- The cursor is opaque. Don't build or edit one; a malformed cursor gets 400.

**NDJSON:** one event per line, then a final line with `schema_version`, `next_cursor` and `has_more`.

```powershell
curl.exe -sS -H "Authorization: Bearer <EXPORT_TOKEN>" "$BACKEND/api/export/v1/events?format=ndjson&limit=1000" -o events.ndjson
$meta = Get-Content events.ndjson | Select-Object -Last 1 | ConvertFrom-Json
$meta.next_cursor; $meta.has_more
(Get-Content events.ndjson | Measure-Object -Line).Lines - 1     # number of events
```

**Status codes:**

| Code | Meaning |
|---|---|
| 200 | OK |
| 400 | Bad parameter or cursor |
| 401 | Missing, wrong, rotated-out or disabled token (always the same body) |
| 403 | Source IP not allowed, or `org` outside the client's scope |
| 429 | Rate limit: 60 requests a minute per client, 120 a minute per address |
| 502 | Store unavailable, e.g. the `ingest_seq` SQL not run |
| 503 | Export switched off |

---

## 5. IP check (do this before the first vendor goes live)

**What it confirms:** the backend sees the **real** caller address, and a forged `X-Forwarded-For` header can't get round the allow-list.

**Why it matters:** the backend trusts exactly one proxy hop (Railway's edge) and uses the right-most `X-Forwarded-For` entry. If that assumption is wrong for your deployment, step 5c returns 200. In that case **stop and switch the export off (section 7)**.

**Setup:** run all three steps from the same machine, with `EXPORT_API_ENABLED=true`. Find your public address and create two temporary clients:

```powershell
$MY_PUBLIC_IP = (Invoke-RestMethod -Uri 'https://api.ipify.org')   # or ask your network admin; fill in <MY_PUBLIC_IP>
$mine = Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients" -Headers $ADMIN -ContentType 'application/json' `
    -Body (@{ name = 'ip-check-allowed'; org_ids = @('<ORG_SLUG>'); allowed_cidrs = @("$MY_PUBLIC_IP/32") } | ConvertTo-Json)
$other = Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients" -Headers $ADMIN -ContentType 'application/json' `
    -Body (@{ name = 'ip-check-denied'; org_ids = @('<ORG_SLUG>'); allowed_cidrs = @('192.0.2.0/24') } | ConvertTo-Json)
```

**5a. Your own IP is allowed.** Expect `200`.

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" -H "Authorization: Bearer $($mine.token)" "$BACKEND/api/export/v1/events?limit=1"
```

**5b. A different IP gets 403.** This client only allows `192.0.2.0/24`, which you are not in. Expect `403`.

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" -H "Authorization: Bearer $($other.token)" "$BACKEND/api/export/v1/events?limit=1"
```

**5c. A spoofed `X-Forwarded-For` still gets 403.** Claim to be inside the allowed range. Railway's edge appends your real address after the forged one, and the backend uses that last entry. Expect `403`.

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" -H "Authorization: Bearer $($other.token)" -H "X-Forwarded-For: 192.0.2.10" "$BACKEND/api/export/v1/events?limit=1"
```

**Results:**
- **Pass:** `200`, `403`, `403`.
- **Fail, any other result:** disable the export (section 7) and investigate before any vendor gets a token.
  - **5a gives 403:** the backend sees a different address. For example a CDN or WAF in front of Railway adds a hop.
  - **5c gives 200:** the forged header is trusted.

**Clean up:** disable both test clients. Their tokens also disappear from your session.

```powershell
Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients/$($mine.client.id)/disable" -Headers $ADMIN
Invoke-RestMethod -Method Post -Uri "$BACKEND/api/admin/export-clients/$($other.client.id)/disable" -Headers $ADMIN
Remove-Variable mine, other
```

**Re-run this check** whenever a CDN, WAF or load balancer is added or changed in front of the backend.

---

## 6. What the vendor receives

Each event contains:
- `id`, `org_id`, `event_time`, `received_at`, `severity`
- `rule {id, level, description}`, `agent {id, name, ip}`, `mitre_ids`, `location`
- `network {src_ip, src_port, dst_ip, dst_port, protocol}`: `null` where unknown; nothing is inferred.
- `raw` (`standard` profile only): passwords, tokens, API keys, Authorization values, bearer tokens and private keys are masked as `[REDACTED]`. If redaction fails, the field is dropped.

Every call by a known client is recorded in `export_access_log`: client id, time, source IP, org scope, row count, cursors and status. No payloads and no tokens.

---

## 7. Switch the export off

| Scope | How | Effect |
|---|---|---|
| **One vendor** (immediate) | `POST /api/admin/export-clients/<CLIENT_ID>/disable` (section 3) | That vendor's token gets 401. Others are unaffected. |
| **One vendor's token leaked** | `POST …/<CLIENT_ID>/rotate` | The leaked token dies on the next request. Hand over the new one securely. |
| **Everyone** (global kill switch) | In Railway, set `EXPORT_API_ENABLED` to anything other than exactly `true` (or delete it), then redeploy or restart | Every export request gets 503. The admin endpoints keep working. |

**Confirming the global switch-off:**

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" -H "Authorization: Bearer <EXPORT_TOKEN>" "$BACKEND/api/export/v1/events?limit=1"   # expect 503
```
