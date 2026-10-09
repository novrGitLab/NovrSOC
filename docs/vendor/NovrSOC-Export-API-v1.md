# NovrSOC Export API, v1

A pull API for security alerts that NovrSOC has collected and enriched for the organisations you're contracted to monitor. You poll one HTTPS endpoint and receive JSON or NDJSON, and you resume from an opaque cursor.

## Endpoint and authentication

```
GET <BASE_URL>/api/export/v1/events
Authorization: Bearer <EXPORT_TOKEN>
```

**`<BASE_URL>`** is given to you by NovrSOC. It is HTTPS only.

**`<EXPORT_TOKEN>`:**
- An opaque token issued once by NovrSOC. Treat it as a secret.
- NovrSOC keeps only a hash of it, so a lost token can't be recovered; ask NovrSOC to rotate it.
- After a rotation, the old token stops working on the next request.

**Source addresses:** you must call from the addresses or CIDR ranges you gave NovrSOC. Requests from any other address get `403`, even with a valid token. Tell NovrSOC before your egress addresses change.

## Parameters

Only these four query parameters are accepted, each at most once. Any other parameter, or a repeated one, gets `400`.

| Parameter | Default | Meaning |
|---|---|---|
| `cursor` | none (start of the feed) | The `next_cursor` value from your previous response. It is opaque: don't build, edit or parse it. A malformed cursor gets `400`. |
| `limit` | `500` | Events per page, a positive integer. Values above `1000` are treated as `1000`. |
| `format` | `json` | `json` or `ndjson` |
| `org` | all of your organisations | A comma-separated list of organisation ids that narrows the feed to a subset of the ones you're authorised for. Any id outside your scope gets `403`. |

There are no other filters. Filter on your side.

## Cursor and delivery semantics

- **Order:** events come in the order NovrSOC **stored** them, not by `event_time`. An alert collected late, for example replayed after a sensor outage, can arrive with an `event_time` older than events you've already received. It is still delivered, once.
- **Polling:** store `next_cursor` after each response and send it on your next request.
- **No gaps, no repeats:** each event is delivered exactly once when you follow `next_cursor`. If you retry the same cursor (for example after a timeout), you get the same events again; de-duplicate on `id`.
- **End of data:** `has_more: false` means there is nothing more to fetch right now. `next_cursor` is then your current position (unchanged if the page was empty), so poll again later with it.
- **`has_more: true`:** fetch the next page immediately.
- **Settle delay:** an event becomes available about **60 seconds** after NovrSOC stores it. This is what guarantees the no-gaps property: events that are still being written are never skipped. Expect a feed latency of roughly one minute plus your polling interval.
- **Starting point:** a request without `cursor` starts at the oldest stored event. NovrSOC keeps alerts for a limited time (90 days by default), so older history isn't available.

## Rate limits

| Limit | Value |
|---|---|
| Per client (token) | 60 requests per minute |
| Per source address, before authentication | 120 requests per minute |

- **Over the limit:** you get `429` with `{"error":"Rate limit exceeded"}` and a `Retry-After` header (seconds). Wait at least that long.
- **Headers:** every response carries `RateLimit-Policy`, `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` (seconds). On authenticated requests they describe your per-client limit.
- **Recommended polling:** when `has_more` is false, every 30–60 seconds. Use `limit=1000` to catch up.

## Response

**JSON (`format=json`):**

```json
{ "schema_version": "1", "events": [ /* event objects */ ], "next_cursor": "…", "has_more": false }
```

**NDJSON (`format=ndjson`):** `Content-Type: application/x-ndjson`. One event object per line, then a final line `{"schema_version":"1","next_cursor":"…","has_more":…}`.

**Page size:**
- A page holds at most `limit` events.
- It may hold fewer if the response would exceed **8 MB**. In that case `has_more` is `true`.
- Responses are sent with `Cache-Control: no-store`.
- `next_cursor` is `null` only when you sent no cursor and nothing is available yet.

## Event schema (`schema_version` "1")

Every field is always present. Where a value is unknown or can't be determined, it is `null`; NovrSOC never invents or infers values.

| Field | Type | Null when |
|---|---|---|
| `id` | string (UUID) | never. NovrSOC's id for this alert; stable, use it to de-duplicate. |
| `org_id` | string | never. The organisation the alert belongs to. |
| `event_time` | string (ISO 8601, UTC offset) | never. When the event happened, according to the sensor. |
| `received_at` | string (ISO 8601) | not in practice. When NovrSOC stored it. |
| `severity` | `"critical"`, `"high"`, `"medium"` or `"low"` | never. Computed from `rule.level`: ≥13 critical, ≥10 high, ≥7 medium, otherwise low. |
| `rule.id` | string | the detection rule id is unknown |
| `rule.level` | integer 0–16 | the rule level is unknown |
| `rule.description` | string | there is no description, or it couldn't be redacted (see below) |
| `agent.id`, `agent.name`, `agent.ip` | string | the sensor didn't report it |
| `mitre_ids` | array of strings (e.g. `"T1110.001"`) | the rule has no MITRE ATT&CK mapping |
| `location` | string (log source, e.g. a file path) | not reported, or couldn't be redacted |
| `network.src_ip`, `network.dst_ip` | string (IPv4 or IPv6) | absent, or not a valid IP address |
| `network.src_port`, `network.dst_port` | integer 0–65535 | absent, or not a valid port |
| `network.protocol` | string (as reported, e.g. `"tcp"`) | absent, or not a plain protocol token |

**Notes on `network`:**
- It comes from the alert's decoded fields (`srcip`, `srcport`, `dstip`, `dstport`, `protocol`). On Windows Sysmon events it falls back, field by field, to Sysmon's `sourceIp`, `sourcePort`, `destinationIp`, `destinationPort` and `protocol`.
- All five are `null` when NovrSOC stored a shortened copy of an oversized alert.

**Optional fields** (only if your client is configured to receive raw alerts):

| Field | Type | Meaning |
|---|---|---|
| `raw` | object | The original sensor alert, after redaction. Omitted entirely if redaction fails. |
| `raw_truncated` | boolean | `true` if the stored alert exceeded 32 KB. `raw` is then `{ "truncated": true, "original_bytes": <n>, "preview": "<first ~32 KB as text>" }`. |

## Redaction

Before anything leaves NovrSOC, every string in `raw` (including the full log line), plus `rule.description` and `location`, is redacted. Masked values become `[REDACTED]`:
- **Secret-named keys:** the values of keys whose name contains `password`, `passwd`, `secret`, `token`, `api_key`, `api-key`, `apikey` or `authorization`. This covers `key=value`, `key: value`, JSON (including escaped JSON) and query strings. In structured data the whole value of such a key is masked, whatever its type.
- **Authorization header values**, including the scheme (`Basic …`, `Bearer …`, `Digest …`).
- **`Bearer` tokens** anywhere in text.
- **PEM private key blocks**, including cut-off ones.
- **Command-line flags** naming a secret, followed by a value (e.g. `--password x`).

**Failure behaviour:** if redaction of a value fails, that value is dropped (`null`, or `raw` omitted). It is never sent unredacted.

**False positives:** redaction is deliberately broad, so harmless values under such keys (e.g. `tokenized=no`) are masked too.

## Status codes

Errors have the body `{"error":"<message>"}`.

| Code | Meaning |
|---|---|
| `200` | OK |
| `400` | Unsupported, repeated or invalid parameter, or malformed cursor |
| `401` | Missing, unknown, rotated-out or disabled token. The body is always `{"error":"Unauthorized"}`. |
| `403` | Source address not allowed, or `org` outside your scope |
| `429` | Rate limited. Honour `Retry-After`. |
| `502` | NovrSOC's store is temporarily unavailable. Retry with backoff. |
| `503` | The export is switched off, or the store is unavailable. Retry with backoff, and contact NovrSOC if it persists. |

## Example (SYNTHETIC)

> **Synthetic data, invented for this document.** No real organisation, host, address or credential. Produced by NovrSOC's actual event-formatting and redaction code from a made-up alert that contained a password, an Authorization header and an API key.

```
GET <BASE_URL>/api/export/v1/events?limit=1&cursor=<previous next_cursor>
Authorization: Bearer <EXPORT_TOKEN>
```

```json
{
  "schema_version": "1",
  "events": [
    {
      "id": "0b6c1d2e-3f40-4a51-8b62-7c83d94e0f15",
      "org_id": "example-org",
      "event_time": "2026-10-09T08:15:42.123+00:00",
      "received_at": "2026-10-09T08:15:44.901+00:00",
      "severity": "high",
      "rule": { "id": "5710", "level": 10, "description": "sshd: Attempt to login using a non-existent user" },
      "agent": { "id": "001", "name": "web-01", "ip": "10.0.0.5" },
      "mitre_ids": ["T1110.001"],
      "location": "/var/log/auth.log",
      "network": { "src_ip": "192.0.2.10", "src_port": 51515, "dst_ip": "10.0.0.5", "dst_port": 22, "protocol": "tcp" },
      "raw": {
        "timestamp": "2026-10-09T08:15:42.123+0000",
        "id": "1760000142.123456",
        "full_log": "Oct  9 08:15:42 web-01 app[811]: login failed user=bob password=[REDACTED] from 192.0.2.10 Authorization: [REDACTED]",
        "data": { "srcip": "192.0.2.10", "srcport": "51515", "dstip": "10.0.0.5", "dstport": "22", "protocol": "tcp", "api_key": "[REDACTED]" }
      },
      "raw_truncated": false
    }
  ],
  "next_cursor": "eyJzIjoiMTg0NDY3In0",
  "has_more": false
}
```

## Versioning

- **`schema_version`** is `"1"`. Fields may be added within v1; treat unknown fields as ignorable.
- **Breaking changes** (removed or retyped fields, a changed cursor meaning) would come with a new path (`/api/export/v2/…`) and advance notice.
