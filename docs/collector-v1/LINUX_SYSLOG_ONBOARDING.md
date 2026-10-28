# Onboarding a Linux/syslog source to Collector V1

For firewalls, switches, Linux hosts, and anything else that speaks standard syslog (RFC 3164 or
5424). For Windows sources, see `WINDOWS_EVENT_FORWARDING.md` instead — Vector's syslog source
accepts the bridged output either way, but Windows needs the WEC bridge described there first.

## 1. Enroll the collector (once per client site, not per source device)

Staff (super_admin/soc_manager) → Collector Management → New collector. Deploy the appliance per
`infra/novrsoc-collector/README.md` before onboarding any individual device — there is nothing to
point a device at until the appliance is running and shows "connected."

## 2. Point the device at the collector

Every device sends to the **same** collector appliance; you are not creating a new Vector source
per device (see `infra/novrsoc-collector/examples/example-syslog-source.toml` for the rare
exception). On the sending device, set:

| Transport | Collector port | When to use it |
|---|---|---|
| UDP | `SYSLOG_UDP_PORT` (default 5514) | Legacy devices that only support UDP syslog. No delivery guarantee at the network layer — a dropped UDP packet is simply lost, by design of the protocol, not a collector fault. |
| TCP | `SYSLOG_TCP_PORT` (default 6514) | Anything that supports TCP syslog. Preferred over UDP when available — a network blip causes a resend, not a loss. |
| TLS | `SYSLOG_TLS_PORT` (default 6515) | Anything leaving the client's own trusted network segment, or carrying sensitive log content. Preferred over plain TCP whenever the sending device supports it. |

Most firewall/switch syslog clients ask for a destination IP/hostname and port only — point them
at the collector appliance's host and the port from the table above.

## 3. Confirm it's arriving

NovrSOC → Collector Management → this collector → **Connected sources** should show the matching
`source_key` (`syslog_tcp`, `syslog_udp`, or `syslog_tls`) with a recent `last_event_at` within a
few minutes of the device actually sending. If it doesn't appear:

- Check the device is actually configured to send (most syslog clients have a test/send-now
  button, or restart the service that owns the syslog client).
- Check the port is reachable from the device's network to the collector's host (firewall rules
  between the two, not NovrSOC's — this collector sits at the client site).
- Check `docker compose logs vector` on the appliance host for a parse error (a device sending a
  non-standard format Vector's `syslog` source can't decode shows up there, not silently).

## 4. Confirm it's readable in NovrSOC

Collector Management → this collector → **Diagnostics** shows the most recent raw log lines
received from it (capped at 32 KB each, with truncation flagged if a line exceeded that — see the
appliance README's limitations). This is a diagnostic sample, not a search interface: Collector
V1 stores raw logs honestly as logs, not as scored alerts (see `WAZUH_COMPATIBILITY.md`), so there
is deliberately no severity, no triage queue and no detection claim attached to what you see here.

## 5. Ongoing operation

- **Revoking a collector** (Collector Management → this collector → Revoke) stops it
  authenticating immediately — any Vector appliance still configured with its old credential gets
  401s and buffers everything on its own disk until someone notices or a replacement is enrolled.
- **Losing the enrollment secret**: there is no "view secret" option by design. Use **Rotate** to
  issue a new one, update `infra/novrsoc-collector/.env`, and restart the appliance
  (`./scripts/stop.sh && ./scripts/start.sh`).
- **Adding a second collector for the same organisation** (e.g. a second site) is a second,
  separate enrollment with its own name — collectors are never shared credentials.
