#!/usr/bin/env python3
"""
NovrSOC SOAR engine.

Called by Wazuh's integratord (via the custom-novrsoc-soar wrapper) once per alert at or above
the integration's <level>. Reads the alert, creates a case in Supabase (deduplicated on the
Wazuh alert id), then responds by tier:

  Tier 1  level 7-9    medium   enrich, auto-close
  Tier 2  level 10-12  high     enrich, block source IP, email the SOC; an analyst reviews
  Tier 3  level 13+    critical enrich, block source IP, isolate agent (selected techniques),
                                CISO email

Every action writes its real outcome to soar_log and the case timeline. Nothing is recorded as
done unless the remote system accepted it; a skipped action says why (e.g. not configured).

Configuration comes from the environment (see soar.env.example). Deployment: infra/soar/README.md.
"""

import hashlib
import html
import ipaddress
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

# ── Logging ──────────────────────────────────────────────────────────────────────────────────
# integratord runs this as the `wazuh` user, which can't create files in /var/log. If the log
# file isn't writable, fall back to stderr (which integratord captures) instead of crashing on
# import — a crash here would silently drop every alert.
LOG_FILE = os.environ.get('SOAR_LOG_FILE', '/var/log/novrsoc-soar.log')
_handlers: list = [logging.StreamHandler()]
try:
    _handlers.insert(0, logging.FileHandler(LOG_FILE))
except OSError:
    pass
logging.basicConfig(level=logging.INFO, format='%(asctime)s [SOAR] %(levelname)s: %(message)s', handlers=_handlers)
log = logging.getLogger('novrsoc-soar')

# ── Configuration ────────────────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get('SUPABASE_URL', '').rstrip('/')
# The spec's wrapper exported SUPABASE_KEY while the script read SUPABASE_SERVICE_KEY, so the
# key was always empty and every request 401'd. Both names are accepted now.
SUPABASE_KEY = os.environ.get('SUPABASE_SERVICE_KEY') or os.environ.get('SUPABASE_KEY', '')
BACKEND_URL = os.environ.get('NOVRSOC_BACKEND', 'https://novrsoc-production-1fb6.up.railway.app').rstrip('/')
SOAR_TOKEN = os.environ.get('SOAR_ENGINE_TOKEN', '')
APP_URL = os.environ.get('NOVRSOC_APP_URL', 'https://novr-soc.vercel.app').rstrip('/')
ORG_ID = os.environ.get('NOVRSOC_ORG_ID', 'cybernovr')

RESEND_KEY = os.environ.get('RESEND_API_KEY', '')
RESEND_FROM = os.environ.get('RESEND_FROM', 'NovrSOC by Cybernovr <alerts@cybernovr.com>')
CISO_EMAIL = os.environ.get('CISO_EMAIL', 'soc@cybernovr.com')
# Team notifications (tier 2, and tier 3 when it differs from CISO_EMAIL).
SOC_EMAIL = os.environ.get('SOC_EMAIL') or os.environ.get('ALERT_EMAIL_TO') or CISO_EMAIL

# OPNsense API auth is an API key + secret pair (System → Access → Users → API keys), used as
# HTTP basic auth — not root + key.
OPNSENSE_URL = os.environ.get('OPNSENSE_URL', '').rstrip('/')
OPNSENSE_KEY = os.environ.get('OPNSENSE_KEY', '')
OPNSENSE_SECRET = os.environ.get('OPNSENSE_SECRET', '')
OPNSENSE_ALIAS = os.environ.get('OPNSENSE_ALIAS', 'novrsoc_blocked')
OPNSENSE_VERIFY_TLS = os.environ.get('OPNSENSE_VERIFY_TLS', 'false').lower() == 'true'

WAZUH_API = os.environ.get('WAZUH_API_URL', 'https://localhost:55000').rstrip('/')
WAZUH_USER = os.environ.get('WAZUH_USER', 'wazuh-wui')
WAZUH_PASSWORD = os.environ.get('WAZUH_PASSWORD', '')
WAZUH_VERIFY_TLS = os.environ.get('WAZUH_VERIFY_TLS', 'false').lower() == 'true'
# Wazuh ships no "isolate host" active response. Name the command of one you have deployed to
# the agents (e.g. a custom AR script registered in ossec.conf); unset means isolation is
# skipped and logged as such, rather than reported as done.
WAZUH_ISOLATE_COMMAND = os.environ.get('WAZUH_ISOLATE_COMMAND', '')
ISOLATE_TECHNIQUES = {'T1486', 'T1021', 'T1055', 'T1210'}

if not OPNSENSE_VERIFY_TLS or not WAZUH_VERIFY_TLS:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Supabase ─────────────────────────────────────────────────────────────────────────────────
def supabase(method: str, table: str, *, params: Optional[dict] = None, data=None, prefer: str = 'return=representation'):
    """Supabase REST call. Returns (status_code, parsed_body). Filters go in `params` so values
    are URL-encoded — an alert id or IP spliced into the path unescaped can break the query."""
    try:
        resp = requests.request(
            method,
            f'{SUPABASE_URL}/rest/v1/{table}',
            headers={
                'apikey': SUPABASE_KEY,
                'Authorization': f'Bearer {SUPABASE_KEY}',
                'Content-Type': 'application/json',
                'Prefer': prefer,
            },
            params=params,
            json=data,
            timeout=10,
        )
    except requests.RequestException as e:
        log.error(f'Supabase {method} {table} failed: {e}')
        return 0, None
    body = None
    if resp.text:
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
    if resp.status_code >= 400:
        log.error(f'Supabase {method} {table} -> {resp.status_code}: {resp.text[:300]}')
    return resp.status_code, body


def add_timeline(case_id: str, action: str, actor: str = 'NovrSOC SOAR', automated: bool = True, details: Optional[str] = None):
    supabase('POST', 'case_timeline', data={'case_id': case_id, 'actor': actor, 'action': action, 'details': details, 'automated': automated}, prefer='return=minimal')


def add_soar_log(case_id: str, tier: int, action: str, result: str):
    supabase('POST', 'soar_log', data={'case_id': case_id, 'tier': tier, 'action': action, 'result': result, 'automated': True, 'executed_at': now_iso()}, prefer='return=minimal')


def update_case(case_id: str, fields: dict):
    fields = {**fields, 'updated_at': now_iso()}
    supabase('PATCH', 'cases', params={'id': f'eq.{case_id}'}, data=fields, prefer='return=minimal')


# ── Alert parsing ────────────────────────────────────────────────────────────────────────────
def is_internal_ip(ip: str) -> bool:
    """Private, loopback, link-local or unparseable. The spec's prefix test treated all of
    172.0.0.0/8 as private; only 172.16.0.0/12 is."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified


def get_severity(level: int) -> tuple:
    if level >= 13:
        return 'critical', 3
    if level >= 10:
        return 'high', 2
    if level >= 7:
        return 'medium', 1
    return 'low', 1


def first(value) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ''
    return str(value) if value else ''


def alert_source_id(alert: dict) -> str:
    """Wazuh's own alert id. A hand-written test alert has none; hashing the alert keeps it
    unique instead of every id-less alert colliding on source_id ''."""
    if alert.get('id'):
        return str(alert['id'])
    return 'sha1:' + hashlib.sha1(json.dumps(alert, sort_keys=True).encode()).hexdigest()


def extract_source_ip(alert: dict) -> str:
    data = alert.get('data') or {}
    win = ((data.get('win') or {}).get('eventdata') or {})
    for candidate in (data.get('srcip'), data.get('src_ip'), win.get('ipAddress'), win.get('sourceAddress')):
        if candidate and candidate != '-':
            return str(candidate)
    return ''


# ── Case creation ────────────────────────────────────────────────────────────────────────────
def find_case(source_id: str) -> Optional[dict]:
    status, body = supabase('GET', 'cases', params={'source': 'eq.wazuh', 'source_id': f'eq.{source_id}', 'select': '*'})
    if status == 200 and isinstance(body, list) and body:
        return body[0]
    return None


def create_case(alert: dict) -> Optional[dict]:
    rule = alert.get('rule') or {}
    agent = alert.get('agent') or {}
    mitre = rule.get('mitre') or {}
    level = int(rule.get('level') or 0)
    severity, tier = get_severity(level)
    source_id = alert_source_id(alert)

    existing = find_case(source_id)
    if existing:
        log.info(f"Alert {source_id} already has case {existing.get('case_number')} — skipping")
        return None

    # mitre.id holds technique IDs (T1110); mitre.technique holds their NAMES. The spec stored
    # the name, which is why isolation never fired: it compared names against an ID list.
    case_data = {
        # case_number is omitted on purpose — the database assigns it from case_number_seq.
        # The spec's "read latest, add one" raced when two alerts arrived together, and the
        # UNIQUE constraint then dropped the second case.
        'org_id': ORG_ID,
        'title': (rule.get('description') or 'Wazuh alert')[:500],
        'description': f"Alert from {agent.get('name', 'unknown')} — Rule {rule.get('id', '')} (level {level}): {rule.get('description', '')}",
        'severity': severity,
        'status': 'open',
        'source': 'wazuh',
        'source_id': source_id,
        'agent_id': agent.get('id', ''),
        'agent_name': agent.get('name', ''),
        'source_ip': extract_source_ip(alert) or None,
        'rule_id': str(rule.get('id', '')),
        'rule_level': level,
        'mitre_technique': first(mitre.get('id')) or None,
        'mitre_tactic': first(mitre.get('tactic')) or None,
        'tags': [g for g in (rule.get('groups') or []) if isinstance(g, str)],
        'tier': tier,
    }

    status, body = supabase('POST', 'cases', data=case_data)
    if status == 409:
        # Another integratord process cased this alert between our lookup and insert.
        log.info(f'Alert {source_id} cased concurrently — skipping')
        return None
    if status not in (200, 201) or not isinstance(body, list) or not body:
        log.error(f'Case creation failed for alert {source_id}')
        return None

    case = body[0]
    log.info(f"Created {case['case_number']} [{severity}] from alert {source_id}")
    add_timeline(case['id'], f"Case {case['case_number']} created from Wazuh alert (rule {case_data['rule_id']}, level {level})")
    return case


# ── Actions ──────────────────────────────────────────────────────────────────────────────────
def enrich_iocs(case: dict, tier: int):
    ip = case.get('source_ip') or ''
    if not ip or is_internal_ip(ip):
        return
    # /api/soar/enrich with the shared token. /api/public/scan is the anonymous scanner, capped at
    # 10 requests an hour per IP — the engine would be throttled after 10 alerts.
    if not SOAR_TOKEN:
        add_soar_log(case['id'], tier, f'Enrich IOC {ip}', 'SKIPPED — SOAR_ENGINE_TOKEN not set')
        return
    try:
        resp = requests.post(f'{BACKEND_URL}/api/soar/enrich', json={'ip': ip}, headers={'X-NovrSOC-SOAR-Token': SOAR_TOKEN}, timeout=30)
    except requests.RequestException as e:
        add_soar_log(case['id'], tier, f'Enrich IOC {ip}', f'ERROR: {e}')
        return
    if not resp.ok:
        add_soar_log(case['id'], tier, f'Enrich IOC {ip}', f'FAILED: HTTP {resp.status_code}')
        return
    result = resp.json()
    verdict, score = result.get('verdict', 'unknown'), int(result.get('risk_score') or 0)
    supabase('POST', 'case_iocs', data={'case_id': case['id'], 'type': 'ip', 'value': ip, 'verdict': verdict, 'risk_score': score, 'enriched_at': now_iso()}, prefer='return=minimal')
    add_timeline(case['id'], f'IOC enriched: {ip} — verdict {verdict}, score {score}')
    add_soar_log(case['id'], tier, f'Enrich IOC {ip}', f'SUCCESS: {verdict} ({score})')


def block_ip(case: dict, tier: int) -> bool:
    ip = case.get('source_ip') or ''
    if not ip or is_internal_ip(ip):
        return False
    if not (OPNSENSE_URL and OPNSENSE_KEY and OPNSENSE_SECRET):
        add_soar_log(case['id'], tier, f'Block IP {ip}', 'SKIPPED — OPNsense not configured')
        return False
    try:
        # alias_util/add inserts into the live pf table immediately — no reconfigure needed.
        # The alias must already exist (type Host(s)) and be referenced by a block rule.
        resp = requests.post(
            f'{OPNSENSE_URL}/api/firewall/alias_util/add/{OPNSENSE_ALIAS}',
            json={'address': ip},
            auth=(OPNSENSE_KEY, OPNSENSE_SECRET),
            verify=OPNSENSE_VERIFY_TLS,
            timeout=10,
        )
    except requests.RequestException as e:
        add_soar_log(case['id'], tier, f'Block IP {ip}', f'ERROR: {e}')
        return False
    try:
        body = resp.json() if resp.ok else {}
    except ValueError:
        body = {}
    # OPNsense answers {"status": "done"} on success and {"status": "failed"} otherwise, both 200.
    if resp.ok and str(body.get('status', '')).lower() == 'done':
        add_timeline(case['id'], f'Source IP {ip} blocked at OPNsense (alias {OPNSENSE_ALIAS})')
        add_soar_log(case['id'], tier, f'Block IP {ip}', 'SUCCESS')
        update_case(case['id'], {'containment_done': True})
        return True
    add_soar_log(case['id'], tier, f'Block IP {ip}', f'FAILED: HTTP {resp.status_code} {resp.text[:120]}')
    return False


def wazuh_token() -> Optional[str]:
    """The Wazuh API takes a JWT from /security/user/authenticate — basic auth on
    /active-response itself is rejected."""
    try:
        resp = requests.post(f'{WAZUH_API}/security/user/authenticate', auth=(WAZUH_USER, WAZUH_PASSWORD), verify=WAZUH_VERIFY_TLS, timeout=10)
    except requests.RequestException as e:
        log.error(f'Wazuh auth failed: {e}')
        return None
    if not resp.ok:
        log.error(f'Wazuh auth failed: HTTP {resp.status_code}')
        return None
    return (resp.json().get('data') or {}).get('token')


def isolate_agent(case: dict, tier: int) -> bool:
    technique = case.get('mitre_technique') or ''
    agent_id = case.get('agent_id') or ''
    base_technique = technique.split('.')[0]
    if base_technique not in ISOLATE_TECHNIQUES or not agent_id or agent_id == '000':
        return False
    action = f'Isolate agent {agent_id}'
    if not WAZUH_ISOLATE_COMMAND:
        add_soar_log(case['id'], tier, action, 'SKIPPED — WAZUH_ISOLATE_COMMAND not set (Wazuh ships no isolation response)')
        return False
    if not WAZUH_PASSWORD:
        add_soar_log(case['id'], tier, action, 'SKIPPED — WAZUH_PASSWORD not set')
        return False
    token = wazuh_token()
    if not token:
        add_soar_log(case['id'], tier, action, 'FAILED: could not authenticate to the Wazuh API')
        return False
    try:
        resp = requests.put(
            f'{WAZUH_API}/active-response',
            params={'agents_list': agent_id},
            json={'command': WAZUH_ISOLATE_COMMAND, 'alert': {'data': {'srcip': case.get('source_ip') or ''}}},
            headers={'Authorization': f'Bearer {token}'},
            verify=WAZUH_VERIFY_TLS,
            timeout=15,
        )
    except requests.RequestException as e:
        add_soar_log(case['id'], tier, action, f'ERROR: {e}')
        return False
    affected = ((resp.json().get('data') or {}).get('affected_items') or []) if resp.ok else []
    if resp.ok and agent_id in [str(a) for a in affected]:
        # "REQUESTED", not "isolated": the manager accepted the command for the agent; whether the
        # script succeeded on the endpoint is only visible in that agent's active-responses.log.
        add_timeline(case['id'], f'Isolation ({WAZUH_ISOLATE_COMMAND}) sent to agent {agent_id} via Wazuh active response')
        add_soar_log(case['id'], tier, action, 'REQUESTED — accepted by Wazuh manager')
        update_case(case['id'], {'containment_done': True})
        return True
    add_soar_log(case['id'], tier, action, f'FAILED: HTTP {resp.status_code} {resp.text[:120]}')
    return False


def send_resend(to: str, subject: str, body: str):
    """One Resend send. Returns (ok, detail)."""
    try:
        resp = requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {RESEND_KEY}'},
            json={'from': RESEND_FROM, 'to': [to], 'subject': subject, 'html': body},
            timeout=10,
        )
    except requests.RequestException as err:
        return False, f'ERROR: {err}'
    if resp.ok:
        return True, 'SUCCESS'
    return False, f'FAILED: HTTP {resp.status_code} {resp.text[:120]}'


def case_email_body(case: dict, heading: str, colour: str) -> str:
    e = lambda v: html.escape(str(v or 'N/A'))  # alert text is interpolated into HTML
    return f"""
        <div style="font-family:sans-serif;max-width:600px">
            <div style="background:{colour};padding:20px;border-radius:12px 12px 0 0">
                <h2 style="color:white;margin:0">{e(heading)}</h2>
            </div>
            <div style="background:#f8f9fc;padding:20px;border-radius:0 0 12px 12px">
                <p><strong>Case:</strong> {e(case.get('case_number'))}</p>
                <p><strong>Title:</strong> {e(case.get('title'))}</p>
                <p><strong>Severity:</strong> {e((case.get('severity') or '').upper())}</p>
                <p><strong>Agent:</strong> {e(case.get('agent_name'))}</p>
                <p><strong>Source IP:</strong> {e(case.get('source_ip'))}</p>
                <p><strong>MITRE:</strong> {e(case.get('mitre_technique'))}</p>
                <a href="{APP_URL}/admin/secops/cases?id={e(case.get('id'))}" style="display:inline-block;background:#520385;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin-top:16px">View in NovrSOC →</a>
            </div>
        </div>"""


def notify_email(case: dict, tier: int):
    """Team notification to the SOC mailbox (SOC_EMAIL)."""
    if not RESEND_KEY:
        add_soar_log(case['id'], tier, 'Email notification', 'SKIPPED — RESEND_API_KEY not set')
        return
    severity = (case.get('severity') or 'medium').upper()
    ok, detail = send_resend(
        SOC_EMAIL,
        f"[NovrSOC] {severity}: {case.get('case_number')} — {case.get('title')}",
        case_email_body(case, f'New {severity.lower()} case', '#E8730C' if severity == 'HIGH' else '#520385'),
    )
    add_soar_log(case['id'], tier, 'Email notification', detail)
    if ok:
        add_timeline(case['id'], f'Email notification sent to {SOC_EMAIL}')


def notify_ciso(case: dict, tier: int):
    if not RESEND_KEY:
        add_soar_log(case['id'], tier, 'CISO email', 'SKIPPED — RESEND_API_KEY not set')
        return
    ok, detail = send_resend(
        CISO_EMAIL,
        f"🚨 CRITICAL: {case.get('case_number')} — {case.get('title')}",
        case_email_body(case, 'Critical Case — Immediate Action Required', '#CC2B2B'),
    )
    add_soar_log(case['id'], tier, 'CISO email', detail)
    # Marked escalated only when Resend accepted the message.
    if ok:
        add_timeline(case['id'], f'CISO escalation email sent to {CISO_EMAIL}')
        update_case(case['id'], {'escalated': True})


def auto_close(case: dict, level: int):
    reason = f'Level {level} alert — auto-resolved by SOAR tier 1'
    update_case(case['id'], {'status': 'resolved', 'auto_closed': True, 'resolved_at': now_iso()})
    add_timeline(case['id'], f'Case auto-closed: {reason}')
    add_soar_log(case['id'], 1, 'Auto-close', f'SUCCESS: {reason}')
    log.info(f"Auto-closed {case.get('case_number')}")


# ── Pipeline ─────────────────────────────────────────────────────────────────────────────────
def process_alert(alert: dict):
    rule = alert.get('rule') or {}
    level = int(rule.get('level') or 0)
    severity, tier = get_severity(level)
    log.info(f"Alert level {level} [{severity}] — {(rule.get('description') or '')[:60]}")

    if level < 7:
        return  # below the case threshold; the ossec.conf <level> should already filter these

    case = create_case(alert)
    if not case:
        return

    enrich_iocs(case, tier)

    if tier == 1:
        auto_close(case, level)
        return

    block_ip(case, tier)
    if tier == 3:
        isolate_agent(case, tier)
    if tier == 2:
        notify_email(case, tier)
    else:
        notify_ciso(case, tier)
        # Only when it's a different inbox — by default both are soc@, and the CISO email
        # already carries everything the team one would.
        if SOC_EMAIL.lower() != CISO_EMAIL.lower():
            notify_email(case, tier)
    add_soar_log(case['id'], tier, f'Tier {tier} processing complete',
                 'Awaiting analyst review.' if tier == 2 else 'Automated response finished; see entries above for each action.')


# ── Alert forwarder (phase R2) ───────────────────────────────────────────────────────────────
# A separate, long-running mode: `soar.py --forward` (systemd unit novrsoc-forwarder.service).
# The integratord path above only ever sees one alert at a time and keeps no state, so anything
# missed while it was down would be lost. The forwarder instead reads alerts from the Wazuh
# Indexer, resolves each agent's groups through the Wazuh API, and POSTs batches to
# NOVRSOC_BACKEND/api/ingest/alerts. It persists a checkpoint — the (timestamp, alert id) sort
# position of the last alert the backend acknowledged — so a restart or an outage resumes exactly
# where it stopped, and no burst of alerts can stall it (forward_once). On first run it backfills
# SOAR_BACKFILL_HOURS. Late-indexed alerts are caught by reading only settled alerts
# (SOAR_FORWARD_SETTLE_SECONDS) and by a bounded periodic sweep of the overlap window; the backend
# de-duplicates on the Wazuh alert id, so what that re-sends is harmless.
#
# It shares no code path with the response actions: a forwarding failure can't block a response
# and a response failure can't block forwarding. ALERT_INGEST_TOKEN is sent only in the
# Authorization header and never logged.
INGEST_TOKEN = os.environ.get('ALERT_INGEST_TOKEN', '')
INDEXER_URL = os.environ.get('WAZUH_INDEXER_URL', 'https://localhost:9200').rstrip('/')
INDEXER_USER = os.environ.get('WAZUH_INDEXER_USER', '')
INDEXER_PASSWORD = os.environ.get('WAZUH_INDEXER_PASSWORD', '')
ALERTS_INDEX = os.environ.get('WAZUH_ALERTS_INDEX', 'wazuh-alerts-4.x-*')
CURSOR_FILE = os.environ.get('SOAR_CURSOR_FILE', '/var/lib/novrsoc/ingest_cursor.json')


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except ValueError:
        return default


BACKFILL_HOURS = _int_env('SOAR_BACKFILL_HOURS', 24, 0, 24 * 30)
FORWARD_INTERVAL = _int_env('SOAR_FORWARD_INTERVAL', 30, 5, 3600)          # seconds between cycles
FORWARD_BATCH = _int_env('SOAR_FORWARD_BATCH', 100, 1, 100)                # the backend's batch cap
FORWARD_OVERLAP = _int_env('SOAR_FORWARD_OVERLAP_SECONDS', 120, 0, 3600)   # late-sweep window behind the checkpoint
# Alerts are read only once they are at least this old, so ones the indexer stores a little late are
# still read in order by the main pass.
FORWARD_SETTLE = _int_env('SOAR_FORWARD_SETTLE_SECONDS', 60, 0, 3600)
FORWARD_LATE_EVERY = _int_env('SOAR_FORWARD_LATE_EVERY', 10, 0, 10_000)     # late sweep every N cycles; 0 = never
FORWARD_LATE_MAX_PAGES = _int_env('SOAR_FORWARD_LATE_MAX_PAGES', 5, 1, 50)
FORWARD_MIN_LEVEL = _int_env('SOAR_FORWARD_MIN_LEVEL', 0, 0, 16)           # 0 = everything the indexer holds
MAX_PAGES_PER_CYCLE = 50
GROUP_CACHE_SECONDS = 300
RETRY_DELAYS = (2, 4, 8, 16, 32)
# Deterministic total order: timestamp, then Wazuh's own alert id (unique per manager). The checkpoint
# is a position in this order, so equal timestamps never stall or skip.
SORT = [{'timestamp': {'order': 'asc'}}, {'id': {'order': 'asc', 'unmapped_type': 'keyword', 'missing': '_last'}}]


def parse_ts(ts: str) -> Optional[datetime]:
    """Wazuh writes 2026-10-09T10:00:00.123+0000; fromisoformat wants +00:00."""
    if not ts:
        return None
    t = ts.strip().replace('Z', '+00:00')
    if len(t) >= 5 and t[-5] in '+-' and t[-4:].isdigit():
        t = f'{t[:-2]}:{t[-2:]}'
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── Checkpoint ───────────────────────────────────────────────────────────────────────────────
# The cursor file holds the position of the last alert the backend acknowledged:
#
#   {"last_forwarded_timestamp": "<ISO>",          # as before; still written, still read
#    "search_after": [<timestamp ms>, "<alert id>"], # version 2: the exact Indexer sort position
#    "version": 2, "saved_at": "<ISO>"}
#
# Reading resumes strictly after `search_after` in the deterministic (timestamp, id) order, so a
# cycle always moves forward whatever the volume. A version-1 file (timestamp only) resumes once
# from timestamp - overlap, as before; the first acknowledged page writes version 2.

def _valid_sort(value) -> Optional[list]:
    """[timestamp ms, alert id] as the Indexer returns it for SORT, else None."""
    if not isinstance(value, list) or len(value) != 2:
        return None
    ms, alert_id = value
    if isinstance(ms, bool) or not isinstance(ms, (int, float)) or not isinstance(alert_id, str) or not alert_id:
        return None
    return [int(ms), alert_id]


def _ms_to_dt(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


class Checkpoint:
    def __init__(self, ts: datetime, sort: Optional[list] = None):
        self.ts, self.sort = ts, sort


def load_checkpoint() -> Optional[Checkpoint]:
    try:
        with open(CURSOR_FILE, encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        log.error(f'Forwarder: cursor file unreadable ({e}) — treating as first run')
        return None
    if not isinstance(data, dict):
        log.error('Forwarder: cursor file is not an object — treating as first run')
        return None
    sort = _valid_sort(data.get('search_after'))
    ts = _ms_to_dt(sort[0]) if sort else parse_ts(str(data.get('last_forwarded_timestamp') or ''))
    if ts is None:
        log.error('Forwarder: cursor file has no usable position — treating as first run')
        return None
    return Checkpoint(ts, sort)


def save_checkpoint(cp: Checkpoint):
    """Atomic write: a crash mid-write must not leave a corrupt cursor."""
    os.makedirs(os.path.dirname(CURSOR_FILE) or '.', exist_ok=True)
    tmp = f'{CURSOR_FILE}.tmp'
    body: dict = {'last_forwarded_timestamp': cp.ts.isoformat(), 'saved_at': now_iso()}
    if cp.sort:
        body.update({'search_after': cp.sort, 'version': 2})
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(body, f)
    os.replace(tmp, CURSOR_FILE)


def load_cursor() -> Optional[datetime]:
    """The checkpoint's timestamp (kept for callers and tooling that read only the time)."""
    cp = load_checkpoint()
    return cp.ts if cp else None


def save_cursor(ts: datetime):
    """A timestamp-only (version 1) checkpoint, e.g. to replay from a chosen time."""
    save_checkpoint(Checkpoint(ts))


class AgentGroups:
    """agent id -> Wazuh groups, from GET /agents, refreshed every GROUP_CACHE_SECONDS."""

    def __init__(self):
        self.groups: dict = {}
        self.loaded_at = 0.0

    def refresh(self) -> bool:
        token = wazuh_token()
        if not token:
            return False
        groups, offset = {}, 0
        while True:
            try:
                resp = requests.get(f'{WAZUH_API}/agents', params={'select': 'id,group', 'limit': 500, 'offset': offset},
                                    headers={'Authorization': f'Bearer {token}'}, verify=WAZUH_VERIFY_TLS, timeout=15)
            except requests.RequestException as e:
                log.error(f'Forwarder: Wazuh agent list failed: {e}')
                return False
            if not resp.ok:
                log.error(f'Forwarder: Wazuh agent list failed: HTTP {resp.status_code}')
                return False
            data = (resp.json().get('data') or {})
            items = data.get('affected_items') or []
            for a in items:
                groups[str(a.get('id'))] = [g for g in (a.get('group') or []) if isinstance(g, str)]
            offset += len(items)
            if not items or offset >= int(data.get('total_affected_items') or 0):
                break
        self.groups, self.loaded_at = groups, time.monotonic()
        return True

    def get(self, agent_id: str) -> list:
        if time.monotonic() - self.loaded_at > GROUP_CACHE_SECONDS:
            self.refresh()  # on failure the previous map (possibly stale) is kept
        return self.groups.get(str(agent_id), [])


def search_alerts(since: datetime, search_after: Optional[list], until: Optional[datetime] = None) -> Optional[list]:
    """One page of alerts in [since, until], in SORT order after `search_after`. None on failure."""
    rng: dict = {'gte': since.isoformat()}
    if until is not None:
        rng['lte'] = until.isoformat()
    query: dict = {'bool': {'filter': [{'range': {'timestamp': rng}}]}}
    if FORWARD_MIN_LEVEL > 0:
        query['bool']['filter'].append({'range': {'rule.level': {'gte': FORWARD_MIN_LEVEL}}})
    body: dict = {'size': FORWARD_BATCH, 'sort': SORT, 'query': query}
    if search_after:
        body['search_after'] = search_after
    try:
        resp = requests.post(f'{INDEXER_URL}/{ALERTS_INDEX}/_search', json=body, auth=(INDEXER_USER, INDEXER_PASSWORD),
                             verify=WAZUH_VERIFY_TLS, timeout=30)
    except requests.RequestException as e:
        log.error(f'Forwarder: indexer search failed: {e}')
        return None
    if not resp.ok:
        log.error(f'Forwarder: indexer search failed: HTTP {resp.status_code}')
        return None
    try:
        data = resp.json()
    except ValueError:
        log.error('Forwarder: indexer answered with something other than JSON')
        return None
    shards = data.get('_shards') or {}
    if data.get('error') is not None or (shards.get('failed') or 0) > 0:
        # A partial answer would let the checkpoint jump over alerts on the shards that failed.
        log.error(f"Forwarder: indexer search incomplete ({shards.get('failed') or 0} shard(s) failed) — not advancing")
        return None
    return (data.get('hits') or {}).get('hits') or []


def to_ingest(alert: dict, groups: AgentGroups) -> dict:
    """The backend's ingest shape. Org, severity and status are never sent — the backend derives
    them. The whole alert goes along as `raw` (the backend caps it at 32 KB)."""
    rule = alert.get('rule') or {}
    agent = alert.get('agent') or {}
    mitre = rule.get('mitre') or {}
    out: dict = {
        'id': alert_source_id(alert),
        'timestamp': alert.get('timestamp') or '',
        'rule': {'id': str(rule.get('id', '')), 'level': int(rule.get('level') or 0)},
        'agent': {k: str(agent[k]) for k in ('id', 'name', 'ip') if agent.get(k)},
        'agent_groups': groups.get(agent.get('id', '')),
        'raw': alert,
    }
    if rule.get('description'):
        out['rule']['description'] = str(rule['description'])[:2000]
    ids = mitre.get('id')
    if ids:
        out['rule']['mitre'] = {'id': [str(i) for i in (ids if isinstance(ids, list) else [ids])][:50]}
    if alert.get('location'):
        out['location'] = str(alert['location'])[:1024]
    return out


def post_batch(alerts: list) -> bool:
    """POST one batch, retrying network errors, 429 and 5xx with backoff. True = the backend took
    it (accepted, duplicate or rejected as unmappable), so the cursor may advance."""
    url = f'{BACKEND_URL}/api/ingest/alerts'
    headers = {'Authorization': f'Bearer {INGEST_TOKEN}', 'Content-Type': 'application/json'}
    for attempt, delay in enumerate((0, *RETRY_DELAYS)):
        if delay:
            time.sleep(delay)
        try:
            resp = requests.post(url, json={'alerts': alerts}, headers=headers, timeout=30)
        except requests.RequestException as e:
            log.warning(f'Forwarder: ingest POST failed (attempt {attempt + 1}): {type(e).__name__}')
            continue
        if resp.ok:
            try:
                r = resp.json()
            except ValueError:
                r = {}
            log.info(f"Forwarder: {len(alerts)} sent — accepted {r.get('accepted')}, duplicates {r.get('duplicates')}, "
                     f"rejected {r.get('rejected')} (quarantined {r.get('quarantined')}, invalid {r.get('invalid')})")
            if r.get('invalid'):
                # Refused by validation and not recoverable from the backend: their reasons are in
                # alert_ingest_rejects; replay this time range once the cause is fixed.
                log.warning(f"Forwarder: {r.get('invalid')} alert(s) failed validation and were not stored — see alert_ingest_rejects")
            return True
        if resp.status_code == 429 or resp.status_code >= 500:
            log.warning(f'Forwarder: ingest returned HTTP {resp.status_code} (attempt {attempt + 1})')
            continue
        # 401 (wrong token), 400/413 (a bug in this shape): retrying won't help. Stop without
        # advancing, so nothing is skipped once it is fixed.
        log.error(f'Forwarder: ingest refused the batch: HTTP {resp.status_code} — not advancing the cursor')
        return False
    log.error('Forwarder: ingest unavailable after retries — will resume from the cursor next cycle')
    return False


def forward_once(groups: AgentGroups, cycle: int = 0) -> int:
    """One cycle. Returns the number of alerts the backend took.

    Main pass: alerts at least FORWARD_SETTLE seconds old, strictly after the checkpoint in SORT
    order, at most MAX_PAGES_PER_CYCLE pages. The checkpoint moves to the last alert of each page
    the backend acknowledged — never past a page it did not — so the next cycle (or a restart)
    continues exactly there, however many alerts share one timestamp or one overlap window.

    Every FORWARD_LATE_EVERY cycles, a late sweep re-reads the FORWARD_OVERLAP seconds behind the
    checkpoint (at most FORWARD_LATE_MAX_PAGES pages) for alerts the indexer stored after the main
    pass had passed their time. It never moves the checkpoint, so it cannot hold forwarding back;
    what it re-sends the backend counts as duplicates."""
    cp = load_checkpoint()
    now = datetime.now(timezone.utc)
    until = now - timedelta(seconds=FORWARD_SETTLE)
    if cp is None:
        since, after = now - timedelta(hours=BACKFILL_HOURS), None
        log.info(f'Forwarder: no cursor — backfilling from {since.isoformat()} ({BACKFILL_HOURS}h)')
    elif cp.sort is None:
        # Version-1 cursor: the time only. Re-read the overlap once; the first acknowledged page
        # stores the exact sort position and every later cycle resumes from that.
        since, after = cp.ts - timedelta(seconds=FORWARD_OVERLAP), None
    else:
        since, after = cp.ts, cp.sort

    sent = 0
    for _ in range(MAX_PAGES_PER_CYCLE):
        hits = search_alerts(since, after, until)
        if hits is None or not hits:
            break
        position = next((s for s in (_valid_sort(h.get('sort')) for h in reversed(hits)) if s), None)
        if position is None:
            log.error('Forwarder: indexer returned a page without sort values — not advancing')
            break
        if not post_batch([to_ingest(h.get('_source') or {}, groups) for h in hits]):
            break  # nothing past the last acknowledged page is skipped: the next cycle replays it
        sent += len(hits)
        cp = Checkpoint(_ms_to_dt(position[0]), position)
        save_checkpoint(cp)
        after = position
        if len(hits) < FORWARD_BATCH:
            break

    if cp is not None and cp.sort and FORWARD_LATE_EVERY and cycle % FORWARD_LATE_EVERY == 0:
        late_sweep(cp, groups)
    return sent


def late_sweep(cp: Checkpoint, groups: AgentGroups) -> int:
    """Re-send the FORWARD_OVERLAP seconds up to the checkpoint (bounded; never moves it)."""
    since, after, sent = cp.ts - timedelta(seconds=FORWARD_OVERLAP), None, 0
    for _ in range(FORWARD_LATE_MAX_PAGES):
        hits = search_alerts(since, after, cp.ts)
        if not hits:
            return sent
        if not post_batch([to_ingest(h.get('_source') or {}, groups) for h in hits]):
            return sent
        sent += len(hits)
        after = _valid_sort(hits[-1].get('sort'))
        if len(hits) < FORWARD_BATCH or after is None:
            return sent
    log.warning(f'Forwarder: late sweep stopped after {FORWARD_LATE_MAX_PAGES} page(s); the overlap window holds more '
                f'alerts than that, so a late-indexed alert in its newer part may be missed (raise SOAR_FORWARD_SETTLE_SECONDS)')
    return sent


def forward_loop():
    missing = [n for n, v in (('ALERT_INGEST_TOKEN', INGEST_TOKEN), ('WAZUH_INDEXER_USER', INDEXER_USER),
                              ('WAZUH_INDEXER_PASSWORD', INDEXER_PASSWORD), ('WAZUH_PASSWORD', WAZUH_PASSWORD)) if not v]
    if missing:
        log.error(f"Forwarder: {', '.join(missing)} not set — not starting")
        sys.exit(1)
    log.info(f'Forwarder: started — {INDEXER_URL}/{ALERTS_INDEX} -> {BACKEND_URL}/api/ingest/alerts every {FORWARD_INTERVAL}s, cursor {CURSOR_FILE}')
    groups = AgentGroups()
    cycle = 0
    while True:
        cycle += 1
        try:
            forward_once(groups, cycle)
        except Exception as e:  # noqa: BLE001 — one bad cycle must not stop the service
            log.exception(f'Forwarder cycle failed: {e}')
        time.sleep(FORWARD_INTERVAL)


def main():
    if '--forward' in sys.argv[1:]:
        forward_loop()
        return
    if not SUPABASE_URL or not SUPABASE_KEY:
        log.error('SUPABASE_URL / SUPABASE_SERVICE_KEY not set — cannot record cases')
        sys.exit(1)
    # integratord passes the alert file path as argv[1]; stdin is supported for manual tests.
    raw = open(sys.argv[1], encoding='utf-8').read() if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]) else sys.stdin.read()
    try:
        alert = json.loads(raw)
    except json.JSONDecodeError as e:
        log.error(f'Invalid alert JSON: {e}')
        sys.exit(1)
    try:
        process_alert(alert)
    except Exception as e:  # noqa: BLE001 — never let one bad alert kill the integration silently
        log.exception(f'SOAR processing error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
