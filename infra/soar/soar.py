#!/usr/bin/env python3
"""
NovrSOC SOAR engine.

Called by Wazuh's integratord (via the custom-novrsoc-soar wrapper) once per alert at or above
the integration's <level>. Reads the alert, creates a case in Supabase (deduplicated on the
Wazuh alert id), then responds by tier:

  Tier 1  level 7-9    medium   enrich, auto-close
  Tier 2  level 10-12  high     enrich, block source IP, Slack; an analyst reviews
  Tier 3  level 13+    critical enrich, block source IP, isolate agent (selected techniques),
                                Slack, CISO email

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
from datetime import datetime, timezone
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

SLACK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')
RESEND_KEY = os.environ.get('RESEND_API_KEY', '')
RESEND_FROM = os.environ.get('RESEND_FROM', 'NovrSOC Alerts <alerts@cybernovr.com>')
CISO_EMAIL = os.environ.get('CISO_EMAIL', 'rayne@cybernovr.com')

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


def notify_slack(case: dict, tier: int):
    if not SLACK_URL:
        add_soar_log(case['id'], tier, 'Slack notification', 'SKIPPED — SLACK_WEBHOOK_URL not set')
        return
    severity = (case.get('severity') or 'medium').upper()
    emoji = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡'
    text = (f"{emoji} *{case.get('case_number')} — {severity}*\n*{case.get('title')}*\n"
            f"Agent: {case.get('agent_name') or 'N/A'} | IP: {case.get('source_ip') or 'N/A'} | MITRE: {case.get('mitre_technique') or 'N/A'}\n"
            f"<{APP_URL}/admin/secops/cases|View in NovrSOC →>")
    try:
        resp = requests.post(SLACK_URL, json={'text': f'{emoji} {severity} case created', 'blocks': [{'type': 'section', 'text': {'type': 'mrkdwn', 'text': text}}]}, timeout=5)
    except requests.RequestException as e:
        add_soar_log(case['id'], tier, 'Slack notification', f'ERROR: {e}')
        return
    if resp.ok:
        add_timeline(case['id'], 'Slack notification sent')
        add_soar_log(case['id'], tier, 'Slack notification', 'SUCCESS')
    else:
        add_soar_log(case['id'], tier, 'Slack notification', f'FAILED: HTTP {resp.status_code}')


def notify_ciso(case: dict, tier: int):
    if not RESEND_KEY:
        add_soar_log(case['id'], tier, 'CISO email', 'SKIPPED — RESEND_API_KEY not set')
        return
    e = lambda v: html.escape(str(v or 'N/A'))  # alert text is interpolated into HTML
    body = f"""
        <div style="font-family:sans-serif;max-width:600px">
            <div style="background:#CC2B2B;padding:20px;border-radius:12px 12px 0 0">
                <h2 style="color:white;margin:0">Critical Case — Immediate Action Required</h2>
            </div>
            <div style="background:#f8f9fc;padding:20px;border-radius:0 0 12px 12px">
                <p><strong>Case:</strong> {e(case.get('case_number'))}</p>
                <p><strong>Title:</strong> {e(case.get('title'))}</p>
                <p><strong>Severity:</strong> {e((case.get('severity') or '').upper())}</p>
                <p><strong>Agent:</strong> {e(case.get('agent_name'))}</p>
                <p><strong>Source IP:</strong> {e(case.get('source_ip'))}</p>
                <p><strong>MITRE:</strong> {e(case.get('mitre_technique'))}</p>
                <a href="{APP_URL}/admin/secops/cases" style="display:inline-block;background:#520385;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin-top:16px">View in NovrSOC →</a>
            </div>
        </div>"""
    try:
        resp = requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {RESEND_KEY}'},
            json={'from': RESEND_FROM, 'to': [CISO_EMAIL], 'subject': f"🚨 CRITICAL: {case.get('case_number')} — {case.get('title')}", 'html': body},
            timeout=10,
        )
    except requests.RequestException as err:
        add_soar_log(case['id'], tier, 'CISO email', f'ERROR: {err}')
        return
    # Marked escalated only when Resend accepted the message — the spec set it unconditionally.
    if resp.ok:
        add_timeline(case['id'], f'CISO escalation email sent to {CISO_EMAIL}')
        add_soar_log(case['id'], tier, 'CISO email', 'SUCCESS')
        update_case(case['id'], {'escalated': True})
    else:
        add_soar_log(case['id'], tier, 'CISO email', f'FAILED: HTTP {resp.status_code} {resp.text[:120]}')


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
    notify_slack(case, tier)
    if tier == 3:
        notify_ciso(case, tier)
    add_soar_log(case['id'], tier, f'Tier {tier} processing complete',
                 'Awaiting analyst review.' if tier == 2 else 'Automated response finished; see entries above for each action.')


def main():
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
