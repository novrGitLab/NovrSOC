#!/usr/bin/env python3
"""NovrSOC VMS scanner worker (phase P4).

Runs on a dedicated scanning host with the ProjectDiscovery tools and Nmap installed. It pulls
jobs from the NovrSOC backend (/api/vms/worker), runs the tools against the job's targets and
sends normalised observations back. It decides nothing about scope on its own authority: the
backend validated every target when the job was queued and re-checks every result. The worker
still re-checks scope before each tool runs, as a second line of defence.

  discovery  subfinder (passive subdomains) -> dnsx (A/AAAA/CNAME) -> httpx (live HTTP, title,
             status, server, technologies)
  ports      nmap -sT -sV (TCP connect + service/version detection; no root needed)
  vuln_nuclei   nuclei templates (non-disruptive), after a TCP reachability check
  vuln_openvas  Greenbone/OpenVAS over gvmd's local socket (GMP, python-gvm); 1.8.0: one task per
                job reused across redelivery, bounded retries and time limit, scan-configuration
                safety gate (safe checks, no vhost expansion), results attributed only to the
                submitted targets, per-target outcomes from the report

Safety: tools are run with argument lists (never a shell); every target is re-validated as a
plain hostname, IP or the job's own CIDR; rates and timeouts are conservative; a heartbeat every
30 s reports progress and stops the running tool when the backend asks to cancel (e.g. scope
revoked). The API token is read from the environment and never logged.

Presence (phase P10): besides polling for jobs, the worker sends its own heartbeat every
VMS_PRESENCE_SECONDS (default 60) with its kinds and which tools are installed. The backend records
every authenticated request, and that record is what the dashboard calls "connected". The log says
when the worker connects, explains each kind of failure once (wrong token, wrong URL or old backend,
rejected request, backend not ready) instead of repeating it every poll, and writes a short status
line every VMS_STATUS_LOG_SECONDS (default 600) so a quiet log is never ambiguous.

  python3 worker.py --check       one heartbeat to the backend and a plain-language result; claims nothing
  python3 worker.py --self-test   preflight for deployment: configuration (no secret printed), tools and
                                  their versions, then the heartbeat; exit 0 only when all pass
  python3 worker.py --health [--json] [--gvm-permission-probe]
                                  health of the worker and each dependency by layer: local, reachability,
                                  authentication, functional, end-to-end (never claimed: needs a real job).
                                  Read-only towards Greenbone; one heartbeat to the backend. Exit 1 on a failure.
                                  --gvm-permission-probe also creates and deletes a test target and task
                                  (TEST-NET 192.0.2.1, never started) to prove the GVM user may create them

Outcomes (1.3.0): every target of a ports or discovery job gets a host-level result with an
assessment, so "nothing found" is never confused with "could not look":
  reachable_open      something answered and at least one port is open
  reachable_no_open   something answered (closed ports reply), nothing open in the ports scanned
  unreachable         nothing answered from this scanner — the device may still be online (a
                      firewall dropping every probe looks the same)
  no_route            a private address outside the networks this worker declares
                      (VMS_WORKER_NETWORKS): not attempted, with the reason
  insufficient_evidence  the tool reported nothing usable for the target
A tool error or unreadable output fails the job. Raw tool output (bounded, redacted) is sent as
evidence; the backend keeps it 30 days. SIGTERM stops the running tool and hands the job back to
the queue instead of leaving it to time out.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterable, Optional

import requests
import signal
import socket

log = logging.getLogger('vms-worker')

API = os.environ.get('NOVRSOC_API_URL', '').rstrip('/')
TOKEN = os.environ.get('VMS_WORKER_TOKEN', '')
WORKER_ID = os.environ.get('VMS_WORKER_ID', 'vms-worker-1')
KINDS = [k.strip() for k in os.environ.get('VMS_WORKER_KINDS', 'discovery,ports').split(',') if k.strip()]
POLL_SECONDS = int(os.environ.get('VMS_POLL_SECONDS', '20'))
HEARTBEAT_SECONDS = 30
VERSION = '1.8.1'
# What this worker enforces itself; the backend only gives jobs that need a feature to workers announcing it.
FEATURES = ['exclusions', 'pinned_addresses']
# Networks this worker can actually reach besides the public internet (comma-separated CIDRs), e.g.
# a VPN into a client LAN. Private, link-local and CGNAT addresses outside them are not scanned.
WORKER_NETWORKS = [n.strip() for n in os.environ.get('VMS_WORKER_NETWORKS', '').split(',') if n.strip()]
EVIDENCE_MAX_BYTES = 64 * 1024         # per tool run; the rest is cut and marked truncated
HEARTBEAT_RETRY_DELAY = 2              # seconds before the single retry on a fresh connection
HEARTBEAT_MAX_BACKOFF = 600            # seconds between heartbeats while the backend stays unreachable
COMPLETE_RETRY_DELAYS = (5, 15, 45)   # seconds between attempts to report a finished job
PRESENCE_SECONDS = max(15, int(os.environ.get('VMS_PRESENCE_SECONDS', '60')))
STATUS_LOG_SECONDS = max(60, int(os.environ.get('VMS_STATUS_LOG_SECONDS', '600')))
ERROR_REPEAT_SECONDS = 600   # the same failure is logged again at most this often
BATCH = 200
TOOL_TIMEOUT = int(os.environ.get('VMS_TOOL_TIMEOUT_SECONDS', '3600'))
HTTPX_RATE = os.environ.get('VMS_HTTPX_RATE', '50')         # requests per second
NMAP_MAX_RATE = os.environ.get('VMS_NMAP_MAX_RATE', '300')  # packets per second
TOOLS = {name: os.environ.get(f'VMS_{name.upper()}_PATH', name) for name in ('subfinder', 'dnsx', 'httpx', 'nmap', 'nuclei')}
NUCLEI_RATE = os.environ.get('VMS_NUCLEI_RATE', '50')                    # requests per second
NUCLEI_SEVERITIES = os.environ.get('VMS_NUCLEI_SEVERITIES', 'low,medium,high,critical')
# Templates that could disrupt a service or brute-force credentials are never run.
NUCLEI_EXCLUDE_TAGS = 'dos,fuzz,intrusive,bruteforce'
# OpenVAS / Greenbone (Release 2, optional): reached over gvmd's local management socket (GMP) with
# python-gvm, so no Greenbone port is ever exposed. See docs/runbooks/vms-openvas.md.
GVM_SOCKET = os.environ.get('GVM_SOCKET', '/run/gvmd/gvmd.sock')
GVM_USER = os.environ.get('GVM_USER', '')
GVM_PASSWORD = os.environ.get('GVM_PASSWORD', '')
# Greenbone's built-in object ids (same on every installation); override if yours differ.
GVM_CONFIG_ID = os.environ.get('GVM_CONFIG_ID', 'daba56c8-73ec-11df-a475-002264764cea')        # "Full and fast"
GVM_SCANNER_ID = os.environ.get('GVM_SCANNER_ID', '08b69003-5fc2-4037-a479-93b440211c73')      # "OpenVAS Default"
GVM_PORT_LIST_ID = os.environ.get('GVM_PORT_LIST_ID', '33d0cd82-57c6-11e1-8ed1-406186ea4fc5')  # "All IANA assigned TCP"
GVM_XML_FORMAT_ID = 'a994b278-1f62-11e1-96ac-406186ea4fc5'
GVM_SCAN_TIMEOUT = max(600, int(os.environ.get('GVM_SCAN_TIMEOUT_SECONDS', '14400')))   # whole scan; stopped after this
GVM_POLL_SECONDS = max(10, int(os.environ.get('GVM_POLL_SECONDS', '30')))
GVM_SOCKET_TIMEOUT = max(30, int(os.environ.get('GVM_SOCKET_TIMEOUT_SECONDS', '300')))  # one GMP call (reports can be slow)
# Optional target alive test (python-gvm AliveTest values); unset = the scan configuration's default.
GVM_ALIVE_TEST = os.environ.get('GVM_ALIVE_TEST', '').strip()
GVM_ALIVE_TESTS = ('Scan Config Default', 'ICMP Ping', 'TCP-ACK Service Ping', 'TCP-SYN Service Ping', 'ARP Ping',
                   'ICMP & TCP-ACK Service Ping', 'ICMP & ARP Ping', 'TCP-ACK Service & ARP Ping',
                   'ICMP, TCP-ACK Service & ARP Ping', 'Consider Alive')
# Where the scanner's own settings live, read only to confirm vhost expansion is off (see gvm_config_safety).
GVM_OPENVAS_CONF = os.environ.get('GVM_OPENVAS_CONF', '/etc/openvas/openvas.conf')
# min_qod=70 is Greenbone's own default quality threshold; rows=-1 with ignore_pagination returns every result.
GVM_REPORT_FILTER = 'apply_overrides=0 min_qod=70 first=1 rows=-1'
GVM_RETRY_DELAYS = (5, 15, 45)    # seconds between attempts after a transient Greenbone failure
GVM_MAX_POLL_FAILURES = 5         # consecutive failed status checks before the job fails
GVM_TASK_PREFIX = 'novrsoc-'      # task and target names: novrsoc-<job id>; only these are ever touched
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')

LABEL = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')


# ── Scope (same rules as backend lib/vmsScope.ts) ─────────────────────────────────────────────
def normalize_hostname(s: str) -> Optional[str]:
    h = (s or '').strip().lower().rstrip('.')
    if not h or len(h) > 253:
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    labels = h.split('.')
    if len(labels) < 2 or not all(LABEL.match(x) for x in labels) or labels[-1].isdigit():
        return None
    return h


def parse_target(s: str):
    s = (s or '').strip()
    try:
        return ('ip', str(ipaddress.ip_address(s)))
    except ValueError:
        h = normalize_hostname(s)
        return ('host', h) if h else None


def is_excluded(t: tuple, exclusions) -> bool:
    """Same rules as the backend (lib/vmsScope.ts isExcluded): host, '.suffix', IP or CIDR."""
    for x in exclusions or []:
        x = str(x).strip().lower()
        if not x:
            continue
        if t[0] == 'host':
            if x == t[1] or (x.startswith('.') and (t[1] == x[1:] or t[1].endswith(x))):
                return True
        else:
            if x == t[1]:
                return True
            if '/' in x:
                try:
                    if ipaddress.ip_address(t[1]) in ipaddress.ip_network(x, strict=False):
                        return True
                except ValueError:
                    pass
    return False


def in_scope(target: str, scopes: list[dict], activity: str) -> bool:
    """True when an active, unexpired scope entry covers target for activity (discovery|ports|vuln).

    An entry with allow_discovery false authorises passive monitoring only (the backend asks third
    parties); this worker touches targets, so it treats such an entry as covering nothing. Entries
    from a backend before P9 carry no allow_discovery and keep their old meaning (allowed)."""
    t = parse_target(target)
    if not t:
        return False
    now = time.time()
    for e in scopes:
        if e.get('status') != 'active':
            continue
        try:
            exp = datetime.fromisoformat(str(e['expires_at']).replace('Z', '+00:00')).timestamp()
        except (KeyError, ValueError):
            continue
        if exp <= now:
            continue
        if is_excluded(t, e.get('exclusions')):
            continue
        if not e.get('allow_discovery', True):
            continue
        if activity == 'ports' and not e.get('allow_port_scan'):
            continue
        if activity == 'vuln' and not e.get('allow_vuln_scan'):
            continue
        kind, value = e.get('kind'), str(e.get('value', '')).lower()
        if t[0] == 'host' and kind == 'domain' and (t[1] == value or (e.get('include_subdomains') and t[1].endswith('.' + value))):
            return True
        if t[0] == 'ip' and kind == 'ip' and t[1] == value:
            return True
        if t[0] == 'ip' and kind == 'cidr':
            try:
                if ipaddress.ip_address(t[1]) in ipaddress.ip_network(value, strict=False):
                    return True
            except ValueError:
                pass
    return False


def _unexpired(e: dict) -> bool:
    try:
        return datetime.fromisoformat(str(e['expires_at']).replace('Z', '+00:00')).timestamp() > time.time()
    except (KeyError, ValueError):
        return False


def resolve_addresses(host: str) -> set:
    """Every address the name resolves to from this worker, now (empty when it does not resolve)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return set()
    out = set()
    for i in infos:
        try:
            out.add(str(ipaddress.ip_address(str(i[4][0]).split('%')[0])))
        except ValueError:
            continue
    return out


RESOLVE = resolve_addresses   # replaced in tests


def pins_ok(target: str, scopes: list[dict], activity: str) -> tuple:
    """1.7.0: a name authorised only by CNII entries pinned to approved addresses may be scanned only
    while it resolves within them, checked here just before the tool runs. A name also covered by an
    unpinned entry keeps that entry's authorisation. Returns (allowed, reason)."""
    t = parse_target(target)
    if not t or t[0] != 'host':
        return True, None
    covering = [e for e in scopes if in_scope(target, [e], activity)]
    if not covering or any(not e.get('pinned_addresses') for e in covering):
        return True, None
    pins = {str(p).lower() for e in covering for p in e.get('pinned_addresses') or []}
    now = {a.lower() for a in RESOLVE(t[1])}
    if not now:
        return False, f'{t[1]} does not resolve from this worker; its CNII authorisation is pinned to {", ".join(sorted(pins))}'
    extra = sorted(now - pins)
    if extra:
        return False, f'{t[1]} now resolves to {", ".join(extra)}, outside its CNII approval ({", ".join(sorted(pins))}); not scanned until re-approved'
    return True, None


def job_target_allowed(raw: str, scopes: list[dict], activity: str) -> bool:
    """A job target is a host/IP in scope (and, for a CNII-pinned name, resolving within its approved
    addresses), or exactly an approved CIDR entry."""
    if '/' not in raw and in_scope(raw, scopes, activity):
        ok, why = pins_ok(raw, scopes, activity)
        if not ok:
            log.warning('target refused: %s', why)
        return ok
    if '/' in raw:
        return any(e.get('kind') == 'cidr' and e.get('status') == 'active' and str(e.get('value')) == raw
                   and _unexpired(e) and e.get('allow_discovery', True) and not e.get('exclusions')
                   and (activity != 'ports' or e.get('allow_port_scan'))
                   and (activity != 'vuln' or e.get('allow_vuln_scan')) for e in scopes)
    return in_scope(raw, scopes, activity)


# ── Tool output parsers (pure; tested in test_worker.py) ──────────────────────────────────────
def parse_subfinder(lines: Iterable[str], domain: str) -> list[str]:
    out = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            host = json.loads(line).get('host', '')
        except json.JSONDecodeError:
            host = line
        h = normalize_hostname(host)
        if h and (h == domain or h.endswith('.' + domain)):
            out.add(h)
    return sorted(out)


def parse_dnsx(lines: Iterable[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        h = normalize_hostname(d.get('host', ''))
        if not h:
            continue
        def ips(key):
            vals = []
            for v in d.get(key) or []:
                try:
                    vals.append(str(ipaddress.ip_address(v)))
                except ValueError:
                    pass
            return vals
        out[h] = {'a': ips('a'), 'aaaa': ips('aaaa'), 'cname': [c for c in (d.get('cname') or []) if normalize_hostname(c)]}
    return out


def parse_httpx(lines: Iterable[str]) -> list[dict]:
    out = []
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = d.get('input') or d.get('host') or ''
        t = parse_target(host.split(':')[0] if host.count(':') == 1 else host)
        if not t:
            continue
        techs = []
        for item in d.get('tech') or []:
            name, _, version = str(item).partition(':')
            if name.strip():
                techs.append({'name': name.strip()[:80], 'version': version.strip()[:60] or None})
        ips = []
        for v in (d.get('a') or []) + (d.get('aaaa') or []):
            try:
                ips.append(str(ipaddress.ip_address(v)))
            except ValueError:
                pass
        status = d.get('status_code') if isinstance(d.get('status_code'), int) and 100 <= d.get('status_code') <= 599 else None
        out.append({
            'type': 'host', 'host': t[1], 'ips': sorted(set(ips)), 'alive': True, 'source': 'httpx', 'technologies': techs[:100],
            'http': {'url': str(d.get('url', ''))[:2048], 'status': status, 'title': (d.get('title') or None) and str(d['title'])[:300],
                     'webserver': (d.get('webserver') or None) and str(d['webserver'])[:200], 'cdn': (d.get('cdn_name') or None) and str(d['cdn_name'])[:80]},
        })
    return out


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Open/filtered ports per host from `nmap -oX -`. The host is reported by its hostname when
    nmap was given one (user-supplied), else by IP."""
    out = []
    root = ET.fromstring(xml_text)
    for host in root.findall('host'):
        addr = next((a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')), None)
        user_name = next((h.get('name') for h in host.findall('hostnames/hostname') if h.get('type') == 'user'), None)
        name = user_name or addr
        if not name:
            continue
        for p in host.findall('ports/port'):
            state = p.find('state')
            st = state.get('state') if state is not None else ''
            if st not in ('open', 'filtered', 'closed'):
                continue
            svc = p.find('service')
            cpes = [c.text for c in (svc.findall('cpe') if svc is not None else []) if c.text][:10]
            out.append({
                'type': 'service', 'host': name, 'port': int(p.get('portid')), 'protocol': p.get('protocol'), 'state': st, 'source': 'nmap',
                'service': svc.get('name') if svc is not None else None,
                'product': svc.get('product') if svc is not None else None,
                'version': ' '.join(x for x in (svc.get('version'), svc.get('extrainfo')) if x)[:80] or None if svc is not None else None,
                # Omitted when nmap gave none: backends before the fix rejected cpe: null, which made
                # every service without a CPE an "invalid observation" (1.8.0).
                **({'cpe': cpes} if cpes else {}),
            })
    return out


def parse_nmap_hosts(xml_text: str) -> dict[str, dict]:
    """Per host in `nmap -oX -` output: its reported status and how every scanned port answered,
    including ports nmap summarises as <extraports> (e.g. 997 filtered). Keyed by address.
    Raises ET.ParseError on unreadable XML (the caller fails the job)."""
    root = ET.fromstring(xml_text)
    hosts: dict[str, dict] = {}
    for host in root.findall('host'):
        addr = next((a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')), None)
        if not addr:
            continue
        st = host.find('status')
        counts: dict[str, int] = {}
        for prt in host.findall('ports/port'):
            state = prt.find('state')
            k = state.get('state') if state is not None else 'unknown'
            counts[k] = counts.get(k, 0) + 1
        for ex in host.findall('ports/extraports'):
            try:
                n = int(ex.get('count', '0'))
            except ValueError:
                n = 0
            k = ex.get('state') or 'unknown'
            counts[k] = counts.get(k, 0) + n
        hosts[addr] = {
            'address': addr,
            'host_status': st.get('state') if st is not None else 'unknown',
            'host_status_reason': st.get('reason') if st is not None else None,
            'port_states': counts,
            'ports_scanned': sum(counts.values()),
        }
    return hosts


def classify_nmap(target: str, host: Optional[dict]) -> tuple[str, str]:
    """An outcome and a plain reason for one target, from what nmap reported. Never claims a device
    is offline: no answer only means nothing answered this scanner."""
    if host is None:
        return 'insufficient_evidence', 'nmap reported no result for this target (host timeout, or it was skipped)'
    c = host['port_states']
    n = host['ports_scanned']
    if host['host_status'] == 'down':
        return 'unreachable', 'nmap reported the host down: nothing answered this scanner. The device may still be online; a firewall dropping every probe looks the same'
    open_n = c.get('open', 0)
    answered = open_n + c.get('closed', 0) + c.get('unfiltered', 0)
    if open_n:
        return 'reachable_open', f'{open_n} open of {n} port(s) scanned'
    if answered:
        return 'reachable_no_open', f'the host answered (closed ports replied) but none of the {n} port(s) scanned is open'
    if n:
        return 'unreachable', (f'none of the {n} port(s) scanned answered this scanner (all {"/".join(sorted(c))}). '
                               'Unreachable from this scanner, or every port is filtered; the device may still be online')
    return 'insufficient_evidence', 'nmap reported the host but no port results'


def target_route(target: str) -> tuple[bool, Optional[str]]:
    """Whether this worker has a path to the target: any public address, or a non-public one inside
    VMS_WORKER_NETWORKS. Hostnames are resolved by the tool, so they are not judged here."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return True, None
    if ip.is_global:
        return True, None
    for n in WORKER_NETWORKS:
        try:
            if ip in ipaddress.ip_network(n, strict=False):
                return True, None
        except ValueError:
            continue
    declared = ', '.join(WORKER_NETWORKS) or 'none'
    return False, (f'{target} is a private/non-public address and worker {WORKER_ID} declares no route to it '
                   f'(VMS_WORKER_NETWORKS: {declared}). Run a worker inside that network, or declare the network '
                   'on this worker if it really has a route (e.g. a VPN). Not attempted.')


def _net_within(net, cidr: str) -> bool:
    try:
        return net.subnet_of(ipaddress.ip_network(cidr, strict=False))
    except (ValueError, TypeError):   # invalid, or IPv4 against IPv6
        return False


def _in_net(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _evidence_target(targets: list[str]) -> str:
    """As many whole targets as fit the backend's 253-character evidence target (never a cut name)."""
    out = ''
    for t in targets:
        nxt = f'{out},{t}' if out else t
        if len(nxt) > 253:
            break
        out = nxt
    return out or targets[0][:253]


REACH_TIMEOUT = 5
REACH_DEFAULT_PORTS = (443, 80)


def reach_ports(spec) -> list[int]:
    """The ports a reachability probe tries: a job's explicit port list (a verification rescan
    names the finding's port), else 443 and 80. At most five; ranges and top-N lists fall back."""
    out = []
    for part in str(spec or '').split(','):
        part = part.strip()
        if part.isdigit() and 0 < int(part) < 65536 and int(part) not in out:
            out.append(int(part))
    return out[:5] or list(REACH_DEFAULT_PORTS)


def tcp_reach(target: str, ports: list[int], connect=None) -> tuple[str, str]:
    """One TCP connection attempt per port, stopping at the first that is accepted (version 1.6.0).
    Says whether the target answered this scanner, so "the check found nothing" can be told apart
    from "the check never got an answer". Nothing is sent over the connection."""
    connect = connect or socket.create_connection
    tried = []
    for port in ports:
        try:
            conn = connect((target, port), REACH_TIMEOUT)
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            return 'reachable_open', f'{target}:{port} accepted a TCP connection'
        except socket.gaierror:
            return 'unreachable', f'{target} does not resolve from this scanner'
        except OSError as e:
            tried.append(f'{port} ({type(e).__name__})')
    return 'unreachable', f'no TCP answer from {target} on {", ".join(tried)}: unreachable from this scanner, or filtered'


def job_outcome(target_outcomes: dict[str, dict]) -> str:
    """One word for the job from its targets' outcomes."""
    vals = [v['outcome'] for v in target_outcomes.values()]
    if not vals:
        return 'insufficient_evidence'
    if all(v.startswith('reachable') for v in vals):
        return 'assessed'
    if all(v == 'no_route' for v in vals):
        return 'no_route'
    if all(v == 'unreachable' for v in vals):
        return 'unreachable'
    if all(v == 'insufficient_evidence' for v in vals):
        return 'insufficient_evidence'
    return 'partial'


def _sev_from_score(score: Optional[float]) -> str:
    if score is None:
        return 'info'
    return 'critical' if score >= 9.0 else 'high' if score >= 7.0 else 'medium' if score >= 4.0 else 'low' if score > 0 else 'info'


def _host_port_from_url(u: str):
    m = re.match(r'^[a-z]+://\[?([^\]/:]+)\]?(?::(\d+))?', u or '', re.I)
    if not m:
        return None, None
    return m.group(1), int(m.group(2)) if m.group(2) else (443 if u.lower().startswith('https') else 80 if u.lower().startswith('http') else None)


def parse_nuclei(lines: Iterable[str]) -> list[dict]:
    """Nuclei -jsonl output into finding observations. Requests/responses are not kept."""
    out = []
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get('info') or {}
        cls = info.get('classification') or {}
        host_field = str(d.get('host') or '')
        host, port = _host_port_from_url(host_field) if '://' in host_field else (host_field.split(':')[0], None)
        if d.get('port') and str(d.get('port')).isdigit():
            port = int(d['port'])
        t = parse_target(host or '')
        tid = str(d.get('template-id') or d.get('templateID') or '')
        if not t or not tid:
            continue
        sev = str(info.get('severity') or 'info').lower()
        cvss = cls.get('cvss-score')
        cves = [c.upper() for c in (cls.get('cve-id') or []) if isinstance(c, str) and CVE_RE.match(c.upper())]
        refs = info.get('reference') or []
        out.append({
            'type': 'finding', 'host': t[1], 'port': port, 'protocol': 'tcp', 'scanner': 'nuclei', 'rule_id': tid[:200],
            'title': str(info.get('name') or tid)[:300], 'severity': sev if sev in ('critical', 'high', 'medium', 'low', 'info') else 'info',
            'cve_ids': cves, 'cvss': float(cvss) if isinstance(cvss, (int, float)) and 0 <= cvss <= 10 else None,
            'description': (info.get('description') or None) and str(info['description'])[:8000],
            'remediation': (info.get('remediation') or None) and str(info['remediation'])[:8000],
            'references': [str(r)[:1000] for r in (refs if isinstance(refs, list) else [refs]) if r][:50],
            'matched_at': str(d.get('matched-at') or d.get('matched') or '')[:2048] or None,
            'finding_type': 'vulnerability' if cves else 'misconfiguration' if 'misconfig' in (info.get('tags') or []) else 'exposure' if sev == 'info' else 'vulnerability',
            'evidence': {'template': tid, 'matcher': d.get('matcher-name'), 'extracted': (d.get('extracted-results') or [])[:10], 'type': d.get('type')},
        })
    return out


_GVM_PORT = re.compile(r'^(\d{1,5})/(tcp|udp)$')
_NOT_FINDINGS = ('Log', 'Debug', 'False Positive')
_GVM_THREAT_SEVERITY = {'Critical': 'critical', 'High': 'high', 'Medium': 'medium', 'Low': 'low'}


def _gvm_score(*texts) -> Optional[float]:
    for t in texts:
        try:
            v = float((t or '').strip())
        except ValueError:
            continue
        if 0 <= v <= 10:
            return v
    return None


_CVSS_TAG = re.compile(r'cvss_base_vector=([^|]+)')


def _gvm_cvss(nvt) -> tuple[Optional[str], Optional[str]]:
    """(version, vector) of an NVT's CVSS, from what the report states — never guessed.
    Current GMP: nvt/severities/severity type="cvss_base_v3|cvss_base_v2" with the vector in <value>;
    older GMP: a cvss_base_vector=… entry in nvt/tags (CVSS v2). (None, None) when absent."""
    sev = nvt.find('severities/severity')
    vector = ((sev.findtext('value') if sev is not None else '') or '').strip()
    kind = ((sev.get('type') if sev is not None else '') or '').strip()
    if not vector:
        m = _CVSS_TAG.search(nvt.findtext('tags') or '')
        vector = m.group(1).strip() if m else ''
    for prefix, version in (('CVSS:4.0/', '4.0'), ('CVSS:3.1/', '3.1'), ('CVSS:3.0/', '3.0')):
        if vector.startswith(prefix):
            return version, vector[:200]
    if vector and vector.startswith('AV:'):
        return '2.0', vector[:200]
    if kind == 'cvss_base_v2':
        return '2.0', vector[:200] or None
    if kind == 'cvss_base_v3':
        return '3.x', vector[:200] or None
    return None, vector[:200] or None


def _result_host(r) -> tuple[str, str]:
    """(ip, hostname) of a GMP <result>: <host>IP<hostname>name</hostname></host>."""
    h = r.find('host')
    if h is None:
        return '', ''
    return (h.text or '').strip(), (h.findtext('hostname') or '').strip().lower().rstrip('.')


def openvas_results(xml_text: str, attribute=None, context: Optional[dict] = None) -> tuple[list[dict], dict]:
    """A GMP XML report into finding observations, plus counts of what was not turned into one.

    attribute(ip, hostname) names the submitted target a result belongs to, or None to drop it (a
    host OpenVAS found on its own, such as a vhost from a TLS certificate, is never attributed).
    Without it, the reported hostname or IP is used. Log/debug/false-positive results are skipped;
    results missing a host, NVT or usable fields are counted, never fatal. Raises ET.ParseError
    only when the XML itself cannot be read."""
    attribute = attribute or (lambda ip, name: (parse_target(name) or parse_target(ip) or (None, None))[1])
    context = context or {}
    out: list[dict] = []
    stats = {'results': 0, 'not_findings': 0, 'incomplete': 0, 'unattributed': 0}
    root = ET.fromstring(xml_text)
    # When OpenVAS ran the scan, as the report states (GMP <scan_start>/<scan_end>).
    scan_times = {'scan_started_at': (root.findtext('.//scan_start') or '').strip() or None, 'scan_ended_at': (root.findtext('.//scan_end') or '').strip() or None}
    for r in root.iter('result'):
        if r.find('nvt') is None and r.find('host') is None:
            continue   # a <result> reference elsewhere in the report, not a result
        stats['results'] += 1
        threat = (r.findtext('threat') or '').strip()
        if threat in _NOT_FINDINGS:
            stats['not_findings'] += 1
            continue
        ip, hostname = _result_host(r)
        nvt = r.find('nvt')
        oid = (nvt.get('oid') or '').strip() if nvt is not None else ''
        if not (ip or hostname) or not oid:
            stats['incomplete'] += 1
            continue
        host = attribute(ip, hostname)
        if not host:
            stats['unattributed'] += 1
            continue
        # Current GMP: <severity> on the result, CVSS under nvt/severities; older: nvt/cvss_base.
        score = _gvm_score(r.findtext('severity'), nvt.findtext('severities/severity/score'), nvt.findtext('cvss_base'))
        port_txt = (r.findtext('port') or '').strip()
        m = _GVM_PORT.match(port_txt)
        cve_ids = {(ref.get('id') or '').upper() for ref in nvt.iter('ref') if ref.get('type') == 'cve'}
        cve_ids |= {c.strip().upper() for c in (nvt.findtext('cve') or '').split(',')}   # older GMP: one comma list
        cves = sorted(c for c in cve_ids if CVE_RE.match(c))
        refs = [ref.get('id') for ref in nvt.iter('ref') if ref.get('type') == 'url' and ref.get('id')][:50]
        solution = nvt.find('solution')
        cvss_version, cvss_vector = _gvm_cvss(nvt)
        out.append({
            'type': 'finding', 'host': host, 'port': int(m.group(1)) if m and int(m.group(1)) <= 65535 else None,
            'protocol': m.group(2) if m else None, 'scanner': 'openvas',
            'rule_id': oid[:200], 'title': (nvt.findtext('name') or oid).strip()[:300] or oid[:300],
            # The score decides; without one, Greenbone's own threat level (reported, not guessed).
            'severity': _sev_from_score(score) if score is not None else _GVM_THREAT_SEVERITY.get(threat, 'info'),
            'cve_ids': cves, 'cvss': score, 'cvss_version': cvss_version, 'cvss_vector': cvss_vector,
            'description': (r.findtext('description') or '').strip()[:8000] or None,
            'remediation': ((solution.text if solution is not None else '') or '').strip()[:8000] or None,
            'references': refs, 'matched_at': f'{host}:{port_txt}'[:2048] if port_txt else host, 'finding_type': 'vulnerability',
            'evidence': {
                'oid': oid, 'threat': threat or None, 'severity': score, 'qod': r.findtext('qod/value'),
                'result_id': r.get('id'), 'scanned_ip': ip or None, 'reported_hostname': hostname or None, 'port': port_txt or None,
                'solution_type': solution.get('type') if solution is not None else None,
                'detected_at': (r.findtext('creation_time') or '').strip() or None,
                'cvss_version': cvss_version, 'cvss_vector': cvss_vector, 'nvt_family': (nvt.findtext('family') or '').strip() or None,
                **{k: v for k, v in scan_times.items() if v},
                **{k: v for k, v in context.items() if v},
            },
        })
    return out, stats


def parse_openvas_report(xml_text: str) -> list[dict]:
    """A GMP XML report into finding observations (hostname, else IP). Log/debug-level results are skipped."""
    return openvas_results(xml_text)[0]


def openvas_hosts(xml_text: str) -> dict[str, dict]:
    """What the report says OpenVAS actually scanned, keyed by IP: hostnames it reported and the
    ports with results. A host its alive test found dead is absent. Raises ET.ParseError on bad XML."""
    root = ET.fromstring(xml_text)
    hosts: dict[str, dict] = {}

    def entry(ip: str) -> dict:
        return hosts.setdefault(ip, {'hostnames': set(), 'ports': set(), 'results': 0})
    # Report-level host summaries are the <host> elements that carry an <ip> child.
    for h in root.iter('host'):
        ip = (h.findtext('ip') or '').strip()
        if not ip:
            continue
        e = entry(ip)
        for d in h.findall('detail'):
            name, value = (d.findtext('name') or '').strip(), (d.findtext('value') or '').strip()
            if name == 'hostname' and value:
                e['hostnames'].add(value.lower().rstrip('.'))
            elif name in ('ports', 'tcp_ports', 'udp_ports') and value:
                proto = 'udp' if name == 'udp_ports' else 'tcp'
                e['ports'].update(f'{p.strip()}/{proto}' for p in value.split(',') if p.strip().isdigit())
    for r in root.iter('result'):
        ip, hostname = _result_host(r)
        if not ip:
            continue
        e = entry(ip)
        e['results'] += 1
        if hostname:
            e['hostnames'].add(hostname)
        port_txt = (r.findtext('port') or '').strip()
        if _GVM_PORT.match(port_txt):
            e['ports'].add(port_txt)
    return hosts


def classify_openvas(target: str, ips: set, hosts: dict[str, dict], required_port: Optional[int] = None) -> tuple[str, str]:
    """An outcome for one submitted target from the report. Like nmap, never claims a device is down:
    absent from the report only means OpenVAS got no answer. A scan that found no port with a result
    proves nothing either way (closed and filtered look the same), so it is insufficient evidence."""
    seen = {ip: hosts[ip] for ip in ips if ip in hosts}
    if not seen:
        return 'unreachable', (f'OpenVAS did not report {target}: its alive test got no answer from this scanner, or the host '
                               'was not scanned. The device may still be online; a firewall dropping every probe looks the same')
    ports = sorted({p for h in seen.values() for p in h['ports']}, key=lambda p: (int(p.split('/')[0]), p))
    if required_port is not None:
        if any(p.split('/')[0] == str(required_port) for p in ports):
            return 'reachable_open', f'OpenVAS scanned {", ".join(sorted(seen))} and port {required_port} answered'
        return 'insufficient_evidence', f'OpenVAS scanned {", ".join(sorted(seen))} but port {required_port} produced no result, so the check proves nothing for it'
    if ports:
        return 'reachable_open', f'OpenVAS scanned {", ".join(sorted(seen))}: {len(ports)} port(s) with results ({", ".join(ports[:8])}{"…" if len(ports) > 8 else ""})'
    return 'insufficient_evidence', f'OpenVAS scanned {", ".join(sorted(seen))} but reported no port with a result; closed and filtered cannot be told apart'


class OpenvasSubmission:
    """The exact targets handed to Greenbone, with the addresses each name resolved to just before
    submission. Results are attributed only to these; nothing OpenVAS discovers is followed."""

    def __init__(self):
        self.names: dict[str, set] = {}       # hostname -> addresses it resolved to
        self.ips: set = set()
        self.nets: list = []                  # (text, ip_network)

    @property
    def hosts(self) -> list[str]:
        return sorted(self.names) + sorted(self.ips) + [t for t, _ in self.nets]

    def attribute(self, ip: str, hostname: str) -> Optional[str]:
        try:
            addr = str(ipaddress.ip_address(ip.split('%')[0])) if ip else ''
        except ValueError:
            addr = ''
        if hostname in self.names and (not addr or addr in self.names[hostname]):
            return hostname
        if addr and addr in self.ips:
            return addr
        if addr and any(ipaddress.ip_address(addr) in n for _, n in self.nets):
            return addr
        if addr and not hostname:
            owners = [n for n, a in self.names.items() if addr in a]
            if len(owners) == 1:
                return owners[0]
        return None


# ── Backend API ───────────────────────────────────────────────────────────────────────────────
_URL_QUERY = re.compile(r'(https?://[^\s?\'"]+)\?[^\s\'"]*')
_BEARER = re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*')


def redact_text(text: str, limit: int = 300) -> str:
    """Removes the worker token, bearer credentials and URL query strings, and caps the length."""
    t = str(text)
    for secret in (TOKEN, GVM_PASSWORD):
        if secret:
            t = t.replace(secret, '[REDACTED]')
    t = _BEARER.sub('Bearer [REDACTED]', t)
    t = _URL_QUERY.sub(r'\1?[REDACTED]', t)
    return t[:limit]


def root_cause(e: BaseException) -> str:
    """'ConnectionError <- RemoteDisconnected: Remote end closed connection without response':
    the outer exception class and the deepest cause requests/urllib3 wrapped, redacted."""
    cur: BaseException = e
    for _ in range(8):
        nxt = getattr(cur, 'reason', None)
        if not isinstance(nxt, BaseException):
            nxt = cur.__cause__ or cur.__context__
        if not isinstance(nxt, BaseException) and cur.args and isinstance(cur.args[0], BaseException):
            nxt = cur.args[0]
        if not isinstance(nxt, BaseException) or nxt is cur:
            break
        cur = nxt
    if cur is e:
        return f'{type(e).__name__}: {redact_text(str(e), 200)}'
    return f'{type(e).__name__} <- {type(cur).__name__}: {redact_text(str(cur), 200)}'


class ApiError(RuntimeError):
    """A backend answer other than success, with what it means for the operator."""

    def __init__(self, path: str, status: Optional[int], detail: str):
        self.path, self.status, self.detail = path, status, detail
        super().__init__(explain(path, status, detail))


def _server_error(text: str) -> str:
    """The backend's error, with its reason and detail when it gives them (e.g. why the queue failed)."""
    try:
        d = json.loads(text)
        parts = [str(d.get('error', ''))] + [str(d[k]) for k in ('reason', 'detail') if d.get(k)]
        return ' — '.join(x for x in parts if x)[:300]
    except (ValueError, AttributeError):
        return text.strip()[:200]


def explain(path: str, status: Optional[int], detail: str) -> str:
    """A plain-language reason for a failed call. Never includes the token."""
    where = f'{API}/api/vms/worker{path}'
    if status is None:
        return f'cannot reach the backend at {where}: {detail}'
    if status == 401:
        return f'the backend rejected the worker token (HTTP 401 on {path}): VMS_WORKER_TOKEN on this host is not the value set on Railway'
    if status == 404:
        return f'endpoint not found (HTTP 404 at {where}): NOVRSOC_API_URL is wrong, or the backend is not running a version with this endpoint'
    if status == 400:
        hint = ' — check VMS_WORKER_ID and VMS_WORKER_KINDS' if path in ('/claim', '/heartbeat') else ' — this worker and the backend disagree on the request format: install the worker version that matches the backend'
        return f'the backend rejected the request (HTTP 400 on {path}): {detail}{hint}'
    if status == 409:
        return f'the backend refused this for the job (HTTP 409 on {path}): {detail}'
    if status == 429:
        return f'rate limited by the backend (HTTP 429 on {path})'
    if status == 503:
        return f'the backend is not ready for workers (HTTP 503 on {path}): {detail}'
    return f'HTTP {status} on {path}: {detail}'


class Api:
    """One HTTP session. Not shared between threads: each thread that talks to the backend has its own."""

    def __init__(self):
        self.s = self._session()

    @staticmethod
    def _session() -> requests.Session:
        s = requests.Session()
        s.headers.update({'Authorization': f'Bearer {TOKEN}', 'Content-Type': 'application/json'})
        return s

    def reset(self) -> None:
        """Drops pooled connections (e.g. one the far end closed while idle)."""
        try:
            self.s.close()
        finally:
            self.s = self._session()

    def post(self, path: str, body: dict, timeout: int = 60) -> dict:
        try:
            r = self.s.post(f'{API}/api/vms/worker{path}', json=body, timeout=timeout)
        except requests.RequestException as e:
            raise ApiError(path, None, root_cause(e)) from None
        if r.status_code >= 400:
            raise ApiError(path, r.status_code, _server_error(r.text))
        return r.json()


class ConnectionLog:
    """Logs state changes and a periodic status line instead of one line per poll."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.connected: Optional[bool] = None
        self.last_error: dict[str, tuple[str, float]] = {}
        self.polls = self.jobs = 0
        self.queued: Optional[int] = None
        self.window_start = clock()

    def ok(self, what: str) -> None:
        with self.lock:
            if self.connected is not True:
                log.info('connected: the backend accepted this worker (%s)%s', what, ' again' if self.connected is False else '')
            self.connected = True
            self.last_error.pop(what, None)

    def fail(self, what: str, err: Exception) -> None:
        msg = str(err)
        now = self.clock()
        with self.lock:
            prev = self.last_error.get(what)
            if prev is None or prev[0] != msg or now - prev[1] >= ERROR_REPEAT_SECONDS:
                log.error('%s failed: %s', what, msg)
                self.last_error[what] = (msg, now)
            self.connected = False

    def poll(self, got_job: bool) -> None:
        with self.lock:
            self.polls += 1
            self.jobs += 1 if got_job else 0

    def status_due(self) -> Optional[str]:
        now = self.clock()
        with self.lock:
            if now - self.window_start < STATUS_LOG_SECONDS:
                return None
            minutes = round((now - self.window_start) / 60)
            line = (f'status: {"connected" if self.connected else "NOT connected"}; {self.polls} poll(s), {self.jobs} job(s) in the last {minutes} min'
                    + (f'; backend reports {self.queued} queued job(s) for this worker\'s kinds' if self.queued is not None else ''))
            self.polls = self.jobs = 0
            self.window_start = now
            return line


def tool_inventory() -> dict:
    """Which tools this host has (by PATH lookup). OpenVAS counts when python-gvm and the socket exist."""
    tools = {n: bool(shutil.which(TOOLS[n])) for n in ('subfinder', 'dnsx', 'httpx', 'nmap', 'nuclei')}
    try:
        import gvm  # noqa: F401
        tools['openvas'] = os.path.exists(GVM_SOCKET)
    except ImportError:
        tools['openvas'] = False
    return tools


_VERSION_RE = re.compile(r'(?:version|v)\s*:?\s*v?(\d+\.\d+(?:\.\d+)?[\w.+-]*)', re.I)
_TOOL_VERSIONS: dict = {}


def parse_tool_version(output: str) -> Optional[str]:
    """'Nmap version 7.94SVN ...' -> '7.94SVN'; 'Current Version: v1.6.8' -> '1.6.8'."""
    m = _VERSION_RE.search(output or '')
    return m.group(1)[:80] if m else None


def tool_versions(refresh: bool = False) -> dict:
    """Each installed tool's version, as it reports it (asked once, cached)."""
    if _TOOL_VERSIONS and not refresh:
        return dict(_TOOL_VERSIONS)
    flags = {'nmap': ['--version'], 'subfinder': ['-version'], 'dnsx': ['-version'], 'httpx': ['-version'], 'nuclei': ['-version']}
    out = {}
    for name, args in flags.items():
        exe = shutil.which(TOOLS[name])
        if not exe:
            continue
        try:
            r = subprocess.run([exe, *args], capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
            out[name] = parse_tool_version((r.stdout or '') + '\n' + (r.stderr or '')) or 'unknown'
        except (OSError, subprocess.TimeoutExpired):
            out[name] = 'unknown'
    _TOOL_VERSIONS.clear()
    _TOOL_VERSIONS.update(out)
    return dict(out)


def heartbeat_body() -> dict:
    versions = tool_versions()
    try:
        gvm = openvas_summary()
    except Exception:  # noqa: BLE001 — presence must never fail because Greenbone did
        gvm = None
    if gvm:
        versions = {**versions, 'openvas': gvm}
    return {'worker_id': WORKER_ID, 'kinds': KINDS, 'version': VERSION, 'tools': tool_inventory(), 'networks': WORKER_NETWORKS, 'features': FEATURES, 'tool_versions': versions}


VALID_KINDS = ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas')
KIND_TOOLS = {'discovery': ['subfinder', 'dnsx', 'httpx'], 'ports': ['nmap'], 'vuln_nuclei': ['nuclei'], 'vuln_openvas': ['openvas']}


def preflight() -> list[str]:
    """Problems that should stop a deployment. Never includes the token or other secret values."""
    problems = []
    if not (API.startswith('https://') or API.startswith('http://127.0.0.1')):
        problems.append('NOVRSOC_API_URL must be the backend https URL')
    if len(TOKEN) < 32:
        problems.append('VMS_WORKER_TOKEN is not set or shorter than 32 characters')
    if not re.match(r'^[\w.-]{1,64}$', WORKER_ID):
        problems.append('VMS_WORKER_ID may hold letters, digits, _ . - (at most 64)')
    bad = [k for k in KINDS if k not in VALID_KINDS]
    if bad or not KINDS:
        problems.append(f'VMS_WORKER_KINDS has unknown kinds: {", ".join(bad) or "(empty)"}')
    for n in WORKER_NETWORKS:
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            problems.append(f'VMS_WORKER_NETWORKS has an invalid CIDR: {n}')
    if 'vuln_openvas' in KINDS:
        if not GVM_USER or not GVM_PASSWORD:
            problems.append('vuln_openvas is in VMS_WORKER_KINDS but GVM_USER / GVM_PASSWORD are not set')
        if GVM_ALIVE_TEST and GVM_ALIVE_TEST not in GVM_ALIVE_TESTS:
            problems.append(f'GVM_ALIVE_TEST must be one of: {", ".join(GVM_ALIVE_TESTS)}')
    tools = tool_inventory()
    for k in KINDS:
        missing = [t for t in KIND_TOOLS.get(k, []) if not tools.get(t)]
        if missing:
            problems.append(f'{k} is in VMS_WORKER_KINDS but {", ".join(missing)} is not installed')
    return problems


def self_test() -> int:
    print(f'worker {WORKER_ID} version {VERSION}; kinds {",".join(KINDS)}; private networks: {", ".join(WORKER_NETWORKS) or "none declared"}')
    tools, versions = tool_inventory(), tool_versions()
    for t, ok in tools.items():
        print(f'  {t:10} {"installed " + versions.get(t, "") if ok else "not installed"}')
    problems = preflight()
    if not problems and 'vuln_openvas' in KINDS:
        info, gvm_problems = greenbone_check()
        for line in info:
            print(f'  {line}')
        problems += gvm_problems
    for p_ in problems:
        print(f'FAIL: {p_}')
    if problems:
        return 1
    return check()


def send_heartbeat(api: 'Api', body: dict, sleep=time.sleep) -> dict:
    """One heartbeat. A network failure is retried once, after HEARTBEAT_RETRY_DELAY seconds, on a
    fresh connection (a pooled one may have been closed while idle). HTTP errors are not retried."""
    try:
        return api.post('/heartbeat', body, timeout=30)
    except ApiError as e:
        if e.status is not None:
            raise
        api.reset()
        sleep(HEARTBEAT_RETRY_DELAY)
        return api.post('/heartbeat', body, timeout=30)


def next_presence_delay(consecutive_failures: int) -> int:
    """Normal cadence while healthy; doubling, capped, while the backend stays unreachable."""
    if consecutive_failures <= 0:
        return PRESENCE_SECONDS
    return min(PRESENCE_SECONDS * (2 ** consecutive_failures), HEARTBEAT_MAX_BACKOFF)


def presence_loop(conn: ConnectionLog, stop: threading.Event) -> None:
    """The worker's own heartbeat, separate from jobs (its own session: requests sessions are not thread-safe)."""
    api = Api()
    unsupported = False
    failures = 0
    while True:
        try:
            r = send_heartbeat(api, heartbeat_body())
            conn.queued = int(r.get('queued', 0))
            conn.ok('heartbeat')
            failures = 0
        except ApiError as e:
            if e.status == 404 and not unsupported:
                # An older backend has /claim but no /heartbeat; claims still count as presence there.
                log.warning('%s; heartbeats are skipped, job polling continues', e)
                unsupported = True
            elif e.status != 404:
                conn.fail('heartbeat', e)
                failures += 1 if e.status is None else 0
        except Exception as e:  # noqa: BLE001 — keep the presence thread alive
            conn.fail('heartbeat', e)
        if stop.wait(next_presence_delay(failures)):
            return


class Cancelled(Exception):
    pass


# ── Greenbone / OpenVAS adapter (GMP over gvmd's local socket) ────────────────────────────────
class GreenboneError(RuntimeError):
    """A Greenbone failure with a plain reason, never a credential. retryable: worth another try."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def gvm_problem(e: BaseException) -> GreenboneError:
    """Maps python-gvm and socket errors (by class name, so tests need no python-gvm) to a reason."""
    if isinstance(e, GreenboneError):
        return e
    name = type(e).__name__
    text = redact_text(getattr(e, 'message', None) or str(e) or name, 200)
    status = str(getattr(e, 'status', '') or '')
    if isinstance(e, PermissionError):
        return GreenboneError(f'no permission to use the gvmd socket {GVM_SOCKET}: add the worker user to the group that owns it')
    if name == 'GvmResponseError':   # gvmd answered 4xx
        if status == '400' and 'auth' in text.lower():
            return GreenboneError('Greenbone rejected GVM_USER / GVM_PASSWORD (authentication failed)')
        return GreenboneError(f'Greenbone refused the request (GMP {status or "4xx"}): {text}')
    if name == 'GvmServerError':     # gvmd answered 5xx, e.g. 503 while a feed sync holds its lock
        return GreenboneError(f'Greenbone could not process the request (GMP {status or "5xx"}): {text}', retryable=True)
    if name in ('ParseError', 'XMLSyntaxError'):   # a response gvmd sent that is not readable XML
        return GreenboneError(f'the OpenVAS report could not be read: Greenbone sent a response that is not valid XML ({text})')
    if 'unsupported version' in text.lower():
        return GreenboneError(f'{text} (update python-gvm on this host)')
    if name == 'GvmError' or isinstance(e, (OSError, EOFError)):
        return GreenboneError(f'cannot talk to gvmd at {GVM_SOCKET}: {text}', retryable=True)
    return GreenboneError(f'Greenbone call failed ({name}): {text}')


def gmp_session():
    """A python-gvm session on the local gvmd socket (use as `with gmp_session() as gmp:`)."""
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
    return Gmp(connection=UnixSocketConnection(path=GVM_SOCKET, timeout=GVM_SOCKET_TIMEOUT), transform=EtreeCheckCommandTransform())


GMP_FACTORY = gmp_session   # replaced in tests


def xml_text(el) -> str:
    """A GMP response element as text (python-gvm returns lxml elements; tests use ElementTree)."""
    if isinstance(el, (str, bytes)):
        return el.decode('utf-8', 'replace') if isinstance(el, bytes) else el
    if isinstance(el, ET.Element):
        return ET.tostring(el, encoding='unicode')
    from lxml import etree   # installed with python-gvm
    return etree.tostring(el, encoding='unicode')


def _flag(v) -> Optional[bool]:
    v = str(v if v is not None else '').strip().lower()
    return True if v in ('yes', '1', 'true') else False if v in ('no', '0', 'false') else None


def read_openvas_conf() -> Optional[str]:
    try:
        with open(GVM_OPENVAS_CONF, encoding='utf-8', errors='replace') as f:
            return f.read(256 * 1024)
    except OSError:
        return None


def gvm_config_safety(config_el, conf_text: Optional[str]) -> tuple[bool, str]:
    """Whether the scan configuration is safe to run against an authorised target. Fails closed:
      • safe_checks must not be off (checks that can disrupt a service);
      • expand_vhosts must be confirmed off. When on, OpenVAS adds hostnames it learns from reverse DNS
        and TLS certificates and tests them too: names nobody authorised, on shared hosting often
        someone else's sites. A configuration value wins; otherwise openvas.conf; otherwise refused,
        since OpenVAS defaults it to on."""
    prefs: dict[str, Optional[str]] = {}
    for p in config_el.iter('preference'):
        nvt = p.find('nvt')
        if nvt is not None and (nvt.get('oid') or '').strip():
            continue   # an individual check's preference, not a scanner setting
        name = (p.findtext('name') or '').strip()
        if name:
            prefs[name] = p.findtext('value')
    safe = _flag(prefs.get('safe_checks'))
    if safe is False:
        return False, 'the scan configuration has safe_checks off, which allows checks that can disrupt a service; use one with safe checks on'
    if 'expand_vhosts' in prefs:
        source, expand = 'the scan configuration', _flag(prefs['expand_vhosts'])
    else:
        source = GVM_OPENVAS_CONF
        if conf_text is None:
            return False, f'cannot confirm vhost expansion is off: the scan configuration does not set expand_vhosts and {GVM_OPENVAS_CONF} could not be read'
        m = re.findall(r'^\s*expand_vhosts\s*=\s*(\S+)', conf_text, re.M)
        expand = _flag(m[-1]) if m else None
        if not m:
            return False, f'cannot confirm vhost expansion is off: neither the scan configuration nor {GVM_OPENVAS_CONF} sets expand_vhosts, and OpenVAS defaults it to yes'
    if expand is not False:
        return False, f'vhost expansion is on ({source}: expand_vhosts): OpenVAS would also test hostnames it discovers, which are not authorised. Set expand_vhosts = no'
    return True, f'safe checks {"on" if safe else "at the scanner default"}; vhost expansion off ({source})'


TASK_IN_PROGRESS_HINT = 'New, Requested, Queued, Running, Stop Requested'
TASK_FAILED = ('Stopped', 'Interrupted', 'Delete Requested', 'Ultimate Delete Requested')


class GreenboneScan:
    """One vuln_openvas job's task in Greenbone, named novrsoc-<job id>.

    Each step opens a short GMP session (connect + authenticate). Submission is find-or-create by
    that name, so a job re-sent after a crash resumes its existing task instead of starting a second
    scan, and a retried step never duplicates one. Only objects with this exact name are touched."""

    def __init__(self, job_id: str, submission: OpenvasSubmission, cancel: threading.Event, on_progress=None,
                 factory=None, clock=time.monotonic, sleep=None, conf_reader=read_openvas_conf):
        self.name = f'{GVM_TASK_PREFIX}{job_id}'
        self.sub, self.cancel = submission, cancel
        self.on_progress = on_progress or (lambda status, pct: None)
        self.factory = factory or GMP_FACTORY
        self.clock = clock
        self.sleep = sleep or (lambda s: cancel.wait(s))
        self.conf_reader = conf_reader
        self.task_id: Optional[str] = None
        self.target_id: Optional[str] = None
        self.report_id: Optional[str] = None
        self.resumed = False
        self.safety = ''

    # Sessions
    def _session(self, fn):
        try:
            with self.factory() as gmp:
                gmp.authenticate(GVM_USER, GVM_PASSWORD)
                return fn(gmp)
        except (Cancelled, GreenboneError):
            raise
        except Exception as e:  # noqa: BLE001 — every python-gvm/socket failure gets a plain reason
            raise gvm_problem(e) from None

    def _with_retry(self, what: str, fn):
        for delay in (*GVM_RETRY_DELAYS, None):
            try:
                return self._session(fn)
            except GreenboneError as e:
                if not e.retryable or delay is None:
                    raise
                log.warning('greenbone %s failed (%s); retrying in %ss', what, e, delay)
                self.sleep(delay)
                if self.cancel.is_set():
                    raise Cancelled() from None

    # Lookups (GMP XML)
    def _own(self, gmp, kind: str) -> list:
        get = gmp.get_tasks if kind == 'task' else gmp.get_targets
        resp = get(filter_string=f'name="{self.name}" rows=-1')
        return [el for el in resp.findall(kind) if (el.findtext('name') or '').strip() == self.name and el.get('id')]

    @staticmethod
    def _report_of(task) -> Optional[str]:
        for path in ('current_report/report', 'last_report/report'):
            r = task.find(path)
            if r is not None and r.get('id'):
                return r.get('id')
        return None

    def _hosts_of(self, gmp, target_id: Optional[str]) -> set:
        if not target_id:
            return set()
        try:
            t = gmp.get_target(target_id).find('target')
        except Exception as e:  # noqa: BLE001 — a missing target makes the task stale, not the job fail
            if gvm_problem(e).retryable:
                raise
            return set()
        text = (t.findtext('hosts') if t is not None else '') or ''
        return {h.strip().lower() for h in text.split(',') if h.strip()}

    def _delete(self, gmp, task_id: Optional[str], target_id: Optional[str]) -> None:
        for fn, oid in ((gmp.delete_task, task_id), (gmp.delete_target, target_id)):
            if oid:
                try:
                    fn(oid, ultimate=True)
                except Exception as e:  # noqa: BLE001 — leftovers are named and logged for the operator
                    log.warning('could not delete Greenbone object %s (%s): %s', oid, self.name, gvm_problem(e))

    # Steps
    def prepare(self) -> None:
        """Checks the scan configuration is safe, then reuses or creates this job's task."""
        def go(gmp):
            ok, why = gvm_config_safety(gmp.get_scan_config(GVM_CONFIG_ID), self.conf_reader())
            if not ok:
                raise GreenboneError(f'OpenVAS scan refused: {why}')
            self.safety = why
            wanted = {h.lower() for h in self.sub.hosts}
            for task in self._own(gmp, 'task'):
                status = (task.findtext('status') or '').strip()
                target = task.find('target')
                tgt = target.get('id') if target is not None else None
                if status not in TASK_FAILED and self._hosts_of(gmp, tgt) == wanted:
                    self.task_id, self.target_id, self.resumed = task.get('id'), tgt, True
                    self.report_id = self._report_of(task)
                    if status == 'New' or not self.report_id:
                        self.report_id = gmp.start_task(self.task_id).findtext('report_id')
                    log.info('greenbone task %s for this job already exists (%s): resuming it, not submitting again', self.name, status)
                    return
                if status not in TASK_FAILED:
                    gmp.stop_task(task.get('id'))
                log.info('removing stale greenbone task %s (%s, different targets or ended)', self.name, status or 'unknown')
                self._delete(gmp, task.get('id'), tgt)
            for target in self._own(gmp, 'target'):   # a target left by an interrupted submission
                self._delete(gmp, None, target.get('id'))
            kw = {'name': self.name, 'hosts': self.sub.hosts, 'port_list_id': GVM_PORT_LIST_ID}
            if GVM_ALIVE_TEST:
                kw['alive_test'] = GVM_ALIVE_TEST
            self.target_id = gmp.create_target(**kw).get('id')
            self.task_id = gmp.create_task(name=self.name, config_id=GVM_CONFIG_ID, target_id=self.target_id, scanner_id=GVM_SCANNER_ID).get('id')
            self.report_id = gmp.start_task(self.task_id).findtext('report_id')
            if not (self.target_id and self.task_id and self.report_id):
                raise GreenboneError('Greenbone did not return the new target, task or report id')
            log.info('greenbone task %s started for %d target(s)', self.name, len(self.sub.hosts))
        self._with_retry('submission', go)

    def wait(self) -> None:
        """Polls the task until Done; bounded by GVM_SCAN_TIMEOUT. Stops the task on cancel/timeout."""
        deadline = self.clock() + GVM_SCAN_TIMEOUT
        failures = 0
        warned: set = set()
        while True:
            if self.cancel.is_set():
                self.stop()
                raise Cancelled()
            if self.clock() >= deadline:
                self.stop()
                raise GreenboneError(f'the OpenVAS scan did not finish within {GVM_SCAN_TIMEOUT}s (GVM_SCAN_TIMEOUT_SECONDS); it was stopped')
            try:
                task = self._session(lambda g: g.get_task(self.task_id).find('task'))
                failures = 0
            except GreenboneError as e:
                failures += 1
                if not e.retryable or failures >= GVM_MAX_POLL_FAILURES:
                    raise GreenboneError(f'checking the OpenVAS task failed{f" {failures} times in a row" if failures > 1 else ""}: {e}') from None
                log.warning('greenbone status check failed (%s); %d of %d', e, failures, GVM_MAX_POLL_FAILURES)
            else:
                if task is None:
                    raise GreenboneError(f'the OpenVAS task {self.name} no longer exists (deleted outside NovrSOC)')
                status, pct = (task.findtext('status') or '').strip(), (task.findtext('progress') or '').strip()
                self.on_progress(status, pct)
                if status == 'Done':
                    self.report_id = self._report_of(task) or self.report_id
                    return
                if status in TASK_FAILED:
                    raise GreenboneError(f'the OpenVAS task ended as {status} (stopped outside NovrSOC, or the scanner failed; see gvmd and ospd-openvas logs)')
                if status not in ('New', 'Requested', 'Queued', 'Running', 'Stop Requested', 'Processing') and status not in warned:
                    warned.add(status)
                    log.warning('greenbone task %s reports an unrecognised status %r; still waiting (time limit applies)', self.name, status)
            self.sleep(GVM_POLL_SECONDS)

    def report(self) -> str:
        if not self.report_id:
            raise GreenboneError('the OpenVAS task finished without a report id')
        return self._with_retry('report download', lambda g: xml_text(g.get_report(
            self.report_id, filter_string=GVM_REPORT_FILTER, report_format_id=GVM_XML_FORMAT_ID, ignore_pagination=True, details=True)))

    def stop(self) -> None:
        if not self.task_id:
            return
        try:
            self._session(lambda g: g.stop_task(self.task_id))
        except GreenboneError as e:
            log.warning('could not stop greenbone task %s: %s', self.name, e)

    def cleanup(self) -> None:
        """Deletes this job's task (with its report) and target. Best effort; leftovers are logged."""
        if not (self.task_id or self.target_id):
            return
        try:
            self._session(lambda g: self._delete(g, self.task_id, self.target_id))
        except GreenboneError as e:
            log.warning('could not clean up greenbone objects %s: %s', self.name, e)


FEED_MAX_AGE_DAYS = 7


def _feed_age_days(version: str, now: Optional[datetime] = None) -> Optional[float]:
    """Greenbone feed versions are timestamps (YYYYMMDDHHMM); None when it is not one."""
    try:
        t = datetime.strptime(version[:12], '%Y%m%d%H%M')
    except ValueError:
        return None
    return ((now or datetime.now(timezone.utc).replace(tzinfo=None)) - t).total_seconds() / 86400


def gvm_feed_rows(feeds_el, now: Optional[datetime] = None) -> list[dict]:
    """One health row per feed from a GMP get_feeds answer: version, age, and whether it is syncing."""
    rows = []
    for f in feeds_el.iter('feed'):
        kind = (f.findtext('type') or f.findtext('name') or 'feed').strip()
        version = (f.findtext('version') or '').strip()
        age = _feed_age_days(version, now)
        if f.find('sync_not_available') is not None:
            err = (f.findtext('sync_not_available/error') or 'sync not available').strip()
            rows.append({'status': 'fail', 'detail': f'{kind}: {err[:160]}'})
            continue
        syncing = f.find('currently_syncing') is not None
        if not version:
            rows.append({'status': 'fail', 'detail': f'{kind}: gvmd reports no feed version (not loaded)'})
        elif age is not None and age > FEED_MAX_AGE_DAYS:
            rows.append({'status': 'warn', 'detail': f'{kind} {version}: {age:.0f} days old{" (syncing now)" if syncing else ""}'})
        else:
            rows.append({'status': 'warn' if syncing else 'ok',
                         'detail': f'{kind} {version}' + (f': {age:.1f} days old' if age is not None else '') + (' (syncing now: scans may queue)' if syncing else '')})
    return rows or [{'status': 'fail', 'detail': 'gvmd listed no feeds'}]


HEALTH_LAYERS = ('local', 'reachability', 'authentication', 'functional', 'end_to_end')
# TEST-NET-1 (RFC 5737): never routed. The permission probe's target is created and deleted, never scanned.
PERMCHECK_HOST = '192.0.2.1'
GVM_SUMMARY_SECONDS = 6 * 3600
_GVM_SUMMARY: dict = {'at': None, 'value': None}


def openvas_summary(factory=None, clock=time.monotonic) -> Optional[str]:
    """What the heartbeat reports for Greenbone (tool_versions.openvas, at most 80 characters): the
    GMP version and feed state, asked at most every 6 hours, or why it could not be asked. Only when
    vuln_openvas is enabled with credentials; read-only."""
    if 'vuln_openvas' not in KINDS or not GVM_USER or not GVM_PASSWORD:
        return None
    if _GVM_SUMMARY['at'] is not None and clock() - _GVM_SUMMARY['at'] < GVM_SUMMARY_SECONDS:
        return _GVM_SUMMARY['value']
    try:
        with (factory or GMP_FACTORY)() as g:
            g.authenticate(GVM_USER, GVM_PASSWORD)
            version = g.get_version().findtext('version') or '?'
            feeds_el = g.get_feeds()
        rows = gvm_feed_rows(feeds_el)
        ages = [a for a in (_feed_age_days((f.findtext('version') or '').strip()) for f in feeds_el.iter('feed')) if a is not None]
        bad = sum(r['status'] == 'fail' for r in rows)
        warn = sum(r['status'] == 'warn' for r in rows)
        state = 'feeds current' if not bad and not warn else f'feeds {warn} warn, {bad} fail'
        value = f'GMP {version}; {state}' + (f' (oldest {max(ages):.1f}d)' if ages else '')
    except Exception as e:  # noqa: BLE001
        value = f'unavailable: {gvm_problem(e)}'
    _GVM_SUMMARY.update(at=clock(), value=value[:80])
    return _GVM_SUMMARY['value']


def health_report(api_factory=None, gmp_factory=None, conf_reader=read_openvas_conf, which=shutil.which, permission_probe: bool = False) -> list[dict]:
    """Health of the worker and each dependency, one row per (component, layer). Never reports a
    component healthy because a process runs, a file exists or a port answers: each layer is the
    strongest evidence actually obtained. Read-only towards Greenbone (no target, task or scan is
    created); sends one heartbeat to the backend (as --check does). Secrets are never included."""
    rows: list[dict] = []

    def row(component, layer, status, detail):
        rows.append({'component': component, 'layer': layer, 'status': status, 'detail': redact_text(str(detail), 300)})

    # Worker configuration
    problems = preflight()
    row('worker', 'local', 'fail' if problems else 'ok', '; '.join(problems) or f'{WORKER_ID} {VERSION}; kinds {",".join(KINDS)}')

    # Scanning tools: present on PATH is only "local"; answering --version is "functional".
    versions = tool_versions(refresh=True)
    for tool in ('subfinder', 'dnsx', 'httpx', 'nmap', 'nuclei'):
        needed = any(tool in KIND_TOOLS.get(k, []) for k in KINDS)
        if not which(TOOLS[tool]):
            row(tool, 'local', 'fail' if needed else 'not_configured', 'not installed' + ('' if needed else ' (not used by this worker\'s kinds)'))
            continue
        row(tool, 'local', 'ok', f'installed at {which(TOOLS[tool])}')
        v = versions.get(tool)
        row(tool, 'functional', 'ok' if v and v != 'unknown' else 'warn', f'answers --version: {v}' if v and v != 'unknown' else 'did not report a version when run')

    # Backend: reachability, authentication and recording are separate facts.
    try:
        r = send_heartbeat((api_factory or Api)(), heartbeat_body())
        row('backend', 'reachability', 'ok', f'{API} answered')
        row('backend', 'authentication', 'ok', 'worker token accepted')
        row('backend', 'functional', 'ok', f'heartbeat recorded at {r.get("server_time")}; {r.get("queued", 0)} job(s) queued for these kinds')
    except ApiError as e:
        if e.status is None:
            row('backend', 'reachability', 'fail', e)
        else:
            row('backend', 'reachability', 'ok', f'{API} answered (HTTP {e.status})')
            row('backend', 'authentication', 'fail' if e.status == 401 else 'ok', e if e.status == 401 else 'token accepted')
            if e.status != 401:
                row('backend', 'functional', 'fail', e)
    row('backend', 'end_to_end', 'not_checked', 'proven only by a completed, authorised scan job whose results were accepted (see the job in NovrSOC)')

    # Greenbone: independently configurable; skipped entirely unless vuln_openvas is enabled or credentials are set.
    if 'vuln_openvas' not in KINDS and not GVM_USER:
        row('greenbone', 'local', 'not_configured', 'vuln_openvas is not in VMS_WORKER_KINDS and GVM_USER is unset')
        return rows
    if (gmp_factory or GMP_FACTORY) is gmp_session:
        try:
            import gvm
            row('greenbone', 'local', 'ok', f'python-gvm {gvm.get_version()}')
        except ImportError:
            row('greenbone', 'local', 'fail', 'python-gvm is not installed')
            return rows
        if not os.path.exists(GVM_SOCKET):
            row('greenbone', 'local', 'fail', f'gvmd socket {GVM_SOCKET} not found (set GVM_SOCKET; container installs keep it in a Docker volume)')
            return rows
        if not os.access(GVM_SOCKET, os.R_OK | os.W_OK):
            row('greenbone', 'local', 'fail', f'gvmd socket {GVM_SOCKET} exists but this user may not use it')
            return rows
        row('greenbone', 'local', 'ok', f'gvmd socket {GVM_SOCKET} present and usable by this user (not yet proof gvmd answers)')
    try:
        with (gmp_factory or GMP_FACTORY)() as g:
            row('greenbone', 'reachability', 'ok', f'gvmd answered on {GVM_SOCKET}: GMP {g.get_version().findtext("version") or "unknown"}')
            try:
                g.authenticate(GVM_USER, GVM_PASSWORD)
            except Exception as e:  # noqa: BLE001
                row('greenbone', 'authentication', 'fail', gvm_problem(e))
                return rows
            row('greenbone', 'authentication', 'ok', 'logged in as the configured GVM user')
            for name, fn in (
                ('scanner', lambda: g.verify_scanner(GVM_SCANNER_ID)),
                ('scan configuration', lambda: g.get_scan_config(GVM_CONFIG_ID)),
                ('port list', lambda: g.get_port_list(GVM_PORT_LIST_ID)),
                ('feeds', lambda: g.get_feeds()),
                ('NovrSOC tasks', lambda: g.get_tasks(filter_string=f'name~"{GVM_TASK_PREFIX}" rows=-1')),
                # Report retrieval, read-only: lists the newest reports (no report content, no task change).
                ('reports', lambda: g.get_reports(filter_string='rows=5 sort-reverse=date', details=False)),
            ):
                try:
                    el = fn()
                except Exception as e:  # noqa: BLE001
                    row(f'greenbone {name}', 'functional', 'fail', gvm_problem(e))
                    continue
                if name == 'scanner':
                    row('greenbone scanner', 'functional', 'ok', f'gvmd verified scanner {GVM_SCANNER_ID} ({el.findtext("version") or "version not reported"})')
                elif name == 'scan configuration':
                    ok, why = gvm_config_safety(el, conf_reader())
                    row('greenbone scan configuration', 'functional', 'ok' if ok else 'fail', why)
                elif name == 'port list':
                    row('greenbone port list', 'functional', 'ok', f'{GVM_PORT_LIST_ID} found')
                elif name == 'feeds':
                    for f in gvm_feed_rows(el):
                        row('greenbone feed', 'functional', f['status'], f['detail'])
                elif name == 'reports':
                    reps = [r for r in el.findall('report') if r.get('id')]
                    newest = next(((r.findtext('creation_time') or r.findtext('report/timestamp') or '').strip() for r in reps), '')
                    row('greenbone reports', 'functional', 'ok', f'report list readable: {len(reps)} shown (newest first){f", newest {newest}" if newest else ""}' if reps else 'report list readable: no reports yet')
                else:
                    tasks = [t for t in el.findall('task') if (t.findtext('name') or '').startswith(GVM_TASK_PREFIX)]
                    states: dict[str, int] = {}
                    for t in tasks:
                        st = (t.findtext('status') or 'unknown').strip()
                        states[st] = states.get(st, 0) + 1
                    summary = ', '.join(f'{n} {s}' for s, n in sorted(states.items())) or 'none'
                    row('greenbone tasks', 'functional', 'ok' if not tasks else 'warn',
                        f'NovrSOC tasks in Greenbone: {summary}' + ('' if not tasks else ' (one may be running now; leftovers come from a worker killed mid-scan)'))
            if permission_probe:
                rows.append(_permission_probe(g))
    except Exception as e:  # noqa: BLE001
        row('greenbone', 'reachability', 'fail', gvm_problem(e))
        return rows
    row('greenbone', 'end_to_end', 'not_checked', 'proven only by an authorised vuln_openvas job on an owned test host (docs/runbooks/vms-openvas.md, step 7)')
    return rows


def _permission_probe(g) -> dict:
    """--gvm-permission-probe: proves the GVM user may create targets and tasks by creating one of
    each for PERMCHECK_HOST and deleting both. Nothing is started, so nothing is scanned."""
    name = f'{GVM_TASK_PREFIX}permcheck-{int(time.time())}'
    target_id = task_id = None
    status, detail = 'ok', ''
    try:
        target_id = g.create_target(name=name, hosts=[PERMCHECK_HOST], port_list_id=GVM_PORT_LIST_ID).get('id')
        task_id = g.create_task(name=name, config_id=GVM_CONFIG_ID, target_id=target_id, scanner_id=GVM_SCANNER_ID).get('id')
        detail = f'the GVM user may create targets and tasks (test target {PERMCHECK_HOST} and task {name} created and deleted; nothing was started)'
    except Exception as e:  # noqa: BLE001
        status, detail = 'fail', f'creating a target and task was refused: {gvm_problem(e)}'
    finally:
        leftovers = []
        for fn, oid in ((g.delete_task, task_id), (g.delete_target, target_id)):
            if oid:
                try:
                    fn(oid, ultimate=True)
                except Exception:  # noqa: BLE001
                    leftovers.append(oid)
        if leftovers:
            status = 'warn' if status == 'ok' else status
            detail += f'; could not delete {", ".join(leftovers)} ({name}): delete it in GSA'
    return {'component': 'greenbone permissions', 'layer': 'functional', 'status': status, 'detail': redact_text(detail, 300)}


def print_health(rows: list[dict], as_json: bool = False) -> int:
    if as_json:
        print(json.dumps({'worker_id': WORKER_ID, 'version': VERSION, 'checks': rows}, indent=1))
    else:
        mark = {'ok': 'OK  ', 'warn': 'WARN', 'fail': 'FAIL', 'not_checked': '--  ', 'not_configured': 'n/a '}
        for r in rows:
            print(f'{mark.get(r["status"], r["status"])}  {r["component"]:30} {r["layer"]:15} {r["detail"]}')
        print('\nlayers: local (installed/configured) < reachability (answers) < authentication < functional (works) < end_to_end (a real job)')
    return 1 if any(r['status'] == 'fail' for r in rows) else 0


def greenbone_check(factory=None, conf_reader=read_openvas_conf) -> tuple[list[str], list[str]]:
    """--self-test for vuln_openvas: socket, login, GMP version, the configured scanner, port list and
    scan configuration, and that configuration's safety. Returns (info lines, problems). No secrets."""
    info: list[str] = []
    try:
        with (factory or GMP_FACTORY)() as g:
            g.authenticate(GVM_USER, GVM_PASSWORD)
            info.append(f'greenbone: GMP {g.get_version().findtext("version") or "unknown"} at {GVM_SOCKET}; logged in as the configured GVM user')
            for what, call, oid in (('scanner', g.get_scanner, GVM_SCANNER_ID), ('port list', g.get_port_list, GVM_PORT_LIST_ID)):
                el = call(oid)
                info.append(f'greenbone: {what} {oid}: {next((x.findtext("name") for x in el if x.get("id") == oid), None) or "found"}')
            cfg = g.get_scan_config(GVM_CONFIG_ID)
            cname = next((x.findtext('name') for x in cfg if x.get('id') == GVM_CONFIG_ID), None) or 'found'
            ok, why = gvm_config_safety(cfg, conf_reader())
            info.append(f'greenbone: scan configuration {GVM_CONFIG_ID}: {cname}; {why}')
            return info, ([] if ok else [f'vuln_openvas: {why}'])
    except Exception as e:  # noqa: BLE001
        return info, [f'vuln_openvas: {gvm_problem(e)}']


class JobRunner:
    def __init__(self, api: Api, job: dict, scopes: list[dict]):
        self.api, self.job, self.scopes = api, job, scopes
        # The job heartbeat runs in its own thread, so it gets its own session.
        self.hb_api = Api() if isinstance(api, Api) else api
        self.cancel = threading.Event()
        self.stopping = False          # set on SIGTERM: hand the job back instead of reporting it
        self.proc: Optional[subprocess.Popen] = None
        self.progress = {'phase': 'starting'}
        self.summary = {'observations': 0, 'accepted': 0, 'rejected_out_of_scope': 0, 'rejected_invalid': 0}
        self.target_outcomes: dict[str, dict] = {}
        self.evidence_enabled = True
        self._stop_hb = threading.Event()

    def stop_for_shutdown(self) -> None:
        """Called from the SIGTERM handler: stop the running tool; run() releases the job."""
        self.stopping = True
        self.cancel.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def record_outcome(self, target: str, outcome: str, reason: str) -> None:
        self.target_outcomes[target] = {'outcome': outcome, 'reason': reason[:300]}

    def send_evidence(self, target: str, tool: str, text: str) -> None:
        """Bounded, redacted raw tool output, kept by the backend for 30 days. Optional: if the
        backend cannot take it, the job carries on and the log says so once."""
        if not self.evidence_enabled or not text:
            return
        raw = text.encode('utf-8', 'replace')
        truncated = len(raw) > EVIDENCE_MAX_BYTES
        content = redact_text(raw[:EVIDENCE_MAX_BYTES].decode('utf-8', 'ignore'), EVIDENCE_MAX_BYTES)
        try:
            self.api.post(f'/jobs/{self.job["id"]}/evidence', {'worker_id': WORKER_ID, 'target': target, 'tool': tool, 'content': content, 'truncated': truncated}, timeout=60)
        except ApiError as e:
            log.warning('raw output not kept for job %s: %s', self.job['id'], e)
            self.evidence_enabled = False

    def heartbeat_loop(self):
        while not self._stop_hb.wait(HEARTBEAT_SECONDS):
            try:
                r = self.hb_api.post(f'/jobs/{self.job["id"]}/heartbeat', {'worker_id': WORKER_ID, 'progress': self.progress})
                if r.get('cancel'):
                    self.cancel.set()
                    if self.proc and self.proc.poll() is None:
                        self.proc.terminate()
            except Exception as e:  # noqa: BLE001 — a missed heartbeat is retried next round
                log.warning('job heartbeat failed: %s', e)

    def run_tool(self, args: list[str], stdin: Optional[str] = None) -> str:
        if self.cancel.is_set():
            raise Cancelled()
        exe = shutil.which(args[0])
        if not exe:
            raise RuntimeError(f'{args[0]} is not installed on this worker')
        log.info('running %s', args[0])
        self.proc = subprocess.Popen([exe, *args[1:]], stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            out, err = self.proc.communicate(stdin, timeout=TOOL_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise RuntimeError(f'{args[0]} exceeded {TOOL_TIMEOUT}s')
        if self.cancel.is_set():
            raise Cancelled()
        if self.proc.returncode != 0:
            # A tool that failed must fail the job, with its reason, never pass as "found nothing".
            reason = (err or '').strip().splitlines()[-1:] or ['no error output']
            raise RuntimeError(f'{os.path.basename(args[0])} exited {self.proc.returncode}: {reason[0][:300]}')
        return out or ''

    def send(self, observations: list[dict], activity: str):
        # Second line of defence: drop anything outside scope before it leaves the worker.
        kept = [o for o in observations if in_scope(o['host'], self.scopes, activity)]
        for i in range(0, len(kept), BATCH):
            r = self.api.post(f'/jobs/{self.job["id"]}/results', {'worker_id': WORKER_ID, 'observations': kept[i:i + BATCH]}, timeout=120)
            for k in ('accepted', 'rejected_out_of_scope', 'rejected_invalid'):
                self.summary[k] += int(r.get(k, 0))
            # Why the backend rejected observations (field and rule, never a value), kept with the job.
            reasons = [str(x)[:200] for x in (r.get('invalid_reasons') or []) if x][:5]
            if reasons:
                known = self.summary.setdefault('invalid_reasons', [])
                new = [x for x in reasons if x not in known]
                known.extend(new[:max(0, 10 - len(known))])
                if new:
                    log.warning('job %s: the backend rejected %s observation(s) as invalid: %s', self.job['id'], r.get('rejected_invalid', '?'), '; '.join(new))
        self.summary['observations'] += len(observations)
        self.summary['dropped_by_worker'] = self.summary.get('dropped_by_worker', 0) + len(observations) - len(kept)

    def discovery(self):
        targets = [t for t in self.job['targets'] if job_target_allowed(t, self.scopes, 'discovery')]
        hosts: set[str] = set()
        ips_or_ranges: list[str] = []
        for i, t in enumerate(targets):
            self.progress = {'phase': 'subfinder', 'done': i, 'total': len(targets)}
            p = parse_target(t)
            if p and p[0] == 'host':
                hosts.add(p[1])
                if any(e.get('kind') == 'domain' and e.get('value') == p[1] and e.get('include_subdomains') for e in self.scopes):
                    out = self.run_tool([TOOLS['subfinder'], '-d', p[1], '-silent', '-oJ', '-timeout', '30'])
                    hosts.update(h for h in parse_subfinder(out.splitlines(), p[1]) if in_scope(h, self.scopes, 'discovery'))
            else:
                ips_or_ranges.append(t)
        host_list = sorted(hosts)
        self.progress = {'phase': 'dnsx', 'done': 0, 'total': len(host_list)}
        dns = parse_dnsx(self.run_tool([TOOLS['dnsx'], '-silent', '-json', '-a', '-aaaa', '-cname', '-resp', '-retry', '2'], '\n'.join(host_list)).splitlines()) if host_list else {}
        obs = [{'type': 'host', 'host': h, 'ips': sorted(set(dns.get(h, {}).get('a', []) + dns.get(h, {}).get('aaaa', []))), 'dns': dns.get(h, {}), 'source': 'dnsx' if h in dns else 'subfinder'} for h in host_list]
        self.send(obs, 'discovery')
        probe = host_list + ips_or_ranges
        self.progress = {'phase': 'httpx', 'done': 0, 'total': len(probe)}
        # Private addresses this worker has no route to are not probed.
        routable = []
        for t in ips_or_ranges:
            ok, why = target_route(t) if '/' not in t else (True, None)
            if ok:
                routable.append(t)
            else:
                self.record_outcome(t, 'no_route', why or '')
        probe = host_list + routable
        answered: list[dict] = []
        if probe:
            out = self.run_tool([TOOLS['httpx'], '-silent', '-json', '-status-code', '-title', '-tech-detect', '-web-server', '-ip', '-cdn',
                                 '-timeout', '10', '-retries', '1', '-rate-limit', HTTPX_RATE, '-no-color'], '\n'.join(probe))
            answered = parse_httpx(out.splitlines())
            self.send_evidence(','.join(probe)[:253], 'httpx', out)
        # An authorised IP target is inventory even when nothing answers on HTTP: record it with what
        # was (and was not) learned. No HTTP answer says nothing about whether the host is up.
        seen = {o['host'] for o in answered}
        for o in answered:
            if parse_target(o['host']) and parse_target(o['host'])[0] == 'ip':
                o['assessment'] = {'outcome': 'reachable_open', 'reason': f'HTTP answered ({(o.get("http") or {}).get("status")})', 'method': 'httpx'}
                self.record_outcome(o['host'], 'reachable_open', 'HTTP answered')
        bare = []
        for t in ips_or_ranges:
            if '/' in t or t in seen or not parse_target(t):
                continue
            if t in self.target_outcomes:   # no_route
                why = self.target_outcomes[t]['reason']
                bare.append({'type': 'host', 'host': t, 'ips': [t], 'source': 'httpx', 'assessment': {'outcome': 'no_route', 'reason': why, 'method': 'httpx'}})
                continue
            why = 'no HTTP answer on the default ports; this is not evidence the host is unreachable — a port scan says more'
            self.record_outcome(t, 'insufficient_evidence', why)
            bare.append({'type': 'host', 'host': t, 'ips': [t], 'source': 'httpx', 'assessment': {'outcome': 'insufficient_evidence', 'reason': why, 'method': 'httpx'}})
        self.send(answered + bare, 'discovery')
        self.summary['hosts'] = len(host_list)
        self.summary['http_responses'] = len(answered)

    def ports(self):
        targets = [t for t in self.job['targets'] if job_target_allowed(t, self.scopes, 'ports')]
        if not targets:
            raise RuntimeError('No target of this job is in port-scan scope')
        spec = str((self.job.get('options') or {}).get('ports', 'top-1000'))
        port_args = ['--top-ports', spec.split('-', 1)[1]] if spec.startswith('top-') else ['-p', spec]
        for i, t in enumerate(targets):
            self.progress = {'phase': 'nmap', 'done': i, 'total': len(targets), 'message': t}
            ok, why = target_route(t) if '/' not in t else (True, None)
            if not ok:
                self.record_outcome(t, 'no_route', why or '')
                self.send([{'type': 'host', 'host': t, 'ips': [t], 'source': 'nmap', 'assessment': {'outcome': 'no_route', 'reason': why, 'method': 'nmap'}}], 'ports')
                continue
            xml = self.run_tool([TOOLS['nmap'], '-sT', '-sV', '-Pn', '-T3', '--max-retries', '2', '--max-rate', NMAP_MAX_RATE,
                                 '--host-timeout', '45m', *port_args, '-oX', '-', '--', t])
            if not xml.strip():
                raise RuntimeError(f'nmap produced no output for {t}')
            self.send_evidence(t, 'nmap', xml)
            try:
                services = parse_nmap_xml(xml)
                hosts = parse_nmap_hosts(xml)
            except ET.ParseError as e:
                raise RuntimeError(f'nmap output for {t} could not be read: {e}') from None
            if '/' in t:
                # A whole range: one host result per address nmap reported.
                for addr, h in hosts.items():
                    outcome, reason = classify_nmap(addr, h)
                    self.record_outcome(addr, outcome, reason)
                host_obs = [self.host_observation(addr, h) for addr, h in hosts.items()]
            else:
                h = hosts.get(t) or (next(iter(hosts.values())) if len(hosts) == 1 else None)
                outcome, reason = classify_nmap(t, h)
                self.record_outcome(t, outcome, reason)
                host_obs = [self.host_observation(t, h, outcome, reason)] if parse_target(t) and parse_target(t)[0] == 'ip' else []
            self.send(host_obs + services, 'ports')
        self.summary['targets'] = len(targets)

    @staticmethod
    def host_observation(addr: str, h: Optional[dict], outcome: Optional[str] = None, reason: Optional[str] = None) -> dict:
        if outcome is None:
            outcome, reason = classify_nmap(addr, h)
        a = {'outcome': outcome, 'reason': reason, 'method': 'nmap'}
        if h:
            a.update({'host_status': h['host_status'], 'host_status_reason': h['host_status_reason'], 'port_states': h['port_states'], 'ports_scanned': h['ports_scanned']})
        obs = {'type': 'host', 'host': addr, 'ips': [addr], 'source': 'nmap', 'assessment': a}
        if outcome.startswith('reachable'):
            obs['alive'] = True   # something answered; "no answer" never sets alive=false
        return obs

    def vuln_nuclei(self):
        targets = [t for t in self.job['targets'] if job_target_allowed(t, self.scopes, 'vuln')]
        if not targets:
            raise RuntimeError('No target of this job is in vulnerability-scan scope')
        opts = self.job.get('options') or {}
        # Reachability first (1.6.0): Nuclei reports matches only, so without this a host that never
        # answered would look like a clean result — and a verification rescan would close a finding.
        ports = reach_ports(opts.get('ports'))
        reachable = []
        for t in targets:
            ok, why = target_route(t)
            if not ok:
                self.record_outcome(t, 'no_route', why or '')
                continue
            outcome, reason = tcp_reach(t, ports, getattr(self, 'connect', None))
            self.record_outcome(t, outcome, reason)
            if outcome.startswith('reachable'):
                reachable.append(t)
        self.summary['targets'] = len(targets)
        if not reachable:
            return
        targets = reachable
        templates = [x for x in (opts.get('templates') or []) if re.match(r'^[\w./-]{1,200}$', str(x))]
        args = [TOOLS['nuclei'], '-silent', '-jsonl', '-duc', '-no-color', '-rl', NUCLEI_RATE, '-c', '10', '-timeout', '10', '-retries', '1', '-etags', NUCLEI_EXCLUDE_TAGS]
        # A verification rescan runs exactly the check that found the issue (any severity).
        args += ['-id', ','.join(templates)] if templates else ['-severity', NUCLEI_SEVERITIES]
        self.progress = {'phase': 'nuclei', 'done': 0, 'total': len(targets)}
        out = self.run_tool(args, '\n'.join(targets))
        self.send(parse_nuclei(out.splitlines()), 'vuln')

    def openvas_submission(self, targets: list[str]) -> OpenvasSubmission:
        """What may be handed to Greenbone, decided here just before submission. A name is resolved
        now; it is refused if it does not resolve, if any address is a private one this worker has no
        declared route to (DNS must not point the scanner into an internal network), or if it is
        CNII-pinned and resolves outside its approved addresses. Refusals are recorded as outcomes."""
        sub = OpenvasSubmission()
        for t in targets:
            if '/' in t:
                try:
                    net = ipaddress.ip_network(t, strict=False)
                except ValueError:
                    self.record_outcome(t, 'insufficient_evidence', f'{t} is not a valid range; not submitted')
                    continue
                routed = net.is_global or any(_net_within(net, n) for n in WORKER_NETWORKS)
                if not routed:
                    self.record_outcome(t, 'no_route', f'{t} is a private range and this worker declares no route to it (VMS_WORKER_NETWORKS); not attempted')
                    continue
                sub.nets.append((t, net))
                continue
            p = parse_target(t)
            if not p:
                continue
            if p[0] == 'ip':
                ok, why = target_route(p[1])
                if not ok:
                    self.record_outcome(p[1], 'no_route', why or '')
                    continue
                sub.ips.add(p[1])
                continue
            addrs = {a.lower() for a in RESOLVE(p[1])}
            if not addrs:
                self.record_outcome(p[1], 'unreachable', f'{p[1]} does not resolve from this scanner; not submitted to OpenVAS')
                continue
            blocked = sorted(a for a in addrs if not target_route(a)[0])
            if blocked:
                self.record_outcome(p[1], 'no_route', f'{p[1]} resolves to {", ".join(blocked)}, a private address this worker declares no route to; not submitted, so DNS cannot point OpenVAS into an internal network')
                continue
            covering = [e for e in self.scopes if in_scope(p[1], [e], 'vuln')]
            if covering and all(e.get('pinned_addresses') for e in covering):
                pins = {str(x).lower() for e in covering for x in e.get('pinned_addresses') or []}
                if not addrs <= pins:
                    self.record_outcome(p[1], 'no_route', f'{p[1]} now resolves to {", ".join(sorted(addrs - pins))}, outside its CNII approval ({", ".join(sorted(pins))}); not scanned until re-approved')
                    continue
            sub.names[p[1]] = addrs
        return sub

    def vuln_openvas(self):
        targets = [t for t in self.job['targets'] if job_target_allowed(t, self.scopes, 'vuln')]
        if not targets:
            raise RuntimeError('No target of this job is in vulnerability-scan scope')
        if GMP_FACTORY is gmp_session:
            try:
                import gvm  # noqa: F401
            except ImportError:
                raise RuntimeError('OpenVAS is not available on this worker (python-gvm not installed)') from None
        if not GVM_USER or not GVM_PASSWORD:
            raise RuntimeError('OpenVAS credentials (GVM_USER / GVM_PASSWORD) are not set on this worker')
        self.summary['targets'] = len(targets)
        sub = self.openvas_submission(targets)
        if not sub.hosts:
            return   # every target was refused; each outcome says why
        opts = self.job.get('options') or {}
        # A verification rescan of one finding must show the finding's own port answered.
        vports = reach_ports(opts.get('ports')) if opts.get('finding_ids') and opts.get('ports') else []
        required = vports[0] if len(vports) == 1 else None

        def progress(status: str, pct: str):
            self.progress = {'phase': 'openvas', 'message': f'{status} {pct}%'[:300] if pct and pct != '-1' else status[:300]}
        scan = GreenboneScan(self.job['id'], sub, self.cancel, progress)
        try:
            self.progress = {'phase': 'openvas', 'message': 'submitting'}
            scan.prepare()
            scan.wait()
            xml = scan.report()
            ctx = {'task_id': scan.task_id, 'report_id': scan.report_id, 'scan_config_id': GVM_CONFIG_ID}
            try:
                findings, stats = openvas_results(xml, sub.attribute, ctx)
                hosts = openvas_hosts(xml)
            except ET.ParseError as e:
                raise RuntimeError(f'the OpenVAS report could not be read: {e}') from None
            for name, addrs in sub.names.items():
                self.record_outcome(name, *classify_openvas(name, addrs, hosts, required))
            for ip in sorted(sub.ips):
                self.record_outcome(ip, *classify_openvas(ip, {ip}, hosts, required))
            for text, net in sub.nets:
                inside = sorted(ip for ip in hosts if _in_net(ip, net))
                for ip in inside:
                    self.record_outcome(ip, *classify_openvas(ip, {ip}, hosts, required))
                if not inside:
                    self.record_outcome(text, 'unreachable', f'OpenVAS reported no host in {text}: nothing answered its alive test from this scanner')
            self.send(findings, 'vuln')
            if stats['unattributed']:
                log.info('job %s: %d OpenVAS result(s) for hosts not submitted (e.g. discovered names) were dropped', self.job['id'], stats['unattributed'])
            self.summary['openvas'] = {**stats, 'findings': len(findings), 'task_id': scan.task_id, 'report_id': scan.report_id,
                                       'resumed_existing_task': scan.resumed, 'config_check': scan.safety}
            self.send_evidence(_evidence_target(sub.hosts), 'openvas', json.dumps({
                'task': scan.name, 'task_id': scan.task_id, 'report_id': scan.report_id, 'scan_config_id': GVM_CONFIG_ID,
                'port_list_id': GVM_PORT_LIST_ID, 'submitted': sub.hosts, 'resolved': {k: sorted(v) for k, v in sub.names.items()},
                'scanned_hosts': {ip: {'hostnames': sorted(h['hostnames']), 'ports': sorted(h['ports']), 'results': h['results']} for ip, h in hosts.items()},
                'counts': stats, 'findings': [{'host': f['host'], 'port': f['port'], 'oid': f['rule_id'], 'severity': f['severity'], 'title': f['title']} for f in findings[:200]],
            }, indent=1))
        finally:
            scan.cleanup()

    def run(self):
        hb = threading.Thread(target=self.heartbeat_loop, daemon=True)
        hb.start()
        status, error = 'succeeded', None
        try:
            {'discovery': self.discovery, 'ports': self.ports, 'vuln_nuclei': self.vuln_nuclei, 'vuln_openvas': self.vuln_openvas}[self.job['kind']]()
        except Cancelled:
            status, error = 'cancelled', 'Cancelled on request'
        except Exception as e:  # noqa: BLE001 — reported to the backend as the job's failure
            status, error = 'failed', str(e)[:1000]
            log.exception('job %s failed', self.job['id'])
        finally:
            self._stop_hb.set()
        if self.stopping:
            self.release('the worker is stopping (service stop or restart)')
            return
        if self.target_outcomes:
            self.summary['outcome'] = job_outcome(self.target_outcomes) if status == 'succeeded' else 'failed'
            self.summary['target_outcomes'] = dict(list(self.target_outcomes.items())[:50])
            # Nothing could even be attempted: that is a failed scan, with the reason, not a success.
            if status == 'succeeded' and self.summary['outcome'] == 'no_route':
                status, error = 'failed', next(iter(self.target_outcomes.values()))['reason']
        self.complete(status, error)
        log.info('job %s %s: %s', self.job['id'], status, {k: v for k, v in self.summary.items() if k != 'target_outcomes'})

    def release(self, reason: str) -> None:
        """Hands an unfinished job back to the queue (the backend requeues it or, after repeated
        releases, fails it). Results already sent stay stored."""
        for delay in (None, 2):
            if delay:
                time.sleep(delay)
            try:
                self.api.post(f'/jobs/{self.job["id"]}/release', {'worker_id': WORKER_ID, 'reason': reason}, timeout=10)
                log.info('job %s handed back to the queue: %s', self.job['id'], reason)
                return
            except ApiError as e:
                log.warning('could not hand job %s back: %s', self.job['id'], e)
        log.warning('job %s stays assigned to this worker; it is re-sent when the worker asks for work again', self.job['id'])

    def complete(self, status: str, error: Optional[str], sleep=time.sleep) -> bool:
        """Reports the outcome. Retries network/429/5xx failures (completion is idempotent on the
        backend); a 400 or 409 is reported once and not retried. Returns True when recorded."""
        body = {'worker_id': WORKER_ID, 'status': status, 'summary': self.summary}
        if error:
            body['error'] = error[:1000]
        for attempt, delay in enumerate((*COMPLETE_RETRY_DELAYS, None)):
            try:
                self.api.post(f'/jobs/{self.job["id"]}/complete', body)
                return True
            except ApiError as e:
                retryable = e.status is None or e.status == 429 or e.status >= 500
                if not retryable or delay is None:
                    log.error('could not report job %s as %s: %s', self.job['id'], status, e)
                    return False
                log.warning('reporting job %s failed (%s); retrying in %ss', self.job['id'], e, delay)
                sleep(delay)
        return False


def check() -> int:
    """One heartbeat, a plain-language result and an exit code. Claims no job."""
    try:
        r = Api().post('/heartbeat', heartbeat_body(), timeout=30)
    except ApiError as e:
        print(f'FAIL: {e}')
        return 1
    tools = ', '.join('%s %s' % (k, 'yes' if v else 'no') for k, v in heartbeat_body()['tools'].items())
    print('OK: the backend accepted worker %s (%s) at %s; %s job(s) queued for these kinds. Tools: %s'
          % (WORKER_ID, ','.join(KINDS), r.get('server_time'), r.get('queued', 0), tools))
    return 0


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [vms-worker] %(levelname)s: %(message)s')
    if '--self-test' in sys.argv[1:]:
        sys.exit(self_test())
    if '--health' in sys.argv[1:]:
        sys.exit(print_health(health_report(permission_probe='--gvm-permission-probe' in sys.argv[1:]), as_json='--json' in sys.argv[1:]))
    if not API.startswith('https://') and not API.startswith('http://127.0.0.1'):
        sys.exit('NOVRSOC_API_URL must be the backend https URL')
    if len(TOKEN) < 32:
        sys.exit('VMS_WORKER_TOKEN is not set (or shorter than 32 characters)')
    if '--check' in sys.argv[1:]:
        sys.exit(check())
    missing = [n for n in ('subfinder', 'dnsx', 'httpx', 'nmap') if not shutil.which(TOOLS[n])]
    if missing:
        log.warning('not installed: %s — jobs needing them will fail with that reason', ', '.join(missing))
    log.info('started as %s (version %s) for %s against %s; private networks reachable: %s', WORKER_ID, VERSION, ','.join(KINDS), API, ', '.join(WORKER_NETWORKS) or 'none declared')
    conn = ConnectionLog()
    stop = threading.Event()
    install_signal_handlers(stop)
    threading.Thread(target=presence_loop, args=(conn, stop), daemon=True).start()
    run_loop(Api(), conn, stop)
    log.info('stopped')


CURRENT: dict[str, Optional[JobRunner]] = {'runner': None}


def install_signal_handlers(stop: threading.Event) -> None:
    """SIGTERM/SIGINT: stop polling, stop the running tool and hand its job back to the queue."""
    def handle(signum, _frame):
        log.info('received %s: finishing up', signal.Signals(signum).name)
        stop.set()
        runner = CURRENT['runner']
        if runner is not None:
            runner.stop_for_shutdown()
    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)


def run_loop(api: Api, conn: ConnectionLog, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            r = api.post('/claim', {'worker_id': WORKER_ID, 'kinds': KINDS})
            conn.ok('job polling')
            conn.poll(bool(r.get('job')))
            if r.get('job'):
                log.info('%s job %s (%s)', 're-received unfinished' if r.get('redelivered') else 'claimed', r['job'].get('id'), r['job'].get('kind'))
                runner = JobRunner(api, r['job'], r.get('scopes') or [])
                CURRENT['runner'] = runner
                try:
                    runner.run()
                finally:
                    CURRENT['runner'] = None
                continue
        except Exception as e:  # noqa: BLE001 — keep polling
            conn.fail('job polling', e)
        line = conn.status_due()
        if line:
            log.info(line)
        stop.wait(POLL_SECONDS)


if __name__ == '__main__':
    main()
