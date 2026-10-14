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

Safety: tools are run with argument lists (never a shell); every target is re-validated as a
plain hostname, IP or the job's own CIDR; rates and timeouts are conservative; a heartbeat every
30 s reports progress and stops the running tool when the backend asks to cancel (e.g. scope
revoked). The API token is read from the environment and never logged.
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
from datetime import datetime
from typing import Iterable, Optional

import requests

log = logging.getLogger('vms-worker')

API = os.environ.get('NOVRSOC_API_URL', '').rstrip('/')
TOKEN = os.environ.get('VMS_WORKER_TOKEN', '')
WORKER_ID = os.environ.get('VMS_WORKER_ID', 'vms-worker-1')
KINDS = [k.strip() for k in os.environ.get('VMS_WORKER_KINDS', 'discovery,ports').split(',') if k.strip()]
POLL_SECONDS = int(os.environ.get('VMS_POLL_SECONDS', '20'))
HEARTBEAT_SECONDS = 30
BATCH = 200
TOOL_TIMEOUT = int(os.environ.get('VMS_TOOL_TIMEOUT_SECONDS', '3600'))
HTTPX_RATE = os.environ.get('VMS_HTTPX_RATE', '50')         # requests per second
NMAP_MAX_RATE = os.environ.get('VMS_NMAP_MAX_RATE', '300')  # packets per second
TOOLS = {name: os.environ.get(f'VMS_{name.upper()}_PATH', name) for name in ('subfinder', 'dnsx', 'httpx', 'nmap')}

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


def in_scope(target: str, scopes: list[dict], activity: str) -> bool:
    """True when an active, unexpired scope entry covers target for activity (discovery|ports|vuln)."""
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


def job_target_allowed(raw: str, scopes: list[dict], activity: str) -> bool:
    """A job target is a host/IP in scope, or exactly an approved CIDR entry."""
    if '/' in raw:
        return any(e.get('kind') == 'cidr' and e.get('status') == 'active' and str(e.get('value')) == raw
                   and (activity != 'ports' or e.get('allow_port_scan')) for e in scopes)
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
                'cpe': cpes or None,
            })
    return out


# ── Backend API ───────────────────────────────────────────────────────────────────────────────
class Api:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({'Authorization': f'Bearer {TOKEN}', 'Content-Type': 'application/json'})

    def post(self, path: str, body: dict, timeout: int = 60) -> dict:
        r = self.s.post(f'{API}/api/vms/worker{path}', json=body, timeout=timeout)
        if r.status_code >= 400:
            raise RuntimeError(f'{path}: HTTP {r.status_code} {r.text[:200]}')
        return r.json()


class Cancelled(Exception):
    pass


class JobRunner:
    def __init__(self, api: Api, job: dict, scopes: list[dict]):
        self.api, self.job, self.scopes = api, job, scopes
        self.cancel = threading.Event()
        self.proc: Optional[subprocess.Popen] = None
        self.progress = {'phase': 'starting'}
        self.summary = {'observations': 0, 'accepted': 0, 'rejected_out_of_scope': 0, 'rejected_invalid': 0}
        self._stop_hb = threading.Event()

    def heartbeat_loop(self):
        while not self._stop_hb.wait(HEARTBEAT_SECONDS):
            try:
                r = self.api.post(f'/jobs/{self.job["id"]}/heartbeat', {'worker_id': WORKER_ID, 'progress': self.progress})
                if r.get('cancel'):
                    self.cancel.set()
                    if self.proc and self.proc.poll() is None:
                        self.proc.terminate()
            except Exception as e:  # noqa: BLE001 — a missed heartbeat is retried next round
                log.warning('heartbeat failed: %s', e)

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
        if self.proc.returncode not in (0,):
            log.warning('%s exited %s: %s', args[0], self.proc.returncode, (err or '')[:300])
        return out or ''

    def send(self, observations: list[dict], activity: str):
        # Second line of defence: drop anything outside scope before it leaves the worker.
        kept = [o for o in observations if in_scope(o['host'], self.scopes, activity)]
        for i in range(0, len(kept), BATCH):
            r = self.api.post(f'/jobs/{self.job["id"]}/results', {'worker_id': WORKER_ID, 'observations': kept[i:i + BATCH]}, timeout=120)
            for k in ('accepted', 'rejected_out_of_scope', 'rejected_invalid'):
                self.summary[k] += int(r.get(k, 0))
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
        if probe:
            out = self.run_tool([TOOLS['httpx'], '-silent', '-json', '-status-code', '-title', '-tech-detect', '-web-server', '-ip', '-cdn',
                                 '-timeout', '10', '-retries', '1', '-rate-limit', HTTPX_RATE, '-no-color'], '\n'.join(probe))
            self.send(parse_httpx(out.splitlines()), 'discovery')
        self.summary['hosts'] = len(host_list)

    def ports(self):
        targets = [t for t in self.job['targets'] if job_target_allowed(t, self.scopes, 'ports')]
        if not targets:
            raise RuntimeError('No target of this job is in port-scan scope')
        spec = str((self.job.get('options') or {}).get('ports', 'top-1000'))
        port_args = ['--top-ports', spec.split('-', 1)[1]] if spec.startswith('top-') else ['-p', spec]
        for i, t in enumerate(targets):
            self.progress = {'phase': 'nmap', 'done': i, 'total': len(targets), 'message': t}
            xml = self.run_tool([TOOLS['nmap'], '-sT', '-sV', '-Pn', '-T3', '--max-retries', '2', '--max-rate', NMAP_MAX_RATE,
                                 '--host-timeout', '45m', *port_args, '-oX', '-', '--', t])
            self.send(parse_nmap_xml(xml) if xml.strip() else [], 'ports')
        self.summary['targets'] = len(targets)

    def run(self):
        hb = threading.Thread(target=self.heartbeat_loop, daemon=True)
        hb.start()
        status, error = 'succeeded', None
        try:
            {'discovery': self.discovery, 'ports': self.ports}[self.job['kind']]()
        except Cancelled:
            status, error = 'cancelled', 'Cancelled on request'
        except Exception as e:  # noqa: BLE001 — reported to the backend as the job's failure
            status, error = 'failed', str(e)[:1000]
            log.exception('job %s failed', self.job['id'])
        finally:
            self._stop_hb.set()
        self.api.post(f'/jobs/{self.job["id"]}/complete', {'worker_id': WORKER_ID, 'status': status, 'error': error, 'summary': self.summary})
        log.info('job %s %s: %s', self.job['id'], status, self.summary)


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [vms-worker] %(levelname)s: %(message)s')
    if not API.startswith('https://') and not API.startswith('http://127.0.0.1'):
        sys.exit('NOVRSOC_API_URL must be the backend https URL')
    if len(TOKEN) < 32:
        sys.exit('VMS_WORKER_TOKEN is not set')
    missing = [n for n in ('subfinder', 'dnsx', 'httpx', 'nmap') if not shutil.which(TOOLS[n])]
    if missing:
        log.warning('not installed: %s — jobs needing them will fail with that reason', ', '.join(missing))
    api = Api()
    log.info('started as %s for %s', WORKER_ID, ','.join(KINDS))
    while True:
        try:
            r = api.post('/claim', {'worker_id': WORKER_ID, 'kinds': KINDS})
            if r.get('job'):
                JobRunner(api, r['job'], r.get('scopes') or []).run()
                continue
        except Exception as e:  # noqa: BLE001 — keep polling
            log.warning('poll failed: %s', e)
        time.sleep(POLL_SECONDS)


if __name__ == '__main__':
    main()
