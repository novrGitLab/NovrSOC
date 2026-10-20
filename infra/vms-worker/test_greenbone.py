"""Tests for the Greenbone/OpenVAS adapter (worker 1.8.0). A fake gvmd stands in for python-gvm: it
answers GMP calls with GMP-shaped XML, and its errors carry python-gvm's class names. No scan runs
and no network or socket is used; names are reserved test domains, addresses documentation ranges."""
import json
import logging
import os
import sys
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
import worker  # noqa: E402

FUTURE = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
PAST = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
SECRET = 'gvm-test-password-value'
FRESH = (datetime.now(timezone.utc) - timedelta(hours=6)).strftime('%Y%m%d%H%M')
STALE = (datetime.now(timezone.utc) - timedelta(days=40)).strftime('%Y%m%d%H%M')


def scope(kind, value, **kw):
    e = {'kind': kind, 'value': value, 'include_subdomains': False, 'allow_port_scan': True, 'allow_vuln_scan': True,
         'status': 'active', 'expires_at': FUTURE, 'exclusions': [], 'pinned_addresses': []}
    e.update(kw)
    return e


SCOPES = [
    scope('domain', 'app.example.test'),
    scope('ip', '203.0.113.10'),
    scope('cidr', '198.51.100.0/30'),
    scope('domain', 'cnii.example.test', pinned_addresses=['203.0.113.50']),
    scope('domain', 'internal.example.test'),
    scope('domain', 'novuln.example.test', allow_vuln_scan=False),
    scope('domain', 'expired.example.test', expires_at=PAST),
    scope('cidr', '198.51.100.64/30', exclusions=['198.51.100.65']),
]
DNS = {'app.example.test': {'203.0.113.20'}, 'cnii.example.test': {'203.0.113.50'}, 'internal.example.test': {'10.1.2.3'}}


# ── fake python-gvm ────────────────────────────────────────────────────────────────────────────
class GvmError(Exception):
    def __init__(self, message=None, *args):
        super().__init__(message)
        self.message = message


class GvmResponseError(GvmError):
    def __init__(self, status=None, message=None):
        super().__init__(message)
        self.status = status


class GvmServerError(GvmError):
    def __init__(self, status=None, message=None):
        super().__init__(message)
        self.status = status


def config_xml(expand='no', safe='yes'):
    prefs = ''.join(
        f'<preference><nvt oid=""><name/></nvt><name>{n}</name><value>{v}</value></preference>'
        for n, v in (('safe_checks', safe), ('expand_vhosts', expand)) if v is not None)
    # An NVT's own preference with the same name must not count as the scanner setting.
    prefs += '<preference><nvt oid="1.3.6.1.4.1.25623.1.0.9"><name>x</name></nvt><name>expand_vhosts</name><value>no</value></preference>'
    return f'<get_configs_response status="200"><config id="{worker.GVM_CONFIG_ID}"><name>Full and fast</name><preferences>{prefs}</preferences></config></get_configs_response>'


def result(ip, port, threat, sev, oid, name='Check', hostname=None, cves=(), extra=''):
    hn = f'<hostname>{hostname}</hostname>' if hostname else ''
    refs = ''.join(f'<ref type="cve" id="{c}"/>' for c in cves) + '<ref type="url" id="https://example.test/advisory"/>'
    return (f'<result id="r-{oid}-{ip}"><host>{ip}{hn}</host><port>{port}</port><threat>{threat}</threat><severity>{sev}</severity>'
            f'<creation_time>2026-10-19T10:00:00Z</creation_time><qod><value>80</value></qod><description>evidence for {name}</description>'
            f'<nvt oid="{oid}"><name>{name}</name><solution type="VendorFix">Upgrade it.</solution><refs>{refs}</refs></nvt>{extra}</result>')


def report_xml(results='', hosts=''):
    return f'<get_reports_response status="200"><report id="rep-1"><report id="rep-1"><results>{results}</results>{hosts}</report></report></get_reports_response>'


class World:
    """gvmd's state and the calls it received."""

    def __init__(self):
        self.calls, self.tasks, self.targets = [], {}, {}
        self.n = 0
        self.statuses = ['Queued', 'Running', 'Done']
        self.config = config_xml()
        self.report = report_xml()
        self.report_raw = False
        self.scanner_down = False
        self.feeds = ''.join(f'<feed><type>{t}</type><name>Greenbone Community Feed</name><version>{FRESH}</version></feed>' for t in ('NVT', 'SCAP', 'CERT', 'GVMD_DATA'))
        self.connect_errors: list = []
        self.poll_errors: list = []
        self.auth_error = None

    def nid(self, p):
        self.n += 1
        return f'{p}-{self.n}'


class FakeGmp:
    def __init__(self, w: World):
        self.w = w

    def __enter__(self):
        if self.w.connect_errors:
            raise self.w.connect_errors.pop(0)
        return self

    def __exit__(self, *a):
        return False

    def _c(self, *call):
        self.w.calls.append(call)

    def authenticate(self, user, password):
        self._c('authenticate')
        if self.w.auth_error:
            raise self.w.auth_error

    def get_version(self):
        return ET.fromstring('<get_version_response status="200"><version>22.7</version></get_version_response>')

    def get_scanner(self, oid):
        return ET.fromstring(f'<r><scanner id="{oid}"><name>OpenVAS Default</name></scanner></r>')

    def get_port_list(self, oid):
        return ET.fromstring(f'<r><port_list id="{oid}"><name>All IANA assigned TCP</name></port_list></r>')

    def verify_scanner(self, oid):
        self._c('verify_scanner', oid)
        if self.w.scanner_down:
            raise GvmResponseError('400', 'Failed to verify scanner')
        return ET.fromstring('<verify_scanner_response status="200"><version>OSP 22.4</version></verify_scanner_response>')

    def get_feeds(self):
        self._c('get_feeds')
        return ET.fromstring(f'<get_feeds_response status="200">{self.w.feeds}</get_feeds_response>')

    def get_scan_config(self, oid):
        self._c('get_scan_config', oid)
        return ET.fromstring(self.w.config)

    def get_tasks(self, filter_string=None):
        self._c('get_tasks', filter_string)
        body = ''.join(f'<task id="{i}"><name>{t["name"]}</name><status>{t["status"]}</status><progress>{t.get("progress", 0)}</progress>'
                       f'<target id="{t["target"]}"/><last_report><report id="{t.get("report", "")}"/></last_report></task>' for i, t in self.w.tasks.items())
        return ET.fromstring(f'<get_tasks_response status="200">{body}</get_tasks_response>')

    def get_targets(self, filter_string=None):
        self._c('get_targets', filter_string)
        body = ''.join(f'<target id="{i}"><name>{t["name"]}</name></target>' for i, t in self.w.targets.items())
        return ET.fromstring(f'<get_targets_response status="200">{body}</get_targets_response>')

    def get_target(self, oid):
        t = self.w.targets[oid]
        return ET.fromstring(f'<get_targets_response status="200"><target id="{oid}"><name>{t["name"]}</name><hosts>{", ".join(t["hosts"])}</hosts></target></get_targets_response>')

    def create_target(self, name, hosts, port_list_id, alive_test=None):
        self._c('create_target', name, tuple(hosts), port_list_id, alive_test)
        oid = self.w.nid('target')
        self.w.targets[oid] = {'name': name, 'hosts': list(hosts)}
        return ET.fromstring(f'<create_target_response status="201" id="{oid}"/>')

    def create_task(self, name, config_id, target_id, scanner_id):
        self._c('create_task', name, config_id, target_id, scanner_id)
        oid = self.w.nid('task')
        self.w.tasks[oid] = {'name': name, 'status': 'New', 'target': target_id}
        return ET.fromstring(f'<create_task_response status="201" id="{oid}"/>')

    def start_task(self, oid):
        self._c('start_task', oid)
        self.w.tasks[oid].update(status='Requested', report='rep-1')
        return ET.fromstring('<start_task_response status="202"><report_id>rep-1</report_id></start_task_response>')

    def get_task(self, oid):
        self._c('get_task', oid)
        if self.w.poll_errors:
            raise self.w.poll_errors.pop(0)
        if oid not in self.w.tasks:
            return ET.fromstring('<get_tasks_response status="200"/>')
        t = self.w.tasks[oid]
        if self.w.statuses:
            t['status'] = self.w.statuses.pop(0)
        return ET.fromstring(f'<get_tasks_response status="200"><task id="{oid}"><name>{t["name"]}</name><status>{t["status"]}</status>'
                             f'<progress>{50 if t["status"] == "Running" else -1}</progress><last_report><report id="rep-1"/></last_report></task></get_tasks_response>')

    def get_report(self, report_id, filter_string=None, report_format_id=None, ignore_pagination=None, details=None):
        self._c('get_report', report_id, filter_string, report_format_id, ignore_pagination, details)
        if self.w.report_raw:
            return self.w.report   # text as received, so the worker's own parsing is exercised
        return ET.fromstring(self.w.report)

    def stop_task(self, oid):
        self._c('stop_task', oid)
        if oid in self.w.tasks:
            self.w.tasks[oid]['status'] = 'Stopped'

    def delete_task(self, oid, ultimate=False):
        self._c('delete_task', oid, ultimate)
        self.w.tasks.pop(oid, None)

    def delete_target(self, oid, ultimate=False):
        self._c('delete_target', oid, ultimate)
        self.w.targets.pop(oid, None)


class Api:
    """The backend: records results, evidence and the completion."""

    def __init__(self):
        self.results, self.evidence, self.completed = [], [], None

    def post(self, path, body, timeout=60):
        if path.endswith('/results'):
            self.results.extend(body['observations'])
            return {'accepted': len(body['observations'])}
        if path.endswith('/evidence'):
            self.evidence.append(body)
        if path.endswith('/complete'):
            self.completed = body
        return {}


class Base(unittest.TestCase):
    def setUp(self):
        self.saved = {k: getattr(worker, k) for k in ('GMP_FACTORY', 'RESOLVE', 'GVM_USER', 'GVM_PASSWORD', 'GVM_RETRY_DELAYS', 'GVM_POLL_SECONDS',
                                                       'GVM_SCAN_TIMEOUT', 'GVM_ALIVE_TEST', 'WORKER_NETWORKS', 'read_openvas_conf')}
        self.w = World()
        worker.GMP_FACTORY = lambda: FakeGmp(self.w)
        worker._GVM_SUMMARY.update(at=None, value=None)
        worker.RESOLVE = lambda h: set(DNS.get(h, set()))
        worker.GVM_USER, worker.GVM_PASSWORD = 'novrsoc', SECRET
        worker.GVM_RETRY_DELAYS, worker.GVM_POLL_SECONDS, worker.GVM_SCAN_TIMEOUT = (0, 0, 0), 0, 3600
        # Documentation ranges are not public addresses: declare them as this worker's networks, the
        # way an operator declares a VPN. 10.0.0.0/8 stays undeclared.
        worker.GVM_ALIVE_TEST, worker.WORKER_NETWORKS = '', ['203.0.113.0/24', '198.51.100.0/24']
        self.logs = []
        handler = logging.Handler()
        handler.emit = lambda rec: self.logs.append(rec.getMessage() + (str(rec.exc_info[1]) if rec.exc_info else ''))
        worker.log.addHandler(handler)
        self.addCleanup(worker.log.removeHandler, handler)
        worker.log.propagate = False
        self.addCleanup(setattr, worker.log, 'propagate', True)

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(worker, k, v)

    def run_job(self, targets, options=None, cancel_at_poll=None):
        api = Api()
        job = {'id': '11111111-2222-3333-4444-555555555555', 'kind': 'vuln_openvas', 'targets': targets, 'options': options or {}}
        r = worker.JobRunner(api, job, SCOPES)
        if cancel_at_poll is not None:
            orig = FakeGmp.get_task

            def get_task(gmp, oid):
                if sum(1 for c in self.w.calls if c[0] == 'get_task') >= cancel_at_poll:
                    r.cancel.set()
                return orig(gmp, oid)
            FakeGmp.get_task = get_task
            self.addCleanup(setattr, FakeGmp, 'get_task', orig)
        r.run()
        return api, r

    def names(self):
        return [c[0] for c in self.w.calls]


class HappyPath(Base):
    def test_scan_is_submitted_polled_downloaded_normalised_and_cleaned_up(self):
        self.w.report = report_xml(
            result('203.0.113.20', '443/tcp', 'High', '7.5', '1.3.6.1.4.1.25623.1.0.100', 'TLS weak cipher', hostname='app.example.test', cves=['CVE-2016-2183'])
            + result('203.0.113.20', '443/tcp', 'Log', '0.0', '1.3.6.1.4.1.25623.1.0.1', 'Service detection', hostname='app.example.test')
            + result('203.0.113.10', '22/tcp', 'Medium', '5.3', '1.3.6.1.4.1.25623.1.0.200', 'SSH weak MAC'),
            hosts='<host><ip>203.0.113.20</ip><detail><name>hostname</name><value>app.example.test</value></detail></host><host><ip>203.0.113.10</ip></host>')
        api, r = self.run_job(['app.example.test', '203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded', api.completed)
        ct = next(c for c in self.w.calls if c[0] == 'create_target')
        self.assertEqual(ct[1], 'novrsoc-11111111-2222-3333-4444-555555555555')
        self.assertEqual(set(ct[2]), {'app.example.test', '203.0.113.10'}, 'exactly the job targets, never broadened')
        self.assertEqual(ct[3], worker.GVM_PORT_LIST_ID)
        task = next(c for c in self.w.calls if c[0] == 'create_task')
        self.assertEqual((task[2], task[4]), (worker.GVM_CONFIG_ID, worker.GVM_SCANNER_ID))
        rep = next(c for c in self.w.calls if c[0] == 'get_report')
        self.assertEqual(rep[2:], (worker.GVM_REPORT_FILTER, worker.GVM_XML_FORMAT_ID, True, True))
        self.assertEqual(self.w.tasks, {}, 'task deleted')
        self.assertEqual(self.w.targets, {}, 'target deleted')
        self.assertTrue(all(c[2] is True for c in self.w.calls if c[0] in ('delete_task', 'delete_target')), 'ultimate delete')
        by_host = {(f['host'], f['rule_id']): f for f in api.results}
        self.assertEqual(set(by_host), {('app.example.test', '1.3.6.1.4.1.25623.1.0.100'), ('203.0.113.10', '1.3.6.1.4.1.25623.1.0.200')})
        f = by_host[('app.example.test', '1.3.6.1.4.1.25623.1.0.100')]
        self.assertEqual((f['port'], f['protocol'], f['severity'], f['cvss'], f['cve_ids'], f['scanner']), (443, 'tcp', 'high', 7.5, ['CVE-2016-2183'], 'openvas'))
        self.assertEqual((f['remediation'], f['references']), ('Upgrade it.', ['https://example.test/advisory']))
        ev = f['evidence']
        self.assertEqual((ev['task_id'], ev['report_id'], ev['scanned_ip'], ev['detected_at'], ev['solution_type']), ('task-2', 'rep-1', '203.0.113.20', '2026-10-19T10:00:00Z', 'VendorFix'))
        outcomes = r.summary['target_outcomes']
        self.assertEqual(outcomes['app.example.test']['outcome'], 'reachable_open')
        self.assertEqual(outcomes['203.0.113.10']['outcome'], 'reachable_open')
        self.assertEqual(r.summary['outcome'], 'assessed')
        self.assertEqual(r.summary['openvas']['not_findings'], 1)
        evidence = json.loads(api.evidence[0]['content'])
        self.assertEqual((api.evidence[0]['tool'], evidence['task_id'], evidence['report_id']), ('openvas', 'task-2', 'rep-1'))
        self.assertNotIn(SECRET, json.dumps(api.completed) + json.dumps(api.evidence) + '\n'.join(self.logs))

    def test_alive_test_is_passed_only_when_configured(self):
        worker.GVM_ALIVE_TEST = 'Consider Alive'
        self.run_job(['203.0.113.10'])
        self.assertEqual(next(c for c in self.w.calls if c[0] == 'create_target')[4], 'Consider Alive')


class Failures(Base):
    def test_authentication_failure_is_not_retried_and_says_so_without_the_password(self):
        self.w.auth_error = GvmResponseError('400', 'Authentication failed')
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertIn('rejected GVM_USER / GVM_PASSWORD', api.completed['error'])
        self.assertEqual(self.names().count('authenticate'), 1, 'not retried')
        self.assertNotIn('create_target', self.names())
        self.assertNotIn(SECRET, api.completed['error'] + '\n'.join(self.logs))

    def test_transient_socket_failures_are_retried_a_bounded_number_of_times(self):
        self.w.connect_errors = [GvmError('Socket /run/gvmd/gvmd.sock does not exist'), GvmServerError('503', 'Service temporarily down')]
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded')
        self.w = World()
        worker.GMP_FACTORY = lambda: FakeGmp(self.w)
        self.w.connect_errors = [GvmError('Socket /run/gvmd/gvmd.sock does not exist')] * 10
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertIn('cannot talk to gvmd', api.completed['error'])
        self.assertEqual(len(self.w.connect_errors), 6, 'four attempts, then it gives up')

    def test_socket_permission_problem_is_explained(self):
        self.w.connect_errors = [PermissionError(13, 'Permission denied')]
        api, _ = self.run_job(['203.0.113.10'])
        self.assertIn('no permission to use the gvmd socket', api.completed['error'])

    def test_status_checks_tolerate_brief_outages_but_not_long_ones(self):
        self.w.poll_errors = [GvmError('Remote closed the connection')] * 2
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded')
        self.w = World()
        worker.GMP_FACTORY = lambda: FakeGmp(self.w)
        self.w.statuses = ['Running'] * 50
        self.w.poll_errors = [None] * 0 + [GvmError('Remote closed the connection')] * worker.GVM_MAX_POLL_FAILURES
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertIn(f'{worker.GVM_MAX_POLL_FAILURES} times in a row', api.completed['error'])
        self.assertEqual(self.w.tasks, {}, 'cleaned up after failing')

    def test_timeout_stops_the_task_fails_the_job_and_cleans_up(self):
        worker.GVM_SCAN_TIMEOUT = 0
        self.w.statuses = ['Running'] * 10
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertIn('did not finish within', api.completed['error'])
        self.assertIn('stop_task', self.names())
        self.assertEqual((self.w.tasks, self.w.targets), ({}, {}))
        self.assertEqual(api.results, [])

    def test_cancel_stops_the_task(self):
        self.w.statuses = ['Running'] * 10
        api, _ = self.run_job(['203.0.113.10'], cancel_at_poll=2)
        self.assertEqual(api.completed['status'], 'cancelled')
        self.assertIn('stop_task', self.names())
        self.assertEqual(self.w.tasks, {})

    def test_task_stopped_outside_novrsoc_fails_the_job(self):
        self.w.statuses = ['Running', 'Stopped']
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertIn('ended as Stopped', api.completed['error'])

    def test_unrecognised_status_keeps_waiting_and_is_logged_once(self):
        self.w.statuses = ['Processing-ish', 'Processing-ish', 'Done']
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded')
        self.assertEqual(sum('unrecognised status' in m for m in self.logs), 1)

    def test_malformed_report_fails_the_job_with_the_reason(self):
        for raw in (True, False):   # broken text reaching the worker; broken XML inside python-gvm's own parsing
            self.w = World()
            worker.GMP_FACTORY = lambda: FakeGmp(self.w)
            self.w.report, self.w.report_raw = '<get_reports_response><report><results><result>', raw
            api, _ = self.run_job(['203.0.113.10'])
            self.assertEqual(api.completed['status'], 'failed')
            self.assertIn('report could not be read', api.completed['error'])
            self.assertEqual(api.results, [])
            self.assertEqual(self.w.tasks, {})

    def test_partial_report_does_not_crash(self):
        self.w.report = report_xml(
            '<result><host>203.0.113.10</host><threat>High</threat></result>'                              # no NVT
            '<result><port>22/tcp</port><threat>High</threat><nvt oid="1.2.3"/></result>'                    # no host
            '<result><host>203.0.113.10</host><threat>Medium</threat><severity>n/a</severity><nvt oid="1.2.4"/></result>'  # no port, name, severity
            + result('203.0.113.10', '99999/tcp', 'High', '11', '1.2.5'))                                    # impossible port and score
        api, r = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded')
        self.assertEqual(r.summary['openvas']['incomplete'], 2)
        by_oid = {f['rule_id']: f for f in api.results}
        self.assertEqual((by_oid['1.2.4']['port'], by_oid['1.2.4']['title'], by_oid['1.2.4']['severity'], by_oid['1.2.4']['cvss']), (None, '1.2.4', 'info', None))
        self.assertEqual((by_oid['1.2.5']['port'], by_oid['1.2.5']['cvss']), (None, None))


class Duplicates(Base):
    def seed(self, status, hosts, report='rep-1'):
        self.w.targets['target-old'] = {'name': 'novrsoc-11111111-2222-3333-4444-555555555555', 'hosts': hosts}
        self.w.tasks['task-old'] = {'name': 'novrsoc-11111111-2222-3333-4444-555555555555', 'status': status, 'target': 'target-old', 'report': report}

    def test_a_redelivered_job_resumes_its_running_task_instead_of_submitting_again(self):
        self.seed('Running', ['203.0.113.10'])
        self.w.statuses = ['Running', 'Done']
        api, r = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded')
        self.assertNotIn('create_target', self.names())
        self.assertNotIn('create_task', self.names())
        self.assertNotIn('start_task', self.names())
        self.assertTrue(r.summary['openvas']['resumed_existing_task'])

    def test_a_finished_task_is_reported_without_scanning_again(self):
        self.seed('Done', ['203.0.113.10'])
        self.w.statuses = []
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded')
        self.assertNotIn('start_task', self.names())
        self.assertIn('get_report', self.names())

    def test_a_task_for_different_targets_or_that_ended_is_replaced(self):
        for status, hosts in (('Running', ['203.0.113.10', '203.0.113.99']), ('Interrupted', ['203.0.113.10'])):
            self.w = World()
            worker.GMP_FACTORY = lambda: FakeGmp(self.w)
            self.seed(status, hosts)
            api, _ = self.run_job(['203.0.113.10'])
            self.assertEqual(api.completed['status'], 'succeeded', status)
            self.assertIn(('delete_task', 'task-old', True), self.w.calls)
            self.assertIn('create_task', self.names())
            if status == 'Running':
                self.assertIn(('stop_task', 'task-old'), self.w.calls)

    def test_a_task_whose_target_is_gone_is_replaced_not_fatal(self):
        self.w.tasks['task-old'] = {'name': 'novrsoc-11111111-2222-3333-4444-555555555555', 'status': 'Running', 'target': 'target-gone', 'report': 'rep-1'}
        orig = FakeGmp.get_target

        def get_target(gmp, oid):
            if oid == 'target-gone':
                raise GvmResponseError('404', "Failed to find target 'target-gone'")
            return orig(gmp, oid)
        FakeGmp.get_target = get_target
        self.addCleanup(setattr, FakeGmp, 'get_target', orig)
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'succeeded')
        self.assertIn(('delete_task', 'task-old', True), self.w.calls)
        self.assertIn('create_task', self.names())

    def test_a_leftover_target_from_an_interrupted_submission_is_removed(self):
        self.w.targets['target-old'] = {'name': 'novrsoc-11111111-2222-3333-4444-555555555555', 'hosts': ['203.0.113.10']}
        api, _ = self.run_job(['203.0.113.10'])
        self.assertIn(('delete_target', 'target-old', True), self.w.calls)
        self.assertEqual(self.names().count('create_target'), 1)

    def test_only_this_jobs_objects_are_touched(self):
        self.w.tasks['task-other'] = {'name': 'novrsoc-other-job', 'status': 'Running', 'target': 't', 'report': 'x'}
        self.w.tasks['task-person'] = {'name': 'Quarterly scan', 'status': 'Running', 'target': 't', 'report': 'y'}
        self.run_job(['203.0.113.10'])
        self.assertEqual(set(self.w.tasks), {'task-other', 'task-person'})
        self.assertTrue(all(c[1] in ('task-2', 'target-1') for c in self.w.calls if c[0] in ('stop_task', 'delete_task', 'delete_target')))


class ConfigSafety(Base):
    def test_vhost_expansion_on_refuses_the_scan_before_anything_is_created(self):
        self.w.config = config_xml(expand='yes')
        api, _ = self.run_job(['203.0.113.10'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertIn('vhost expansion is on', api.completed['error'])
        self.assertNotIn('create_target', self.names())

    def test_safe_checks_off_is_refused(self):
        self.w.config = config_xml(safe='no')
        api, _ = self.run_job(['203.0.113.10'])
        self.assertIn('safe_checks off', api.completed['error'])

    def test_falls_back_to_openvas_conf_and_fails_closed(self):
        root = ET.fromstring(config_xml(expand=None))
        self.assertTrue(worker.gvm_config_safety(root, '# scanner\nexpand_vhosts = no\n')[0])
        self.assertFalse(worker.gvm_config_safety(root, 'expand_vhosts = yes\n')[0])
        ok, why = worker.gvm_config_safety(root, 'max_hosts = 20\n')
        self.assertFalse(ok)
        self.assertIn('defaults it to yes', why)
        ok, why = worker.gvm_config_safety(root, None)
        self.assertFalse(ok)
        self.assertIn('could not be read', why)
        self.assertFalse(worker.gvm_config_safety(ET.fromstring(config_xml(expand='maybe')), None)[0], 'an unreadable value is not "off"')


class Authorisation(Base):
    def test_out_of_scope_expired_and_unauthorised_targets_never_reach_greenbone(self):
        for t in ('other.example.test', 'expired.example.test', 'novuln.example.test', '192.0.2.1', '198.51.100.64/30', '198.51.100.0/29'):
            self.w = World()
            worker.GMP_FACTORY = lambda: FakeGmp(self.w)
            api, _ = self.run_job([t])
            self.assertEqual(api.completed['status'], 'failed', t)
            self.assertIn('No target of this job is in vulnerability-scan scope', api.completed['error'])
            self.assertEqual(self.w.calls, [], f'{t}: Greenbone was never contacted')

    def test_cnii_pinned_name_resolving_elsewhere_is_refused(self):
        DNS['cnii.example.test'] = {'203.0.113.99'}
        self.addCleanup(DNS.__setitem__, 'cnii.example.test', {'203.0.113.50'})
        api, _ = self.run_job(['cnii.example.test'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertEqual(self.w.calls, [])

    def test_a_name_resolving_into_a_private_network_is_not_submitted(self):
        api, r = self.run_job(['internal.example.test', '203.0.113.10'])
        ct = next(c for c in self.w.calls if c[0] == 'create_target')
        self.assertEqual(ct[2], ('203.0.113.10',))
        self.assertEqual(r.summary['target_outcomes']['internal.example.test']['outcome'], 'no_route')
        self.assertIn('10.1.2.3', r.summary['target_outcomes']['internal.example.test']['reason'])

    def test_when_nothing_can_be_submitted_the_job_fails_with_the_reason(self):
        api, _ = self.run_job(['internal.example.test'])
        self.assertEqual(api.completed['status'], 'failed')
        self.assertIn('private address', api.completed['error'])
        self.assertEqual(self.w.calls, [])

    def test_an_approved_range_is_submitted_as_is_and_only_its_addresses_are_kept(self):
        self.w.report = report_xml(result('198.51.100.1', '80/tcp', 'High', '7.0', '1.9') + result('198.51.100.9', '80/tcp', 'High', '7.0', '1.9'),
                                   hosts='<host><ip>198.51.100.1</ip></host><host><ip>198.51.100.9</ip></host>')
        api, r = self.run_job(['198.51.100.0/30'])
        self.assertEqual(next(c for c in self.w.calls if c[0] == 'create_target')[2], ('198.51.100.0/30',))
        self.assertEqual([f['host'] for f in api.results], ['198.51.100.1'])
        self.assertEqual(r.summary['openvas']['unattributed'], 1)
        self.assertEqual(r.summary['target_outcomes']['198.51.100.1']['outcome'], 'reachable_open')

    def test_hosts_openvas_discovered_on_its_own_are_dropped(self):
        self.w.report = report_xml(
            result('203.0.113.20', '443/tcp', 'High', '7.5', '1.1', hostname='app.example.test')
            + result('203.0.113.20', '443/tcp', 'High', '7.5', '1.2', hostname='someone-else.example.org')   # vhost from a certificate
            + result('203.0.113.21', '443/tcp', 'High', '7.5', '1.3', hostname='app.example.test')           # an address the name did not resolve to
            + result('203.0.113.20', '443/tcp', 'High', '7.5', '1.4'))                                       # no hostname: the one name owning that address
        api, r = self.run_job(['app.example.test'])
        self.assertEqual(sorted((f['host'], f['rule_id']) for f in api.results), [('app.example.test', '1.1'), ('app.example.test', '1.4')])
        self.assertEqual(r.summary['openvas']['unattributed'], 2)


class Normalisation(unittest.TestCase):
    def test_older_gmp_cve_list_and_cvss_location(self):
        xml = report_xml('<result><host>203.0.113.10</host><port>80/tcp</port><threat>High</threat>'
                         '<nvt oid="1.5"><name>Old</name><cvss_base>8.1</cvss_base><cve>CVE-2020-1234, CVE-2021-9999, NOCVE</cve></nvt></result>')
        f = worker.parse_openvas_report(xml)[0]
        self.assertEqual((f['cvss'], f['severity'], f['cve_ids']), (8.1, 'high', ['CVE-2020-1234', 'CVE-2021-9999']))

    def test_outcomes(self):
        hosts = {'203.0.113.20': {'hostnames': set(), 'ports': {'443/tcp', '80/tcp'}, 'results': 3}, '203.0.113.30': {'hostnames': set(), 'ports': set(), 'results': 1}}
        self.assertEqual(worker.classify_openvas('a', {'203.0.113.20'}, hosts)[0], 'reachable_open')
        self.assertEqual(worker.classify_openvas('a', {'203.0.113.30'}, hosts)[0], 'insufficient_evidence')
        self.assertEqual(worker.classify_openvas('a', {'203.0.113.40'}, hosts)[0], 'unreachable')
        self.assertEqual(worker.classify_openvas('a', {'203.0.113.20'}, hosts, 443)[0], 'reachable_open')
        self.assertEqual(worker.classify_openvas('a', {'203.0.113.20'}, hosts, 8443)[0], 'insufficient_evidence', 'verification needs the finding port itself')

    def test_report_hosts_from_details_and_results(self):
        xml = report_xml(result('203.0.113.20', 'general/tcp', 'Log', '0', '1.1', hostname='app.example.test'),
                         '<host><ip>203.0.113.20</ip><detail><name>ports</name><value>22,443</value></detail></host>')
        h = worker.openvas_hosts(xml)['203.0.113.20']
        self.assertEqual((h['ports'], h['hostnames'], h['results']), ({'22/tcp', '443/tcp'}, {'app.example.test'}, 1))


class VerificationRescan(Base):
    def test_a_rescan_reports_whether_the_findings_port_answered(self):
        self.w.report = report_xml(result('203.0.113.10', '22/tcp', 'Log', '0', '1.1'), '<host><ip>203.0.113.10</ip></host>')
        _, r = self.run_job(['203.0.113.10'], options={'finding_ids': ['f1'], 'ports': '443'})
        self.assertEqual(r.summary['target_outcomes']['203.0.113.10']['outcome'], 'insufficient_evidence',
                         'port 443 gave no result, so the backend must not mark the finding verified')
        self.w = World()
        worker.GMP_FACTORY = lambda: FakeGmp(self.w)
        self.w.report = report_xml(result('203.0.113.10', '443/tcp', 'Log', '0', '1.1'), '<host><ip>203.0.113.10</ip></host>')
        _, r = self.run_job(['203.0.113.10'], options={'finding_ids': ['f1'], 'ports': '443'})
        self.assertEqual(r.summary['target_outcomes']['203.0.113.10']['outcome'], 'reachable_open')


class Operations(Base):
    def test_self_test_reports_greenbone_without_secrets(self):
        info, problems = worker.greenbone_check(lambda: FakeGmp(self.w), lambda: None)
        self.assertEqual(problems, [])
        text = '\n'.join(info)
        self.assertIn('GMP 22.7', text)
        self.assertIn('OpenVAS Default', text)
        self.assertIn('vhost expansion off', text)
        self.assertNotIn(SECRET, text)
        self.w.config = config_xml(expand='yes')
        self.assertIn('vhost expansion is on', worker.greenbone_check(lambda: FakeGmp(self.w), lambda: None)[1][0])
        self.w.auth_error = GvmResponseError('400', 'Authentication failed')
        self.assertIn('rejected GVM_USER / GVM_PASSWORD', worker.greenbone_check(lambda: FakeGmp(self.w), lambda: None)[1][0])

    def test_preflight_checks_greenbone_settings(self):
        saved = worker.KINDS
        worker.KINDS = ['vuln_openvas']
        self.addCleanup(setattr, worker, 'KINDS', saved)
        worker.GVM_PASSWORD = ''
        worker.GVM_ALIVE_TEST = 'Ping Everything'
        problems = '\n'.join(worker.preflight())
        self.assertIn('GVM_USER / GVM_PASSWORD are not set', problems)
        self.assertIn('GVM_ALIVE_TEST must be one of', problems)

    def test_the_password_is_redacted_from_anything_sent_or_logged(self):
        self.assertNotIn(SECRET, worker.redact_text(f'gvmd said: bad password {SECRET}'))
        self.assertNotIn(SECRET, str(worker.gvm_problem(GvmError(f'oops {SECRET}'))))

    def test_xml_text_handles_strings_and_elements(self):
        self.assertEqual(worker.xml_text('<a/>'), '<a/>')
        self.assertIn('<a', worker.xml_text(ET.fromstring('<a><b/></a>')))


class Health(Base):
    def setUp(self):
        super().setUp()
        self.saved_kinds = worker.KINDS
        worker.KINDS = ['ports', 'vuln_openvas']
        self.addCleanup(setattr, worker, 'KINDS', self.saved_kinds)

    def report(self, api=None, which=lambda t: f'/usr/bin/{t}' if t == 'nmap' else None):
        class OkApi:
            def post(self, path, body, timeout=60):
                return {'ok': True, 'server_time': '2026-10-20T08:00:00Z', 'queued': 0}
        saved = worker.tool_versions
        worker.tool_versions = lambda refresh=False: {'nmap': '7.94SVN'}
        self.addCleanup(setattr, worker, 'tool_versions', saved)
        rows = worker.health_report(api_factory=api or OkApi, gmp_factory=lambda: FakeGmp(self.w), conf_reader=lambda: None, which=which)
        return {(r['component'], r['layer']): r for r in rows}, rows

    def test_every_layer_is_reported_and_end_to_end_is_never_claimed(self):
        by, rows = self.report()
        self.assertEqual(by[('nmap', 'local')]['status'], 'ok')
        self.assertEqual(by[('nmap', 'functional')]['status'], 'ok')
        self.assertEqual([by[('backend', x)]['status'] for x in ('reachability', 'authentication', 'functional', 'end_to_end')], ['ok', 'ok', 'ok', 'not_checked'])
        self.assertEqual([by[('greenbone', x)]['status'] for x in ('reachability', 'authentication', 'end_to_end')], ['ok', 'ok', 'not_checked'])
        self.assertIn('GMP 22.7', by[('greenbone', 'reachability')]['detail'])
        self.assertEqual(by[('greenbone scanner', 'functional')]['status'], 'ok')
        self.assertEqual(by[('greenbone scan configuration', 'functional')]['status'], 'ok')
        feeds = [r for r in rows if r['component'] == 'greenbone feed']
        self.assertEqual([r['status'] for r in feeds], ['ok'] * 4)
        self.assertNotIn(SECRET, json.dumps(rows))
        self.assertNotIn('create_target', self.names(), 'health checks create nothing in Greenbone')
        self.assertNotIn('create_task', self.names())

    def test_a_reachable_gvmd_with_bad_credentials_is_not_healthy(self):
        self.w.auth_error = GvmResponseError('400', 'Authentication failed')
        by, rows = self.report()
        self.assertEqual(by[('greenbone', 'reachability')]['status'], 'ok')
        self.assertEqual(by[('greenbone', 'authentication')]['status'], 'fail')
        self.assertNotIn(('greenbone', 'end_to_end'), by)
        self.assertEqual(worker.print_health(rows), 1)

    def test_scanner_feeds_and_unsafe_config_are_failures_or_warnings(self):
        self.w.scanner_down = True
        self.w.config = config_xml(expand='yes')
        self.w.feeds = (f'<feed><type>NVT</type><version>{STALE}</version></feed>'
                        f'<feed><type>SCAP</type><version>{FRESH}</version><currently_syncing><timestamp>x</timestamp></currently_syncing></feed>'
                        '<feed><type>CERT</type><sync_not_available><error>Feed lock held by another process</error></sync_not_available></feed>'
                        '<feed><type>GVMD_DATA</type></feed>')
        self.w.tasks['t'] = {'name': 'novrsoc-old-job', 'status': 'Interrupted', 'target': 'x', 'report': 'r'}
        by, rows = self.report()
        self.assertEqual(by[('greenbone scanner', 'functional')]['status'], 'fail')
        self.assertEqual(by[('greenbone scan configuration', 'functional')]['status'], 'fail')
        feeds = {r['detail'].split(':')[0].split(' ')[0]: r['status'] for r in rows if r['component'] == 'greenbone feed'}
        self.assertEqual(feeds, {'NVT': 'warn', 'SCAP': 'warn', 'CERT': 'fail', 'GVMD_DATA': 'fail'})
        self.assertEqual(by[('greenbone tasks', 'functional')]['status'], 'warn')
        self.assertIn('1 Interrupted', by[('greenbone tasks', 'functional')]['detail'])

    def test_backend_layers_are_distinguished(self):
        class Down:
            def post(self, *a, **k):
                raise worker.ApiError('/heartbeat', None, 'ConnectionError')

            def reset(self):
                pass

        class Rejected:
            def post(self, *a, **k):
                raise worker.ApiError('/heartbeat', 401, 'Invalid or missing worker token')
        saved = worker.HEARTBEAT_RETRY_DELAY
        worker.HEARTBEAT_RETRY_DELAY = 0
        self.addCleanup(setattr, worker, 'HEARTBEAT_RETRY_DELAY', saved)
        by, _ = self.report(api=Down)
        self.assertEqual(by[('backend', 'reachability')]['status'], 'fail')
        self.assertNotIn(('backend', 'authentication'), by)
        by, _ = self.report(api=Rejected)
        self.assertEqual([by[('backend', 'reachability')]['status'], by[('backend', 'authentication')]['status']], ['ok', 'fail'])

    def test_greenbone_is_independent_when_not_configured(self):
        worker.KINDS, worker.GVM_USER = ['ports'], ''
        by, _ = self.report()
        self.assertEqual(by[('greenbone', 'local')]['status'], 'not_configured')
        self.assertEqual(self.w.calls, [], 'Greenbone is not contacted')
        self.assertEqual(by[('nuclei', 'local')]['status'], 'not_configured', 'tools a worker does not use are not failures')


class PermissionProbeAndHeartbeat(Base):
    def test_permission_probe_creates_and_deletes_without_starting_anything(self):
        row = worker._permission_probe(FakeGmp(self.w))
        self.assertEqual(row['status'], 'ok', row)
        target = next(c for c in self.w.calls if c[0] == 'create_target')
        self.assertEqual(target[2], (worker.PERMCHECK_HOST,))
        self.assertTrue(target[1].startswith('novrsoc-permcheck-'))
        self.assertIn('create_task', self.names())
        self.assertNotIn('start_task', self.names(), 'nothing is started, so nothing is scanned')
        self.assertEqual((self.w.tasks, self.w.targets), ({}, {}), 'both deleted')

    def test_permission_probe_reports_a_refusal_and_still_cleans_up(self):
        orig = FakeGmp.create_task

        def refuse(gmp, *a, **k):
            raise GvmResponseError('403', 'Permission denied')
        FakeGmp.create_task = refuse
        self.addCleanup(setattr, FakeGmp, 'create_task', orig)
        row = worker._permission_probe(FakeGmp(self.w))
        self.assertEqual(row['status'], 'fail')
        self.assertIn('GMP 403', row['detail'])
        self.assertEqual(self.w.targets, {}, 'the test target is removed')

    def test_heartbeat_reports_gmp_and_feed_state_cached(self):
        saved = worker.KINDS
        worker.KINDS = ['ports', 'vuln_openvas']
        self.addCleanup(setattr, worker, 'KINDS', saved)
        t = [1000.0]
        v = worker.openvas_summary(clock=lambda: t[0])
        self.assertRegex(v, r'^GMP 22\.7; feeds current \(oldest 0\.\dd\)$')
        self.assertLessEqual(len(v), 80, 'the backend accepts at most 80 characters')
        n = len(self.w.calls)
        t[0] += 3600
        self.assertEqual(worker.openvas_summary(clock=lambda: t[0]), v)
        self.assertEqual(len(self.w.calls), n, 'asked at most every 6 hours')
        self.assertEqual(worker.heartbeat_body()['tool_versions']['openvas'], v)
        self.assertNotIn(SECRET, json.dumps(worker.heartbeat_body()))

    def test_heartbeat_survives_greenbone_failures_and_skips_when_not_enabled(self):
        saved = worker.KINDS
        self.addCleanup(setattr, worker, 'KINDS', saved)
        worker.KINDS = ['ports']
        self.assertIsNone(worker.openvas_summary())
        self.assertNotIn('openvas', worker.heartbeat_body()['tool_versions'])
        self.assertEqual(self.w.calls, [], 'Greenbone not contacted when vuln_openvas is off')
        worker.KINDS = ['vuln_openvas']
        self.w.auth_error = GvmResponseError('400', 'Authentication failed')
        self.assertTrue(worker.openvas_summary().startswith('unavailable: Greenbone rejected GVM_USER'))


class NmapObservations(unittest.TestCase):
    def test_a_service_without_cpe_omits_the_field_instead_of_sending_null(self):
        xml = ('<nmaprun><host><status state="up" reason="user-set"/><address addr="203.0.113.9" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>'
               '<port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table" conf="3"/></port>'
               '<port protocol="tcp" portid="81"><state state="filtered"/></port></ports></host></nmaprun>')
        out = {o['port']: o for o in worker.parse_nmap_xml(xml)}
        self.assertEqual(out[22]['cpe'], ['cpe:/a:openbsd:openssh:8.9p1'])
        self.assertNotIn('cpe', out[80])
        self.assertNotIn('cpe', out[81])

    def test_backend_rejection_reasons_are_kept_and_logged_once(self):
        class Api:
            def post(self, path, body, timeout=60):
                return {'accepted': 1, 'rejected_invalid': 4, 'invalid_reasons': ['service cpe: Invalid input: expected array, received null (x4)']}
        r = worker.JobRunner(Api(), {'id': 'j', 'kind': 'ports', 'targets': ['203.0.113.9']}, [scope('ip', '203.0.113.9')])
        with self.assertLogs(worker.log, 'WARNING') as logs:
            r.send([{'type': 'host', 'host': '203.0.113.9', 'source': 'nmap'}], 'ports')
            r.send([{'type': 'host', 'host': '203.0.113.9', 'source': 'nmap'}], 'ports')
        self.assertEqual(r.summary['invalid_reasons'], ['service cpe: Invalid input: expected array, received null (x4)'])
        self.assertEqual(r.summary['rejected_invalid'], 8)
        self.assertEqual(len(logs.output), 1, 'the same reason is logged once per job')


if __name__ == '__main__':
    unittest.main()
