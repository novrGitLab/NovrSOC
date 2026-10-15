"""Tests for the VMS worker's pure parts: tool-output parsers and scope rules. No tool runs and no
network is used; all names are reserved test domains and documentation IP ranges."""
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
import worker  # noqa: E402

FUTURE = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
PAST = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
SCOPES = [
    {'kind': 'domain', 'value': 'example.test', 'include_subdomains': True, 'allow_port_scan': False, 'allow_vuln_scan': False, 'status': 'active', 'expires_at': FUTURE},
    {'kind': 'cidr', 'value': '203.0.113.0/28', 'include_subdomains': False, 'allow_port_scan': True, 'allow_vuln_scan': False, 'status': 'active', 'expires_at': FUTURE},
    {'kind': 'domain', 'value': 'old.test', 'include_subdomains': True, 'allow_port_scan': True, 'allow_vuln_scan': True, 'status': 'active', 'expires_at': PAST},
    {'kind': 'ip', 'value': '198.51.100.7', 'include_subdomains': False, 'allow_port_scan': True, 'allow_vuln_scan': False, 'status': 'revoked', 'expires_at': FUTURE},
]


class Scope(unittest.TestCase):
    def test_rules_match_the_backend(self):
        self.assertTrue(worker.in_scope('api.example.test', SCOPES, 'discovery'))
        self.assertFalse(worker.in_scope('notexample.test', SCOPES, 'discovery'))
        self.assertFalse(worker.in_scope('api.example.test', SCOPES, 'ports'), 'no port-scan permission on the domain')
        self.assertTrue(worker.in_scope('203.0.113.9', SCOPES, 'ports'))
        self.assertFalse(worker.in_scope('203.0.113.20', SCOPES, 'ports'))
        self.assertFalse(worker.in_scope('www.old.test', SCOPES, 'discovery'), 'expired')
        self.assertFalse(worker.in_scope('198.51.100.7', SCOPES, 'ports'), 'revoked')
        for bad in ['*.example.test', 'http://example.test', 'example.test;rm -rf /', '-x.example.test', '']:
            self.assertFalse(worker.in_scope(bad, SCOPES, 'discovery'), bad)

    def test_job_targets(self):
        self.assertTrue(worker.job_target_allowed('203.0.113.0/28', SCOPES, 'ports'), 'the approved range itself')
        self.assertFalse(worker.job_target_allowed('203.0.113.0/24', SCOPES, 'ports'), 'a wider range is not approved')
        self.assertFalse(worker.job_target_allowed('example.test', SCOPES, 'ports'))
        self.assertFalse(worker.job_target_allowed('203.0.113.0/28', SCOPES, 'vuln'), 'the range does not allow vulnerability scans')

    def test_passive_only_entries_cover_nothing_here(self):
        passive = [
            {'kind': 'domain', 'value': 'cnii.test', 'include_subdomains': True, 'allow_discovery': False, 'allow_port_scan': False, 'allow_vuln_scan': False, 'status': 'active', 'expires_at': FUTURE},
            {'kind': 'cidr', 'value': '192.0.2.0/28', 'include_subdomains': False, 'allow_discovery': False, 'allow_port_scan': True, 'allow_vuln_scan': True, 'status': 'active', 'expires_at': FUTURE},
            {'kind': 'asn', 'value': 'AS64500', 'include_subdomains': False, 'allow_discovery': False, 'allow_port_scan': False, 'allow_vuln_scan': False, 'status': 'active', 'expires_at': FUTURE},
        ]
        for activity in ('discovery', 'ports', 'vuln'):
            self.assertFalse(worker.in_scope('www.cnii.test', passive, activity), activity)
            self.assertFalse(worker.in_scope('192.0.2.3', passive, activity), activity)
            self.assertFalse(worker.job_target_allowed('192.0.2.0/28', passive, activity), activity)
            self.assertFalse(worker.job_target_allowed('AS64500', passive, activity), activity)

    def test_expired_range_is_not_a_job_target(self):
        expired = [{'kind': 'cidr', 'value': '192.0.2.0/28', 'include_subdomains': False, 'allow_port_scan': True, 'allow_vuln_scan': True, 'status': 'active', 'expires_at': PAST}]
        self.assertFalse(worker.job_target_allowed('192.0.2.0/28', expired, 'ports'))


class Parsers(unittest.TestCase):
    def test_subfinder_keeps_only_the_domain(self):
        lines = [json.dumps({'host': 'API.example.test', 'source': 'crtsh'}), json.dumps({'host': 'evil.test'}),
                 json.dumps({'host': 'x.notexample.test'}), 'mail.example.test', '', '{bad json']
        self.assertEqual(worker.parse_subfinder(lines, 'example.test'), ['api.example.test', 'mail.example.test'])

    def test_dnsx(self):
        d = worker.parse_dnsx([json.dumps({'host': 'api.example.test', 'a': ['203.0.113.5', 'nope'], 'aaaa': ['2001:db8::5'], 'cname': ['edge.cdn.test']})])
        self.assertEqual(d['api.example.test'], {'a': ['203.0.113.5'], 'aaaa': ['2001:db8::5'], 'cname': ['edge.cdn.test']})

    def test_httpx(self):
        o = worker.parse_httpx([json.dumps({'input': 'api.example.test', 'url': 'https://api.example.test', 'status_code': 200, 'title': 'API',
                                            'webserver': 'nginx/1.25.3', 'tech': ['Nginx:1.25.3', 'React'], 'a': ['203.0.113.5'], 'cdn_name': None})])[0]
        self.assertEqual(o['host'], 'api.example.test')
        self.assertEqual(o['http']['status'], 200)
        self.assertEqual(o['technologies'], [{'name': 'Nginx', 'version': '1.25.3'}, {'name': 'React', 'version': None}])
        self.assertEqual(o['ips'], ['203.0.113.5'])

    def test_nmap_xml(self):
        xml = """<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.5" addrtype="ipv4"/>
        <hostnames><hostname name="api.example.test" type="user"/></hostnames><ports>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>
        <port protocol="tcp" portid="25"><state state="filtered"/></port></ports></host>
        <host><address addr="203.0.113.6" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>"""
        out = worker.parse_nmap_xml(xml)
        self.assertEqual([(o['host'], o['port'], o['state']) for o in out], [('api.example.test', 22, 'open'), ('api.example.test', 25, 'filtered'), ('203.0.113.6', 443, 'open')])
        self.assertEqual(out[0]['product'], 'OpenSSH')
        self.assertEqual(out[0]['version'], '8.9p1 Ubuntu')
        self.assertEqual(out[0]['cpe'], ['cpe:/a:openbsd:openssh:8.9p1'])


class VulnParsers(unittest.TestCase):
    def test_nuclei_jsonl(self):
        line = json.dumps({'template-id': 'CVE-2023-12345', 'host': 'https://api.example.test:8443', 'matched-at': 'https://api.example.test:8443/login',
                           'type': 'http', 'matcher-name': 'version', 'extracted-results': ['1.2.3'],
                           'info': {'name': 'Example RCE', 'severity': 'critical', 'description': 'An RCE.', 'remediation': 'Upgrade to 1.2.4.',
                                    'reference': ['https://nvd.nist.gov/vuln/detail/CVE-2023-12345'],
                                    'classification': {'cve-id': ['cve-2023-12345', 'bogus'], 'cvss-score': 9.8}},
                           'request': 'GET / HTTP/1.1', 'response': 'HTTP/1.1 200 OK secret=abc'})
        o = worker.parse_nuclei([line, 'not json', json.dumps({'template-id': 'x', 'host': 'not a host!'})])
        self.assertEqual(len(o), 1)
        f = o[0]
        self.assertEqual((f['host'], f['port'], f['rule_id'], f['severity'], f['cve_ids'], f['cvss']), ('api.example.test', 8443, 'CVE-2023-12345', 'critical', ['CVE-2023-12345'], 9.8))
        self.assertNotIn('response', json.dumps(f), 'raw requests/responses are not sent')

    def test_openvas_report(self):
        xml = """<report><report><results>
          <result><host>203.0.113.5<hostname>api.example.test</hostname></host><port>443/tcp</port><threat>High</threat><severity>7.5</severity>
            <nvt oid="1.3.6.1.4.1.25623.1.0.123456"><name>TLS weak cipher</name><solution>Disable weak ciphers.</solution>
              <refs><ref type="cve" id="CVE-2016-2183"/><ref type="url" id="https://example.test/advisory"/></refs></nvt>
            <description>Weak cipher suites accepted.</description><qod><value>80</value></qod></result>
          <result><host>203.0.113.5</host><port>general/tcp</port><threat>Log</threat><severity>0.0</severity><nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>OS detection</name></nvt></result>
        </results></report></report>"""
        o = worker.parse_openvas_report(xml)
        self.assertEqual(len(o), 1, 'log-level results skipped')
        f = o[0]
        self.assertEqual((f['host'], f['port'], f['protocol'], f['severity'], f['cve_ids'], f['scanner']), ('api.example.test', 443, 'tcp', 'high', ['CVE-2016-2183'], 'openvas'))
        self.assertEqual(f['references'], ['https://example.test/advisory'])


class SendFiltersScope(unittest.TestCase):
    def test_out_of_scope_results_never_leave_the_worker(self):
        sent = []

        class FakeApi:
            def post(self, path, body, timeout=60):
                sent.extend(body.get('observations', []))
                return {'accepted': len(body.get('observations', []))}

        r = worker.JobRunner(FakeApi(), {'id': 'j1', 'kind': 'discovery', 'targets': ['example.test']}, SCOPES)
        r.send([{'type': 'host', 'host': 'api.example.test', 'source': 'subfinder'}, {'type': 'host', 'host': 'other.test', 'source': 'subfinder'}], 'discovery')
        self.assertEqual([o['host'] for o in sent], ['api.example.test'])
        self.assertEqual(r.summary['dropped_by_worker'], 1)


class Presence(unittest.TestCase):
    """Phase P10: failures explained once and without the token, connection state logged on change,
    a periodic status line, and --check that claims nothing."""

    SECRET = 's' * 40

    def setUp(self):
        self._token, self._api = worker.TOKEN, worker.API
        worker.TOKEN, worker.API = self.SECRET, 'https://backend.example.test'

    def tearDown(self):
        worker.TOKEN, worker.API = self._token, self._api

    def test_each_failure_is_explained_without_the_token(self):
        cases = {
            401: 'VMS_WORKER_TOKEN on this host is not the value set on Railway',
            404: 'NOVRSOC_API_URL is wrong, or the backend is not running a version with this endpoint',
            400: 'check VMS_WORKER_ID and VMS_WORKER_KINDS',
            503: 'not ready for workers',
            None: 'cannot reach the backend',
        }
        for status, phrase in cases.items():
            msg = str(worker.ApiError('/claim', status, 'detail'))
            self.assertIn(phrase, msg, status)
            self.assertNotIn(self.SECRET, msg)
        self.assertIn('https://backend.example.test/api/vms/worker/claim', str(worker.ApiError('/claim', 404, '')))

    def test_state_changes_are_logged_once_and_repeats_are_throttled(self):
        now = [0.0]
        conn = worker.ConnectionLog(clock=lambda: now[0])
        err = worker.ApiError('/claim', 401, 'Invalid or missing worker token')
        with self.assertLogs('vms-worker', level='INFO') as cm:
            conn.fail('job polling', err)
            conn.fail('job polling', err)            # same error, same window: silent
            now[0] += worker.ERROR_REPEAT_SECONDS
            conn.fail('job polling', err)            # repeated after the window
            conn.ok('job polling')
            conn.ok('job polling')                   # already connected: silent
        lines = [r.getMessage() for r in cm.records]
        self.assertEqual(sum('job polling failed' in x for x in lines), 2)
        self.assertEqual(sum(x.startswith('connected:') for x in lines), 1)
        self.assertIn('again', lines[-1])
        self.assertFalse(any(self.SECRET in x for x in lines))

    def test_status_line_reports_polls_jobs_and_queue(self):
        now = [0.0]
        conn = worker.ConnectionLog(clock=lambda: now[0])
        conn.ok('job polling')
        for got in (False, False, True):
            conn.poll(got)
        conn.queued = 0
        self.assertIsNone(conn.status_due(), 'not before the interval')
        now[0] += worker.STATUS_LOG_SECONDS
        line = conn.status_due()
        self.assertIn('status: connected; 3 poll(s), 1 job(s)', line)
        self.assertIn('0 queued job(s)', line)
        self.assertEqual((conn.polls, conn.jobs), (0, 0), 'counters reset per window')

    def test_check_sends_one_heartbeat_and_never_claims(self):
        calls = []
        real = worker.Api

        class OkApi:
            def post(self, path, body, timeout=60):
                calls.append((path, body))
                return {'ok': True, 'server_time': '2026-10-15T18:40:00Z', 'queued': 2}

        class RejectedApi:
            def post(self, path, body, timeout=60):
                raise worker.ApiError(path, 401, 'Invalid or missing worker token')

        try:
            worker.Api = OkApi
            self.assertEqual(worker.check(), 0)
            self.assertEqual([c[0] for c in calls], ['/heartbeat'])
            body = calls[0][1]
            self.assertEqual((body['worker_id'], body['kinds'], body['version']), (worker.WORKER_ID, worker.KINDS, worker.VERSION))
            self.assertEqual(set(body['tools']), {'subfinder', 'dnsx', 'httpx', 'nmap', 'nuclei', 'openvas'})
            worker.Api = RejectedApi
            self.assertEqual(worker.check(), 1)
        finally:
            worker.Api = real


class Lifecycle(unittest.TestCase):
    """Job completion matches the backend contract, retries only what is safe to retry, tool failures
    fail the job, and an authorised IP with no web server is still recorded."""

    def runner(self, api, job=None):
        return worker.JobRunner(api, job or {'id': 'j1', 'kind': 'discovery', 'targets': ['203.0.113.9']}, SCOPES)

    def test_completion_body_omits_null_fields(self):
        sent = []

        class Api:
            def post(self, path, body, timeout=60):
                sent.append((path, body))
                return {'ok': True}

        r = self.runner(Api())
        self.assertTrue(r.complete('succeeded', None, sleep=lambda s: None))
        self.assertEqual(sent[0][0], '/jobs/j1/complete')
        self.assertNotIn('error', sent[0][1], 'no "error": null')
        self.assertEqual(set(sent[0][1]), {'worker_id', 'status', 'summary'})
        r.complete('failed', 'nmap exited 1: boom', sleep=lambda s: None)
        self.assertEqual(sent[1][1]['error'], 'nmap exited 1: boom')

    def test_completion_retries_transient_failures_only(self):
        calls, slept = [], []

        class Flaky:
            def __init__(self, statuses):
                self.statuses = list(statuses)

            def post(self, path, body, timeout=60):
                calls.append(path)
                st = self.statuses.pop(0)
                if st != 200:
                    raise worker.ApiError(path, st, 'x')
                return {'ok': True}

        self.assertTrue(self.runner(Flaky([503, None, 200])).complete('succeeded', None, sleep=slept.append))
        self.assertEqual(slept, [5, 15])
        calls.clear()
        self.assertFalse(self.runner(Flaky([400])).complete('succeeded', None, sleep=slept.append))
        self.assertEqual(len(calls), 1, '400 is not retried')
        calls.clear()
        self.assertFalse(self.runner(Flaky([409])).complete('succeeded', None, sleep=slept.append))
        self.assertEqual(len(calls), 1, '409 is not retried')
        calls.clear()
        self.assertFalse(self.runner(Flaky([503, 503, 503, 503])).complete('succeeded', None, sleep=lambda s: None))
        self.assertEqual(len(calls), 4, 'gives up after the last delay')

    def test_a_failing_tool_fails_the_job_with_its_reason(self):
        r = self.runner(object())
        with self.assertRaises(RuntimeError) as cm:
            r.run_tool([sys.executable, '-c', 'import sys; sys.stderr.write("first\\nfatal: bad flag\\n"); sys.exit(2)'])
        self.assertIn('exited 2: fatal: bad flag', str(cm.exception))
        self.assertEqual(r.run_tool([sys.executable, '-c', 'print("ok")']).strip(), 'ok')

    def test_an_ip_without_a_web_server_is_still_recorded(self):
        sent = []

        class Api:
            def post(self, path, body, timeout=60):
                sent.extend(body.get('observations', []))
                return {'accepted': len(body.get('observations', []))}

        r = self.runner(Api(), {'id': 'j2', 'kind': 'discovery', 'targets': ['203.0.113.9']})
        r.run_tool = lambda args, stdin=None: ''   # httpx: nothing answered
        r.discovery()
        self.assertEqual([(o['host'], o['ips'], o['source']) for o in sent], [('203.0.113.9', ['203.0.113.9'], 'httpx')])
        self.assertNotIn('alive', sent[0], 'no HTTP answer does not mean down')
        self.assertEqual(r.summary['http_responses'], 0)


if __name__ == '__main__':
    unittest.main()
