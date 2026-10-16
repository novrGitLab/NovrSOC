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


def nmap_xml(addr: str, status: str = 'up', reason: str = 'user-set', ports: str = '', extra: str = '') -> str:
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -Pn {addr}"><host><status state="{status}" reason="{reason}"/>'
            f'<address addr="{addr}" addrtype="ipv4"/><ports>{extra}{ports}</ports></host><runstats><finished exit="success"/></runstats></nmaprun>')


ALL_FILTERED = nmap_xml('203.0.113.9', extra='<extraports state="filtered" count="1000"><extrareasons reason="no-response" count="1000"/></extraports>')
ALL_CLOSED = nmap_xml('203.0.113.9', extra='<extraports state="closed" count="1000"><extrareasons reason="conn-refused" count="1000"/></extraports>')
ONE_OPEN = nmap_xml('203.0.113.9', extra='<extraports state="closed" count="999"/>',
                    ports='<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6"/></port>')
HOST_DOWN = nmap_xml('203.0.113.9', status='down', reason='no-response')


class NmapOutcomes(unittest.TestCase):
    """P12: host status and <extraports> are read; each target gets an honest outcome."""

    def test_host_status_and_extraports_are_counted(self):
        h = worker.parse_nmap_hosts(ALL_FILTERED)['203.0.113.9']
        self.assertEqual((h['host_status'], h['host_status_reason'], h['port_states'], h['ports_scanned']), ('up', 'user-set', {'filtered': 1000}, 1000))
        self.assertEqual(worker.parse_nmap_xml(ALL_FILTERED), [], 'no individual ports: the old parser saw nothing')
        h = worker.parse_nmap_hosts(ONE_OPEN)['203.0.113.9']
        self.assertEqual(h['port_states'], {'closed': 999, 'open': 1})
        self.assertEqual(worker.parse_nmap_hosts(HOST_DOWN)['203.0.113.9']['host_status'], 'down')

    def test_outcomes(self):
        cases = [
            (ALL_FILTERED, 'unreachable', 'none of the 1000 port(s) scanned answered'),
            (ALL_CLOSED, 'reachable_no_open', 'none of the 1000 port(s) scanned is open'),
            (ONE_OPEN, 'reachable_open', '1 open of 1000'),
            (HOST_DOWN, 'unreachable', 'may still be online'),
        ]
        for xml, outcome, phrase in cases:
            o, reason = worker.classify_nmap('203.0.113.9', worker.parse_nmap_hosts(xml).get('203.0.113.9'))
            self.assertEqual(o, outcome, xml[:80])
            self.assertIn(phrase, reason)
            self.assertNotIn('offline', reason.lower())
        self.assertEqual(worker.classify_nmap('203.0.113.9', None)[0], 'insufficient_evidence')
        self.assertEqual(worker.job_outcome({'a': {'outcome': 'reachable_open'}, 'b': {'outcome': 'reachable_no_open'}}), 'assessed')
        self.assertEqual(worker.job_outcome({'a': {'outcome': 'reachable_open'}, 'b': {'outcome': 'unreachable'}}), 'partial')
        self.assertEqual(worker.job_outcome({'a': {'outcome': 'unreachable'}}), 'unreachable')
        self.assertEqual(worker.job_outcome({'a': {'outcome': 'no_route'}}), 'no_route')
        self.assertEqual(worker.job_outcome({}), 'insufficient_evidence')


class PortsJob(unittest.TestCase):
    """The ports job end to end with mocked nmap output (nothing is scanned)."""

    SCOPES = [{'kind': 'cidr', 'value': '203.0.113.0/28', 'allow_port_scan': True, 'allow_vuln_scan': False, 'status': 'active', 'expires_at': FUTURE},
              {'kind': 'ip', 'value': '10.88.1.139', 'allow_port_scan': True, 'allow_vuln_scan': False, 'status': 'active', 'expires_at': FUTURE}]

    def setUp(self):
        self._nets = worker.WORKER_NETWORKS
        worker.WORKER_NETWORKS = ['203.0.113.0/24']   # the documentation range stands in for a routable network
        self.posts = []

    def tearDown(self):
        worker.WORKER_NETWORKS = self._nets

    def api(self):
        posts = self.posts

        class Api:
            def post(self, path, body, timeout=60):
                posts.append((path, body))
                return {'accepted': len(body.get('observations', [])), 'ok': True}
        return Api()

    def run_job(self, target: str, xml: Optional_str = None, nmap_calls=None):
        r = worker.JobRunner(self.api(), {'id': 'p1', 'kind': 'ports', 'targets': [target], 'options': {'ports': 'top-1000'}}, self.SCOPES)

        def fake_tool(args, stdin=None):
            if nmap_calls is not None:
                nmap_calls.append(args)
            if isinstance(xml, Exception):
                raise xml
            return xml or ''
        r.run_tool = fake_tool
        r.run()
        return r

    def sent(self, path_end):
        return [b for p, b in self.posts if p.endswith(path_end)]

    def test_filtered_target_is_recorded_as_unreachable_not_success_with_nothing(self):
        self.run_job('203.0.113.9', ALL_FILTERED)
        obs = [o for b in self.sent('/results') for o in b['observations']]
        self.assertEqual(len(obs), 1)
        h = obs[0]
        self.assertEqual((h['type'], h['host'], h['assessment']['outcome'], h['assessment']['port_states']), ('host', '203.0.113.9', 'unreachable', {'filtered': 1000}))
        self.assertNotIn('alive', h, 'no answer never says offline')
        done = self.sent('/complete')[0]
        self.assertEqual(done['status'], 'succeeded')
        self.assertEqual(done['summary']['outcome'], 'unreachable')
        self.assertEqual(done['summary']['target_outcomes']['203.0.113.9']['outcome'], 'unreachable')
        ev = self.sent('/evidence')[0]
        self.assertEqual((ev['tool'], ev['target'], ev['truncated']), ('nmap', '203.0.113.9', False))
        self.assertIn('<extraports state="filtered"', ev['content'])

    def test_open_port_gives_host_and_service(self):
        self.run_job('203.0.113.9', ONE_OPEN)
        obs = [o for b in self.sent('/results') for o in b['observations']]
        self.assertEqual([o['type'] for o in obs], ['host', 'service'])
        self.assertEqual((obs[0]['assessment']['outcome'], obs[0]['alive']), ('reachable_open', True))
        self.assertEqual((obs[1]['port'], obs[1]['state']), (22, 'open'))
        self.assertEqual(self.sent('/complete')[0]['summary']['outcome'], 'assessed')

    def test_closed_ports_mean_reachable_with_nothing_open(self):
        self.run_job('203.0.113.9', ALL_CLOSED)
        self.assertEqual(self.sent('/complete')[0]['summary']['outcome'], 'assessed')
        self.assertEqual(self.sent('/results')[0]['observations'][0]['assessment']['outcome'], 'reachable_no_open')

    def test_private_target_without_route_is_not_scanned_and_fails_with_the_reason(self):
        calls = []
        self.run_job('10.88.1.139', ALL_FILTERED, nmap_calls=calls)
        self.assertEqual(calls, [], 'nmap never ran')
        h = self.sent('/results')[0]['observations'][0]
        self.assertEqual(h['assessment']['outcome'], 'no_route')
        done = self.sent('/complete')[0]
        self.assertEqual((done['status'], done['summary']['outcome']), ('failed', 'no_route'))
        self.assertIn('VMS_WORKER_NETWORKS', done['error'])
        self.assertIn('Run a worker inside that network', done['error'])

    def test_declared_network_allows_a_private_target(self):
        worker.WORKER_NETWORKS = ['10.88.0.0/16']
        calls = []
        self.run_job('10.88.1.139', nmap_xml('10.88.1.139', extra='<extraports state="closed" count="1000"/>'), nmap_calls=calls)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.sent('/complete')[0]['summary']['outcome'], 'assessed')

    def test_empty_or_unreadable_output_fails_the_job(self):
        self.run_job('203.0.113.9', '')
        self.assertEqual(self.sent('/complete')[-1]['status'], 'failed')
        self.assertIn('produced no output', self.sent('/complete')[-1]['error'])
        self.posts.clear()
        self.run_job('203.0.113.9', '<nmaprun><host><status')
        done = self.sent('/complete')[-1]
        self.assertEqual(done['status'], 'failed')
        self.assertIn('could not be read', done['error'])
        self.assertEqual(done['summary'].get('outcome'), None, 'a failed scan carries no reachability claim')

    def test_missing_host_is_insufficient_evidence(self):
        self.run_job('203.0.113.9', '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>')
        done = self.sent('/complete')[0]
        self.assertEqual(done['summary']['outcome'], 'insufficient_evidence')

    def test_evidence_is_bounded_and_redacted(self):
        worker.TOKEN, saved = 'T' * 40, worker.TOKEN
        try:
            big = 'Authorization: Bearer abc.def ' + worker.TOKEN + ' ' + 'x' * (worker.EVIDENCE_MAX_BYTES + 10)
            r = worker.JobRunner(self.api(), {'id': 'e1', 'kind': 'ports', 'targets': []}, [])
            r.send_evidence('203.0.113.9', 'nmap', big)
            ev = self.sent('/evidence')[0]
            self.assertTrue(ev['truncated'])
            self.assertLessEqual(len(ev['content'].encode()), worker.EVIDENCE_MAX_BYTES)
            self.assertNotIn(worker.TOKEN, ev['content'])
            self.assertNotIn('abc.def', ev['content'])
        finally:
            worker.TOKEN = saved

    def test_evidence_failure_does_not_fail_the_job(self):
        posts = []

        class Api:
            def post(self, path, body, timeout=60):
                posts.append(path)
                if path.endswith('/evidence'):
                    raise worker.ApiError(path, 503, 'Raw evidence is not set up yet')
                return {'accepted': 1, 'ok': True}
        r = worker.JobRunner(Api(), {'id': 'p2', 'kind': 'ports', 'targets': ['203.0.113.9'], 'options': {}}, self.SCOPES)
        r.run_tool = lambda args, stdin=None: ALL_CLOSED
        r.run()
        self.assertTrue(any(p.endswith('/complete') for p in posts))
        self.assertFalse(r.evidence_enabled)


Optional_str = str


class ReliabilityP1(unittest.TestCase):
    def test_root_cause_is_kept_and_redacted(self):
        import requests
        worker.TOKEN, saved = 'S' * 40, worker.TOKEN
        try:
            inner = ConnectionResetError(f'reset by peer while sending Bearer abc.def to https://x.test/api?token={worker.TOKEN}')
            mid = RuntimeError('pool')
            mid.__cause__ = inner
            outer = requests.ConnectionError(mid)
            msg = worker.root_cause(outer)
            self.assertTrue(msg.startswith('ConnectionError <- ConnectionResetError: reset by peer'))
            self.assertNotIn(worker.TOKEN, msg)
            self.assertNotIn('abc.def', msg)
            self.assertIn('?[REDACTED]', msg)
        finally:
            worker.TOKEN = saved

    def test_heartbeat_retries_once_on_a_fresh_connection_and_no_more(self):
        class Flaky:
            def __init__(self, fails):
                self.fails, self.calls, self.resets = fails, 0, 0

            def post(self, path, body, timeout=60):
                self.calls += 1
                if self.calls <= self.fails:
                    raise worker.ApiError(path, None, 'ConnectionError <- RemoteDisconnected: closed')
                return {'ok': True}

            def reset(self):
                self.resets += 1

        slept = []
        a = Flaky(1)
        self.assertEqual(worker.send_heartbeat(a, {}, sleep=slept.append), {'ok': True})
        self.assertEqual((a.calls, a.resets, slept), (2, 1, [worker.HEARTBEAT_RETRY_DELAY]))
        b = Flaky(5)
        with self.assertRaises(worker.ApiError):
            worker.send_heartbeat(b, {}, sleep=lambda s: None)
        self.assertEqual(b.calls, 2, 'exactly one retry')

        class Rejected(Flaky):
            def post(self, path, body, timeout=60):
                self.calls += 1
                raise worker.ApiError(path, 401, 'Invalid or missing worker token')
        c = Rejected(0)
        with self.assertRaises(worker.ApiError):
            worker.send_heartbeat(c, {}, sleep=lambda s: None)
        self.assertEqual(c.calls, 1, 'HTTP errors are not retried')

    def test_presence_backoff_is_bounded(self):
        self.assertEqual(worker.next_presence_delay(0), worker.PRESENCE_SECONDS)
        self.assertEqual(worker.next_presence_delay(1), worker.PRESENCE_SECONDS * 2)
        self.assertEqual(worker.next_presence_delay(50), worker.HEARTBEAT_MAX_BACKOFF)

    def test_job_heartbeat_has_its_own_session(self):
        r = worker.JobRunner(worker.Api(), {'id': 'j', 'kind': 'ports', 'targets': []}, [])
        self.assertIsNot(r.hb_api, r.api)
        self.assertIsNot(r.hb_api.s, r.api.s)

    def test_shutdown_hands_the_job_back_instead_of_completing_it(self):
        posts = []

        class Api:
            def post(self, path, body, timeout=60):
                posts.append((path, body))
                return {'ok': True, 'accepted': 0}
        r = worker.JobRunner(Api(), {'id': 's1', 'kind': 'ports', 'targets': ['203.0.113.9'], 'options': {}}, PortsJob.SCOPES)

        def tool(args, stdin=None):
            r.stop_for_shutdown()          # SIGTERM arrives while nmap runs
            raise worker.Cancelled()
        r.run_tool = tool
        saved = worker.WORKER_NETWORKS
        worker.WORKER_NETWORKS = ['203.0.113.0/24']
        try:
            r.run()
        finally:
            worker.WORKER_NETWORKS = saved
        paths = [p for p, _ in posts]
        self.assertIn('/jobs/s1/release', paths)
        self.assertNotIn('/jobs/s1/complete', paths)
        self.assertIn('stopping', dict(posts)['/jobs/s1/release']['reason'])

    def test_run_loop_stops_without_claiming_once_stop_is_set(self):
        calls = []

        class Api:
            def post(self, path, body, timeout=60):
                calls.append(path)
                return {'job': None}
        stop = __import__('threading').Event()
        stop.set()
        worker.run_loop(Api(), worker.ConnectionLog(), stop)
        self.assertEqual(calls, [])

    def test_heartbeat_announces_declared_networks(self):
        saved = worker.WORKER_NETWORKS
        worker.WORKER_NETWORKS = ['10.88.0.0/16']
        try:
            self.assertEqual(worker.heartbeat_body()['networks'], ['10.88.0.0/16'])
            self.assertEqual(worker.target_route('10.88.1.139'), (True, None))
            self.assertFalse(worker.target_route('192.168.1.5')[0])
            self.assertTrue(worker.target_route('8.8.8.8')[0])
            self.assertTrue(worker.target_route('scanme.example.test')[0], 'hostnames are judged by the tool')
        finally:
            worker.WORKER_NETWORKS = saved


if __name__ == '__main__':
    unittest.main()
