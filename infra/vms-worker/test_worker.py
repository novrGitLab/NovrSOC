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


if __name__ == '__main__':
    unittest.main()
