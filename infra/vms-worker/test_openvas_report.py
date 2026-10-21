"""Greenbone report parsing (worker 1.8.1) against a representative GMP report fixture
(fixtures/greenbone-report.xml): CVE identifiers, CVSS score / version / vector, host, port and
protocol, name, description, evidence, remediation, scanner and scan times, skipped and incomplete
results, empty and unreadable reports. Also keeps the backend's ingestion fixture in step with
what this parser produces (backend/src/routes/__tests__/fixtures/openvas-observations.json).

    python -m unittest test_openvas_report
    python test_openvas_report.py --write-backend-fixture   (regenerates the backend fixture)
"""
import json
import os
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import worker  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, 'fixtures', 'greenbone-report.xml')
BACKEND_FIXTURE = os.path.join(HERE, '..', '..', 'backend', 'src', 'routes', '__tests__', 'fixtures', 'openvas-observations.json')
SUBMITTED = {'192.0.2.10': 'app.qa-alpha.test', '192.0.2.20': '192.0.2.20'}
CONTEXT = {'task_id': 'task-fixture-0001', 'report_id': 'rep-fixture-0001', 'scan_config_id': 'cfg-safe'}


def attribute(ip, hostname):
    """As the worker does for a job: only submitted targets; a host OpenVAS found itself is dropped."""
    return SUBMITTED.get(ip)


def parse():
    with open(FIXTURE, encoding='utf8') as f:
        return worker.openvas_results(f.read(), attribute, CONTEXT)


class GreenboneReport(unittest.TestCase):
    def setUp(self):
        self.findings, self.stats = parse()
        self.by_oid = {f['rule_id']: f for f in self.findings}

    def test_counts_what_was_not_turned_into_a_finding(self):
        self.assertEqual(self.stats, {'results': 8, 'not_findings': 2, 'incomplete': 1, 'unattributed': 1})
        self.assertEqual(len(self.findings), 4)

    def test_current_format_cvss_v31_with_several_cves(self):
        f = self.by_oid['1.3.6.1.4.1.25623.1.0.108031']
        self.assertEqual((f['host'], f['port'], f['protocol'], f['scanner']), ('app.qa-alpha.test', 443, 'tcp', 'openvas'))
        self.assertEqual(f['cve_ids'], ['CVE-2016-2183', 'CVE-2016-6329'])
        self.assertEqual((f['cvss'], f['cvss_version'], f['severity']), (7.5, '3.1', 'high'))
        self.assertEqual(f['cvss_vector'], 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
        self.assertEqual(f['title'], 'SSL/TLS: Report Vulnerable Cipher Suites for HTTPS')
        self.assertIn('TLS_RSA_WITH_3DES_EDE_CBC_SHA', f['description'])
        self.assertTrue(f['remediation'].startswith('Disable the reported vulnerable cipher suites'))
        self.assertEqual(f['references'], ['https://sweet32.info/'])
        ev = f['evidence']
        self.assertEqual((ev['oid'], ev['qod'], ev['result_id'], ev['scanned_ip'], ev['solution_type'], ev['threat']), ('1.3.6.1.4.1.25623.1.0.108031', '98', 'res-0001', '192.0.2.10', 'Mitigation', 'High'))
        self.assertEqual((ev['scan_started_at'], ev['scan_ended_at'], ev['detected_at']), ('2026-10-21T09:00:04Z', '2026-10-21T09:41:37Z', '2026-10-21T09:12:10Z'))
        self.assertEqual((ev['task_id'], ev['report_id'], ev['nvt_family']), ('task-fixture-0001', 'rep-fixture-0001', 'SSL and TLS'))

    def test_critical_from_score(self):
        f = self.by_oid['1.3.6.1.4.1.25623.1.0.104879']
        self.assertEqual((f['port'], f['cvss'], f['cvss_version'], f['severity'], f['cve_ids']), (22, 9.8, '3.1', 'critical', ['CVE-2023-38408']))
        self.assertEqual(f['remediation'], 'Update to version 9.3p2 or later.')

    def test_older_format_cvss_v2_tag_and_comma_cve_list(self):
        f = self.by_oid['1.3.6.1.4.1.25623.1.0.143812']
        self.assertEqual((f['host'], f['port'], f['cvss'], f['cvss_version'], f['cvss_vector'], f['severity']), ('192.0.2.20', 80, 4.3, '2.0', 'AV:N/AC:M/Au:N/C:N/I:P/A:N', 'medium'))
        self.assertEqual(f['cve_ids'], ['CVE-2020-11022', 'CVE-2020-11023'])

    def test_general_icmp_result_has_no_port(self):
        f = self.by_oid['1.3.6.1.4.1.25623.1.0.103190']
        self.assertEqual((f['port'], f['protocol'], f['matched_at'], f['cvss_version'], f['severity']), (None, None, '192.0.2.20:general/icmp', '2.0', 'low'))

    def test_log_false_positive_incomplete_and_unsubmitted_results_are_never_findings(self):
        oids = set(self.by_oid)
        for skipped in ('1.3.6.1.4.1.25623.1.0.105937', '1.3.6.1.4.1.25623.1.0.999999', '1.3.6.1.4.1.25623.1.0.108522'):
            self.assertNotIn(skipped, oids)
        self.assertNotIn('', oids)

    def test_without_attribution_the_reported_host_is_used(self):
        with open(FIXTURE, encoding='utf8') as f:
            all_hosts = {x['host'] for x in worker.parse_openvas_report(f.read())}
        self.assertEqual(all_hosts, {'app.qa-alpha.test', '192.0.2.20', '203.0.113.99'})

    def test_no_value_is_invented(self):
        xml = ('<report><results><result id="r"><host>192.0.2.30</host><port>8443/tcp</port>'
               '<nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>Check without CVSS or CVE</name></nvt><threat>Medium</threat></result></results></report>')
        f = worker.openvas_results(xml)[0][0]
        self.assertEqual((f['cvss'], f['cvss_version'], f['cvss_vector'], f['cve_ids'], f['description'], f['remediation']), (None, None, None, [], None, None))
        self.assertEqual(f['severity'], 'medium', 'no score: the reported threat level, not a guess')
        self.assertNotIn('scan_started_at', f['evidence'])

    def test_empty_report_and_unreadable_report(self):
        self.assertEqual(worker.openvas_results('<get_reports_response status="200"><report id="x"><report><results/></report></report></get_reports_response>'),
                         ([], {'results': 0, 'not_findings': 0, 'incomplete': 0, 'unattributed': 0}))
        with self.assertRaises(ET.ParseError):
            worker.openvas_results('<report><results><result>')

    def test_scanned_hosts_summary(self):
        with open(FIXTURE, encoding='utf8') as f:
            hosts = worker.openvas_hosts(f.read())
        self.assertEqual(sorted(hosts['192.0.2.10']['ports']), ['22/tcp', '443/tcp'])
        self.assertIn('app.qa-alpha.test', hosts['192.0.2.10']['hostnames'])
        self.assertIn('8080/tcp', hosts['192.0.2.20']['ports'])

    def test_backend_ingestion_fixture_matches_this_parser(self):
        with open(BACKEND_FIXTURE, encoding='utf8') as f:
            committed = json.load(f)
        self.assertEqual(committed, self.findings, 'regenerate with: python test_openvas_report.py --write-backend-fixture')


if __name__ == '__main__':
    if '--write-backend-fixture' in sys.argv:
        os.makedirs(os.path.dirname(BACKEND_FIXTURE), exist_ok=True)
        with open(BACKEND_FIXTURE, 'w', encoding='utf8') as out:
            json.dump(parse()[0], out, indent=1)
            out.write('\n')
        print('wrote', os.path.normpath(BACKEND_FIXTURE))
    else:
        unittest.main()
