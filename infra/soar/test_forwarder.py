"""Unit tests for soar.py's alert forwarder (--forward). No network: requests is mocked.

    cd infra/soar && python -m unittest test_forwarder -v
"""
import json
import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

TMP = tempfile.mkdtemp(prefix='novrsoc-forwarder-test-')
TOKEN = 'unit-test-ingest-token-do-not-log'
os.environ.update({
    'SOAR_LOG_FILE': os.path.join(TMP, 'soar.log'),
    'SOAR_CURSOR_FILE': os.path.join(TMP, 'state', 'ingest_cursor.json'),
    'ALERT_INGEST_TOKEN': TOKEN,
    'NOVRSOC_BACKEND': 'http://backend.test',
    'WAZUH_API_URL': 'https://wazuh.test:55000',
    'WAZUH_PASSWORD': 'x',
    'WAZUH_INDEXER_URL': 'https://indexer.test:9200',
    'WAZUH_INDEXER_USER': 'u',
    'WAZUH_INDEXER_PASSWORD': 'p',
    'WAZUH_VERIFY_TLS': 'true',
    'SOAR_BACKFILL_HOURS': '24',
    'SOAR_FORWARD_BATCH': '3',
    'SOAR_FORWARD_OVERLAP_SECONDS': '120',
})
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soar  # noqa: E402


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body if body is not None else {}
        self.ok = 200 <= status < 300
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


def alert(n, minute=0, agent='001'):
    ts = datetime(2026, 10, 9, 8, minute, n, tzinfo=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000+0000')
    return {'_source': {'id': f'169.{n}', 'timestamp': ts, 'rule': {'id': '5710', 'level': 10, 'description': 'sshd', 'mitre': {'id': ['T1110']}},
                        'agent': {'id': agent, 'name': 'web-01', 'ip': '10.0.0.5'}, 'location': '/var/log/auth.log'},
            'sort': [n, f'169.{n}']}


class Fake:
    """Routes requests.post / requests.get by URL and records every call."""

    def __init__(self, pages, ingest_responses=None):
        self.pages = list(pages)
        self.ingest_responses = list(ingest_responses or [])
        self.searches, self.ingests, self.agent_calls = [], [], 0
        self.verify_flags = []

    def post(self, url, **kw):
        self.verify_flags.append((url, kw.get('verify')))
        if url.endswith('/security/user/authenticate'):
            return Resp(200, {'data': {'token': 'wazuh-jwt'}})
        if url.endswith('/_search'):
            self.searches.append(kw['json'])
            return Resp(200, {'hits': {'hits': self.pages.pop(0) if self.pages else []}})
        if url == 'http://backend.test/api/ingest/alerts':
            self.ingests.append(kw)
            r = self.ingest_responses.pop(0) if self.ingest_responses else Resp(200, {'accepted': len(kw['json']['alerts']), 'duplicates': 0, 'rejected': 0})
            if isinstance(r, Exception):
                raise r
            return r
        raise AssertionError(f'unexpected POST {url}')

    def get(self, url, **kw):
        self.verify_flags.append((url, kw.get('verify')))
        assert url == 'https://wazuh.test:55000/agents', url
        self.agent_calls += 1
        return Resp(200, {'data': {'affected_items': [{'id': '001', 'group': ['acme-servers']}, {'id': '002', 'group': ['beta']}], 'total_affected_items': 2}})


class ForwarderTest(unittest.TestCase):
    def setUp(self):
        if os.path.exists(soar.CURSOR_FILE):
            os.remove(soar.CURSOR_FILE)
        self.sleep = mock.patch.object(soar.time, 'sleep').start()
        self.addCleanup(mock.patch.stopall)

    def run_once(self, fake):
        mock.patch.object(soar.requests, 'post', side_effect=fake.post).start()
        mock.patch.object(soar.requests, 'get', side_effect=fake.get).start()
        return soar.forward_once(soar.AgentGroups())

    def test_first_run_backfills_and_saves_cursor(self):
        fake = Fake([[alert(1), alert(2)]])
        before = datetime.now(timezone.utc)
        self.assertEqual(self.run_once(fake), 2)
        since = soar.parse_ts(fake.searches[0]['query']['bool']['filter'][0]['range']['timestamp']['gte'])
        self.assertAlmostEqual((before - since).total_seconds(), 24 * 3600, delta=60)
        self.assertEqual(soar.load_cursor(), soar.parse_ts(alert(2)['_source']['timestamp']))

    def test_resumes_from_cursor_minus_overlap(self):
        cursor = datetime(2026, 10, 9, 7, 0, 0, tzinfo=timezone.utc)
        soar.save_cursor(cursor)
        fake = Fake([[alert(3)]])
        self.run_once(fake)
        since = soar.parse_ts(fake.searches[0]['query']['bool']['filter'][0]['range']['timestamp']['gte'])
        self.assertEqual(since, cursor - timedelta(seconds=120))
        self.assertEqual(soar.load_cursor(), soar.parse_ts(alert(3)['_source']['timestamp']))

    def test_pages_with_search_after_and_batches_of_at_most_the_cap(self):
        fake = Fake([[alert(1), alert(2), alert(3)], [alert(4), alert(5), alert(6)], [alert(7)]])
        self.assertEqual(self.run_once(fake), 7)
        self.assertNotIn('search_after', fake.searches[0])
        self.assertEqual(fake.searches[1]['search_after'], [3, '169.3'])
        self.assertTrue(all(len(c['json']['alerts']) <= 3 for c in fake.ingests))

    def test_outage_retries_with_backoff_and_keeps_the_cursor(self):
        soar.save_cursor(datetime(2026, 10, 9, 7, 0, 0, tzinfo=timezone.utc))
        before = soar.load_cursor()
        fake = Fake([[alert(1)]], [Resp(503)] * 6)
        self.assertEqual(self.run_once(fake), 0)
        self.assertEqual(len(fake.ingests), 6)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], list(soar.RETRY_DELAYS))
        self.assertEqual(soar.load_cursor(), before, 'nothing skipped: the next cycle replays from here')

    def test_recovers_after_transient_errors(self):
        fake = Fake([[alert(1)]], [soar.requests.ConnectionError('down'), Resp(502), Resp(200, {'accepted': 1, 'duplicates': 0, 'rejected': 0})])
        self.assertEqual(self.run_once(fake), 1)
        self.assertEqual(len(fake.ingests), 3)
        self.assertIsNotNone(soar.load_cursor())

    def test_refused_batch_is_not_retried_and_does_not_advance(self):
        fake = Fake([[alert(1)]], [Resp(401, {'error': 'Invalid or missing ingest token'})])
        self.assertEqual(self.run_once(fake), 0)
        self.assertEqual(len(fake.ingests), 1)
        self.assertIsNone(soar.load_cursor())

    def test_payload_carries_groups_and_never_org_severity_or_status(self):
        fake = Fake([[alert(1, agent='001'), alert(2, agent='999')]])
        self.run_once(fake)
        sent = fake.ingests[0]['json']['alerts']
        self.assertEqual(sent[0]['agent_groups'], ['acme-servers'])
        self.assertEqual(sent[1]['agent_groups'], [], 'unknown agent: the backend rejects it as unmapped')
        for a in sent:
            self.assertFalse({'org_id', 'org', 'severity', 'status'} & set(a), a.keys())
            self.assertEqual(a['rule']['level'], 10)
            self.assertIn('raw', a)
        self.assertEqual(fake.ingests[0]['headers']['Authorization'], f'Bearer {TOKEN}')

    def test_agent_groups_cached_for_five_minutes(self):
        fake = Fake([])
        mock.patch.object(soar.requests, 'post', side_effect=fake.post).start()
        mock.patch.object(soar.requests, 'get', side_effect=fake.get).start()
        clock = mock.patch.object(soar.time, 'monotonic', return_value=1000.0).start()
        g = soar.AgentGroups()
        g.get('001'); g.get('002')
        self.assertEqual(fake.agent_calls, 1)
        clock.return_value = 1000.0 + soar.GROUP_CACHE_SECONDS + 1
        g.get('001')
        self.assertEqual(fake.agent_calls, 2)

    def test_tls_verification_follows_wazuh_verify_tls(self):
        fake = Fake([[alert(1)]])
        self.run_once(fake)
        wazuh_calls = [v for u, v in fake.verify_flags if 'wazuh.test' in u or 'indexer.test' in u]
        self.assertTrue(wazuh_calls and all(v is True for v in wazuh_calls))

    def test_token_is_never_logged(self):
        with self.assertLogs('novrsoc-soar', level=logging.DEBUG) as logs:
            self.run_once(Fake([[alert(1)]], [Resp(503), Resp(401)]))
            self.run_once(Fake([[alert(2)]]))
            soar.log.info('marker')
        self.assertFalse(any(TOKEN in line for line in logs.output))

    def test_parse_ts_handles_wazuh_offsets(self):
        self.assertEqual(soar.parse_ts('2026-10-09T08:00:01.123+0000'), datetime(2026, 10, 9, 8, 0, 1, 123000, tzinfo=timezone.utc))
        self.assertEqual(soar.parse_ts('2026-10-09T09:00:00+0100'), datetime(2026, 10, 9, 8, 0, 0, tzinfo=timezone.utc))
        self.assertIsNone(soar.parse_ts('yesterday'))


if __name__ == '__main__':
    unittest.main()
