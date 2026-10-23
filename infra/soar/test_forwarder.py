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
    'SOAR_FORWARD_SETTLE_SECONDS': '60',
    'SOAR_FORWARD_LATE_EVERY': '10',
    'SOAR_FORWARD_LATE_MAX_PAGES': '5',
})
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soar  # noqa: E402

BASE = datetime(2026, 10, 9, 8, 0, 0, tzinfo=timezone.utc)
ms = lambda dt: int(dt.timestamp() * 1000)  # noqa: E731


class Resp:
    def __init__(self, status=200, body=None, text=None):
        self.status_code, self._body = status, body if body is not None else {}
        self.ok = 200 <= status < 300
        self.text = text if text is not None else json.dumps(self._body)

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def alert(n, minute=0, agent='001', at=None, ident=None):
    """A wazuh-alerts hit as the Indexer returns it for soar.SORT: sort = [timestamp ms, id]."""
    dt = at or BASE.replace(minute=minute, second=n % 60)
    ident = ident or f'169.{n}'
    ts = dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}+0000'
    return {'_source': {'id': ident, 'timestamp': ts, 'rule': {'id': '5710', 'level': 10, 'description': 'sshd', 'mitre': {'id': ['T1110']}},
                        'agent': {'id': agent, 'name': 'web-01', 'ip': '10.0.0.5'}, 'location': '/var/log/auth.log'},
            'sort': [ms(dt), ident]}


class Fake:
    """Routes requests.post / requests.get by URL and records every call. `pages` are served in
    order, whatever the query (for tests of the request shape)."""

    def __init__(self, pages, ingest_responses=None):
        self.pages = list(pages)
        self.ingest_responses = list(ingest_responses or [])
        self.searches, self.ingests, self.agent_calls = [], [], 0
        self.verify_flags = []

    def search(self, body):
        return Resp(200, {'_shards': {'total': 1, 'failed': 0}, 'hits': {'hits': self.pages.pop(0) if self.pages else []}})

    def post(self, url, **kw):
        self.verify_flags.append((url, kw.get('verify')))
        if url.endswith('/security/user/authenticate'):
            return Resp(200, {'data': {'token': 'wazuh-jwt'}})
        if url.endswith('/_search'):
            self.searches.append(kw['json'])
            return self.search(kw['json'])
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

    def sent_ids(self):
        return [a['id'] for c in self.ingests for a in c['json']['alerts']]


class FakeIndexer(Fake):
    """A small Indexer: applies the timestamp range, sorts by (timestamp ms, id) and honours
    search_after and size — the semantics the checkpoint relies on."""

    def __init__(self, docs, ingest_responses=None, fail=None):
        super().__init__([], ingest_responses)
        self.docs = list(docs)
        self.fail = list(fail or [])  # per search: None = answer, else a Resp to return instead

    def search(self, body):
        if self.fail:
            f = self.fail.pop(0)
            if f is not None:
                return f
        rng = body['query']['bool']['filter'][0]['range']['timestamp']
        lo = ms(soar.parse_ts(rng['gte']))
        hi = ms(soar.parse_ts(rng['lte'])) if 'lte' in rng else None
        assert body['sort'] == soar.SORT, body['sort']
        rows = sorted((d for d in self.docs if d['sort'][0] >= lo and (hi is None or d['sort'][0] <= hi)), key=lambda d: (d['sort'][0], d['sort'][1]))
        if 'search_after' in body:
            sa = tuple(body['search_after'])
            rows = [d for d in rows if (d['sort'][0], d['sort'][1]) > sa]
        return Resp(200, {'_shards': {'total': 1, 'failed': 0}, 'hits': {'hits': rows[:body['size']]}})


def burst(count, at, prefix='b'):
    """`count` alerts that all carry the same timestamp — the shape of the 2026-10-16 stall."""
    return [alert(0, at=at, ident=f'{prefix}.{i:06d}') for i in range(count)]


class ForwarderTest(unittest.TestCase):
    def setUp(self):
        if os.path.exists(soar.CURSOR_FILE):
            os.remove(soar.CURSOR_FILE)
        self.sleep = mock.patch.object(soar.time, 'sleep').start()
        self.addCleanup(mock.patch.stopall)

    def patch(self, fake):
        mock.patch.object(soar.requests, 'post', side_effect=fake.post).start()
        mock.patch.object(soar.requests, 'get', side_effect=fake.get).start()

    def run_once(self, fake, cycle=1):
        self.patch(fake)
        return soar.forward_once(soar.AgentGroups(), cycle)

    def start_at(self, dt):
        """A version-2 checkpoint just before `dt` (these fixtures are older than the 24 h backfill)."""
        soar.save_checkpoint(soar.Checkpoint(dt - timedelta(seconds=1), [ms(dt - timedelta(seconds=1)), '0']))

    def cursor_file(self):
        with open(soar.CURSOR_FILE, encoding='utf-8') as f:
            return json.load(f)

    # ── Request shape, retries, payload (unchanged behaviour) ────────────────────────────────

    def test_first_run_backfills_and_saves_cursor(self):
        fake = Fake([[alert(1), alert(2)]])
        before = datetime.now(timezone.utc)
        self.assertEqual(self.run_once(fake), 2)
        rng = fake.searches[0]['query']['bool']['filter'][0]['range']['timestamp']
        self.assertAlmostEqual((before - soar.parse_ts(rng['gte'])).total_seconds(), 24 * 3600, delta=60)
        self.assertAlmostEqual((before - soar.parse_ts(rng['lte'])).total_seconds(), 60, delta=5, msg='only settled alerts')
        self.assertEqual(soar.load_cursor(), soar.parse_ts(alert(2)['_source']['timestamp']))
        self.assertEqual(self.cursor_file()['search_after'], alert(2)['sort'])

    def test_version1_cursor_resumes_once_from_cursor_minus_overlap(self):
        cursor = datetime(2026, 10, 9, 7, 0, 0, tzinfo=timezone.utc)
        soar.save_cursor(cursor)
        self.assertNotIn('search_after', self.cursor_file(), 'save_cursor writes a timestamp-only cursor, as before')
        fake = Fake([[alert(3)]])
        self.run_once(fake)
        since = soar.parse_ts(fake.searches[0]['query']['bool']['filter'][0]['range']['timestamp']['gte'])
        self.assertEqual(since, cursor - timedelta(seconds=120))
        self.assertNotIn('search_after', fake.searches[0])
        saved = self.cursor_file()
        self.assertEqual((saved['version'], saved['search_after']), (2, alert(3)['sort']))
        self.assertEqual(soar.parse_ts(saved['last_forwarded_timestamp']), soar.parse_ts(alert(3)['_source']['timestamp']), 'v1 field still written')

    def test_version2_cursor_resumes_strictly_after_its_position(self):
        soar.save_checkpoint(soar.Checkpoint(soar.parse_ts(alert(5)['_source']['timestamp']), alert(5)['sort']))
        fake = Fake([[alert(6)]])
        self.run_once(fake)
        q = fake.searches[0]
        self.assertEqual(q['search_after'], alert(5)['sort'])
        self.assertEqual(soar.parse_ts(q['query']['bool']['filter'][0]['range']['timestamp']['gte']), soar.parse_ts(alert(5)['_source']['timestamp']))

    def test_pages_with_search_after_and_batches_of_at_most_the_cap(self):
        fake = Fake([[alert(1), alert(2), alert(3)], [alert(4), alert(5), alert(6)], [alert(7)]])
        self.assertEqual(self.run_once(fake), 7)
        self.assertNotIn('search_after', fake.searches[0])
        self.assertEqual(fake.searches[1]['search_after'], alert(3)['sort'])
        self.assertEqual(fake.searches[0]['sort'], soar.SORT)
        self.assertTrue(all(len(c['json']['alerts']) <= 3 for c in fake.ingests))

    def test_outage_retries_with_backoff_and_keeps_the_cursor(self):
        soar.save_cursor(datetime(2026, 10, 9, 7, 0, 0, tzinfo=timezone.utc))
        before = self.cursor_file()
        fake = Fake([[alert(1)]], [Resp(503)] * 6)
        self.assertEqual(self.run_once(fake), 0)
        self.assertEqual(len(fake.ingests), 6)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], list(soar.RETRY_DELAYS))
        self.assertEqual(self.cursor_file()['last_forwarded_timestamp'], before['last_forwarded_timestamp'], 'nothing skipped: the next cycle replays from here')

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
        self.patch(fake)
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

    # ── Regression: the 2026-10-16 stall ─────────────────────────────────────────────────────

    def test_burst_larger_than_a_cycle_inside_the_overlap_window_is_fully_forwarded(self):
        # Production, 2026-10-16: a version-1 cursor at T, and at least MAX_PAGES_PER_CYCLE ×
        # FORWARD_BATCH alerts inside [T - overlap, T]. The old loop re-read exactly that window
        # every cycle and never passed T. Here: three cycles' worth all on one timestamp, then more.
        per_cycle = soar.MAX_PAGES_PER_CYCLE * soar.FORWARD_BATCH
        t = BASE + timedelta(minutes=5)
        docs = burst(3 * per_cycle + 7, t) + [alert(i, at=t + timedelta(seconds=i), ident=f'after.{i}') for i in range(1, 5)]
        soar.save_cursor(t)  # the stalled production cursor: timestamp only, at the burst
        fake = FakeIndexer(docs)
        self.patch(fake)
        groups, sent, positions = soar.AgentGroups(), [], []
        for cycle in range(1, 12):
            sent.append(soar.forward_once(groups, cycle))
            positions.append(tuple(self.cursor_file()['search_after']))
            if sent[-1] == 0:
                break
        self.assertEqual(set(fake.sent_ids()), {d['_source']['id'] for d in docs}, 'every alert reached the backend')
        self.assertEqual(len(fake.sent_ids()), len(docs), 'the main pass sends each alert once')
        self.assertEqual(positions, sorted(positions), 'the checkpoint never moves back')
        self.assertEqual(len(set(positions[:-1])), len(positions) - 1, 'and moves on every cycle that sent something')
        self.assertEqual(self.cursor_file()['search_after'], docs[-1]['sort'])
        self.assertEqual(sent[-1], 0, 'caught up: an idle cycle sends nothing')

    def test_restart_mid_burst_resumes_exactly_where_it_stopped(self):
        t = BASE + timedelta(minutes=7)
        docs = burst(40, t)
        self.start_at(t)
        fake = FakeIndexer(docs, ingest_responses=[Resp(200, {'accepted': 3})] * 4 + [Resp(500)] * 6)
        self.assertEqual(self.run_once(fake, cycle=1), 12)  # 4 pages acknowledged, then the backend fails
        self.assertEqual(self.cursor_file()['search_after'], docs[11]['sort'], 'never past the last acknowledged page')
        # A new process: fresh state, reads the checkpoint from disk.
        fake2 = FakeIndexer(docs)
        self.run_once(fake2, cycle=1)
        self.assertEqual(fake2.searches[0]['search_after'], docs[11]['sort'])
        self.assertEqual(fake2.sent_ids(), [d['_source']['id'] for d in docs[12:]], 'nothing skipped, nothing re-sent')

    def test_duplicates_acknowledged_by_the_backend_still_advance_and_do_not_loop(self):
        docs = [alert(i, at=BASE + timedelta(seconds=i), ident=f'd.{i}') for i in range(6)]
        dup = lambda n: Resp(200, {'accepted': 0, 'duplicates': n, 'rejected': 0})  # noqa: E731
        self.start_at(BASE)
        fake = FakeIndexer(docs, ingest_responses=[dup(3), dup(3)])
        self.assertEqual(self.run_once(fake, cycle=1), 6)
        self.assertEqual(self.cursor_file()['search_after'], docs[-1]['sort'])
        again = FakeIndexer(docs)
        self.assertEqual(self.run_once(again, cycle=2), 0)
        self.assertEqual(again.ingests, [], 'no replay outside the bounded late sweep')

    def test_malformed_cursor_files(self):
        os.makedirs(os.path.dirname(soar.CURSOR_FILE), exist_ok=True)
        for content in ['{not json', '[]', json.dumps({'last_forwarded_timestamp': 'yesterday'})]:
            with open(soar.CURSOR_FILE, 'w', encoding='utf-8') as f:
                f.write(content)
            self.assertIsNone(soar.load_checkpoint(), content)
        # A broken search_after falls back to the timestamp it was saved with (version-1 path).
        with open(soar.CURSOR_FILE, 'w', encoding='utf-8') as f:
            json.dump({'last_forwarded_timestamp': '2026-10-09T08:00:05.000+00:00', 'search_after': ['x', 5], 'version': 2}, f)
        cp = soar.load_checkpoint()
        self.assertEqual((cp.ts, cp.sort), (datetime(2026, 10, 9, 8, 0, 5, tzinfo=timezone.utc), None))

    def test_alert_with_malformed_timestamp_text_does_not_stall_or_move_the_checkpoint_wrongly(self):
        bad = alert(2, ident='bad.2')
        bad['_source']['timestamp'] = 'not-a-time'  # what the backend rejects as invalid: timestamp
        fake = Fake([[alert(1), bad, alert(3)]])
        self.assertEqual(self.run_once(fake), 3)
        self.assertEqual(self.cursor_file()['search_after'], alert(3)['sort'], 'the position comes from the Indexer sort, not the text')

    def test_page_without_sort_values_is_not_sent_and_does_not_advance(self):
        soar.save_cursor(BASE)
        before = self.cursor_file()
        page = [alert(1), alert(2)]
        for h in page:
            h.pop('sort')
        fake = Fake([page])
        self.assertEqual(self.run_once(fake), 0)
        self.assertEqual(fake.ingests, [])
        self.assertEqual(self.cursor_file(), before)

    def test_indexer_failures_never_advance(self):
        soar.save_checkpoint(soar.Checkpoint(BASE, [ms(BASE), 'start']))
        before = self.cursor_file()
        docs = [alert(i, at=BASE + timedelta(seconds=i), ident=f'f.{i}') for i in range(1, 4)]
        failures = [
            Resp(500, {'error': 'boom'}),
            Resp(200, {'error': {'type': 'security_exception'}, 'status': 403}),
            Resp(200, {'_shards': {'total': 2, 'failed': 1}, 'hits': {'hits': docs}}),
            Resp(200, ValueError('not json'), text='<html>'),
        ]
        for f in failures:
            fake = FakeIndexer(docs, fail=[f])
            self.assertEqual(self.run_once(fake, cycle=1), 0, f.text)
            self.assertEqual(fake.ingests, [])
            self.assertEqual(self.cursor_file(), before)
        with mock.patch.object(soar.requests, 'post', side_effect=soar.requests.ConnectionError('indexer down')):
            self.assertEqual(soar.forward_once(soar.AgentGroups(), 1), 0)
        self.assertEqual(self.cursor_file(), before)

    def test_unsettled_alerts_wait_for_a_later_cycle(self):
        now = datetime.now(timezone.utc)
        soar.save_checkpoint(soar.Checkpoint(now - timedelta(minutes=10), [ms(now - timedelta(minutes=10)), 'start']))
        docs = [alert(0, at=now - timedelta(minutes=5), ident='settled'), alert(0, at=now - timedelta(seconds=5), ident='fresh')]
        fake = FakeIndexer(docs)
        self.run_once(fake, cycle=1)
        self.assertEqual(fake.sent_ids(), ['settled'])

    # ── Late-indexed alerts ──────────────────────────────────────────────────────────────────

    def test_late_sweep_resends_the_overlap_on_its_cycle_without_moving_the_checkpoint(self):
        docs = [alert(i, at=BASE + timedelta(seconds=i), ident=f'l.{i}') for i in range(1, 5)]
        self.start_at(BASE)
        self.run_once(FakeIndexer(docs), cycle=1)
        position = self.cursor_file()['search_after']
        late = alert(0, at=BASE + timedelta(seconds=2, milliseconds=500), ident='late.1')  # stored after the pass went by
        fake = FakeIndexer(docs + [late])
        self.run_once(fake, cycle=soar.FORWARD_LATE_EVERY)
        self.assertIn('late.1', fake.sent_ids())
        self.assertEqual(self.cursor_file()['search_after'], position, 'the sweep never moves the checkpoint')
        quiet = FakeIndexer(docs + [late])
        self.run_once(quiet, cycle=soar.FORWARD_LATE_EVERY + 1)
        self.assertEqual(quiet.ingests, [], 'between sweeps nothing is re-sent')

    def test_late_sweep_is_bounded_in_a_huge_window(self):
        t = BASE + timedelta(minutes=9)
        docs = burst(500, t)
        soar.save_checkpoint(soar.Checkpoint(t, docs[-1]['sort']))
        fake = FakeIndexer(docs)
        with self.assertLogs('novrsoc-soar', level=logging.WARNING) as logs:
            self.run_once(fake, cycle=soar.FORWARD_LATE_EVERY)
        self.assertEqual(len(fake.ingests), soar.FORWARD_LATE_MAX_PAGES)
        self.assertTrue(any('late sweep stopped' in line for line in logs.output))
        self.assertEqual(self.cursor_file()['search_after'], docs[-1]['sort'])

    def test_late_sweep_failure_does_not_touch_the_checkpoint(self):
        docs = [alert(i, at=BASE + timedelta(seconds=i), ident=f's.{i}') for i in range(1, 3)]
        self.start_at(BASE)
        self.run_once(FakeIndexer(docs), cycle=1)
        position = self.cursor_file()
        fake = FakeIndexer(docs, ingest_responses=[Resp(401)])
        self.run_once(fake, cycle=soar.FORWARD_LATE_EVERY)
        self.assertEqual(self.cursor_file()['search_after'], position['search_after'])


if __name__ == '__main__':
    unittest.main()
