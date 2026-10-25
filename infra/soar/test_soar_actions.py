"""Unit tests for soar.py's containment actions (F-07, 2026 redesign). No network: requests is
mocked. block_ip() and isolate_agent() must never call OPNsense or the Wazuh active-response API
directly any more — they request approval from the backend instead, and only that call is made.

    cd infra/soar && python -m unittest test_soar_actions -v
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp(prefix='novrsoc-soar-actions-test-')
os.environ.update({
    'SOAR_LOG_FILE': os.path.join(TMP, 'soar.log'),
    'NOVRSOC_BACKEND': 'http://backend.test',
    'SOAR_ENGINE_TOKEN': 'unit-test-soar-engine-token-do-not-log',
    'NOVRSOC_ORG_ID': 'org-a',
    # Deliberately set, to prove they are no longer read by block_ip/isolate_agent: any call to
    # OPNsense or the Wazuh active-response API in this test is a bug, not a skip.
    'OPNSENSE_URL': 'https://opnsense.test',
    'OPNSENSE_KEY': 'k',
    'OPNSENSE_SECRET': 's',
    'WAZUH_API_URL': 'https://wazuh.test:55000',
    'WAZUH_PASSWORD': 'x',
    'WAZUH_ISOLATE_COMMAND': 'isolate-host',
})
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soar  # noqa: E402


class Resp:
    def __init__(self, status=200, body=None, text=None):
        self.status_code, self._body = status, body if body is not None else {}
        self.ok = 200 <= status < 300
        self.text = text if text is not None else '{}'

    def json(self):
        return self._body


def case(**overrides):
    base = {'id': 'case-1', 'source_ip': '185.220.101.47', 'agent_id': '003', 'agent_name': 'web-01', 'mitre_technique': 'T1486.002'}
    base.update(overrides)
    return base


class ContainmentTest(unittest.TestCase):
    def setUp(self):
        self.posts = []
        self.patcher = mock.patch.object(soar.requests, 'post', side_effect=self._post)
        self.patcher.start()
        # No code path under test should ever reach PUT (the old active-response call).
        self.put_patcher = mock.patch.object(soar.requests, 'put', side_effect=AssertionError('PUT must never be called — isolation runs on the backend, not here'))
        self.put_patcher.start()
        self.response = Resp(201, {'approval_id': 'appr-1', 'status': 'pending', 'existing': False})

    def tearDown(self):
        self.patcher.stop()
        self.put_patcher.stop()

    def _post(self, url, **kw):
        self.posts.append((url, kw))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def test_block_ip_requests_approval_instead_of_calling_opnsense(self):
        ok = soar.block_ip(case(), 3)
        self.assertTrue(ok)
        self.assertEqual(len(self.posts), 1)
        url, kw = self.posts[0]
        self.assertEqual(url, 'http://backend.test/api/soar/response-requests')
        self.assertEqual(kw['headers'], {'X-NovrSOC-SOAR-Token': 'unit-test-soar-engine-token-do-not-log'})
        body = kw['json']
        self.assertEqual(body['action'], 'block_ip')
        self.assertEqual(body['target'], '185.220.101.47')
        self.assertIsNone(body['target_label'])
        self.assertEqual(body['case_id'], 'case-1')
        self.assertEqual(body['org_id'], 'org-a')
        self.assertIn('Tier 3', body['reason'])
        # Never OPNsense, whatever OPNSENSE_* holds.
        self.assertFalse(any('opnsense' in u.lower() for u, _ in self.posts))

    def test_block_ip_skips_internal_and_missing_ip_without_any_call(self):
        self.assertFalse(soar.block_ip(case(source_ip='10.0.0.5'), 3))
        self.assertFalse(soar.block_ip(case(source_ip=''), 3))
        self.assertEqual(self.posts, [])

    def test_block_ip_skipped_when_soar_token_unset__no_call_at_all(self):
        with mock.patch.object(soar, 'SOAR_TOKEN', ''):
            ok = soar.block_ip(case(), 2)
        self.assertFalse(ok)
        self.assertEqual(self.posts, [], 'SOAR_ENGINE_TOKEN unset must not fall back to any direct action')

    def test_isolate_agent_requests_approval_instead_of_calling_wazuh_active_response(self):
        ok = soar.isolate_agent(case(), 3)
        self.assertTrue(ok)
        self.assertEqual(len(self.posts), 1)
        url, kw = self.posts[0]
        self.assertEqual(url, 'http://backend.test/api/soar/response-requests')
        body = kw['json']
        self.assertEqual(body['action'], 'isolate_agent')
        self.assertEqual(body['target'], '003')
        self.assertEqual(body['target_label'], 'web-01')
        self.assertFalse(any('active-response' in u for u, _ in self.posts))

    def test_isolate_agent_still_requires_an_allow_listed_technique(self):
        self.assertFalse(soar.isolate_agent(case(mitre_technique='T1059.001'), 3), 'not an isolation technique')
        self.assertFalse(soar.isolate_agent(case(agent_id=''), 3), 'no agent')
        self.assertFalse(soar.isolate_agent(case(agent_id='000'), 3), 'the manager itself')
        self.assertEqual(self.posts, [])

    def test_a_200_with_existing_true_is_logged_as_already_pending_not_a_new_request(self):
        self.response = Resp(200, {'approval_id': 'appr-1', 'status': 'pending', 'existing': True})
        ok = soar.block_ip(case(), 2)
        self.assertTrue(ok)

    def test_backend_refusal_is_reported_and_not_treated_as_success(self):
        self.response = Resp(400, {'error': 'target is required'}, text='{"error":"target is required"}')
        self.assertFalse(soar.block_ip(case(), 2))

    def test_network_error_talking_to_the_backend_is_reported_and_not_treated_as_success(self):
        self.response = soar.requests.RequestException('connection refused')
        self.assertFalse(soar.block_ip(case(), 2))

    def test_process_alert_tier3_never_touches_opnsense_or_wazuh_active_response_even_end_to_end(self):
        """process_alert() calls enrich_iocs, block_ip and isolate_agent in sequence for tier 3;
        none of them may reach OPNsense or PUT /active-response, whatever is configured."""
        with mock.patch.object(soar, 'find_case', return_value=None), \
             mock.patch.object(soar, 'create_case', return_value=case(id='case-2')), \
             mock.patch.object(soar, 'enrich_iocs'), \
             mock.patch.object(soar, 'notify_ciso'), \
             mock.patch.object(soar, 'notify_email'), \
             mock.patch.object(soar, 'add_soar_log'):
            soar.process_alert({'rule': {'level': 15, 'description': 'x', 'mitre': {'id': ['T1486.002']}}, 'agent': {'id': '003', 'name': 'web-01'}, 'data': {'srcip': '185.220.101.47'}})
        self.assertEqual(len(self.posts), 2, 'one request each for block_ip and isolate_agent')
        actions = {kw['json']['action'] for _, kw in self.posts}
        self.assertEqual(actions, {'block_ip', 'isolate_agent'})


if __name__ == '__main__':
    unittest.main()
