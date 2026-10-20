"""Poll orchestration; signing and native transition have separate coverage."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from nebulalog_manager import livepatch as lp
from nebulalog_manager.common import Refused


class PollTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.target = dict(kernel_release='5.14.0-687.56.1.el9_8.x86_64',
                           kernel_image_sha256='a'*64, kernel_config_sha256='b'*64, boot_id='boot')
        self.events = []
        self.observation = dict(state='committed_patch_observed', sequence=2, manifest_sha256='c'*64, active_observed=True)
        self.candidate = dict(state='not_newer', manifest={'sequence':2}, manifest_sha256='c'*64)
        for name, kwargs in (
                ('require_linux_root', {}), ('_tree', {}),
                ('measure_target', {'return_value':self.target}),
                ('status', {'side_effect':self.observe}),
                ('fetch_candidate', {'side_effect':self.fetch}),
                ('apply_bundle', {'side_effect':self.apply})):
            guard = patch.object(lp, name, **kwargs)
            setattr(self, name, guard.start())
            self.addCleanup(guard.stop)

    def observe(self, *args, **kwargs):
        self.events.append('observe')
        return dict(self.observation)

    def fetch(self, *args, **kwargs):
        self.events.append('fetch')
        return self.candidate

    def apply(self, *args, **kwargs):
        self.events.append('reapply' if kwargs.get('reapply') else 'apply')
        self.observation['state'] = 'committed_patch_observed'
        self.observation['active_observed'] = True

    def poll(self):
        return lp.poll(object(), self.state, self.state/'publisher.pem', 'stellaraf/captains-log')

    def test_unchanged_feed_requires_fresh_readback_without_reloading(self):
        result = self.poll()
        self.assertEqual(self.events, ['observe', 'fetch', 'observe'])
        self.apply_bundle.assert_not_called()
        self.assertTrue(result['observation']['active_observed'])

    def test_reboot_reapplication_precedes_network_failure(self):
        self.observation['state'] = 'reapplication_required'
        self.fetch_candidate.side_effect = OSError('network')
        with self.assertRaises(OSError): self.poll()
        self.assertEqual(self.events, ['observe', 'reapply', 'observe'])
        self.apply_bundle.assert_called_once()
        self.assertTrue(self.apply_bundle.call_args.kwargs['reapply'])
        record = json.loads((self.state/'livepatch-poll.json').read_text())
        self.assertEqual(record['state'], 'failed')
        self.assertTrue(record['active_status_requires_readback'])

    def test_missing_feed_does_not_claim_patch_active(self):
        self.observation = {'state':'no_committed_patch', 'active_observed':False}
        self.candidate = {'state':'no_published_patch'}
        result = self.poll()
        self.assertFalse(result['observation']['active_observed'])
        self.apply_bundle.assert_not_called()
        self.assertEqual(self.fetch_candidate.call_args.kwargs['current_sequence'], 0)

    def test_conflicting_or_rolled_back_feed_refused(self):
        for candidate in ({'state':'not_newer','manifest':{'sequence':1},'manifest_sha256':'c'*64},
                          {'state':'not_newer','manifest':{'sequence':2},'manifest_sha256':'d'*64}):
            self.candidate = candidate
            with self.assertRaisesRegex(Refused, 'rolls back or conflicts'): self.poll()
        self.apply_bundle.assert_not_called()

    def test_new_candidate_uses_guarded_apply_then_readback(self):
        self.candidate = {'state':'authenticated_candidate', 'downloaded_bundle':str(self.state/'download')}
        self.poll()
        self.assertEqual(self.events, ['observe','fetch','apply','observe'])
        self.assertEqual(self.apply_bundle.call_args.args[0], self.state/'download')

    def test_interrupted_transaction_prevents_network_and_load(self):
        self.status.side_effect = Refused('recovery required')
        with self.assertRaises(Refused): self.poll()
        self.fetch_candidate.assert_not_called()
        self.apply_bundle.assert_not_called()

    def test_configured_policy_controls_all_network_and_mutations(self):
        from nebulalog_manager import github_updates as gh
        with patch.object(gh, 'load_policy', return_value=({'repository':'stellaraf/captains-log'}, None)), patch.object(gh, 'GitHubTransport') as transport, patch.object(lp, 'poll') as poll:
            self.assertEqual(lp.poll_configured(self.state)['state'], 'disabled')
            transport.assert_not_called()
            poll.assert_not_called()
        with patch.object(gh, 'load_policy', return_value=({'repository':'stellaraf/captains-log','automatic_livepatch':True}, 'private-token')), patch.object(gh, 'GitHubTransport') as transport, patch.object(lp, 'poll', return_value={'state':'checked'}) as poll:
            self.assertEqual(lp.poll_configured(self.state)['state'], 'checked')
            transport.assert_called_once_with('private-token')
            poll.assert_called_once_with(transport.return_value, self.state, gh.PUBLIC_KEY, 'stellaraf/captains-log')

    def test_vendor_factory_policy_does_not_fetch_or_load_self_built_patches(self):
        from nebulalog_manager import github_updates as gh
        policy = json.loads((Path(__file__).resolve().parents[1] / 'security/github-updates.json').read_text())
        self.assertTrue(policy['automatic_updates'])
        self.assertEqual(policy['poll_interval_seconds'], 900)
        with patch.object(gh, 'load_policy', return_value=(policy, None)), \
                patch.object(gh, 'GitHubTransport') as transport, \
                patch.object(lp, 'poll') as poll:
            self.assertEqual(lp.poll_configured(self.state)['state'], 'disabled')
            transport.assert_not_called()
            poll.assert_not_called()
