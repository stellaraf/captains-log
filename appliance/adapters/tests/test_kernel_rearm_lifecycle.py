"""Real rearm/AIDE chain through the lifecycle, with native services injected."""
import json
from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import Mock, patch

import test_kernel_rearm_aide as fixture
from nebulalog_adapters.lifecycle import Lifecycle
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.updates import REQUIRED_CHECKS


class RearmLifecycleTests(TestCase):
    for _name, _method in fixture.RearmAideTests.__dict__.items():
        if callable(_method) and not _name.startswith('test_'):
            locals()[_name] = _method

    def adapter(self):
        self.canceled()
        self.events = []
        def command(argv, **kwargs):
            if argv[0] == 'sync':
                self.events.append('sync'); return ''
            return self.runner(argv, **kwargs)
        adapter = Lifecycle({}, command, state=self.root / 'manager/updates', data=self.root, guard=lambda: None)
        adapter.encrypted = Mock()
        adapter.boot_id = lambda: self.boot_id
        adapter.checked_backup = Mock()
        adapter.unlock_readiness = Mock(return_value={'token_test': True})
        adapter.maintenance = Mock()
        adapter.storage_maintenance = Mock(side_effect=lambda owner, **flags: self.events.append(('storage', flags)))
        adapter.service = Mock(side_effect=lambda action, units: self.events.append(action))
        adapter.health = Mock(side_effect=lambda *a, **k: self.events.append('health') or {'ok': True, 'checks': {name: True for name in REQUIRED_CHECKS}})
        adapter._kernel_candidate = lambda stage: fixture.boot.kernel.load_candidate(stage)
        self.publish_preparing()
        return adapter

    def publish_preparing(self):
        path = self.root / 'manager/os-transaction.json'
        value = json.loads(path.read_text())
        atomic_json(path, {**value, 'state': 'reboot_preparing', 'reboot_pending': True, 'storage_maintenance': 'held',
                          'health': {name: True for name in REQUIRED_CHECKS}})
        atomic_json(self.root / 'manager/os-latest.json', {'stage': str(self.stage), 'state': 'postcheck_passed',
            'boot_id': self.boot_id, 'observed_at': datetime.now(timezone.utc).isoformat()})

    def test_rearm_health_precedes_delivery_fence_and_service_stop_then_abort_retains_owner(self):
        adapter = self.adapter()
        with patch('nebulalog_adapters.lifecycle.local_auth'):
            adapter.reboot_prepare()
        self.assertEqual(fixture.boot._current(self.stage)[1]['phase'], 'rearm')
        fence = ('storage', {'held': True, 'delivery_held': True})
        self.assertLess(self.events.index('health'), self.events.index(fence))
        self.assertLess(self.events.index(fence), self.events.index('stop'))
        journal = self.root / 'manager/os-transaction.json'
        atomic_json(journal, {**json.loads(journal.read_text()), 'state': 'reboot_requested'})
        adapter.reboot_abort()
        self.assertEqual(fixture.boot._current(self.stage)[1]['phase'], 'abort')
        self.assertEqual(json.loads(journal.read_text())['storage_maintenance'], 'held')
        self.assertEqual(json.loads(journal.read_text())['stage'], str(self.stage))
        self.publish_preparing()
        with patch('nebulalog_adapters.lifecycle.local_auth'):
            adapter.reboot_prepare()
        self.assertEqual(fixture.boot._current(self.stage)[1]['phase'], 'rearm')

    def test_rearm_health_failure_never_stops_or_fences_delivery(self):
        adapter = self.adapter()
        before = self.env.read_bytes()
        adapter.health.return_value = {'ok': False, 'checks': {}}
        adapter.health.side_effect = None
        with patch('nebulalog_adapters.lifecycle.local_auth'), self.assertRaises(Refused):
            adapter.reboot_prepare()
        self.assertEqual(self.env.read_bytes(), before)
        self.assertNotIn('stop', self.events)
        adapter.storage_maintenance.assert_not_called()
