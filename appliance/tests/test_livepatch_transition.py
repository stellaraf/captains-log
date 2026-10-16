"""Kernel transition refusal behavior; fixtures do not load native modules."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from nebulalog_manager import livepatch as lp
from nebulalog_manager.common import Refused

KERNEL = '5.14.0-687.56.1.el9_8.x86_64'
MODULE = 'livepatch_qualification'


class TransitionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.files = {
            'proc/sys/kernel/osrelease': KERNEL,
            'proc/sys/kernel/random/boot_id': '11111111-2222-4333-8444-555555555555',
            'sys/module/module/parameters/sig_enforce': 'Y',
            f'sys/module/{MODULE}/initstate': 'live',
            f'sys/kernel/livepatch/{MODULE}/enabled': '1',
            f'sys/kernel/livepatch/{MODULE}/transition': '1',
        }
        for name, value in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value+'\n')
        self.elapsed = 0
        self.action = lambda: None
        guard = patch.object(lp, 'require_linux_root')
        guard.start()
        self.addCleanup(guard.stop)

    def write(self, name, value):
        (self.root / name).write_text(value+'\n')

    def sleep(self, value):
        self.elapsed += value
        self.action()

    def observe(self):
        return lp.wait_for_transition(MODULE, KERNEL, root=self.root, timeout=1,
                                      monotonic=lambda: self.elapsed, sleep=self.sleep)

    def test_waits_for_two_complete_reads_without_claiming_health(self):
        self.action = lambda: self.write(f'sys/kernel/livepatch/{MODULE}/transition', '0')
        result = self.observe()
        self.assertEqual(self.elapsed, 0.5)
        self.assertEqual(result['state'], 'transition_complete')
        self.assertFalse(result['services_verified'])
        self.assertFalse(result['fips_postcheck_verified'])

    def test_stuck_transition_is_bounded_and_never_changes_files(self):
        before = {p: (self.root / p).read_bytes() for p in self.files}
        with self.assertRaisesRegex(Refused, 'timed out'):
            self.observe()
        self.assertEqual(self.elapsed, 1)
        self.assertEqual(before, {p: (self.root / p).read_bytes() for p in self.files})

    def test_one_complete_read_followed_by_transition_does_not_pass(self):
        self.write(f'sys/kernel/livepatch/{MODULE}/transition', '0')
        self.action = lambda: self.write(f'sys/kernel/livepatch/{MODULE}/transition', '1')
        with self.assertRaisesRegex(Refused, 'timed out'):
            self.observe()

    def test_reboot_during_observation_refused(self):
        self.action = lambda: self.write('proc/sys/kernel/random/boot_id', 'aaaaaaaa-2222-4333-8444-555555555555')
        with self.assertRaisesRegex(Refused, 'identity changed'):
            self.observe()

    def test_missing_reversed_unenforced_and_malformed_observations_refused(self):
        changes = [('sys/module/module/parameters/sig_enforce', 'N'),
                   ('proc/sys/kernel/osrelease', KERNEL+'wrong'),
                   (f'sys/module/{MODULE}/initstate', 'going'),
                   (f'sys/kernel/livepatch/{MODULE}/enabled', '0'),
                   (f'sys/kernel/livepatch/{MODULE}/transition', 'garbage')]
        for name, value in changes:
            with self.subTest(name=name):
                self.write(name, value)
                with self.assertRaises(Refused): self.observe()
                self.write(name, self.files[name])
        (self.root / f'sys/kernel/livepatch/{MODULE}/transition').unlink()
        with self.assertRaises(Refused): self.observe()

    def test_symlink_attribute_and_module_path_refused(self):
        target = self.root / f'sys/kernel/livepatch/{MODULE}/transition'
        target.unlink()
        target.symlink_to(self.root / f'sys/kernel/livepatch/{MODULE}/enabled')
        with self.assertRaises(Refused): self.observe()
        with self.assertRaises(Refused): lp.wait_for_transition('../escape', KERNEL, root=self.root)
