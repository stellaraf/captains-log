"""Schema-2 rejected-kernel recovery through the actual AIDE chain.

Signed RPM provenance, native host measurements and the scanner process are
injected by the existing private fixtures. The scanner uses actual pinned AIDE
database bytes, including the eighteen qualified metadata targets and measured
private payload paths. Boot/rollback plans, typed ancestry, immutable
preparation, report parsing, database CAS and completion remain production code.
These tests do not establish native RPM, GRUB or FIPS acceptance.
"""
import unittest

import test_boot_metadata_aide as metadata
import test_kernel_rollback as recovery


class RollbackMetadataAideTests(unittest.TestCase):
    for _name, _method in recovery.RollbackAideTests.__dict__.items():
        if callable(_method) and not _name.startswith('test_') and _name != 'setUp':
            locals()[_name] = _method

    # Upgrade the shared enrollment and scanner before the real rollback
    # fixture constructs any arm/recovery preparation or accepted chain entry.
    for _name in ('enrolled', 'current_database', 'scanner_rows', 'scan_runner',
                  'summary', 'refresh_native', 'metadata_reboot', 'new_boot',
                  'next_candidate_boot'):
        locals()[_name] = metadata.KernelMetadataAideTests.__dict__[_name]

    def setUp(self):
        recovery.RollbackAideTests.setUp(self)
        self.assertEqual(self.initial_snapshot['schema'], 2)

    def later_boot(self, identity='cccccccc-cccc-cccc-cccc-cccccccccccc'):
        recovery.RollbackAideTests.later_boot(self, identity)
        self.metadata_reboot()

    for _name in (
            'test_successful_exact_rollback_keeps_old_default_and_original_enrollment',
            'test_reboot_after_exact_erase_uses_compound_aide_without_rpm',
            'test_crossboot_scanning_interruption_recovers',
            'test_crossboot_ready_input_interruption_recovers',
            'test_crossboot_ready_output_interruption_recovers',
            'test_second_boot_before_compound_prepare_preserves_ancestry',
            'test_wrong_prepared_digest_cannot_accept_even_exact_erasure',
            'test_unrelated_drift_prevents_rpm_and_baseline_change',
            'test_reboot_after_completion_retains_first_completion_and_accepts_new_boot'):
        locals()[_name] = recovery.RollbackAideTests.__dict__[_name]


if __name__ == '__main__':
    unittest.main()
