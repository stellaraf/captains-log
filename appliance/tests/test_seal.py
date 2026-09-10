"""Execute only the sealer's seed-cleanup fragment with shell command doubles."""
from pathlib import Path
import subprocess
import tempfile
import unittest


SEALER = Path(__file__).resolve().parents[1] / "bin/nebulalog-seal"


class RandomSeedSealingTests(unittest.TestCase):
    def fragment(self):
        source = SEALER.read_text()
        start = source.index("systemctl stop systemd-random-seed.service\n")
        end = source.index("\ntruncate -s 0 /etc/machine-id", start)
        self.assertLess(start, source.index("rm -f /etc/ssh/ssh_host_* /var/lib/systemd/random-seed"))
        self.assertLess(end, source.index("dracut --force --no-hostonly"))
        self.assertLess(end, source.index("printf 'sealed\\n'"))
        self.assertFalse(any("random-seed" in line and ("disable" in line or "mask" in line or "--no-block" in line)
                             for line in source.splitlines() if not line.lstrip().startswith("#")))
        return source[start:end]

    def run_fragment(self, mode):
        # PATH is empty, glob expansion is disabled, and both commands used by
        # this isolated source fragment are functions. No host unit/file runs.
        harness = r'''
set -euf -o pipefail
PATH=''
seed=original
state=active
trap 'printf "seed=%s\nstate=%s\n" "$seed" "$state"' EXIT
systemctl() {
  case "$*" in
    'stop systemd-random-seed.service')
      printf 'stop\n' >&2
      if [ "$TEST_MODE" = stop-failure ]; then return 42; fi
      seed=saved-by-ExecStop
      state=inactive
      if [ "$TEST_MODE" = still-active ]; then state=active; fi
      ;;
    'show --property=ActiveState --value systemd-random-seed.service')
      printf 'state\n' >&2
      if [ "$TEST_MODE" = query-failure ]; then return 43; fi
      printf '%s\n' "$state"
      ;;
    *) return 44 ;;
  esac
}
rm() {
  [ "$*" = '-f /etc/ssh/ssh_host_* /var/lib/systemd/random-seed' ]
  printf 'delete\n' >&2
  seed=absent
}
'''
        result = subprocess.run(["/bin/bash", "-c", harness + "\n" + self.fragment()],
                                env={"TEST_MODE": mode}, text=True, capture_output=True, timeout=5)
        return result

    def test_execstop_finishes_before_seed_removal(self):
        result = self.run_fragment("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.splitlines(), ["stop", "state", "delete"])
        self.assertEqual(result.stdout, "seed=absent\nstate=inactive\n")

    def test_stop_failure_or_unconfirmed_inactive_refuses_removal(self):
        for mode in ("stop-failure", "still-active", "query-failure"):
            with self.subTest(mode=mode):
                result = self.run_fragment(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("delete", result.stderr.splitlines())
                self.assertNotIn("seed=absent", result.stdout)

    def test_full_sealer_shell_syntax(self):
        result = subprocess.run(["/bin/bash", "-n", str(SEALER)], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


class MachineIDDirectorySealingTests(unittest.TestCase):
    def run_fragment(self, root):
        source = SEALER.read_text()
        start = source.index("[ ! -L /var/lib/dbus ]")
        end = source.index("\nrm -rf /tmp/nebulalog-appliance", start)
        fragment = source[start:end]
        self.assertIn("install -d -o root -g root -m 0755 /var/lib/dbus", fragment)
        # Execute the real filesystem operations only inside the fixture. The
        # owner/group flags are omitted because this test does not require root.
        fragment = fragment.replace("-o root -g root ", "")
        fragment = fragment.replace("/var/lib/dbus", str(root / "var/lib/dbus"))
        fragment = fragment.replace("/etc/machine-id", str(root / "etc/machine-id"))
        return subprocess.run(["/bin/bash", "-euc", fragment], capture_output=True, text=True, timeout=5)

    def test_absent_or_existing_directory_gets_machine_id_link(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "etc").mkdir()
                (root / "etc/machine-id").write_text("")
                (root / "var/lib").mkdir(parents=True)
                dbus = root / "var/lib/dbus"
                if existing:
                    dbus.mkdir()
                    (dbus / "machine-id").write_text("old-build-identity")
                result = self.run_fragment(root)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(dbus.stat().st_mode & 0o777, 0o755)
                self.assertEqual((dbus / "machine-id").readlink(), root / "etc/machine-id")
                self.assertEqual((dbus / "machine-id").read_text(), "")

    def test_linked_directory_is_refused_before_foreign_file_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "var/lib").mkdir(parents=True)
            foreign = root / "foreign"
            foreign.mkdir()
            (foreign / "machine-id").write_text("preserve")
            (root / "var/lib/dbus").symlink_to(foreign)
            result = self.run_fragment(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((foreign / "machine-id").read_text(), "preserve")


class KdumpSealingTests(unittest.TestCase):
    def run_fragment(self, mode):
        source = SEALER.read_text()
        start = source.index("systemctl disable --now kdump.service\n")
        end = source.index("systemctl disable sshd\n", start)
        self.assertLess(start, source.index("truncate -s 0 /etc/machine-id"))
        self.assertLess(start, source.index("dracut --force --no-hostonly"))
        harness = r"""
set -euf -o pipefail
PATH=''
state=active
enabled=enabled
systemctl() {
  case "$*" in
    'disable --now kdump.service')
      printf 'disable-stop\n' >&2
      if [ "$TEST_MODE" = stop-failure ]; then return 41; fi
      state=inactive
      enabled=disabled
      if [ "$TEST_MODE" = still-active ]; then state=active; fi
      if [ "$TEST_MODE" = still-enabled ]; then enabled=enabled; fi
      ;;
    'show --property=UnitFileState --value kdump.service') printf '%s\n' "$enabled" ;;
    'show --property=ActiveState --value kdump.service') printf '%s\n' "$state" ;;
    *) return 42 ;;
  esac
}
"""
        return subprocess.run(["/bin/bash", "-c", harness + source[start:end] + "\nprintf 'may-clear-identity\\n'"],
                              env={"TEST_MODE": mode}, capture_output=True, text=True, timeout=5)

    def test_crash_kernel_is_stopped_and_disabled_before_identity_clear(self):
        result = self.run_fragment("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "may-clear-identity\n")

    def test_unconfirmed_kdump_stop_or_disable_blocks_sealing(self):
        for mode in ("stop-failure", "still-active", "still-enabled"):
            with self.subTest(mode=mode):
                result = self.run_fragment(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("may-clear-identity", result.stdout)


if __name__ == "__main__":
    unittest.main()
