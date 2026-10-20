"""Fixture-only clone-network cleanup and an offline firstboot profile choice."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from nebulalog_manager.common import Refused
from nebulalog_manager.firstboot import setup_connections
from nebulalog_manager.image_seal_network import sanitize, SETUP_PROFILE


class NetworkSealingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("etc/NetworkManager/system-connections", "etc/sysconfig/network-scripts",
                     "run/NetworkManager/system-connections", "var/lib/NetworkManager", "var/lib/dhclient"):
            (self.root / name).mkdir(parents=True, mode=0o755)
        self.profile = self.root / "etc/NetworkManager/system-connections/build.nmconnection"
        self.profile.write_text("address1=10.4.6.95/24,10.4.6.1\ndns=10.4.6.11;\nmac-address=00:50:56:00:00:01\n")
        self.profile.chmod(0o600)
        for name in ("etc/hostname", "etc/hosts", "etc/resolv.conf", "etc/sysconfig/network",
                     "etc/sysconfig/network-scripts/ifcfg-ens192", "etc/sysconfig/network-scripts/route-ens192",
                     "var/lib/NetworkManager/secret_key", "var/lib/NetworkManager/no-auto-default.state",
                     "var/lib/dhclient/build.lease"):
            (self.root / name).write_text("private-build-address-or-identity\n")
        self.loopback = self.root / "etc/sysconfig/network-scripts/ifcfg-lo"
        self.loopback.write_text("DEVICE=lo\n")

    def apply(self):
        return sanitize(self.root, uid=os.getuid())

    def test_static_build_address_mac_dns_and_lease_identity_removed(self):
        self.apply()
        for name in ("var/lib/NetworkManager", "var/lib/dhclient", "run/NetworkManager/system-connections"):
            self.assertEqual(list((self.root / name).iterdir()), [])
        profiles = list(self.profile.parent.iterdir())
        self.assertEqual([p.name for p in profiles], ["captains-log-setup.nmconnection"])
        self.assertEqual(profiles[0].read_bytes(), SETUP_PROFILE)
        self.assertEqual(profiles[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "etc/hostname").read_text(), "captains-log\n")
        self.assertEqual(self.loopback.read_text(), "DEVICE=lo\n")
        all_content = b"".join(p.read_bytes() for p in self.root.rglob("*") if p.is_file())
        for absent in (b"10.4.6.95", b"10.4.6.1", b"10.4.6.11", b"00:50:56", b"private-build", b"interface-name="):
            self.assertNotIn(absent, all_content)

    def test_resolver_link_replaced_without_following_target(self):
        target = self.root / "run/NetworkManager/resolv.conf"
        target.write_text("nameserver 10.4.6.11\n")
        resolver = self.root / "etc/resolv.conf"
        resolver.unlink()
        resolver.symlink_to("../run/NetworkManager/resolv.conf")
        self.apply()
        self.assertFalse(resolver.is_symlink())
        self.assertEqual(target.read_text(), "nameserver 10.4.6.11\n")

    def test_unknown_symlink_preserves_all_profile_state(self):
        foreign = self.root / "foreign"
        foreign.write_text("untouched")
        link = self.root / "var/lib/NetworkManager/late-link"
        link.symlink_to(foreign)
        original = self.profile.read_bytes()
        with self.assertRaises(Refused):
            self.apply()
        self.assertEqual(self.profile.read_bytes(), original)
        self.assertEqual(foreign.read_text(), "untouched")

    def test_linked_ancestor_and_hardlink_are_refused(self):
        state = self.root / "var/lib/NetworkManager"
        renamed = state.with_name("saved-NetworkManager")
        state.rename(renamed)
        state.symlink_to(renamed)
        with self.assertRaises(Refused):
            self.apply()
        self.assertTrue(self.profile.exists())
        state.unlink()
        renamed.rename(state)
        os.link(self.profile, state / "hardlink")
        with self.assertRaises(Refused):
            self.apply()
        self.assertTrue(self.profile.exists())

    def test_writable_profile_is_refused_before_cleanup(self):
        self.profile.chmod(0o666)
        with self.assertRaises(Refused):
            self.apply()
        self.assertTrue(self.profile.exists())

    def test_sealer_stops_network_before_cleanup_and_keeps_future_service_enabled(self):
        sealer = Path(__file__).resolve().parents[1] / "bin/nebulalog-seal"
        text = sealer.read_text()
        self.assertLess(text.index("systemctl stop sshd"), text.index("systemctl stop NetworkManager.service"))
        self.assertLess(text.index("systemctl stop NetworkManager.service"), text.index("python3.14 -m nebulalog_manager.image_seal_network"))
        self.assertLess(text.index("python3.14 -m nebulalog_manager.image_seal_network"), text.index("dracut --force --no-hostonly"))
        self.assertNotIn("disable NetworkManager", text)
        self.assertNotIn("mask NetworkManager", text)
        self.assertEqual(subprocess.run(["/bin/bash", "-n", str(sealer)], capture_output=True).returncode, 0)


class OfflineNetworkChoiceTests(unittest.TestCase):
    def test_inactive_ethernet_can_be_selected_without_activating_arbitrary_profiles(self):
        ethernet = "11111111-2222-4333-8444-555555555555"
        bridge = "11111111-2222-4333-8444-666666666666"
        calls = []
        def runner(args):
            calls.append(args)
            if args == ["nmcli", "--get-values", "UUID", "connection", "show"]:
                return ethernet + "\n" + bridge + "\n" + ethernet
            return "802-3-ethernet" if args[-1] == ethernet else "bridge"
        self.assertEqual(setup_connections(runner), [ethernet])
        self.assertFalse(any("--active" in args or "up" in args or "modify" in args for args in calls))

    def test_empty_or_only_non_ethernet_profiles_are_refused(self):
        with self.assertRaises(Refused):
            setup_connections(lambda args: "")
        with self.assertRaises(Refused):
            setup_connections(lambda args: "11111111-2222-4333-8444-555555555555" if args[2] == "UUID" else "bridge")


if __name__ == "__main__":
    unittest.main()
