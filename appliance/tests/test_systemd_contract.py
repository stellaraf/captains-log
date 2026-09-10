"""Static source contracts; installed systemd generator/boot remain guest gates."""
from collections import defaultdict
from pathlib import Path
import unittest

APPLIANCE = Path(__file__).resolve().parents[1]


def unit(path):
    result, section = defaultdict(list), ""
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.strip("[]")
        elif "=" in line:
            key, value = line.split("=", 1)
            result[(section, key)].append(value)
    return result


def words(value, section, key):
    return set(" ".join(value[(section, key)]).split())


class StartupContracts(unittest.TestCase):
    def setUp(self):
        self.units = {path.name: unit(path) for path in (APPLIANCE / "systemd").glob("*.service")}
        self.units.update({path.name.removesuffix(".container.in") + ".service": unit(path) for path in (APPLIANCE / "quadlet").glob("*.container.in")})

    def test_declared_startup_order_is_acyclic(self):
        edges = defaultdict(set)
        for name, value in self.units.items():
            for earlier in words(value, "Unit", "After") & self.units.keys():
                edges[earlier].add(name)
            edges[name].update(words(value, "Unit", "Before") & self.units.keys())
        active, visited = set(), set()
        def visit(name):
            self.assertNotIn(name, active, "Declared unit ordering cycle at " + name)
            if name in visited:
                return
            active.add(name)
            for later in edges[name]:
                visit(later)
            active.remove(name)
            visited.add(name)
        for name in self.units:
            visit(name)

    def test_containers_cannot_bypass_measured_storage_gate(self):
        for component in ("api", "ingest", "postgresql", "clickhouse", "keycloak"):
            value = self.units["nebulalog-" + component + ".service"]
            self.assertIn("nebulalog-firstboot.service", words(value, "Unit", "Requires"))
            self.assertIn("nebulalog-firstboot.service", words(value, "Unit", "After"))
            self.assertIn("/var/lib/nebulalog", words(value, "Unit", "RequiresMountsFor"))

    def test_https_cannot_skip_missing_maintenance_configuration(self):
        edge = self.units["nebulalog-edge.service"]
        gate = self.units["nebulalog-maintenance-gate.service"]
        self.assertIn("nebulalog-maintenance-gate.service", words(edge, "Unit", "Requires"))
        self.assertIn("nebulalog-maintenance-gate.service", words(edge, "Unit", "After"))
        self.assertIn("nebulalog-firstboot.service", words(gate, "Unit", "Requires"))
        self.assertFalse(any(key.startswith("Condition") for section, key in gate if section == "Unit"))

    def test_reboot_health_follows_runtime_and_edge_without_stopping_edge(self):
        verify = self.units["nebulalog-reboot-verify.service"]
        for component in ("api", "ingest", "postgresql", "clickhouse", "keycloak", "edge"):
            name = "nebulalog-" + component + ".service"
            self.assertIn(name, words(verify, "Unit", "After"))
            self.assertIn(name, words(verify, "Unit", "Wants"))
        self.assertFalse(words(verify, "Unit", "Conflicts"))

    def test_console_can_enroll_before_runtime_gate_is_ready(self):
        value = self.units["nebulalog-console.service"]
        dependencies = words(value, "Unit", "After") | words(value, "Unit", "Requires")
        self.assertFalse({name for name in dependencies if name.startswith("nebulalog-")})
        self.assertFalse(words(value, "Unit", "Conflicts"))

    def test_status_and_apache_have_separate_public_label_paths(self):
        api = self.units["nebulalog-api.service"]
        mounts = api[("Container", "Volume")]
        self.assertIn("/run/nebulalog-status:/run/nebulalog-status:ro,z", mounts)
        self.assertFalse(any("/run/nebulalog-public" in mount for mount in mounts))
        installer = (APPLIANCE / "install-host.sh").read_text()
        self.assertIn("-t container_file_t '/run/nebulalog-status(/.*)?'", installer)
        self.assertIn("-t httpd_var_run_t '/run/nebulalog-public(/.*)?'", installer)

    def test_managed_aide_config_is_mandatory_protected_and_relabelled(self):
        installer = (APPLIANCE / "install-host.sh").read_text()
        self.assertIn('install -o root -g root -m 0600 "$APPLIANCE_SOURCE/security/aide.conf" /etc/aide.conf\nrestorecon /etc/aide.conf\n', installer)
        config = (APPLIANCE / "security/aide.conf").read_text()
        self.assertIn("@@define DBDIR /var/lib/nebulalog/manager/aide\n", config)
        self.assertIn("database_in=file:@@{DBDIR}/aide.db.gz\n", config)
        self.assertNotIn("aide --init", installer)


if __name__ == "__main__":
    unittest.main()
