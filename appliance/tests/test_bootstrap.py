import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from nebulalog_manager.bootstrap import Bootstrap, ROCKY_9_FINGERPRINT, environment, image_pins, realm_config
from nebulalog_manager.common import Refused, run
from nebulalog_manager.firstboot import Locations, validate_config

REPO = Path(__file__).resolve().parents[2]
SETUP = {"installation_id": "11111111-2222-4333-8444-555555555555", "hostname": "logs.example.test", "administrator": {"username": "appliance-admin"}, "maintenance": {"timezone": "UTC"}, "retention_days": 90, "baseline": "unified"}
RUNTIME = {"health_password": "generated-example-password-Aa1!", "health_totp": "MZXW6YTBOJXXE5DFNZSW45DFON2A", "inspector_service": "a" * 64}


class RuntimeBoundaryTests(unittest.TestCase):
    def test_only_complete_immutable_image_pins(self):
        names = ("NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE")
        valid = {name: "registry.example/qualified@sha256:" + "a" * 64 for name in names}
        self.assertEqual(image_pins(valid), valid)
        for altered in ({**valid, "CLICKHOUSE_IMAGE": "clickhouse:latest"}, {**valid, "OTHER_IMAGE": valid[names[0]]}, {key: value for key, value in valid.items() if key != names[0]}, {**valid, names[0]: "image@sha256:" + "a" * 64 + "\n"}):
            with self.assertRaises(Refused):
                image_pins(altered)

    def test_environment_rejects_newline_secret_injection(self):
        for value in ("credential\nOIDC_ISSUER=http://foreign", "credential\0suffix", "credential\rrest"):
            with self.assertRaises(Refused):
                environment({"PG_PASSWORD": value})
        with self.assertRaises(Refused):
            environment({"unexpected-name": "value"})
        self.assertEqual(environment({"POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=trust"}), b"POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n")

    def test_api_has_only_public_certificate_mounts(self):
        lines = (REPO / "appliance/quadlet/nebulalog-api.container.in").read_text().splitlines()
        volumes = [line.removeprefix("Volume=") for line in lines if line.startswith("Volume=")]
        tls = [volume for volume in volumes if "/tls" in volume]
        self.assertEqual(set(tls), {"/var/lib/nebulalog/configuration/tls/" + name + ":/etc/nebulalog/tls/" + name + ":ro,z" for name in ("ca.crt", "server.crt", "trust-bundle.pem")})
        self.assertFalse(any(".key" in volume or "/configuration:" in volume or "/edge-tls" in volume for volume in volumes))
        self.assertNotIn("GroupAdd=20001", lines)
        self.assertIn("Environment=COLLECTOR_TLS_CA_PATH=/etc/nebulalog/tls/ca.crt", lines)
        self.assertIn("Environment=COLLECTOR_TLS_CERT_PATH=/etc/nebulalog/tls/server.crt", lines)

    def test_application_roles_mount_only_the_read_only_host_storage_fence(self):
        for role in ("api", "ingest"):
            with self.subTest(role=role):
                lines = (REPO / ("appliance/quadlet/nebulalog-" + role + ".container.in")).read_text().splitlines()
                self.assertEqual([line for line in lines if "storage-maintenance" in line], [
                    "Environment=STORAGE_MAINTENANCE_PATH=/run/nebulalog-storage-maintenance/gate.json",
                    "Volume=/var/lib/nebulalog/manager/storage-maintenance:/run/nebulalog-storage-maintenance:ro,z",
                ])

    def test_realm_has_no_password_grant_and_requires_second_factor(self):
        template = json.loads((REPO / "deploy/keycloak/realm.json").read_text())
        original = copy.deepcopy(template)
        realm = realm_config(template, SETUP, RUNTIME)
        self.assertEqual(template, original)
        self.assertEqual(realm["sslRequired"], "all")
        self.assertIn("pbkdf2-sha512", realm["passwordPolicy"])
        client = next(client for client in realm["clients"] if client["clientId"] == "nebulalog")
        self.assertFalse(client["directAccessGrantsEnabled"])
        self.assertEqual(client["redirectUris"], ["https://logs.example.test/*"])
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
        forms = next(flow for flow in realm["authenticationFlows"] if flow["alias"] == "nebulalog-forms")
        factor = next(item for item in forms["authenticationExecutions"] if item.get("flowAlias") == "nebulalog-second-factor")
        self.assertEqual(factor["requirement"], "REQUIRED")
        self.assertEqual({action["alias"] for action in realm["requiredActions"]}, {"CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES"})

    def test_health_identity_is_only_viewer_with_explicit_base32_otp(self):
        realm = realm_config(json.loads((REPO / "deploy/keycloak/realm.json").read_text()), SETUP, RUNTIME)
        self.assertEqual(len(realm["users"]), 1)
        health = realm["users"][0]
        self.assertEqual(health["clientRoles"], {"nebulalog": ["VIEWER"]})
        self.assertEqual(health["requiredActions"], [])
        otp = next(c for c in health["credentials"] if c["type"] == "otp")
        data = json.loads(otp["credentialData"])
        self.assertEqual(data["secretEncoding"], "BASE32")
        self.assertEqual(data["algorithm"], "HmacSHA256")
        self.assertEqual(json.loads(otp["secretData"])["value"], RUNTIME["health_totp"])

    def test_reserved_health_name_cannot_become_administrator(self):
        from test_firstboot import CONFIG
        for username in ("nebulalog-health", "NEBULALOG-HEALTH", "nlbootstrap", "service-account-inspector"):
            config = copy.deepcopy(CONFIG)
            config["administrator"]["username"] = username
            with self.assertRaises(Refused):
                validate_config(config)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.paths = Locations(root / "etc", root / "data", root / "run")
        self.paths.etc.mkdir()
        self.manager = Bootstrap(self.paths, runner=lambda argv, **kwargs: "")
        self.manager.bootstrap.mkdir(parents=True)
        self.manager.setup = copy.deepcopy(SETUP)
        self.manager.secret = {key: "a" * 64 for key in ("postgresql_admin", "postgresql_app", "postgresql_keycloak", "clickhouse", "keycloak_bootstrap", "identity_service")}
        self.manager.runtime = copy.deepcopy(RUNTIME)
        schema_probe = patch.object(self.manager, "_schema_revision", return_value="2")
        schema_probe.start()
        self.addCleanup(schema_probe.stop)
        self.manager.state = {"installation_id": SETUP["installation_id"], "completed": []}

    def test_existing_administrator_is_never_reset(self):
        calls = []
        admin = {"id": "human-id", "username": "appliance-admin", "attributes": {"nebulalog-installation": [SETUP["installation_id"]], "nebulalog-local-operator": ["true"]}, "requiredActions": []}
        def kc(path, token, method="GET", body=None):
            calls.append((path, method, body))
            if path == "":
                return {"attributes": {"nebulalog.installation-id": SETUP["installation_id"]}}
            if path.startswith("users?"):
                return [admin]
            if path == "clients?clientId=nebulalog":
                return [{"id": "application-id"}]
            if path.endswith("/roles/ADMINISTRATOR"):
                return {"id": "admin-role", "name": "ADMINISTRATOR"}
        with patch.object(self.manager, "_kc", side_effect=kc), patch.object(self.manager, "_request", return_value={}), patch.object(self.manager, "_token", return_value="test-token"), patch.object(self.manager, "_service_identity"), patch.object(self.manager, "_disable_bootstrap"):
            self.manager._identity()
        self.assertFalse(any(path == "users" or "reset-password" in path for path, method, body in calls))
        self.assertFalse(any(path == "users/human-id" and method == "PUT" for path, method, body in calls))
        self.assertTrue(self.manager.state["identity_initialized"])

    def test_foreign_administrator_refuses_before_role_assignment(self):
        calls = []
        def kc(path, token, method="GET", body=None):
            calls.append((path, method))
            return {"attributes": {"nebulalog.installation-id": SETUP["installation_id"]}} if path == "" else [{"id": "foreign", "attributes": {}}]
        with patch.object(self.manager, "_kc", side_effect=kc), patch.object(self.manager, "_request", return_value={}), patch.object(self.manager, "_token", return_value="test-token"):
            with self.assertRaisesRegex(Refused, "another installation"):
                self.manager._identity()
        self.assertTrue(all(method == "GET" for _, method in calls))

    def test_secrets_env_files_remain_on_encrypted_data(self):
        calls = []
        self.manager.runner = lambda argv, **kwargs: calls.append((argv, kwargs))
        with patch("nebulalog_manager.bootstrap.os.chown"):
            self.manager._environment()
        for name in ("postgresql", "clickhouse", "keycloak", "api", "ingest"):
            link = self.paths.etc / (name + ".env")
            self.assertTrue(link.is_symlink())
            target = self.manager.configuration / "runtime" / (name + ".env")
            self.assertEqual(link.resolve(), target.resolve())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        secret = next((argv, kwargs) for argv, kwargs in calls if argv[:3] == ["podman", "secret", "create"])
        self.assertNotIn("a" * 64, " ".join(secret[0]))
        self.assertEqual(secret[1]["input"], ("a" * 64).encode())
        ch_secret = next((argv, kwargs) for argv, kwargs in calls if argv[:3] == ["podman", "secret", "create"] and "nebulalog-ch-password" in argv)
        self.assertEqual(ch_secret[1]["input"], self.manager.secret["clickhouse"].encode())
        self.assertNotIn(self.manager.secret["clickhouse"], " ".join(ch_secret[0]))
        ch_env = (self.manager.configuration / "runtime/clickhouse.env").read_text()
        self.assertNotIn("CLICKHOUSE_PASSWORD=", ch_env)
        self.assertIn("CLICKHOUSE_PASSWORD_FILE=/run/secrets/nebulalog-ch-password", ch_env)
        for name in ("api", "ingest"):
            values = (self.manager.configuration / "runtime" / (name + ".env")).read_text()
            self.assertIn("CH_URL=https://clickhouse:8443", values)
            self.assertIn("SSL_CERT_FILE=/etc/nebulalog/tls/trust-bundle.pem", values)
        api = (self.manager.configuration / "runtime/api.env").read_text()
        self.assertIn("COLLECTOR_TLS_CA_PATH=/etc/nebulalog/tls/ca.crt\n", api)
        self.assertIn("COLLECTOR_TLS_CERT_PATH=/etc/nebulalog/tls/server.crt\n", api)
        self.assertNotIn(".key", api)
        client = ET.parse(self.manager.configuration / "clickhouse-client.xml").getroot()
        self.assertEqual(client.findtext("secure"), "true")
        self.assertEqual(client.findtext("host"), "127.0.0.1")
        self.assertEqual(client.findtext("port"), "9440")
        self.assertEqual(client.findtext("openSSL/client/verificationMode"), "strict")
        self.assertEqual(client.findtext("openSSL/client/caConfig"), "/etc/nebulalog/tls/ca.crt")

    def test_initial_migration_receives_only_public_trust_bundle(self):
        calls = []
        self.manager.runner = lambda argv, **kwargs: calls.append(argv) or ""
        self.manager.pins = {"NEBULALOG_IMAGE": "qualified@sha256:" + "a" * 64}
        self.manager._migrate()
        command = calls[0]
        self.assertNotIn("--group-add", command)
        volumes = [command[index + 1] for index, arg in enumerate(command) if arg == "--volume"]
        self.assertEqual(volumes, [str(self.manager.tls / "trust-bundle.pem") + ":/etc/nebulalog/tls/trust-bundle.pem:ro,z"])

    def test_prepare_enrolls_lifecycle_before_https_maintenance_gate(self):
        stages = []
        from nebulalog_manager.bootstrap import RUNTIME_CHECKS
        with patch.object(self.manager.firstboot, "gate"), patch.object(self.manager, "_load"), patch.object(self.manager, "_stage", side_effect=lambda name, operation: stages.append(name)), patch.object(self.manager, "_evidence", return_value={"checks": {name: True for name in RUNTIME_CHECKS}}):
            self.manager.prepare(self.manager.bootstrap / "setup.json", self.manager.bootstrap / "secrets.json")
        self.assertLess(stages.index("lifecycle"), stages.index("edge"))
        self.assertLess(stages.index("edge"), stages.index("installed-release"))
        self.assertLess(stages.index("directories"), stages.index("storage-maintenance"))
        self.assertLess(stages.index("storage-maintenance"), stages.index("images"))
        self.assertLess(stages.index("storage-maintenance"), stages.index("postgresql"))

    def test_evidence_requires_recent_clean_aide_only_for_final_completion(self):
        from nebulalog_manager.firstboot import FINAL_CHECKS, RUNTIME_CHECKS

        self.manager.state["administrator_id"] = "human-id"
        issuer = "https://" + SETUP["hostname"] + "/realms/nebulalog"
        kc_responses = {
            "users/human-id": {"enabled": True, "requiredActions": [], "attributes": {"nebulalog-installation": [SETUP["installation_id"]]}},
            "users/human-id/credentials": [{"type": name} for name in ("password", "otp", "recovery-authn-codes")],
            "": {"browserFlow": "nebulalog-browser", "otpPolicyAlgorithm": "HmacSHA256"},
            "clients?clientId=nebulalog": [{"id": "application-id"}],
            "users/human-id/role-mappings/clients/application-id/composite": [{"name": "ADMINISTRATOR"}],
            "authentication/flows/nebulalog-forms/executions": [
                {"providerId": "auth-username-password-form", "requirement": "REQUIRED"},
                {"displayName": "nebulalog-second-factor", "authenticationFlow": True, "requirement": "REQUIRED"},
            ],
            "authentication/flows/nebulalog-second-factor/executions": [
                {"providerId": name, "requirement": "ALTERNATIVE"}
                for name in ("auth-otp-form", "auth-recovery-authn-code-form")
            ],
        }

        def request(url, **kwargs):
            if url == "https://localhost/api/health":
                return {"postgresql": "ok", "clickhouse": "ok"}
            if url == "https://127.0.0.1:8443/realms/nebulalog/.well-known/openid-configuration":
                return {"issuer": issuer}
            if url.startswith("https://localhost/api/logs?"):
                self.assertEqual(kwargs.get("token"), "health-token")
                return {"events": [{"serial": "test-firewall", "parse_status": "parsed"}]}
            self.fail("Unexpected evidence request: " + url)

        def runner(argv, **kwargs):
            filename = Path(argv[3]).name
            self.assertIn(filename, ("server.crt", "ca.crt"))
            self.assertEqual(argv, ["openssl", "x509", "-in", str(self.manager.tls / filename), "-noout", "-fingerprint", "-sha256"])
            pair = "AA" if filename == "server.crt" else "BB"
            return "sha256 Fingerprint=" + ":".join([pair] * 32)

        self.manager.runner = runner
        with (
            patch.object(self.manager, "_token", return_value="inspector-token"),
            patch.object(self.manager, "_kc", side_effect=lambda path, token: kc_responses[path]),
            patch.object(self.manager, "_read", return_value={"issuer": issuer}),
            patch.object(self.manager, "_publisher_readiness", return_value={"mode": "private-unsealed", "update_ready": False}) as publisher,
            patch.object(self.manager, "_request", side_effect=request),
            patch("nebulalog_adapters.auth.local_auth", return_value=("health-token", {})),
            patch("nebulalog_manager.baseline.firstboot_checks", return_value={"baseline_assessed": True, "baseline_review_complete": True}) as baseline,
            patch("nebulalog_manager.aide.firstboot_checks") as integrity,
        ):
            integrity.side_effect = Refused("AIDE must not gate runtime preparation")
            ready = self.manager._evidence()
            self.assertEqual(ready["state"], "runtime-ready")
            self.assertEqual(ready["checks"], {name: True for name in RUNTIME_CHECKS})
            integrity.assert_not_called()
            baseline.assert_not_called()

            integrity.side_effect = None
            for missing_or_false in ({}, {"aide_enrolled": True}, {"aide_checked_clean": True},
                                     {"aide_enrolled": False, "aide_checked_clean": True},
                                     {"aide_enrolled": True, "aide_checked_clean": False}):
                with self.subTest(aide=missing_or_false):
                    integrity.return_value = missing_or_false
                    pending = self.manager._evidence(final=True)
                    self.assertEqual(pending["state"], "verification-pending")
                    self.assertEqual(set(pending["checks"]), set(FINAL_CHECKS))
                    for name in ("aide_enrolled", "aide_checked_clean"):
                        self.assertIs(pending["checks"][name], missing_or_false.get(name, False))
                    self.assertTrue(all(value is True for name, value in pending["checks"].items() if not name.startswith("aide_")))

            integrity.return_value = {"aide_enrolled": True, "aide_checked_clean": True}
            complete = self.manager._evidence(final=True)
            self.assertEqual(complete["state"], "setup-complete")
            self.assertEqual(complete["checks"], {name: True for name in FINAL_CHECKS})
            self.assertEqual(complete["installation_id"], SETUP["installation_id"])
            self.assertEqual(complete["tls_certificate_sha256"], "aa" * 32)
            self.assertEqual(complete["tls_ca_certificate_sha256"], "bb" * 32)
            integrity.assert_called_with(SETUP["installation_id"])
            baseline.assert_called_with(self.manager.configuration, SETUP["installation_id"], SETUP["baseline"])

            integrity.side_effect = Refused("aide_completion_check_stale")
            with self.assertRaisesRegex(Refused, "^aide_completion_check_stale$"):
                self.manager._evidence(final=True)
            self.assertFalse((self.paths.etc / "configured").exists())

            publisher.side_effect = Refused("factory publisher trust missing")
            for final in (False, True):
                with self.assertRaisesRegex(Refused, "factory publisher trust missing"):
                    self.manager._evidence(final=final)

    def test_installed_release_requires_exact_descriptor_sequence_and_images(self):
        descriptor = self.paths.etc / "initial-release.json"
        descriptor.write_text(json.dumps({"schema": 1, "sequence": 7, "publisher": {"mode": "private-unsealed"}}))
        mapping = {"nebulalog": "NEBULALOG_IMAGE", "postgresql": "POSTGRESQL_IMAGE", "clickhouse": "CLICKHOUSE_IMAGE", "keycloak": "KEYCLOAK_FIPS_IMAGE"}
        self.manager.pins = {image: "qualified/" + name + "@sha256:" + "a" * 64 for name, image in mapping.items()}
        receipt = {"schema": 1, "ok": True, "status": "enrolled", "installation_id": SETUP["installation_id"], "initial_release_sha256": hashlib.sha256(descriptor.read_bytes()).hexdigest(), "current": {"sequence": 7, "version": "0.1.0", "components": {name: {"version": "0.1.0", "image": self.manager.pins[image], "schema_revision": "2"} for name, image in mapping.items()}}, "publisher_trust": "not_enrolled", "qualification_status": "pending", "build_mode": "private-unsealed", "update_ready": False}
        host = {"generation": "1" * 64, "version": "0.0.0-factory.fixture", "host_source_sha256": "2" * 64, "abi": 1}
        receipt["current"]["components"]["host"] = host
        calls = []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return json.dumps(receipt)
        self.manager.runner = runner
        with patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.INITIAL_RELEASE", descriptor), patch("nebulalog_manager.bootstrap.os.access", return_value=True), \
                patch("nebulalog_manager.update_enrollment.UpdateEnrollment._factory_host", return_value=host):
            self.assertEqual(self.manager._installed_release()["current"]["sequence"], 7)
            self.assertEqual(calls, [(["/usr/libexec/nebulalog/enroll-installed-release"], {"timeout": 1800})])
            descriptor.write_text(json.dumps({"schema": 1, "sequence": 7, "publisher": {"mode": "factory"}}))
            receipt.update(initial_release_sha256=hashlib.sha256(descriptor.read_bytes()).hexdigest(), build_mode="factory")
            with self.assertRaisesRegex(Refused, "Factory publisher enrollment must complete"):
                self.manager._installed_release()
            receipt.update(publisher_trust="enrolled", update_ready=True)
            self.assertEqual(self.manager._installed_release()["current"]["sequence"], 7)
            for field, invalid in (("sequence", 0), ("sequence", True)):
                receipt["current"][field] = invalid
                with self.assertRaises(Refused):
                    self.manager._installed_release()
            receipt["current"]["sequence"] = 7
            receipt["current"]["components"]["host"] = {**host, "generation": "3" * 64}
            with self.assertRaisesRegex(Refused, "host generation"):
                self.manager._installed_release()
            receipt["current"]["components"]["host"] = host
            receipt["current"]["components"]["baseline"] = {"version": "guessed-from-package-version"}
            with self.assertRaisesRegex(Refused, "inventory is incomplete"):
                self.manager._installed_release()
            receipt["current"]["components"].pop("baseline")
            receipt["current"]["components"]["clickhouse"]["image"] = "different@sha256:" + "b" * 64
            with self.assertRaises(Refused):
                self.manager._installed_release()

    def test_missing_initial_release_is_not_fabricated(self):
        with patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.INITIAL_RELEASE", self.paths.etc / "missing-release.json"):
            with self.assertRaises(OSError):
                self.manager._installed_release()

    def test_directory_retry_never_recursively_relabels_live_container_data(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return json.dumps({"store": {"graphRoot": str(self.paths.data / "containers")}}) if argv[0] == "podman" else ""
        self.manager.runner = runner
        def directory(path):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        with patch("nebulalog_manager.bootstrap.os.chown"), patch("nebulalog_manager.bootstrap._private_dir", side_effect=directory):
            self.manager._directories()
            first = next(argv for argv in calls if argv[0] == "restorecon")
            self.assertIn(str(self.paths.data / "postgresql"), first)
            calls.clear()
            self.manager._directories()
        self.assertEqual([argv for argv in calls if argv[0] == "restorecon"], [["restorecon", str(self.paths.data)]])

    def test_lifecycle_retry_preserves_policy_but_refuses_changed_health_identity(self):
        key = self.paths.etc / "package-key-fixture"
        key.write_bytes(b"test package key bytes; cryptographic fingerprint verified by installer")
        trust = {"schema": 1, "rocky_key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(), "rocky_key_fingerprint": ROCKY_9_FINGERPRINT, "source": "https://rockylinux.org/resources/gpg-key-info", "key_source": "https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9"}
        (self.paths.etc / "trust.json").write_text(json.dumps(trust))
        with patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.ROCKY_PACKAGE_KEY", key):
            self.manager._lifecycle()
        path = self.manager.configuration / "lifecycle.json"
        original = json.loads(path.read_text())
        original["compliance_policy"] = "/var/lib/nebulalog/configuration/reviewed-policy.json"
        path.write_text(json.dumps(original))
        with patch("nebulalog_manager.firstboot.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.ROCKY_PACKAGE_KEY", key):
            self.manager._lifecycle()
            self.assertEqual(json.loads(path.read_text())["compliance_policy"], original["compliance_policy"])
            original["auth_probe"]["username"] = "different"
            path.write_text(json.dumps(original))
            with self.assertRaisesRegex(Refused, "identity configuration changed"):
                self.manager._lifecycle()

    def test_lifecycle_enrolls_verified_package_key_and_refuses_changed_trust(self):
        key = self.paths.etc / "package-key-fixture"
        key.write_bytes(b"test verified package key")
        trust = {"schema": 1, "rocky_key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(), "rocky_key_fingerprint": ROCKY_9_FINGERPRINT}
        trust_path = self.paths.etc / "trust.json"
        trust_path.write_text(json.dumps(trust))
        with patch("nebulalog_manager.firstboot.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.ROCKY_PACKAGE_KEY", key):
            self.manager._lifecycle()
            path = self.manager.configuration / "lifecycle.json"
            self.assertEqual(json.loads(path.read_text())["rocky_key_sha256"], trust["rocky_key_sha256"])
            original = path.read_bytes()
            key.write_bytes(b"a different key, with changed trust too")
            trust["rocky_key_sha256"] = hashlib.sha256(key.read_bytes()).hexdigest()
            trust_path.write_text(json.dumps(trust))
            with self.assertRaisesRegex(Refused, "cannot rotate or reset trust"):
                self.manager._lifecycle()
            self.assertEqual(path.read_bytes(), original)

    def test_lifecycle_refuses_unqualified_fingerprint_or_key_hash(self):
        key = self.paths.etc / "package-key-fixture"
        key.write_bytes(b"test package key")
        trust = {"schema": 1, "rocky_key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(), "rocky_key_fingerprint": ROCKY_9_FINGERPRINT}
        for field, invalid in (("rocky_key_fingerprint", "0" * 40), ("rocky_key_sha256", "0" * 64), ("schema", True), ("source", "https://foreign.example/key"), ("key_source", "http://dl.rockylinux.org/key"), ("source", "https://user:password@rockylinux.org/key")):
            (self.paths.etc / "trust.json").write_text(json.dumps({**trust, field: invalid}))
            with self.subTest(field=field), patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.ROCKY_PACKAGE_KEY", key):
                with self.assertRaises(Refused):
                    self.manager._lifecycle()
            self.assertFalse((self.manager.configuration / "lifecycle.json").exists())

    def test_edge_template_uses_separate_encrypted_tls_directory(self):
        calls = []
        self.manager.runner = lambda argv, **kwargs: calls.append(argv) or ""
        template = REPO / "appliance/httpd/nebulalog.conf.in"
        output = self.paths.etc / "httpd.conf"
        edge = self.manager.configuration / "edge-tls"
        with patch.object(self.manager, "_edge_certificates", return_value=edge), patch.object(self.manager, "_wait"), patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.EDGE_TEMPLATE", template), patch("nebulalog_manager.bootstrap.EDGE_CONFIG", output):
            self.manager._edge()
        rendered = output.read_text()
        self.assertIn("SSLCertificateKeyFile " + str(edge / "server.key"), rendered)
        self.assertIn("SSLProxyCACertificateFile " + str(edge / "ca.crt"), rendered)
        self.assertNotIn(str(self.manager.tls), rendered)
        self.assertIn(["httpd", "-t"], calls)
        self.assertIn(["systemctl", "restart", "nebulalog-edge.service"], calls)

    def test_edge_tls_rejects_symlink_directory(self):
        outside = self.paths.data / "elsewhere"
        outside.mkdir()
        (self.manager.configuration / "edge-tls").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(Refused, "not a symlink"):
            self.manager._edge_certificates()
        self.assertEqual(list(outside.iterdir()), [])


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for real key/certificate verification")
class CertificateTests(unittest.TestCase):
    def test_actual_ca_server_sans_key_match_and_retry_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = Bootstrap(Locations(root / "etc", root / "data", root / "run"), runner=lambda argv, **kwargs: "" if argv[0] == "restorecon" else run(argv, **kwargs))
            manager.bootstrap.mkdir(parents=True)
            manager.setup = copy.deepcopy(SETUP)
            manager.setup["network"] = {"ipv4": {"method": "auto"}, "ipv6": {"method": "auto"}}
            with patch("nebulalog_manager.bootstrap.os.chown"), patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.SYSTEM_CA", manager.tls / "ca.crt"):
                manager._certificates()
                first = (manager.tls / "server.crt").read_bytes()
                manager._certificates()
            self.assertEqual(first, (manager.tls / "server.crt").read_bytes())
            self.assertEqual(first.count(b"-----BEGIN CERTIFICATE-----"), 2)
            self.assertEqual((manager.tls / "ca.key").stat().st_mode & 0o777, 0o600)
            self.assertEqual((manager.tls / "server.key").stat().st_mode & 0o777, 0o640)
            for name in ("ca.crt", "server.crt", "trust-bundle.pem"):
                self.assertNotIn(b"PRIVATE KEY", (manager.tls / name).read_bytes())
                self.assertEqual((manager.tls / name).stat().st_mode & 0o777, 0o644)
            for name in ("ca.crt", "server.crt"):
                details = run(["openssl", "x509", "-in", str(manager.tls / name), "-text", "-noout"])
                self.assertIn("Public-Key: (3072 bit)", details)
            for hostname in ("logs.example.test", "localhost", "keycloak", "clickhouse"):
                self.assertIn("OK", run(["openssl", "verify", "-CAfile", str(manager.tls / "ca.crt"), "-verify_hostname", hostname, str(manager.tls / "server.crt")]))
            for address in ("127.0.0.1", "::1"):
                self.assertIn("OK", run(["openssl", "verify", "-CAfile", str(manager.tls / "ca.crt"), "-verify_ip", address, str(manager.tls / "server.crt")]))
            with self.assertRaises(Refused):
                run(["openssl", "verify", "-CAfile", str(manager.tls / "ca.crt"), "-verify_hostname", "foreign.example", str(manager.tls / "server.crt")])
            with self.assertRaises(Refused):
                run(["openssl", "verify", "-CAfile", str(manager.tls / "ca.crt"), "-verify_ip", "192.0.2.10", str(manager.tls / "server.crt")])
            # A separately generated CA must not trust this installation's leaf.
            foreign_key, foreign_ca = root / "foreign.key", root / "foreign.crt"
            foreign_key.write_text(run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"]) + "\n")
            foreign_key.chmod(0o600)
            run(["openssl", "req", "-new", "-x509", "-sha256", "-days", "1", "-key", str(foreign_key), "-out", str(foreign_ca), "-subj", "/CN=Unrelated test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
            with self.assertRaises(Refused):
                run(["openssl", "verify", "-CAfile", str(foreign_ca), "-purpose", "sslserver", "-verify_hostname", SETUP["hostname"], str(manager.tls / "server.crt")])

    def test_static_management_addresses_are_verified_without_silent_rotation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                return "" if argv[0] == "restorecon" else run(argv, **kwargs)
            manager = Bootstrap(Locations(root / "etc", root / "data", root / "run"), runner=runner)
            manager.bootstrap.mkdir(parents=True)
            manager.setup = {**copy.deepcopy(SETUP), "network": {
                "ipv4": {"method": "manual", "addresses": ["192.0.2.10/24"]},
                "ipv6": {"method": "manual", "addresses": ["2001:db8::10/64"]},
                "dns": ["192.0.2.53"],
            }}
            with patch("nebulalog_manager.bootstrap.os.chown"), patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.SYSTEM_CA", manager.tls / "ca.crt"):
                manager._certificates()
                original = {name: (manager.tls / name).read_bytes() for name in ("ca.crt", "ca.key", "server.crt", "server.key")}
                for address in ("192.0.2.10", "2001:db8::10"):
                    command = ["openssl", "verify", "-CAfile", str(manager.tls / "ca.crt"), "-verify_ip", address, str(manager.tls / "server.crt")]
                    self.assertIn(command, calls)
                    self.assertIn("OK", run(command))
                self.assertIn("OK", run(["openssl", "verify", "-CAfile", str(manager.tls / "ca.crt"), "-purpose", "sslserver", "-verify_hostname", SETUP["hostname"], str(manager.tls / "server.crt")]))
                for address in ("192.0.2.53", "192.0.2.11", "2001:db8::11"):
                    with self.assertRaises(Refused):
                        run(["openssl", "verify", "-CAfile", str(manager.tls / "ca.crt"), "-verify_ip", address, str(manager.tls / "server.crt")])
                manager._certificates()
                manager.setup["network"]["ipv4"]["addresses"] = ["192.0.2.11/24"]
                with self.assertRaises(Refused):
                    manager._certificates()
                self.assertEqual(original, {name: (manager.tls / name).read_bytes() for name in original})

    def test_actual_edge_copy_key_match_permissions_and_retry_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                return "" if argv[0] == "restorecon" else run(argv, **kwargs)
            manager = Bootstrap(Locations(root / "etc", root / "data", root / "run"), runner=runner)
            manager.bootstrap.mkdir(parents=True)
            manager.setup = copy.deepcopy(SETUP)
            def directory(path):
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            with patch("nebulalog_manager.bootstrap.os.chown") as ownership, patch("nebulalog_manager.bootstrap.trusted_file", lambda path: path), patch("nebulalog_manager.bootstrap.SYSTEM_CA", manager.tls / "ca.crt"), patch("nebulalog_manager.bootstrap._private_dir", side_effect=directory):
                manager._certificates()
                original = {name: (manager.tls / name).read_bytes() for name in ("server.crt", "server.key", "ca.crt")}
                key_generation = sum(command[:2] == ["openssl", "genpkey"] for command in calls)
                edge = manager._edge_certificates()
                manager._edge_certificates()
                self.assertEqual(key_generation, sum(command[:2] == ["openssl", "genpkey"] for command in calls))
                self.assertEqual(edge.stat().st_mode & 0o777, 0o700)
                self.assertFalse((edge / "ca.key").exists())
                for name, content in original.items():
                    self.assertEqual((edge / name).read_bytes(), content)
                    self.assertEqual((manager.tls / name).read_bytes(), content)
                    self.assertEqual((edge / name).stat().st_mode & 0o777, 0o600 if name == "server.key" else 0o644)
                    ownership.assert_any_call(edge / name, 0, 0)
                self.assertEqual((manager.tls / "server.key").stat().st_mode & 0o777, 0o640)
                self.assertIn(["restorecon", "-RF", str(edge)], calls)
                (edge / "server.crt").write_bytes(original["server.crt"] + b"changed")
                with self.assertRaisesRegex(Refused, "cannot rotate"):
                    manager._edge_certificates()
                self.assertEqual((edge / "server.key").read_bytes(), original["server.key"])
                self.assertEqual((manager.tls / "server.crt").read_bytes(), original["server.crt"])


class StorageMaintenanceBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)
        self.calls = []
        self.manager = Bootstrap(Locations(self.root / "etc", self.data, self.root / "run"),
                                 runner=lambda argv, **kwargs: self.calls.append(argv))
        self.manager.state = {"completed": ["directories"]}
        self.directory = self.data / "manager/storage-maintenance"
        self.gate = self.directory / "gate.json"
        self.foreign_inodes = set()
        if os.geteuid() != 0:
            # macOS developer runs retain real modes, types, bytes and descriptor
            # identity. The root Rocky run uses the actual ownership checks too.
            actual = os.fstat
            def ownership(fd):
                info = actual(fd)
                fields = {key: getattr(info, key) for key in (
                    "st_mode", "st_uid", "st_gid", "st_size", "st_dev", "st_ino", "st_nlink", "st_mtime_ns", "st_ctime_ns")}
                fields.update(st_uid=10001 if info.st_ino in self.foreign_inodes else 0, st_gid=0)
                return SimpleNamespace(**fields)
            for replacement in (patch("nebulalog_manager.bootstrap.os.fstat", side_effect=ownership),
                                patch("nebulalog_manager.bootstrap.os.fchown")):
                replacement.start()
                self.addCleanup(replacement.stop)

    def create(self):
        result = self.manager._storage_maintenance()
        self.manager.state["completed"].append("storage-maintenance")
        return result

    def test_fresh_gate_exact_permissions_and_byte_preserving_retry(self):
        expected = {"schema": 1, "held": False, "delivery_held": False, "operation": None}
        previous_umask = os.umask(0o077)  # Match the appliance systemd services.
        try:
            self.assertEqual(self.create(), expected)
        finally:
            os.umask(previous_umask)
        self.assertEqual(self.directory.stat().st_mode & 0o7777, 0o755)
        self.assertEqual(self.gate.stat().st_mode & 0o7777, 0o644)
        if os.geteuid() == 0:
            for path in (self.directory, self.gate):
                self.assertEqual((path.stat().st_uid, path.stat().st_gid), (0, 0))
        before = self.gate.read_bytes(), self.gate.stat().st_ino, self.gate.stat().st_mtime_ns
        self.assertEqual(self.manager._storage_maintenance(), expected)
        self.assertEqual((self.gate.read_bytes(), self.gate.stat().st_ino, self.gate.stat().st_mtime_ns), before)
        self.assertEqual(self.calls, [["restorecon", "-RF", str(self.directory)]])

    def test_existing_foreign_operation_hold_is_preserved_without_normalization(self):
        self.create()
        for delivery in (False, True):
            value = {"schema": 1, "held": True, "delivery_held": delivery, "operation": "f" * 64}
            raw = json.dumps(value, indent=3).encode() + b"\n"
            self.gate.write_bytes(raw)
            before = self.gate.stat().st_ino, self.gate.stat().st_mtime_ns
            self.assertEqual(self.manager._storage_maintenance(), value)
            self.assertEqual(self.gate.read_bytes(), raw)
            self.assertEqual((self.gate.stat().st_ino, self.gate.stat().st_mtime_ns), before)

    def test_lost_gate_or_directory_after_initialization_is_not_recreated(self):
        self.create()
        self.gate.unlink()
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        self.assertFalse(self.gate.exists())
        self.directory.rmdir()
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        self.assertFalse(self.directory.exists())

    def test_existing_empty_directory_and_older_runtime_are_not_adopted(self):
        self.directory.mkdir(parents=True, mode=0o755)
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        self.assertEqual(list(self.directory.iterdir()), [])
        self.directory.rmdir()
        self.manager.state["completed"].append("images")
        with self.assertRaisesRegex(Refused, "lost"):
            self.manager._storage_maintenance()
        self.assertFalse(self.directory.exists())

    def test_symlink_directory_and_gate_are_refused_without_touching_targets(self):
        self.create()
        raw = self.gate.read_bytes()
        target = self.root / "retained.json"
        self.gate.rename(target)
        self.gate.symlink_to(target)
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        self.assertEqual(target.read_bytes(), raw)
        self.gate.unlink()
        self.directory.rmdir()
        self.directory.symlink_to(self.root)
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        self.assertFalse((self.root / "gate.json").exists())

    def test_symlink_manager_is_refused_before_creation(self):
        (self.data / "manager").symlink_to(self.root)
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        self.assertFalse((self.root / "storage-maintenance").exists())

    def test_bad_directory_or_file_permissions_and_owner_are_not_repaired(self):
        self.create()
        for path, bad, good in ((self.directory, 0o777, 0o755), (self.gate, 0o666, 0o644), (self.gate, 0o600, 0o644)):
            with self.subTest(path=path.name, mode=oct(bad)):
                path.chmod(bad)
                with self.assertRaises(Refused):
                    self.manager._storage_maintenance()
                self.assertEqual(path.stat().st_mode & 0o777, bad)
                path.chmod(good)
        if os.geteuid() == 0:
            os.chown(self.gate, 10001, 10001)
        else:
            self.foreign_inodes.add(self.gate.stat().st_ino)
        with self.assertRaisesRegex(Refused, "root-owned"):
            self.manager._storage_maintenance()

    def test_nonregular_hardlinked_and_oversized_gate_are_refused(self):
        self.create()
        os.link(self.gate, self.root / "extra-link")
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        (self.root / "extra-link").unlink()
        self.gate.write_bytes(b" " * 4097)
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()
        self.assertEqual(self.gate.stat().st_size, 4097)
        self.gate.unlink()
        os.mkfifo(self.gate, 0o644)
        with self.assertRaises(Refused):
            self.manager._storage_maintenance()

    def test_invalid_duplicate_and_inconsistent_json_is_preserved(self):
        self.create()
        valid = {"schema": 1, "held": False, "delivery_held": False, "operation": None}
        malformed = [b"{}", b"not-json", b'{"schema":1,"schema":1,"held":false,"delivery_held":false,"operation":null}']
        for change in ({"schema": True}, {"held": None}, {"delivery_held": True}, {"operation": "a" * 64},
                       {"held": True}, {"held": True, "operation": "a" * 63}, {"extra": False}):
            malformed.append(json.dumps({**valid, **change}).encode())
        for raw in malformed:
            with self.subTest(raw=raw):
                self.gate.write_bytes(raw)
                with self.assertRaises(Refused):
                    self.manager._storage_maintenance()
                self.assertEqual(self.gate.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
