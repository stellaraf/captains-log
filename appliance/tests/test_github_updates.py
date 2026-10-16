"""Real RSA verification and manager journals; HTTP and host adapters are fixtures.

These tests do not qualify a booted appliance or a real component replacement.
"""
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from nebulalog_manager import github_updates as github
from nebulalog_manager.common import Refused, atomic_json, locked
import test_manager as fixtures
from test_systemd_contract import APPLIANCE, unit, words


class Response(io.BytesIO):
    def __init__(self, body=b"", status=200, headers=None):
        super().__init__(body)
        self.status, self.headers = status, headers or {}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


class Connections:
    def __init__(self, responses):
        self.responses, self.requests, self.closed = responses, [], 0

    def __call__(self, host, port, **kwargs):
        owner = self
        class Connection:
            def request(self, method, path, headers):
                owner.requests.append((host, port, method, path, headers, kwargs))
            def getresponse(self):
                return owner.responses.pop(0)
            def close(self):
                owner.closed += 1
        return Connection()


class TransportTests(unittest.TestCase):
    def fetch(self, responses, **kwargs):
        self.connections = Connections(responses)
        return github.GitHubTransport("fixture-token", connection_factory=self.connections).fetch(
            "/repos/stellaraf/captains-log/releases/assets/42", maximum=32, **kwargs)

    def test_verified_https_redirect_never_forwards_api_token(self):
        data = b"real bytes"
        result = self.fetch([Response(status=302, headers={"Location": "https://release-assets.githubusercontent.com/asset?signature=private"}),
                             Response(data, headers={"Content-Length": str(len(data))})],
                            expected_size=len(data), expected_hash=hashlib.sha256(data).hexdigest())
        self.assertEqual(result, data)
        first, second = self.connections.requests
        self.assertEqual(first[4]["Authorization"], "Bearer fixture-token")
        self.assertNotIn("Authorization", second[4])
        self.assertTrue(first[5]["context"].check_hostname)
        self.assertEqual(self.connections.closed, 2)

    def test_untrusted_redirects_receive_no_request(self):
        for url in ("http://release-assets.githubusercontent.com/a", "https://evil.invalid/a", "https://api.github.com/a",
                    "https://user@release-assets.githubusercontent.com/a", "https://release-assets.githubusercontent.com:444/a",
                    "//release-assets.githubusercontent.com/a", "https://release-assets.githubusercontent.com/a#fragment"):
            with self.subTest(url=url), self.assertRaises(Refused):
                self.fetch([Response(status=302, headers={"Location": url})])
            self.assertEqual(len(self.connections.requests), 1)

    def test_size_truncation_encoding_and_integrity_fail_closed(self):
        cases = [(Response(b"x" * 33), {}), (Response(b"short", headers={"Content-Length": "8"}), {}),
                 (Response(b"abc", headers={"Content-Length": "900"}), {}),
                 (Response(b"abc", headers={"Content-Encoding": "gzip"}), {}),
                 (Response(b"abc"), {"expected_size": 4}), (Response(b"abc"), {"expected_hash": "0" * 64})]
        for response, args in cases:
            with self.subTest(headers=response.headers, args=args), self.assertRaises(Refused):
                self.fetch([response], **args)
            self.assertEqual(self.connections.closed, 1)

    def test_redirect_loop_and_repository_rename_are_bounded(self):
        with self.assertRaises(Refused):
            self.fetch([Response(status=302, headers={"Location": "https://objects.githubusercontent.com/a"}) for _ in range(4)])
        self.assertEqual(len(self.connections.requests), 4)
        connections = Connections([Response(status=301, headers={"Location": "https://api.github.com/repos/new/name/releases/latest"})])
        with self.assertRaises(Refused):
            github.GitHubTransport(connection_factory=connections).fetch("/repos/stellaraf/captains-log/releases/latest", maximum=32)
        self.assertEqual(len(connections.requests), 1)

    def test_http_error_does_not_return_or_publish_response_body(self):
        for status in (401, 403, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(github.HTTPFailure) as error:
                self.fetch([Response(b"fixture confidential response", status=status)])
            self.assertEqual(error.exception.status, status)
            self.assertNotIn("confidential", str(error.exception))
            self.assertEqual(self.connections.closed, 1)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for local TLS certificates")
class LocalTLSTests(unittest.TestCase):
    """Real loopback TLS handshakes; no requests reach GitHub or the appliance."""
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.key = cls.root / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(cls.key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name, hostname in (("valid", "api.github.com"), ("wrong", "wrong.invalid")):
            config = cls.root / (name + ".cnf")
            config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=" + hostname
                              + "\n[ext]\nsubjectAltName=DNS:" + hostname + "\nbasicConstraints=critical,CA:TRUE\n")
            subprocess.run(["openssl", "req", "-new", "-x509", "-sha256", "-days", "1", "-key", str(cls.key),
                            "-config", str(config), "-out", str(cls.root / (name + ".pem"))],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def make_transport(self, certificate="valid", trusted=True):
        self.requests = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append((self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
            def log_message(self, *args):
                pass
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.root / (certificate + ".pem"), self.key)
        class Server(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(3)
                try:
                    return server_context.wrap_socket(connection, server_side=True), address
                except Exception:
                    connection.close()
                    raise
        server = Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()
            self.assertFalse(thread.is_alive())
        self.addCleanup(cleanup)
        class LoopbackConnection(http.client.HTTPSConnection):
            def connect(self):
                connection = socket.create_connection(server.server_address, timeout=3)
                try:
                    self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
                except Exception:
                    connection.close()
                    raise
        context = ssl.create_default_context()
        if trusted:
            context.load_verify_locations(self.root / (certificate + ".pem"))
        return github.GitHubTransport("fixture-token", context=context, connection_factory=LoopbackConnection)

    def test_verified_certificate_allows_encrypted_api_request(self):
        transport = self.make_transport()
        self.assertEqual(transport.fetch("/repos/stellaraf/captains-log/releases/latest", maximum=32), b"{}")
        self.assertEqual(self.requests, [("/repos/stellaraf/captains-log/releases/latest", "Bearer fixture-token")])

    def test_untrusted_certificate_never_receives_credentials(self):
        transport = self.make_transport(trusted=False)
        with self.assertRaises(ssl.SSLCertVerificationError):
            transport.fetch("/repos/stellaraf/captains-log/releases/latest", maximum=32)
        self.assertEqual(self.requests, [])

    def test_trusted_wrong_hostname_never_receives_credentials(self):
        transport = self.make_transport(certificate="wrong")
        with self.assertRaises(ssl.SSLCertVerificationError):
            transport.fetch("/repos/stellaraf/captains-log/releases/latest", maximum=32)
        self.assertEqual(self.requests, [])


class PolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "github-updates.json"
        self.policy = {"schema": 1, "repository": "stellaraf/captains-log", "automatic_updates": True, "poll_interval_seconds": 900}
        # Keep actual descriptor type/mode/bound checks; only root ownership and
        # ancestry are replaced because these fixtures run as a developer user.
        for mocker in (patch("nebulalog_manager.update_enrollment._tree"),
                       patch("nebulalog_manager.update_enrollment.ROOT_UID", os.getuid())):
            mocker.start(); self.addCleanup(mocker.stop)

    def load(self, value=None):
        atomic_json(self.path, self.policy if value is None else value)
        return github.load_policy(self.path)

    def test_default_channel_needs_no_github_token(self):
        self.assertEqual(self.load(), (self.policy, None))

    def test_unknown_fields_and_wrong_types_or_cadence_refused(self):
        for fields in ({"schema": True}, {"poll_interval_seconds": 900.0}, {"poll_interval_seconds": 86400},
                       {"automatic_updates": 1}, {"automatic_livepatch": 1}, {"download_url": "https://evil.invalid"},
                       {"repository": "stellaraf/captains-log.git"}, {"repository": "stellaraf/../private"},
                       {"repository": "https://github.com/stellaraf/captains-log"}):
            with self.subTest(fields=fields), self.assertRaises(Refused):
                self.load({**self.policy, **fields})

    def test_duplicate_keys_symlinks_and_writable_config_refused(self):
        self.path.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(Refused):
            github.load_policy(self.path)
        self.load()
        self.path.chmod(0o666)
        with self.assertRaises(Refused):
            github.load_policy(self.path)
        self.path.unlink()
        self.path.symlink_to(self.path.parent / "missing")
        with self.assertRaises(Refused):
            github.load_policy(self.path)

    def test_token_cannot_be_loaded_from_unencrypted_or_arbitrary_path(self):
        for path in ("/tmp/token", "/etc/github-token", "/var/lib/nebulalog/configuration/../github-read-token"):
            with self.subTest(path=path), self.assertRaisesRegex(Refused, "fixed encrypted"):
                self.load({**self.policy, "token_file": path})


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for real signing and verification")
class PollTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.SignatureTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.SignatureTests.tearDownClass.__func__)
    sign = fixtures.SignatureTests.sign
    setup_manager = fixtures.TransactionTests.setup_manager

    def setUp(self):
        fixtures.SignatureTests.setUp(self)
        self.manager, self.calls = self.setup_manager()
        self.policy = {"schema": 1, "repository": "stellaraf/captains-log", "automatic_updates": True, "poll_interval_seconds": 900}
        self.now = datetime(2026, 9, 9, 20, 11, tzinfo=timezone.utc)
        for mocker in (patch.object(github, "require_linux_root"), patch.object(github, "_tree"),
                       patch("nebulalog_manager.updates.require_linux_root"),
                       patch("nebulalog_manager.updates.trusted_file", side_effect=lambda p: p)):
            mocker.start(); self.addCleanup(mocker.stop)
        self.release = {"id": 123, "draft": False, "prerelease": False, "tag_name": "v0.1.1", "assets": []}
        self.refresh_assets()

    def refresh_assets(self):
        self.bodies = {}
        self.release["assets"] = []
        for i, name in enumerate(("manifest.json", "manifest.sig", "app.tar"), 1):
            self.bodies[i] = (self.path / name).read_bytes()
            self.release["assets"].append({"id": i, "name": name, "size": len(self.bodies[i]), "state": "uploaded"})

    def poll(self, *, missing=False):
        responses = [Response(status=404)] if missing else [Response(json.dumps(self.release).encode())]
        # The production downloader uses numeric IDs; this fake routes requests
        # rather than silently succeeding when an unexpected asset is selected.
        owner = self
        class Routing(Connections):
            def __call__(self, host, port, **kwargs):
                connection = super().__call__(host, port, **kwargs)
                original = connection.request
                def request(method, path, headers):
                    original(method, path, headers)
                    if "/assets/" in path:
                        self.responses.append(Response(owner.bodies[int(path.rsplit("/", 1)[1])]))
                connection.request = request
                return connection
        self.transport_calls = Routing(responses)
        self.updater = github.GitHubUpdater(self.manager, transport=github.GitHubTransport(connection_factory=self.transport_calls),
                                           public_key=self.public, clock=lambda: self.now)
        return self.updater.poll(self.policy)

    def test_signed_download_automatically_commits_once_and_retains_recovery_copy(self):
        result = self.poll()
        self.assertEqual(result["status"], "installed")
        self.assertEqual(result["next_check_at"], "2026-09-09T20:15:00+00:00")
        self.assertEqual(self.manager.status()["current"]["sequence"], 2)
        self.assertLess(self.calls.index("update-backup"), self.calls.index("update-activate"))
        self.assertEqual(list((self.manager.state / "downloads").iterdir()), [])
        retained = Path(self.manager.status()["transaction"]["release"])
        self.assertEqual((retained / "app.tar").read_bytes(), b"real artifact bytes")
        self.assertEqual(self.poll()["status"], "up_to_date")
        self.assertEqual(self.calls.count("update-activate"), 1)
        self.assertEqual(len(self.transport_calls.requests), 3)

    def test_no_release_and_disabled_do_not_invoke_adapters(self):
        self.assertEqual(self.poll(missing=True)["status"], "no_release")
        self.policy["automatic_updates"] = False
        self.assertEqual(self.poll()["status"], "disabled")
        self.assertEqual(self.transport_calls.requests, [])
        self.assertEqual(self.calls, [])

    def test_invalid_signature_or_expired_metadata_never_downloads_oci_bytes(self):
        self.bodies[1] += b" "
        self.release["assets"][0]["size"] += 1
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 3)
        self.manifest["expires_at"] = "2026-09-02T00:00:00Z"
        self.sign(); self.refresh_assets()
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 3)
        self.assertEqual(self.calls, [])

    def test_missing_trust_never_downloads_or_enrolls_a_key(self):
        (self.manager.state / "publisher-trust.json").unlink()
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 1)
        self.assertFalse((self.manager.state / "publisher-trust.json").exists())

    def test_prerelease_duplicate_or_mismatched_assets_never_install(self):
        for mutation in (lambda: self.release.update(prerelease=True),
                         lambda: self.release["assets"].append(self.release["assets"][0]),
                         lambda: self.release["assets"][2].update(size=20)):
            self.refresh_assets(); self.release["prerelease"] = False
            mutation()
            self.assertEqual(self.poll()["status"], "blocked")
            self.assertEqual(self.calls, [])

    def test_artifact_corruption_never_invokes_a_host_adapter(self):
        self.bodies[3] = b"fake artifact bytes"
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_unsupported_upgrade_path_refused_before_oci_download(self):
        self.manifest["components"]["nebulalog"]["from_versions"] = ["0.0.1"]
        self.sign(); self.refresh_assets()
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 3)
        self.assertEqual(self.calls, [])

    def test_metadata_only_verifies_signature_and_paths_without_claiming_verified_artifacts(self):
        (self.path / "app.tar").unlink()
        result = github.verify_release(self.path / "manifest.json", self.path / "manifest.sig", self.public, self.path,
                                       now=self.now, metadata_only=True)
        self.assertEqual(result["declared_bytes"], 19)
        self.assertEqual(result["verified_bytes"], 0)
        self.assertFalse(result["artifacts_verified"])
        with self.assertRaisesRegex(Refused, "regular files"):
            github.verify_release(self.path / "manifest.json", self.path / "manifest.sig", self.public, self.path, now=self.now)
        self.manifest["artifacts"][0]["name"] = "../escape.tar"
        self.sign()
        with self.assertRaisesRegex(Refused, "unsafe"):
            github.verify_release(self.path / "manifest.json", self.path / "manifest.sig", self.public, self.path,
                                  now=self.now, metadata_only=True)

    def test_unrepresentable_sequence_or_wrong_manifest_types_refused_before_oci(self):
        for fields in ({"sequence": 2**63}, {"sequence": 0}, {"sequence": True}, {"schema": True}, {"version": None}):
            with self.subTest(fields=fields):
                original = dict(self.manifest)
                self.manifest.update(fields)
                self.sign(); self.refresh_assets()
                self.assertEqual(self.poll()["status"], "blocked")
                self.assertEqual(len(self.transport_calls.requests), 3)
                self.manifest = original
        self.assertEqual(self.calls, [])

    def test_migration_release_refused_before_oci_download(self):
        self.manifest["components"]["nebulalog"]["rollback_safe"] = False
        self.sign(); self.refresh_assets()
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 3)
        self.assertEqual(self.calls, [])

    def test_low_disk_reserve_never_downloads_oci(self):
        with patch.object(github.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**3, 0, 1024**3)):
            self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 3)
        self.assertEqual(self.calls, [])

    def test_tag_conflict_or_invalid_tag_type_never_installs(self):
        for tag in ("v0.1.2", "v0.1.1-rc1", None, 123):
            with self.subTest(tag=tag):
                self.release["tag_name"] = tag
                self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_error_observation_and_audit_do_not_include_exception_secrets(self):
        private_message = "fixture-token?private-signed-url=private-value"
        with patch.object(github.GitHubTransport, "fetch", side_effect=RuntimeError(private_message)):
            result = self.poll()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_type"], "RuntimeError")
        for path in (self.manager.state / "github-status.json", self.manager.state / "history.jsonl"):
            self.assertNotIn(private_message, path.read_text())
        self.assertEqual(self.calls, [])

    def test_failed_runtime_health_rolls_back_and_next_poll_does_not_retry(self):
        original = self.manager.runner
        once = True
        def runner(argv, **kwargs):
            nonlocal once
            if Path(argv[0]).name == "update-health" and once:
                once = False
                self.calls.append("update-health")
                from nebulalog_manager.host_dispatch import HookJournal
                journal = HookJournal(Path(argv[1]), self.manager.status()["transaction"])
                ticket = journal.enter("update-health")
                result = {"ok": True, "checks": {"ingestion": False}}
                journal.finish(ticket, "success", result=result)
                return json.dumps(result)
            return original(argv, **kwargs)
        self.manager.runner = runner
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertIn("update-rollback", self.calls)
        self.assertEqual(self.manager.status()["transaction"]["state"], "rolled_back")
        result = self.poll()
        self.assertEqual(result["reason"], "release_rolled_back")
        self.assertEqual(self.calls.count("update-activate"), 1)
        self.assertEqual(len(self.transport_calls.requests), 3)
        # A corrected publisher release must advance the sequence and explicitly
        # support the version restored by rollback; no manual retry of bad bytes.
        self.manifest.update(sequence=3, version="0.1.2")
        self.manifest["components"]["nebulalog"]["version"] = "0.1.2"
        self.release["tag_name"] = "v0.1.2"
        self.sign(); self.refresh_assets()
        self.assertEqual(self.poll()["status"], "installed")
        self.assertEqual(self.calls.count("update-activate"), 2)

    def test_finalization_failure_does_not_rollback_or_reactivate_on_next_poll(self):
        original = self.manager.runner
        def runner(argv, **kwargs):
            if Path(argv[0]).name == "update-finalize":
                raise Refused("fixture finalization failure")
            return original(argv, **kwargs)
        self.manager.runner = runner
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(self.manager.status()["transaction"]["state"], "committed")
        self.assertNotIn("update-rollback", self.calls)
        self.assertEqual(self.poll()["reason"], "recovery_pending")
        self.assertEqual(len(self.transport_calls.requests), 1)
        self.assertEqual(self.calls.count("update-activate"), 1)

    def test_failed_update_and_failed_rollback_block_future_automatic_installs(self):
        original = self.manager.runner
        def runner(argv, **kwargs):
            if Path(argv[0]).name in ("update-health", "update-rollback"):
                raise Refused("fixture unrecovered runtime")
            return original(argv, **kwargs)
        self.manager.runner = runner
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(self.manager.status()["transaction"]["state"], "recovery_required")
        self.assertEqual(self.poll()["reason"], "recovery_pending")
        self.assertEqual(len(self.transport_calls.requests), 1)
        self.assertEqual(self.calls.count("update-activate"), 1)

    def test_pending_recovery_or_os_reboot_does_not_download(self):
        for target, value in ((self.manager.state / "transaction.json", {"state": "committed", "finalization": "failed"}),
                              (self.manager.state.parent / "os-transaction.json", {"state": "reboot_requested"}),
                              (self.manager.state.parent / "os-transaction.json",
                               {"state": "complete", "finalization": "complete", "storage_maintenance": "held"}),
                              (self.manager.state.parent / "os-transaction.json",
                               {"state": "complete", "finalization": "complete", "storage_maintenance": "release_pending"}),
                              *((self.manager.state.parent / "os-transaction.json",
                                 {"state": "complete", "finalization": "complete", field: "recovery_required"})
                                for field in ("kernel_finalization", "kernel_retention", "kernel_rollback"))):
            atomic_json(target, value)
            self.assertEqual(self.poll()["reason"], "recovery_pending")
            self.assertEqual(len(self.transport_calls.requests), 1)
            target.unlink()
        self.assertEqual(self.calls, [])

    def test_parallel_poll_is_refused_and_global_lock_blocks_install(self):
        with locked(self.manager.state / "github-poll.lock"), self.assertRaises(Refused):
            self.poll()
        with locked(self.manager.state.parent / "transaction.lock"):
            self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(self.calls, [])


class ScheduleTests(unittest.TestCase):
    def test_livepatch_schedule_uses_versioned_cli_and_enrollment_gate(self):
        timer = unit(APPLIANCE / 'systemd/nebulalog-livepatch.timer')
        self.assertEqual(timer[('Timer', 'OnBootSec')], ['2min'])
        self.assertEqual(timer[('Timer', 'OnCalendar')], ['*-*-* *:07/15:00'])
        service = unit(APPLIANCE / 'systemd/nebulalog-livepatch.service')
        self.assertEqual(service[('Service', 'ExecStart')], ['/usr/bin/python3 -I -B /usr/libexec/nebulalog/host-boot nebulalog update livepatch-poll'])
        self.assertIn('/etc/nebulalog/configured', words(service, 'Unit', 'ConditionPathExists'))
        self.assertIn('nebulalog-reboot-verify.service', words(service, 'Unit', 'After'))

    def test_installed_policy_and_timer_check_every_quarter_hour(self):
        policy = json.loads((APPLIANCE / "security/github-updates.json").read_text())
        self.assertEqual(policy, {"schema": 1, "repository": "stellaraf/captains-log", "automatic_updates": True, "automatic_livepatch": False, "poll_interval_seconds": 900})
        timer = unit(APPLIANCE / "systemd/nebulalog-app-update.timer")
        self.assertEqual(timer[("Timer", "OnCalendar")], ["*-*-* *:00/15:00"])
        self.assertEqual(timer[("Timer", "Persistent")], ["true"])
        service = unit(APPLIANCE / "systemd/nebulalog-app-update.service")
        self.assertIn("/var/lib/nebulalog", words(service, "Unit", "RequiresMountsFor"))
        self.assertIn("/etc/nebulalog/configured", words(service, "Unit", "ConditionPathExists"))


if __name__ == "__main__":
    unittest.main()
