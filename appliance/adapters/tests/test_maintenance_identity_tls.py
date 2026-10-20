"""Real loopback TLS; canned protocol responses do not qualify Keycloak itself."""
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import parse_qs

from nebulalog_adapters.auth import IdentityHTTPFailure, MaintenanceIdentityAPI
from nebulalog_manager.common import Refused


TOKEN = "synthetic.header.signature"
NAME = "cl-maint-" + "a" * 32
SECRET = "b" * 64
REALM = {"realm": "nebulalog", "id": "owned-realm",
         "attributes": {"nebulalog.installation-id": "owned-installation"}}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self):
        self.server.requests.append((self.command, self.path, dict(self.headers),
                                     self.rfile.read(int(self.headers.get("Content-Length", "0")))))
        if self.server.disconnect:
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        status, body, content_type, extra = self.server.reply
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for key, value in extra.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ssl.SSLError, BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_DELETE = respond


class MaintenanceIdentityTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.root, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-subj", "/CN=Disposable TLS test CA", "-keyout", "ca.key", "-out", "ca.crt")
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-subj", "/CN=Unrelated test CA", "-keyout", "other.key", "-out", "other.crt")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=maintenance.example.invalid", "-keyout", "server.key", "-out", "server.csr")
        (cls.root / "extensions").write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "subjectAltName=DNS:maintenance.example.invalid\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "1", "-extfile", "extensions", "-out", "server.crt")
        for p in cls.root.iterdir():
            p.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.held = True
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
        self.server.requests = []
        self.server.disconnect = False
        self.sni = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / "server.crt", self.root / "server.key")
        context.set_servername_callback(lambda sock, name, ctx: self.sni.append(name))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        self.config = {"issuer": "https://maintenance.example.invalid/realms/nebulalog",
                       "ca_file": str(self.root / "ca.crt")}
        self.reply(200, REALM)
        self.api = MaintenanceIdentityAPI(self.config, lambda: self.held)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def reply(self, status, value, content_type="application/json", headers=None):
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.server.reply = status, body, content_type, headers or {}

    def test_local_peer_preserves_hostname_and_checks_realm_ownership(self):
        self.assertTrue(self.api.probe(TOKEN, "owned-installation", "owned-realm"))
        self.assertFalse(self.api.probe(TOKEN, "other-installation", "owned-realm"))
        self.assertFalse(self.api.probe(TOKEN, "owned-installation", "other-realm"))
        self.assertEqual(set(self.sni), {"maintenance.example.invalid"})
        self.assertEqual(self.server.requests[0][2]["Host"], "maintenance.example.invalid:8443")
        self.assertEqual(self.server.requests[0][1], "/admin/realms/nebulalog")

    def test_client_grant_stays_in_body_and_has_no_password_grant(self):
        self.reply(200, {"token_type": "Bearer", "access_token": TOKEN})
        self.assertEqual(self.api.authenticate(NAME, SECRET), TOKEN)
        method, path, headers, body = self.server.requests[-1]
        self.assertEqual((method, path), ("POST", "/realms/master/protocol/openid-connect/token"))
        self.assertEqual(parse_qs(body.decode()), {"client_id": [NAME], "client_secret": [SECRET],
                                                 "grant_type": ["client_credentials"]})
        self.assertNotIn("Authorization", headers)
        self.assertNotIn(SECRET, path)

    def test_fixed_delete_and_scope_callback(self):
        self.reply(204, b"")
        self.assertIsNone(self.api.delete(TOKEN, "owned-client"))
        self.assertEqual(self.server.requests[-1][:2], ("DELETE", "/admin/realms/master/clients/owned-client"))
        self.reply(200, [])
        self.assertEqual(self.api.call(TOKEN, "clients?clientId=realm-management"), [])
        self.api.call(TOKEN, "clients/id/scope-mappings/clients/owner", "POST", [{"id": "role"}])
        self.assertEqual(json.loads(self.server.requests[-1][3]), [{"id": "role"}])

    def test_fence_rechecked_before_each_request(self):
        self.api.call(TOKEN)
        for unheld in (False, None, 1, "true"):
            self.held = unheld
            with self.subTest(unheld=unheld), self.assertRaises(Refused):
                self.api.call(TOKEN)
        self.assertEqual(len(self.server.requests), 1)

    def test_wrong_ca_and_hostname_never_send_http(self):
        for changes in ({"ca_file": str(self.root / "other.crt")},
                        {"issuer": "https://wrong.example.invalid/realms/nebulalog"}):
            api = MaintenanceIdentityAPI({**self.config, **changes}, lambda: True)
            with self.subTest(changes=changes), self.assertRaises(URLError):
                api.authenticate(NAME, SECRET)
        self.assertEqual(self.server.requests, [])

    def test_proxy_environment_cannot_redirect_credentials(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1",
                                     "https_proxy": "http://127.0.0.1:1", "no_proxy": "", "NO_PROXY": ""}):
            api = MaintenanceIdentityAPI(self.config, lambda: True)
            self.assertEqual(api.call(TOKEN), REALM)

    def test_all_redirects_refused_without_followup_request(self):
        for status in (301, 302, 303, 307, 308):
            for target in ("https://elsewhere.invalid/steal", self.api.base + "/realms/master/other"):
                before = len(self.server.requests)
                self.reply(status, b"", headers={"Location": target})
                with self.subTest(status=status, target=target), self.assertRaises(Refused):
                    self.api.authenticate(NAME, SECRET)
                self.assertEqual(len(self.server.requests), before + 1)

    def test_only_explicit_client_denial_proves_secret_revocation(self):
        for status in (400, 401):
            for error in ("invalid_client", "unauthorized_client"):
                self.reply(status, {"error": error})
                self.assertTrue(self.api.credentials_refused(NAME, SECRET))
        for status, error in ((403, "invalid_client"), (500, "invalid_client"), (401, "server_error")):
            self.reply(status, {"error": error})
            with self.subTest(status=status, error=error), self.assertRaises(IdentityHTTPFailure):
                self.api.credentials_refused(NAME, SECRET)
        self.reply(200, {"token_type": "bearer", "access_token": TOKEN})
        self.assertFalse(self.api.credentials_refused(NAME, SECRET))

    def test_only_json_401_proves_token_refusal(self):
        self.reply(401, {"error": "HTTP 401 Unauthorized"})
        self.assertTrue(self.api.token_refused(TOKEN))
        for status in (403, 404, 429, 500, 503):
            self.reply(status, {"error": "denied"})
            with self.subTest(status=status), self.assertRaises(IdentityHTTPFailure):
                self.api.token_refused(TOKEN)
        self.reply(401, b"<html>gateway failure</html>", "text/html")
        with self.assertRaises(IdentityHTTPFailure):
            self.api.token_refused(TOKEN)
        self.reply(200, REALM)
        self.assertFalse(self.api.token_refused(TOKEN))

    def test_transport_failure_does_not_prove_removal(self):
        self.server.disconnect = True
        for function, args in ((self.api.credentials_refused, (NAME, SECRET)), (self.api.token_refused, (TOKEN,))):
            with self.subTest(function=function.__name__), self.assertRaises((OSError, http.client.HTTPException)):
                function(*args)
        self.assertEqual(len(self.server.requests), 2)

    def test_bounded_json_and_sanitized_http_errors(self):
        for status, body in ((200, b'{"x":1,"x":2}'), (401, b'{"error":'),
                             (200, b'{"x":NaN}'), (200, b"x" * (1024 * 1024 + 1)),
                             (401, b"x" * (1024 * 1024 + 1))):
            self.reply(status, body)
            with self.subTest(status=status, size=len(body)), self.assertRaises(Refused):
                self.api.call(TOKEN)
        self.reply(401, {"error": "invalid_client", "error_description": SECRET})
        with self.assertRaises(IdentityHTTPFailure) as failure:
            self.api.authenticate(NAME, SECRET)
        self.assertNotIn(SECRET, str(failure.exception))
        self.assertNotIn(SECRET, repr(failure.exception))

    def test_invalid_routes_never_send_requests(self):
        for path in ("https://elsewhere.invalid", "//other", "../master", "%2e%2e/master",
                     "clients/id/../../master", "clients?id=x", "clients?clientId=x&secret=y",
                     "clients/id#fragment", "clients/id\n", "clients\\id", "?clientId=x"):
            with self.subTest(path=path), self.assertRaises(Refused):
                self.api.call(TOKEN, path)
        with self.assertRaises(Refused):
            self.api.call(TOKEN, "clients?clientId=x", "POST")
        with self.assertRaises(Refused):
            self.api.delete(TOKEN, "../users/admin")
        self.assertEqual(self.server.requests, [])

    def test_invalid_identity_inputs_never_send_requests(self):
        for issuer in ("http://maintenance.example.invalid/realms/nebulalog",
                       "https://user:pass@maintenance.example.invalid/realms/nebulalog",
                       "https://maintenance.example.invalid/realms/master",
                       "https://maintenance.example.invalid/realms/nebulalog?token=x",
                       "https://maintenance.example.invalid:0/realms/nebulalog",
                       "https://maintenance.example.invalid/\nrealms/nebulalog"):
            with self.subTest(issuer=issuer), self.assertRaises(Refused):
                MaintenanceIdentityAPI({**self.config, "issuer": issuer}, lambda: True)
        for ca in (None, "", "relative.crt"):
            with self.subTest(ca=ca), self.assertRaises(Refused):
                MaintenanceIdentityAPI({**self.config, "ca_file": ca}, lambda: True)
        for token in ("bad", "a.b.c\nInjected: y", "a" * 32769):
            with self.subTest(token_length=len(token)), self.assertRaises(Refused):
                self.api.call(token)
        with self.assertRaises(Refused):
            self.api.authenticate("admin-cli", SECRET)
        self.assertEqual(self.server.requests, [])

    def test_untrusted_ca_file_and_malformed_grants_fail_closed(self):
        ca = self.root / "ca.crt"
        ca.chmod(0o666)
        try:
            with self.assertRaises(Refused):
                MaintenanceIdentityAPI(self.config, lambda: True)
        finally:
            ca.chmod(0o600)
        for body in ([], {"token_type": 3}, {"token_type": "bearer"},
                     {"token_type": "bearer", "access_token": "bad"}):
            self.reply(200, body)
            with self.subTest(body=body), self.assertRaises(Refused):
                self.api.authenticate(NAME, SECRET)


if __name__ == "__main__":
    unittest.main()
