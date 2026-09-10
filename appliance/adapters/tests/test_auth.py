import base64
import hashlib
import io
import json
import ssl
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request
from nebulalog_manager.common import Refused
from nebulalog_adapters.auth import Callback, LocalHTTPSHandler, RestrictedRedirect, local_auth, totp


class Response(io.BytesIO):
    def __init__(self, body, url="https://logs.example.test/realms/nebulalog/login"):
        super().__init__(body.encode())
        self.url = url


class FakeIdentity:
    def __init__(self, *, skip_otp=False, role="VIEWER", external_form=False, bad_state=False):
        self.requests = []
        self.skip_otp, self.role, self.external_form, self.bad_state = skip_otp, role, external_form, bad_state

    def open(self, request, timeout):
        self.requests.append(request)
        count = len(self.requests)
        if count == 1:
            self.authorize = parse_qs(urlsplit(request.full_url).query)
            target = "https://attacker.example.test/collect" if self.external_form else "/realms/nebulalog/login-actions/authenticate"
            return Response('<form action="' + target + '"><input name="username"><input type="password" name="password"><input type="hidden" name="csrf" value="opaque"></form>')
        if count == 2 and not self.skip_otp:
            return Response('<form action="/realms/nebulalog/login-actions/authenticate?execution=otp"><input name="otp"><input type="hidden" name="credentialId" value="health-otp"></form>')
        if count == (2 if self.skip_otp else 3):
            state = "wrong" if self.bad_state else self.authorize["state"][0]
            raise Callback("https://logs.example.test/health-oidc?" + urlencode({"state": state, "code": "one-use-code"}))
        if count == 4:
            values = parse_qs(request.data.decode())
            challenge = base64.urlsafe_b64encode(hashlib.sha256(values["code_verifier"][0].encode()).digest()).decode().rstrip("=")
            if challenge != self.authorize["code_challenge"][0]:
                raise AssertionError("PKCE mismatch")
            return Response(json.dumps({"access_token": "synthetic-test-token"}))
        return Response(json.dumps({"id": "health", "role": self.role}))


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.config = {"issuer": "https://logs.example.test/realms/nebulalog", "api_url": "http://127.0.0.1:8080",
                       "auth_probe": {"client_id": "nebulalog", "redirect_uri": "https://logs.example.test/health-oidc",
                                      "username": "health", "password": "synthetic-fixture-password",
                                      "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}}

    def test_real_steps_pkce_and_viewer_validation_required(self):
        fake = FakeIdentity()
        token, proof = local_auth(self.config, opener_factory=lambda *handlers: fake)
        self.assertEqual(token, "synthetic-test-token")
        self.assertEqual(proof, {"password": True, "otp": True, "pkce": True, "api_role": "VIEWER"})
        password_form = parse_qs(fake.requests[1].data.decode())
        self.assertEqual(password_form["csrf"], ["opaque"])
        self.assertEqual(parse_qs(fake.requests[2].data.decode())["credentialId"], ["health-otp"])
        self.assertEqual(fake.requests[-1].get_header("Authorization"), "Bearer synthetic-test-token")

    def test_password_only_login_is_not_counted_as_local_mfa(self):
        with self.assertRaises(Refused):
            local_auth(self.config, opener_factory=lambda *handlers: FakeIdentity(skip_otp=True))

    def test_external_form_cannot_receive_credentials(self):
        fake = FakeIdentity(external_form=True)
        with self.assertRaises(Refused):
            local_auth(self.config, opener_factory=lambda *handlers: fake)
        self.assertEqual(len(fake.requests), 1)

    def test_callback_state_and_least_privilege_checked(self):
        for fake in (FakeIdentity(bad_state=True), FakeIdentity(role="ADMINISTRATOR")):
            with self.assertRaises(Refused):
                local_auth(self.config, opener_factory=lambda *handlers: fake)

    def test_sha256_rfc6238_vector(self):
        key = base64.b32encode(b"12345678901234567890123456789012").decode().rstrip("=")
        self.assertEqual(totp(key, "SHA256", 8, 30, now=59), "46119246")

    def test_https_handler_preserves_verified_context_without_removed_python_attribute(self):
        handler = LocalHTTPSHandler(context=ssl.create_default_context())
        with patch.object(handler, "do_open", return_value="opened") as opened:
            self.assertEqual(handler.https_open(Request("https://logs.example.test/")), "opened")
        self.assertTrue(opened.call_args.kwargs["context"].check_hostname)
        self.assertNotIn("check_hostname", opened.call_args.kwargs)

    def test_identity_redirect_cannot_escape_issuer(self):
        handler = RestrictedRedirect(self.config["issuer"], self.config["auth_probe"]["redirect_uri"])
        with self.assertRaises(Refused):
            handler.redirect_request(Request(self.config["issuer"]), None, 302, "Found", {}, "https://external.example.test/idp")


if __name__ == "__main__":
    unittest.main()
