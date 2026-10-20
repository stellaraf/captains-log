"""Boundary checks for the separately authorized identity maintenance helper."""
import copy
import json
from pathlib import Path
import unittest

from nebulalog_manager.browser_scopes import _mapper, configure_browser_roles
from nebulalog_manager.common import Refused


class BrowserScopeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads((Path(__file__).resolve().parents[2] / "deploy/keycloak/realm.json").read_text())
        self.client = {**copy.deepcopy(self.template["clients"][0]), "id": "application", "protocol": "openid-connect"}
        self.responses = {
            "": {"realm": "nebulalog", "attributes": {"nebulalog.installation-id": "owned"}},
            "clients?clientId=nebulalog": [self.client],
            "clients/application": self.client,
            "clients/application/protocol-mappers/models": self.client["protocolMappers"],
        }
        self.writes = []

    def call(self, path, method="GET", body=None):
        if method != "GET":
            self.writes.append((path, method, body))
            self.fail("Invalid preflight must not write identity configuration")
        return self.responses[path]

    def migrate(self, identity="owned"):
        return configure_browser_roles(self.call, self.template, identity)

    def test_foreign_or_missing_installation_refused_before_client_lookup(self):
        for identity in ("foreign", "", None):
            with self.subTest(identity=identity), self.assertRaises(Refused):
                self.migrate(identity)
        self.assertEqual(self.writes, [])

    def test_ambiguous_application_refused(self):
        self.responses["clients?clientId=nebulalog"].append(copy.deepcopy(self.client))
        with self.assertRaisesRegex(Refused, "ambiguous"):
            self.migrate()

    def test_unreviewed_authentication_grants_refused(self):
        for key in ("directAccessGrantsEnabled", "serviceAccountsEnabled", "implicitFlowEnabled", "bearerOnly"):
            with self.subTest(key=key):
                self.client[key] = True
                with self.assertRaisesRegex(Refused, "authentication"):
                    self.migrate()
                self.client[key] = False

    def test_missing_pkce_refused(self):
        self.client["attributes"].pop("pkce.code.challenge.method")
        with self.assertRaisesRegex(Refused, "authentication"):
            self.migrate()

    def test_unknown_or_modified_mapper_refused(self):
        self.client["protocolMappers"][0]["config"]["included.client.audience"] = "foreign"
        with self.assertRaisesRegex(Refused, "unreviewed protocol mapper"):
            self.migrate()

    def test_duplicate_mapper_names_refused(self):
        self.client["protocolMappers"].append(copy.deepcopy(self.client["protocolMappers"][0]))
        with self.assertRaisesRegex(Refused, "unreviewed protocol mapper"):
            self.migrate()

    def test_vendor_audience_defaults_match_without_mutating_input(self):
        original = copy.deepcopy(self.template["clients"][0]["protocolMappers"][0])
        explicit = copy.deepcopy(original)
        explicit["config"].update({"introspection.token.claim": "true", "userinfo.token.claim": "false"})
        self.assertEqual(_mapper(original), _mapper(explicit))
        self.assertNotIn("introspection.token.claim", original["config"])
        for field, value in (("userinfo.token.claim", "true"), ("introspection.token.claim", "false"),
                             ("included.client.audience", "other"), ("unreviewed", "true")):
            with self.subTest(field=field):
                changed = copy.deepcopy(explicit)
                changed["config"][field] = value
                self.assertNotEqual(_mapper(original), _mapper(changed))


if __name__ == "__main__":
    unittest.main()
