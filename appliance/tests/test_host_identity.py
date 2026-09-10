"""Synthetic Admin REST drift tests; not a Keycloak browser qualification."""
import copy
import json
from pathlib import Path
import unittest

from nebulalog_manager.common import Refused
from nebulalog_manager.host_identity import (
    ACR, AUDIENCE, CALLBACK_PATH, CLIENT_ID, FACTOR_FLOW, FLOW, KEYCLOAK_VERSION,
    LOA_CONFIG, LOCAL_FLOW, authorization_parameters, definition, verify_read_back,
)

HOSTNAME = "logs.example.test"
BASE = "/admin/realms/nebulalog"
CLIENT = BASE + "/clients/host-client-id"
APP = BASE + "/clients/app-client-id"
TOP = BASE + "/authentication/flows/" + FLOW + "/executions"
LOCAL = BASE + "/authentication/flows/" + LOCAL_FLOW + "/executions"
FACTOR = BASE + "/authentication/flows/" + FACTOR_FLOW + "/executions"
CONFIG = BASE + "/authentication/config/loa-config-id"


def synthetic_read_back():
    candidate = definition(HOSTNAME)
    client = copy.deepcopy(candidate["clients"][0])
    client.update(id="host-client-id", authenticationFlowBindingOverrides={"browser": "top-flow-id"})
    role = {"id": "admin-role-id", "name": "ADMINISTRATOR", "clientRole": True,
            "composite": False, "containerId": "app-client-id"}
    # Reproduce the independently reviewed 26.7.3 Admin REST representation:
    # leaf authenticationFlow is absent; index restarts within each subflow.
    rows = [
        {"id": "e-credentials", "level": 0, "index": 0, "priority": 10,
         "authenticationFlow": True, "flowId": "credentials-flow-id",
         "displayName": LOCAL_FLOW, "requirement": "CONDITIONAL"},
        {"id": "e-loa", "level": 1, "index": 0, "priority": 10,
         "providerId": "conditional-level-of-authentication", "requirement": "REQUIRED",
         "authenticationConfig": "loa-config-id"},
        {"id": "e-password", "level": 1, "index": 1, "priority": 20,
         "providerId": "auth-username-password-form", "requirement": "REQUIRED"},
        {"id": "e-factors", "level": 1, "index": 2, "priority": 30,
         "authenticationFlow": True, "flowId": "factors-flow-id",
         "displayName": FACTOR_FLOW, "requirement": "REQUIRED"},
        {"id": "e-otp", "level": 2, "index": 0, "priority": 10,
         "providerId": "auth-otp-form", "requirement": "ALTERNATIVE"},
        {"id": "e-recovery", "level": 2, "index": 1, "priority": 20,
         "providerId": "auth-recovery-authn-code-form", "requirement": "ALTERNATIVE"},
    ]
    local_rows, factor_rows = copy.deepcopy(rows[1:]), copy.deepcopy(rows[4:])
    for item in local_rows:
        item["level"] -= 1
    for item in factor_rows:
        item["level"] -= 2
    responses = {
        "/admin/serverinfo": {"systemInfo": {"version": "26.7.3"}},
        BASE: {"realm": "nebulalog", "enabled": True, "sslRequired": "all",
               "registrationAllowed": False, "resetPasswordAllowed": False, "rememberMe": False,
               "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA256", "otpPolicyDigits": 6,
               "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1, "otpPolicyCodeReusable": False, "browserFlow": "nebulalog-browser"},
        BASE + "/authentication/flows": [
            {"id": "top-flow-id", "alias": FLOW, "providerId": "basic-flow", "topLevel": True, "builtIn": False},
            {"id": "credentials-flow-id", "alias": LOCAL_FLOW, "providerId": "basic-flow", "topLevel": False, "builtIn": False},
            {"id": "factors-flow-id", "alias": FACTOR_FLOW, "providerId": "basic-flow", "topLevel": False, "builtIn": False},
            {"id": "ordinary-flow-id", "alias": "nebulalog-browser", "providerId": "basic-flow", "topLevel": True, "builtIn": False},
        ],
        BASE + "/clients?clientId=" + CLIENT_ID: [{"clientId": CLIENT_ID, "id": "host-client-id"}],
        CLIENT: client,
        CLIENT + "/default-client-scopes": [], CLIENT + "/optional-client-scopes": [],
        CLIENT + "/protocol-mappers/models": copy.deepcopy(client["protocolMappers"]),
        BASE + "/clients?clientId=nebulalog": [{"clientId": "nebulalog", "id": "app-client-id"}],
        APP: {"clientId": "nebulalog", "id": "app-client-id", "authenticationFlowBindingOverrides": {}},
        BASE + "/identity-provider/instances": [],
        APP + "/roles/ADMINISTRATOR": role,
        CLIENT + "/scope-mappings": {"clientMappings": {"nebulalog": {
            "id": "app-client-id", "client": "nebulalog", "mappings": [copy.deepcopy(role)]}}},
        TOP: rows, LOCAL: local_rows, FACTOR: factor_rows,
        CONFIG: {"id": "loa-config-id", "alias": LOA_CONFIG,
                 "config": {"loa-condition-level": "2", "loa-max-age": "0"}},
    }
    return responses


class HostIdentityDefinitionTests(unittest.TestCase):
    def test_separate_disabled_scoped_candidate_preserves_app_template(self):
        path = Path(__file__).resolve().parents[2] / "deploy/keycloak/realm.json"
        before = path.read_bytes()
        fragment = definition(HOSTNAME)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(set(fragment), {"clients", "authenticationFlows", "authenticatorConfig", "clientScopeMappings"})
        client = fragment["clients"][0]
        self.assertFalse(client["enabled"])
        self.assertFalse(client["publicClient"])
        self.assertEqual(client["clientAuthenticatorType"], "client-secret")
        self.assertEqual(client["redirectUris"], ["https://logs.example.test/api/host/step-up/callback"])
        self.assertEqual(client["webOrigins"], [])
        self.assertNotIn("secret", client)
        self.assertNotIn(CLIENT_ID, before.decode())
        self.assertTrue(definition(HOSTNAME, enabled=True)["clients"][0]["enabled"])
        with self.assertRaises(Refused):
            definition(HOSTNAME, enabled="true")

    def test_whole_password_plus_existing_factor_has_zero_reuse(self):
        fragment = definition(HOSTNAME)
        flows = fragment["authenticationFlows"]
        self.assertEqual(flows[0]["authenticationExecutions"][0]["requirement"], "CONDITIONAL")
        self.assertEqual([item.get("authenticator") for item in flows[1]["authenticationExecutions"][:2]],
                         ["conditional-level-of-authentication", "auth-username-password-form"])
        self.assertTrue(all(item["requirement"] == "REQUIRED" for item in flows[1]["authenticationExecutions"]))
        self.assertEqual([(item["authenticator"], item["requirement"]) for item in flows[2]["authenticationExecutions"]],
                         [("auth-otp-form", "ALTERNATIVE"), ("auth-recovery-authn-code-form", "ALTERNATIVE")])
        self.assertEqual(fragment["authenticatorConfig"][0]["config"], {"loa-condition-level": "2", "loa-max-age": "0"})
        self.assertNotIn("auth-cookie", json.dumps(fragment))
        self.assertNotIn("identity-provider-redirector", json.dumps(fragment))
        self.assertNotIn("requiredActions", fragment)

    def test_par_pkce_exact_acr_and_no_grant_shortcuts(self):
        client = definition(HOSTNAME)["clients"][0]
        self.assertTrue(client["standardFlowEnabled"])
        for key in ("implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled", "fullScopeAllowed"):
            self.assertIs(client[key], False)
        attrs = client["attributes"]
        self.assertEqual(attrs["pkce.code.challenge.method"], "S256")
        self.assertEqual(attrs["require.pushed.authorization.requests"], "true")
        self.assertEqual(attrs["minimum.acr.value"], ACR)
        self.assertEqual(attrs["default.acr.values"], ACR)  # KC delimited string, not JSON.
        self.assertEqual(json.loads(attrs["acr.loa.map"]), {ACR: 2})
        self.assertEqual(attrs["access.token.lifespan"], "120")
        for key in ("use.refresh.tokens", "standard.token.exchange.enabled", "oauth2.jwt.authorization.grant.enabled",
                    "oidc.ciba.grant.enabled", "oauth2.device.authorization.grant.enabled", "external.token.enabled"):
            self.assertEqual(attrs[key], "false")
        self.assertEqual(client["defaultClientScopes"], [])
        self.assertEqual(client["optionalClientScopes"], [])

    def test_audience_and_admin_scope_do_not_grant_a_role(self):
        fragment = definition(HOSTNAME)
        mappers = fragment["clients"][0]["protocolMappers"]
        audience = next(m for m in mappers if m["name"] == "host-control-audience")
        self.assertEqual(audience["config"]["included.custom.audience"], AUDIENCE)
        role = next(m for m in mappers if m["name"] == "host-control-administrator")
        self.assertEqual(role["protocolMapper"], "oidc-usermodel-client-role-mapper")
        self.assertEqual(role["config"]["usermodel.clientRoleMapping.clientId"], "nebulalog")
        self.assertEqual(role["config"]["claim.name"], "resource_access.nebulalog.roles")
        self.assertEqual(fragment["clientScopeMappings"], {"nebulalog": [{"client": CLIENT_ID, "roles": ["ADMINISTRATOR"]}]})
        self.assertNotIn("hardcoded", json.dumps(mappers))
        self.assertNotIn("users", fragment)
        self.assertNotIn("roles", fragment)

    def test_exact_origin_and_bounded_server_side_par_values(self):
        for host in ("https://logs.example.test", "logs.example.test/", "logs.example.test:443", "*.example.test",
                     "logs.example.test?x=y", "user@example.test", "logs.example.test\n", "LOCALHOST", "127.0.0.1", "foo..test"):
            with self.subTest(host=host), self.assertRaises(Refused):
                definition(host)
        parameters = authorization_parameters(HOSTNAME, state="s" * 43, nonce="n" * 43, code_challenge="c" * 43)
        self.assertEqual(parameters["scope"], "openid")
        self.assertEqual(parameters["response_type"], "code")
        self.assertEqual(parameters["prompt"], "login")
        self.assertEqual(parameters["max_age"], "0")
        self.assertEqual(parameters["acr_values"], ACR)
        self.assertEqual(set(parameters), {"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
                                           "code_challenge", "code_challenge_method", "prompt", "max_age", "acr_values", "claims"})
        self.assertEqual(parameters["redirect_uri"], "https://" + HOSTNAME + CALLBACK_PATH)
        self.assertEqual(json.loads(parameters["claims"]), {"id_token": {"acr": {"essential": True, "values": [ACR]}}})
        for invalid in ("", "a" * 42, "a" * 44, "x" * 42 + "=", "secret\n" * 10):
            for field in ("state", "nonce", "code_challenge"):
                values = {"state": "s" * 43, "nonce": "n" * 43, "code_challenge": "c" * 43, field: invalid}
                with self.subTest(field=field, invalid=invalid), self.assertRaises(Refused):
                    authorization_parameters(HOSTNAME, **values)


class HostIdentityReadBackTests(unittest.TestCase):
    def setUp(self):
        self.responses = synthetic_read_back()
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        return copy.deepcopy(self.responses[path])

    def test_exact_readback_is_never_qualification_or_authorization(self):
        result = verify_read_back(self.get, HOSTNAME)
        self.assertTrue(result["configuration_matches"])
        self.assertFalse(result["qualified"])
        self.assertEqual(result["keycloak_version"], KEYCLOAK_VERSION)
        self.assertIn("broker-entrypoint-isolation", result["qualification_required"])
        self.assertIn(CONFIG, self.calls)
        self.assertTrue(all("/users" not in path and "/client-secret" not in path and "/sessions" not in path for path in self.calls))
        self.assertEqual(len(result["definition_sha256"]), 64)

    def test_only_bounded_secret_creation_metadata_can_be_added(self):
        self.responses[CLIENT]["attributes"]["client.secret.creation.time"] = "1788883200"
        self.assertTrue(verify_read_back(self.get, HOSTNAME)["configuration_matches"])
        for value in ("", "-1", "0", "12345678900", "secret-value", True):
            self.responses[CLIENT]["attributes"]["client.secret.creation.time"] = value
            with self.subTest(value=value), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)

    def test_client_security_and_scope_drift_refused(self):
        for field, altered in (("enabled", True), ("publicClient", True), ("clientAuthenticatorType", "none"),
                               ("standardFlowEnabled", False), ("implicitFlowEnabled", True), ("directAccessGrantsEnabled", True),
                               ("serviceAccountsEnabled", True), ("authorizationServicesEnabled", True), ("fullScopeAllowed", True),
                               ("redirectUris", ["https://logs.example.test/*"]), ("webOrigins", ["*"]),
                               ("authenticationFlowBindingOverrides", {"browser": "ordinary-flow-id"}),
                               ("optionalClientScopes", ["offline_access"]), ("rootUrl", "https://other.example.test")):
            with self.subTest(field=field):
                self.responses = synthetic_read_back()
                self.responses[CLIENT][field] = altered
                with self.assertRaises(Refused):
                    verify_read_back(self.get, HOSTNAME)
        for suffix in ("/default-client-scopes", "/optional-client-scopes"):
            self.responses = synthetic_read_back()
            self.responses[CLIENT + suffix] = [{"name": "roles", "id": "inherited-scope"}]
            with self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)

    def test_any_attribute_drift_missing_or_unreviewed_fails_closed(self):
        for field in definition(HOSTNAME)["clients"][0]["attributes"]:
            self.responses = synthetic_read_back()
            self.responses[CLIENT]["attributes"].pop(field)
            with self.subTest(field=field), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)
        self.responses = synthetic_read_back()
        self.responses[CLIENT]["attributes"]["unreviewed.grant.enabled"] = "true"
        with self.assertRaises(Refused):
            verify_read_back(self.get, HOSTNAME)

    def test_static_claim_mapper_or_inherited_mapper_is_refused(self):
        for path in (CLIENT, CLIENT + "/protocol-mappers/models"):
            for change in ("replace", "extra", "duplicate", "remove", "config"):
                self.responses = synthetic_read_back()
                mappers = self.responses[path]["protocolMappers"] if path == CLIENT else self.responses[path]
                if change == "replace":
                    mappers[1]["protocolMapper"] = "oidc-hardcoded-claim-mapper"
                elif change == "extra":
                    mappers.append({"name": "upstream-acr", "protocolMapper": "oidc-usermodel-attribute-mapper"})
                elif change == "duplicate":
                    mappers.append(copy.deepcopy(mappers[0]))
                elif change == "remove":
                    mappers.pop()
                else:
                    mappers[1]["config"]["claim.value"] = ACR
                with self.subTest(path=path, change=change), self.assertRaises(Refused):
                    verify_read_back(self.get, HOSTNAME)

    def test_mfa_bypass_enrollment_reordering_and_reuse_are_refused(self):
        for path, index, field, altered in (
            (TOP, 0, "requirement", "ALTERNATIVE"), (TOP, 2, "providerId", "auth-cookie"),
            (TOP, 3, "requirement", "CONDITIONAL"), (TOP, 4, "requirement", "REQUIRED"),
            (TOP, 4, "providerId", "auth-conditional-otp-form"), (TOP, 5, "requirement", "DISABLED"),
            (LOCAL, 1, "priority", 5), (LOCAL, 1, "level", 2), (FACTOR, 0, "index", 1),
            (TOP, 3, "flowId", "ordinary-flow-id"), (TOP, 2, "authenticationConfig", "unexpected"),
            (TOP, 2, "authenticationFlow", 0), (TOP, 2, "id", "../secrets")):
            self.responses = synthetic_read_back()
            self.responses[path][index][field] = altered
            with self.subTest(path=path, field=field, altered=altered), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)
        for key, value in (("loa-max-age", "300"), ("loa-condition-level", "1"), ("extra", "true")):
            self.responses = synthetic_read_back()
            self.responses[CONFIG]["config"][key] = value
            with self.subTest(config=key), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)
        for path in (TOP, LOCAL, FACTOR):
            self.responses = synthetic_read_back()
            self.responses[path].append(copy.deepcopy(self.responses[path][-1]))
            with self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)

    def test_exact_version_realm_and_no_global_login_override(self):
        for path, key, value in ((BASE, "browserFlow", FLOW), (BASE, "browserFlow", "top-flow-id"),
                                 (BASE, "sslRequired", "external"), (BASE, "registrationAllowed", True),
                                 (BASE, "resetPasswordAllowed", True), (BASE, "otpPolicyAlgorithm", "HmacSHA1")):
            self.responses = synthetic_read_back()
            self.responses[path][key] = value
            with self.subTest(key=key), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)
        self.responses = synthetic_read_back()
        self.responses["/admin/serverinfo"]["systemInfo"]["version"] = "26.3.3"
        with self.assertRaises(Refused):
            verify_read_back(self.get, HOSTNAME)

    def test_ordinary_client_and_broker_flow_bindings_remain_separate(self):
        for reference in (FLOW, LOCAL_FLOW, FACTOR_FLOW, "top-flow-id", "credentials-flow-id", "factors-flow-id"):
            self.responses = synthetic_read_back()
            self.responses[APP]["authenticationFlowBindingOverrides"] = {"browser": reference}
            with self.subTest(reference=reference), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)
            for key in ("firstBrokerLoginFlowAlias", "postBrokerLoginFlowAlias"):
                self.responses = synthetic_read_back()
                self.responses[BASE + "/identity-provider/instances"] = [{"alias": "ordinary-saml", key: reference}]
                with self.subTest(key=key, reference=reference), self.assertRaises(Refused):
                    verify_read_back(self.get, HOSTNAME)

    def test_execution_identity_cannot_change_between_nested_reads(self):
        self.responses[LOCAL][0]["id"], self.responses[LOCAL][1]["id"] = self.responses[LOCAL][1]["id"], self.responses[LOCAL][0]["id"]
        with self.assertRaisesRegex(Refused, "changed during read-back"):
            verify_read_back(self.get, HOSTNAME)

    def test_ordinary_client_bindings_reject_wrong_types_including_falsey_values(self):
        for value in (False, 0, [], "", True, 1, ["browser"], "browser"):
            self.responses = synthetic_read_back()
            self.responses[APP]["authenticationFlowBindingOverrides"] = value
            with self.subTest(value=value), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)
        for missing in (False, True):
            self.responses = synthetic_read_back()
            if missing:
                self.responses[APP].pop("authenticationFlowBindingOverrides")
            else:
                self.responses[APP]["authenticationFlowBindingOverrides"] = None
            with self.subTest(missing=missing):
                self.assertTrue(verify_read_back(self.get, HOSTNAME)["configuration_matches"])

    def test_otp_reuse_cannot_be_enabled_or_implicitly_assumed(self):
        for value in (True, 0, None, "false"):
            self.responses = synthetic_read_back()
            if value is None:
                self.responses[BASE].pop("otpPolicyCodeReusable")
            else:
                self.responses[BASE]["otpPolicyCodeReusable"] = value
            with self.subTest(value=value), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)

    def test_role_scope_only_exact_existing_non_composite_admin(self):
        for change in ("composite", "analyst", "realm", "other-client", "missing"):
            self.responses = synthetic_read_back()
            scopes = self.responses[CLIENT + "/scope-mappings"]
            if change == "composite":
                self.responses[APP + "/roles/ADMINISTRATOR"]["composite"] = True
            elif change == "analyst":
                scopes["clientMappings"]["nebulalog"]["mappings"].append({"name": "ANALYST"})
            elif change == "realm":
                scopes["realmMappings"] = [{"name": "admin"}]
            elif change == "other-client":
                scopes["clientMappings"]["account"] = {"client": "account"}
            else:
                scopes["clientMappings"]["nebulalog"]["mappings"] = []
            with self.subTest(change=change), self.assertRaises(Refused):
                verify_read_back(self.get, HOSTNAME)

    def test_missing_duplicate_and_malformed_readbacks_refuse_without_values(self):
        for path, value in ((TOP, None), (TOP, []), (BASE + "/authentication/flows", [{"alias": FLOW}, {"alias": FLOW}]),
                            (BASE + "/clients?clientId=" + CLIENT_ID, []),
                            (BASE + "/clients?clientId=" + CLIENT_ID, [{"clientId": CLIENT_ID, "id": "../../private"}]),
                            (CONFIG, {"config": {"loa-condition-level": "SECRET-CLAIM"}})):
            self.responses = synthetic_read_back()
            self.responses[path] = value
            with self.subTest(path=path), self.assertRaises(Refused) as caught:
                verify_read_back(self.get, HOSTNAME)
            self.assertNotIn("SECRET-CLAIM", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
