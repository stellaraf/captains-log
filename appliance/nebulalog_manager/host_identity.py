"""Inactive, reviewed-shape Keycloak 26.7.3 host step-up candidate.

Pure definitions and GET-only read-back. Never provisions identity, enables an
AssurancePolicy, certifies authentication behavior, or authorizes a host job.
See docs/HOST_STEP_UP.md for the remaining broker/local-credential qualification.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from urllib.parse import quote

from .common import Refused

KEYCLOAK_VERSION = "26.7.3"
REALM = "nebulalog"
CLIENT_ID = "nebulalog-host-control"
AUDIENCE = CLIENT_ID
ACR = "urn:nebulalog:host-control:local-mfa:v1"
LOA = 2
MAX_AGE = 0  # No reuse in a later authentication, including a later SSO request.
TOKEN_LIFETIME = 120
CALLBACK_PATH = "/api/host/step-up/callback"
FLOW = "nebulalog-host-local-mfa-v1"
LOCAL_FLOW = FLOW + "-credentials"
FACTOR_FLOW = FLOW + "-second-factor"
LOA_CONFIG = FLOW + "-loa"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _origin(hostname):
    # Installation DNS name only: no wildcard, port, path, IP literal or URL.
    if (not isinstance(hostname, str) or len(hostname) > 253 or
            len(hostname.split(".")) < 2 or
            any(not _LABEL.fullmatch(part) for part in hostname.split(".")) or
            all(part.isdigit() for part in hostname.split("."))):
        raise Refused("Host step-up requires an exact canonical installation DNS name")
    return "https://" + hostname


def _execution(provider, requirement, priority, *, flow=False, config=None):
    item = {"requirement": requirement, "priority": priority, "authenticatorFlow": flow,
            "flowAlias" if flow else "authenticator": provider}
    if config:
        item["authenticatorConfig"] = config
    return item


def _mapper(name, provider, config):
    return {"name": name, "protocol": "openid-connect", "protocolMapper": provider, "config": config}


def definition(hostname, *, enabled=False):
    """Return a separate realm import fragment, never a modified app realm.

    Enabled is explicit only to represent an isolated qualification fixture. The
    default is disabled. The caller must arrange IDs when using Admin REST rather
    than import, and supply a generated confidential-client secret separately.
    """
    if type(enabled) is not bool:
        raise Refused("Host step-up enablement must be explicit")
    origin = _origin(hostname)
    both = {"access.token.claim": "true", "id.token.claim": "true", "introspection.token.claim": "true"}
    client = {
        "clientId": CLIENT_ID, "name": "NebulaLog host step-up (candidate)",
        "protocol": "openid-connect", "enabled": enabled, "publicClient": False,
        "clientAuthenticatorType": "client-secret", "bearerOnly": False,
        "standardFlowEnabled": True, "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
        "authorizationServicesEnabled": False, "fullScopeAllowed": False,
        "consentRequired": False, "redirectUris": [origin + CALLBACK_PATH],
        "webOrigins": [], "defaultClientScopes": [], "optionalClientScopes": [],
        "authenticationFlowBindingOverrides": {"browser": FLOW},
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "require.pushed.authorization.requests": "true",
            "access.token.lifespan": str(TOKEN_LIFETIME),
            "client.session.idle.timeout": str(TOKEN_LIFETIME),
            "client.session.max.lifespan": str(TOKEN_LIFETIME),
            "use.refresh.tokens": "false",
            "client_credentials.use_refresh_token": "false",
            "standard.token.exchange.enabled": "false",
            "standard.token.exchange.enableRefreshRequestedTokenType": "NO",
            "oauth2.jwt.authorization.grant.enabled": "false",
            "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false",
            "external.token.enabled": "false",
            "client.use.lightweight.access.token.enabled": "false",
            "allow.token.introspection.without.audience.check": "false",
            "allow.oidc.params.in.redirect.uris": "false",
            "exclude.issuer.from.auth.response": "false",
            "acr.loa.map": json.dumps({ACR: LOA}, separators=(",", ":")),
            "default.acr.values": ACR,
            "minimum.acr.value": ACR,
            "post.logout.redirect.uris": "-",
        },
        "protocolMappers": [
            _mapper("host-control-audience", "oidc-audience-mapper", {
                "included.custom.audience": AUDIENCE, "access.token.claim": "true",
                "id.token.claim": "false", "introspection.token.claim": "true"}),
            _mapper("host-control-acr", "oidc-acr-mapper", both.copy()),
            _mapper("host-control-auth-time", "oidc-usersessionmodel-note-mapper", {
                **both, "user.session.note": "AUTH_TIME", "claim.name": "auth_time",
                "jsonType.label": "long", "userinfo.token.claim": "false"}),
            _mapper("host-control-subject", "oidc-sub-mapper", {
                "access.token.claim": "true", "introspection.token.claim": "true"}),
            _mapper("host-control-administrator", "oidc-usermodel-client-role-mapper", {
                "usermodel.clientRoleMapping.clientId": "nebulalog",
                "claim.name": "resource_access.nebulalog.roles", "jsonType.label": "String",
                "multivalued": "true", "access.token.claim": "true",
                "id.token.claim": "false", "introspection.token.claim": "true",
                "userinfo.token.claim": "false"}),
        ],
    }
    return {
        "clients": [client],
        "clientScopeMappings": {"nebulalog": [{"client": CLIENT_ID, "roles": ["ADMINISTRATOR"]}]},
        "authenticationFlows": [
            {"id": FLOW, "alias": FLOW, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
             "authenticationExecutions": [_execution(LOCAL_FLOW, "CONDITIONAL", 10, flow=True)]},
            {"id": LOCAL_FLOW, "alias": LOCAL_FLOW, "providerId": "basic-flow", "topLevel": False, "builtIn": False,
             "authenticationExecutions": [
                 _execution("conditional-level-of-authentication", "REQUIRED", 10, config=LOA_CONFIG),
                 _execution("auth-username-password-form", "REQUIRED", 20),
                 _execution(FACTOR_FLOW, "REQUIRED", 30, flow=True)]},
            {"id": FACTOR_FLOW, "alias": FACTOR_FLOW, "providerId": "basic-flow", "topLevel": False, "builtIn": False,
             "authenticationExecutions": [
                 _execution("auth-otp-form", "ALTERNATIVE", 10),
                 _execution("auth-recovery-authn-code-form", "ALTERNATIVE", 20)]},
        ],
        "authenticatorConfig": [{"alias": LOA_CONFIG, "config": {
            "loa-condition-level": str(LOA), "loa-max-age": str(MAX_AGE)}}],
    }


def authorization_parameters(hostname, *, state, nonce, code_challenge):
    """Values for the server-authenticated PAR POST; never a browser URL.

    Random generation, transaction persistence, PKCE verifier, credentials, PAR
    transport and response validation belong to the API transaction implementation.
    """
    for value in (state, nonce, code_challenge):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
            raise Refused("Host step-up requires 256-bit base64url transaction values")
    return {
        "client_id": CLIENT_ID, "redirect_uri": _origin(hostname) + CALLBACK_PATH,
        "response_type": "code", "response_mode": "query", "scope": "openid",
        "state": state, "nonce": nonce, "code_challenge": code_challenge,
        "code_challenge_method": "S256", "prompt": "login", "max_age": "0",
        "acr_values": ACR,
        "claims": json.dumps({"id_token": {"acr": {"essential": True, "values": [ACR]}}}, separators=(",", ":")),
    }


def _object(value):
    if not isinstance(value, dict):
        raise Refused("Host identity read-back is malformed")
    return value


def _list(value, maximum=512):
    if not isinstance(value, list) or len(value) > maximum or any(not isinstance(item, dict) for item in value):
        raise Refused("Host identity read-back list is malformed")
    return value


def _same(actual, expected):
    # Python considers True == 1; serialized JSON distinguishes those cases.
    if json.dumps(actual, sort_keys=True, separators=(",", ":")) != json.dumps(expected, sort_keys=True, separators=(",", ":")):
        raise Refused("Host identity configuration differs from the reviewed candidate")


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise Refused("Host identity read-back has an invalid internal identifier")
    return value


def _index(items, field):
    result = {}
    for item in _list(items):
        key = item.get(field)
        if not isinstance(key, str) or not key or key in result:
            raise Refused("Host identity read-back has an ambiguous identifier")
        result[key] = item
    return result


def _mappers(actual, expected):
    actual = _index(actual, "name")
    expected = _index(expected, "name")
    _same(sorted(actual), sorted(expected))
    for name, mapper in expected.items():
        observed = {key: value for key, value in actual[name].items() if key != "id"}
        # Keycloak can return a harmless, historical consent flag.
        if observed.get("consentRequired") is False:
            observed.pop("consentRequired")
        _same(observed, mapper)


def _attributes(actual, expected):
    actual = _object(actual).copy()
    # KeycloakModelUtils.generateSecret adds non-secret creation metadata.
    # No other unknown client attribute is silently accepted.
    created = actual.pop("client.secret.creation.time", None)
    if created is not None and (not isinstance(created, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", created)):
        raise Refused("Host identity client creation metadata is malformed")
    _same(actual, expected)


def _separate_bindings(values, reserved):
    for value in values:
        if value is not None and not isinstance(value, str):
            raise Refused("Host identity read-back has malformed flow bindings")
        if value in reserved:
            raise Refused("Host identity flow must remain scoped to the separate client")


def verify_read_back(get, hostname, *, enabled=False):
    """GET exact live admin representations through caller-owned TLS transport.

    `get(path)` must issue GET only to the trusted installation's admin API using
    a read-only credential. This function never requests a client secret, user,
    credential, token, or session. It returns a non-secret structural receipt,
    always qualified=False. No result can enable an AssurancePolicy.
    """
    expected = definition(hostname, enabled=enabled)
    info = _object(get("/admin/serverinfo"))
    _same(_object(info.get("systemInfo")).get("version"), KEYCLOAK_VERSION)
    base = "/admin/realms/" + REALM
    realm = _object(get(base))
    _same(realm.get("realm"), REALM)
    _same(realm.get("enabled"), True)
    _same(realm.get("sslRequired"), "all")
    for key in ("registrationAllowed", "resetPasswordAllowed", "rememberMe"):
        _same(realm.get(key), False)
    _same(realm.get("otpPolicyType"), "totp")
    _same(realm.get("otpPolicyAlgorithm"), "HmacSHA256")
    _same(realm.get("otpPolicyDigits"), 6)
    _same(realm.get("otpPolicyPeriod"), 30)
    _same(realm.get("otpPolicyLookAheadWindow"), 1)
    _same(realm.get("otpPolicyCodeReusable"), False)
    flows = _index(get(base + "/authentication/flows"), "alias")
    ids = {}
    for flow in expected["authenticationFlows"]:
        observed = _object(flows.get(flow["alias"]))
        ids[flow["alias"]] = _id(observed.get("id"))
        for key in ("providerId", "topLevel", "builtIn"):
            _same(observed.get(key), flow[key])
    if len(set(ids.values())) != len(ids):
        raise Refused("Host identity flow identifiers are ambiguous")
    # This fragment must never become a realm-wide login override.
    reserved = set(ids) | set(ids.values())
    if not isinstance(realm.get("browserFlow"), str) or not realm["browserFlow"]:
        raise Refused("Ordinary browser flow binding is missing")
    _separate_bindings((realm.get(key) for key in ("browserFlow", "directGrantFlow", "firstBrokerLoginFlow", "resetCredentialsFlow")), reserved)
    selected = _list(get(base + "/clients?clientId=" + quote(CLIENT_ID, safe="")), maximum=1)
    if len(selected) != 1 or selected[0].get("clientId") != CLIENT_ID:
        raise Refused("Host identity client is missing or ambiguous")
    client_path = base + "/clients/" + _id(selected[0].get("id"))
    client = _object(get(client_path))
    desired = copy.deepcopy(expected["clients"][0])
    desired["authenticationFlowBindingOverrides"] = {"browser": ids[FLOW]}
    for key, value in desired.items():
        if key == "protocolMappers":
            _mappers(client.get(key), value)
        elif key == "attributes":
            _attributes(client.get(key), value)
        else:
            _same(client.get(key), value)
    for key in ("rootUrl", "baseUrl", "adminUrl"):
        if client.get(key) not in (None, ""):
            raise Refused("Host identity client has an unreviewed URL")
    for suffix in ("/default-client-scopes", "/optional-client-scopes"):
        _same(get(client_path + suffix), [])
    _mappers(get(client_path + "/protocol-mappers/models"), desired["protocolMappers"])
    applications = _list(get(base + "/clients?clientId=nebulalog"), maximum=1)
    if len(applications) != 1 or applications[0].get("clientId") != "nebulalog":
        raise Refused("Application client role scope is missing or ambiguous")
    application_id = _id(applications[0].get("id"))
    application = _object(get(base + "/clients/" + application_id))
    _same(application.get("clientId"), "nebulalog")
    bindings_value = application.get("authenticationFlowBindingOverrides")
    bindings = {} if bindings_value is None else _object(bindings_value)
    _separate_bindings(bindings.values(), reserved)
    for provider in _list(get(base + "/identity-provider/instances")):
        _separate_bindings((provider.get(key) for key in ("firstBrokerLoginFlowAlias", "postBrokerLoginFlowAlias")), reserved)
    role = _object(get(base + "/clients/" + application_id + "/roles/ADMINISTRATOR"))
    role_id = _id(role.get("id"))
    for key, value in {"name": "ADMINISTRATOR", "clientRole": True, "composite": False, "containerId": application_id}.items():
        _same(role.get(key), value)
    scopes = _object(get(client_path + "/scope-mappings"))
    _same(scopes.get("realmMappings", []), [])
    mappings = _object(scopes.get("clientMappings"))
    _same(sorted(mappings), ["nebulalog"])
    mapping = _object(mappings["nebulalog"])
    _same(mapping.get("id"), application_id)
    _same(mapping.get("client"), "nebulalog")
    mapped = _list(mapping.get("mappings"), maximum=1)
    if len(mapped) != 1:
        raise Refused("Host identity administrator role scope is missing")
    for key in ("id", "name", "clientRole", "composite", "containerId"):
        _same(mapped[0].get(key), role.get(key))
    config_ids, execution_ids, execution_identity = set(), set(), {}
    for flow in expected["authenticationFlows"]:
        # This endpoint returns descendants too. Verify the complete depth-first
        # sequence, including each level, index, priority, requirement and flow ID.
        rows = _list(get(base + "/authentication/flows/" + quote(flow["alias"], safe="") + "/executions"), maximum=32)
        flow_map = {item["alias"]: item for item in expected["authenticationFlows"]}
        def flatten(alias, level=0):
            for index, execution in enumerate(flow_map[alias]["authenticationExecutions"]):
                yield execution, level, index, alias
                if execution["authenticatorFlow"]:
                    yield from flatten(execution["flowAlias"], level + 1)
        wanted = list(flatten(flow["alias"]))
        _same(len(rows), len(wanted))
        local_ids = set()
        for row, (execution, level, index, parent) in zip(rows, wanted):
            execution_id = _id(row.get("id"))
            if execution_id in local_ids:
                raise Refused("Host identity execution identifiers are ambiguous")
            local_ids.add(execution_id)
            execution_ids.add(execution_id)
            identity = (parent, index)
            if execution_identity.setdefault(identity, execution_id) != execution_id:
                raise Refused("Host identity changed during read-back")
            for key, value in {"level": level, "index": index, "priority": execution["priority"],
                               "authenticationFlow": execution["authenticatorFlow"], "requirement": execution["requirement"]}.items():
                # 26.7.3 leaves the boxed Boolean unset for leaf executions.
                actual = False if key == "authenticationFlow" and row.get(key) is None else row.get(key)
                _same(actual, value)
            if execution["authenticatorFlow"]:
                _same(row.get("flowId"), ids[execution["flowAlias"]])
                _same(row.get("displayName"), execution["flowAlias"])
                # Admin REST labels nested basic flows with providerId basic-flow.
                if row.get("providerId") not in (None, "basic-flow"):
                    raise Refused("Host identity subflow provider differs")
            else:
                _same(row.get("providerId"), execution["authenticator"])
                if row.get("flowId") not in (None, ""):
                    raise Refused("Host identity leaf unexpectedly references a flow")
            if execution.get("authenticatorConfig"):
                config_id = _id(row.get("authenticationConfig"))
                config_ids.add(config_id)
                config = _object(get(base + "/authentication/config/" + config_id))
                _same({key: value for key, value in config.items() if key != "id"}, expected["authenticatorConfig"][0])
            elif row.get("authenticationConfig") not in (None, ""):
                raise Refused("Host identity execution has an unreviewed configuration")
    if len(config_ids) != 1 or len(execution_ids) != 6:
        raise Refused("Host identity flow topology is inconsistent")
    digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema": 1, "keycloak_version": KEYCLOAK_VERSION, "client_id": CLIENT_ID,
            "definition_sha256": digest, "configuration_matches": True, "qualified": False,
            "qualification_required": ["pinned-browser-negative-paths", "broker-entrypoint-isolation",
                                       "local-credential-provenance", "existing-factor-metadata", "session-revocation-and-outage",
                                       "operation-bound-one-use-transaction"]}
