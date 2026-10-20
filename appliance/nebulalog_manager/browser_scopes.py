"""Owned-realm browser scope reconciliation for a maintenance transaction.

The caller supplies authenticated administration, a trusted realm template and
the installation identity. This module does not obtain elevated credentials,
authorize an update, revoke existing tokens, or release maintenance.
"""
import copy
from urllib.parse import quote

from .common import Refused

APPLICATION = "nebulalog"
PROJECTION = "captains-log-token-roles"
ROLES = {"ADMINISTRATOR", "ANALYST", "VIEWER"}
SCOPES = {"basic", "profile", "email", "acr"}


def _one(items, label):
    if not isinstance(items, list) or len(items) != 1:
        raise Refused(label + " is ambiguous")
    return items[0]


def _mapper(value):
    result = {key: copy.deepcopy(value[key]) for key in ("name", "protocol", "protocolMapper", "config")}
    if result["protocolMapper"] == "oidc-audience-mapper":
        # Keycloak 26.8.1 materializes these defaults when importing the legacy
        # audience mapper. Compare the reviewed effective settings; never drop
        # an explicit conflicting value or an unknown config key.
        result["config"].setdefault("introspection.token.claim", "true")
        result["config"].setdefault("userinfo.token.claim", "false")
    return result


def configure_browser_roles(call, template, installation_id):
    """Reconcile known browser scopes within caller-owned maintenance.

    Validate ownership and customizations before the first write. Only scopes,
    approved protocol mappers and fullScopeAllowed change. Redirects, login
    flows, users, credentials, keys, providers and stored role grants are not
    written. A lost response to the final enable can leave that action uncertain;
    the caller must retain external maintenance and reconcile before release.
    A successful REST readback is not browser or migration acceptance.
    """
    if not isinstance(installation_id, str) or not installation_id:
        raise Refused("Browser scope migration requires an installation identity")
    realm = call("")
    if (realm.get("realm") != APPLICATION
            or realm.get("attributes", {}).get("nebulalog.installation-id") != installation_id):
        raise Refused("Browser realm belongs to another installation")
    desired = _one([c for c in template["clients"] if c["clientId"] == APPLICATION], "Browser template")
    projection = _one([c for c in template["clients"] if c["clientId"] == PROJECTION], "Projection template")
    if (desired.get("fullScopeAllowed") is not False
            or set(desired.get("defaultClientScopes", [])) != SCOPES
            or desired.get("optionalClientScopes") != []):
        raise Refused("Browser template scope policy differs")
    wanted = {_mapper(m)["name"]: _mapper(m) for m in desired["protocolMappers"]}
    if len(wanted) != 5:
        raise Refused("Browser template mapper policy differs")
    client = _one(call("clients?clientId=" + APPLICATION), "Browser client")
    path = "clients/" + client["id"]
    client = call(path)
    if (client.get("clientId") != APPLICATION or client.get("protocol") != "openid-connect"
            or client.get("publicClient") is not True or client.get("standardFlowEnabled") is not True
            or any(client.get(k) is True for k in ("bearerOnly", "implicitFlowEnabled",
                                                   "directAccessGrantsEnabled", "serviceAccountsEnabled"))
            or client.get("attributes", {}).get("pkce.code.challenge.method") != "S256"
            or type(client.get("enabled")) is not bool):
        raise Refused("Browser client has an unsupported authentication configuration")
    existing = call(path + "/protocol-mappers/models")
    if (len({m["name"] for m in existing}) != len(existing)
            or any(m["name"] not in wanted or _mapper(m) != wanted[m["name"]] for m in existing)):
        raise Refused("Browser client has an unreviewed protocol mapper")
    shared = call("client-scopes")
    scope_ids = {name: _one([s for s in shared if s["name"] == name], "Identity scope")["id"]
                 for name in SCOPES}
    links = {kind: call(path + "/" + kind + "-client-scopes") for kind in ("default", "optional")}
    # These are the vendor's ordinary legacy links. Custom scopes need a
    # separate reviewed migration, not silent removal.
    legacy_scopes = {
        "default": SCOPES | {"roles", "web-origins"},
        "optional": {"address", "phone", "offline_access", "organization", "microprofile-jwt"},
    }
    if any(s["name"] not in legacy_scopes[kind] for kind, scopes in links.items() for s in scopes):
        raise Refused("Browser client has an unreviewed client scope")
    for name, scope_id in scope_ids.items():
        inherited = call("client-scopes/" + scope_id + "/scope-mappings")
        if inherited.get("realmMappings") or inherited.get("clientMappings"):
            raise Refused("Identity scope inherits role permissions")
        for mapper in call("client-scopes/" + scope_id + "/protocol-mappers/models"):
            claim = mapper.get("config", {}).get("claim.name", "")
            if (mapper.get("protocolMapper") in ("oidc-usermodel-client-role-mapper",
                                                "oidc-usermodel-realm-role-mapper",
                                                "oidc-hardcoded-role-mapper",
                                                "oidc-role-name-mapper")
                    or claim.startswith(("resource_access", "realm_access"))):
                raise Refused("Identity scope contains a role mapper")
    explicit = call(path + "/scope-mappings")
    if explicit.get("realmMappings"):
        raise Refused("Browser client has unreviewed realm role scopes")
    for owner in explicit.get("clientMappings", {}).values():
        if owner["id"] != client["id"] or {r["name"] for r in owner["mappings"]} - ROLES:
            raise Refused("Browser client has unreviewed role scopes")
    roles = [call(path + "/roles/" + quote(name, safe="")) for name in sorted(ROLES)]
    if ({r["name"] for r in roles} != ROLES
            or any(r.get("containerId") != client["id"] or r.get("composite") is not False for r in roles)):
        raise Refused("Application role definitions changed")
    projections = call("clients?clientId=" + PROJECTION)
    if len(projections) > 1:
        raise Refused("Projection client is ambiguous")
    if projections:
        current = call("clients/" + projections[0]["id"])
        for key in ("clientId", "protocol", "enabled", "bearerOnly", "publicClient",
                    "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
                    "serviceAccountsEnabled", "fullScopeAllowed"):
            if current.get(key) != projection[key]:
                raise Refused("Existing projection client differs from the reviewed policy")
        if (current.get("redirectUris") or current.get("webOrigins")
                or current.get("protocolMappers") or call("clients/" + current["id"] + "/roles")):
            raise Refused("Existing projection client has unreviewed configuration")
        for kind in ("default", "optional"):
            if call("clients/" + current["id"] + "/" + kind + "-client-scopes"):
                raise Refused("Existing projection client has unreviewed scopes")
        scopes = call("clients/" + current["id"] + "/scope-mappings")
        if scopes.get("realmMappings") or scopes.get("clientMappings"):
            raise Refused("Existing projection client has unreviewed role scopes")
    # The application remains disabled until all writes and readbacks succeed.
    call(path, "PUT", {"enabled": False})
    if call(path).get("enabled") is not False:
        raise Refused("Browser client did not enter maintenance")
    if not projections:
        call("clients", "POST", copy.deepcopy(projection))
        projections = [_one(call("clients?clientId=" + PROJECTION), "Created projection client")]
    projection_path = "clients/" + projections[0]["id"]
    for kind in ("default", "optional"):
        for link in call(projection_path + "/" + kind + "-client-scopes"):
            call(projection_path + "/" + kind + "-client-scopes/" + link["id"], "DELETE")
        for link in links[kind]:
            if kind == "optional" or link["id"] not in scope_ids.values():
                call(path + "/" + kind + "-client-scopes/" + link["id"], "DELETE")
    for scope_id in scope_ids.values():
        call(path + "/default-client-scopes/" + scope_id, "PUT")
    present = {m["name"] for m in existing}
    for name, mapper in wanted.items():
        if name not in present:
            call(path + "/protocol-mappers/models", "POST", mapper)
    call(path + "/scope-mappings/clients/" + client["id"], "POST", roles)
    call(path, "PUT", {"fullScopeAllowed": False})
    if call(path).get("fullScopeAllowed") is not False:
        raise Refused("Browser full scope readback failed")
    if ({m["name"]: _mapper(m) for m in call(path + "/protocol-mappers/models")} != wanted
            or {s["id"] for s in call(path + "/default-client-scopes")} != set(scope_ids.values())
            or call(path + "/optional-client-scopes")
            or {r["name"] for r in call(path + "/scope-mappings/clients/" + client["id"])} != ROLES):
        raise Refused("Browser role configuration readback failed")
    for kind in ("default", "optional"):
        if call(projection_path + "/" + kind + "-client-scopes"):
            raise Refused("Projection scope readback failed")
    observed = call(projection_path)
    for key in ("clientId", "protocol", "enabled", "bearerOnly", "publicClient",
                "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
                "serviceAccountsEnabled", "fullScopeAllowed"):
        if observed.get(key) != projection[key]:
            raise Refused("Projection configuration readback failed")
    if observed.get("protocolMappers") or observed.get("redirectUris") or observed.get("webOrigins"):
        raise Refused("Projection configuration readback failed")
    call(path, "PUT", {"enabled": True})
    if call(path).get("enabled") is not True:
        raise Refused("Browser client was not enabled")
    return {"application_client_id": client["id"], "projection_client_id": projections[0]["id"],
            "roles": sorted(ROLES), "existing_tokens_revoked": False}
