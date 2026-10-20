"""Explicit token scopes for noninteractive Keycloak service identities."""
from urllib.parse import quote

from .common import Refused

# Keycloak's read roles include these query permissions. Do not accept a new
# child permission automatically when a vendor version changes the composites.
ROLE_CHILDREN = {
    "view-clients": {"query-clients"},
    "view-users": {"query-users", "query-groups"},
}


def configure_service_roles(call, client_id, allowed):
    """Configure a disabled, owned client; the caller enables it after success.

    ``call`` uses realm-relative Admin REST paths. Role assignment and token
    scope are independent: both must be restricted, including composite roles.
    This does not revoke access tokens issued before the client was disabled.
    """
    client_path = "clients/" + client_id
    client = call(client_path)
    if client.get("enabled") is not False or client.get("fullScopeAllowed") is not False:
        raise Refused("Service client must be disabled with explicit scopes")
    # Updating ClientRepresentation alone does not reconcile these associations.
    # Only change links on this disabled, owned client, never realm defaults.
    role_scopes = [scope for scope in call("client-scopes") if scope["name"] == "roles"]
    if len(role_scopes) != 1:
        raise Refused("Service roles client scope is ambiguous")
    roles_scope_id = role_scopes[0]["id"]
    for kind in ("default", "optional"):
        for scope in call(client_path + "/" + kind + "-client-scopes"):
            if kind == "optional" or scope["id"] != roles_scope_id:
                call(client_path + "/" + kind + "-client-scopes/" + scope["id"], "DELETE")
    call(client_path + "/default-client-scopes/" + roles_scope_id, "PUT")
    management = call("clients?clientId=realm-management")
    application = call("clients?clientId=nebulalog")
    if len(management) != 1 or len(application) != 1:
        raise Refused("Service role owner is ambiguous")
    owner = management[0]["id"]
    user = call(client_path + "/service-account-user")
    grants = "users/" + user["id"] + "/role-mappings/clients/"
    expected = allowed | set().union(*(ROLE_CHILDREN.get(name, set()) for name in allowed))
    effective = call(grants + owner + "/composite")
    if {role["name"] for role in effective} - expected:
        raise Refused("Service identity has unexpected administration privileges")
    if call(grants + application[0]["id"] + "/composite"):
        raise Refused("Service identity must not hold interactive application roles")
    roles = [call("clients/" + owner + "/roles/" + quote(name, safe="")) for name in sorted(allowed)]
    for name, role in zip(sorted(allowed), roles):
        children = ROLE_CHILDREN.get(name, set())
        if role["name"] != name or role.get("containerId") != owner or bool(role.get("composite")) != bool(children):
            raise Refused("Service administration role definition changed")
        if children:
            actual = call("clients/" + owner + "/roles/" + quote(name, safe="") + "/composites")
            if ({child["name"] for child in actual} != children
                    or any(child.get("composite") or child.get("containerId") != owner for child in actual)):
                raise Refused("Service administration role children changed")

    scopes = client_path + "/scope-mappings"
    existing = call(scopes)
    if existing.get("realmMappings"):
        raise Refused("Service client has unexpected realm role scopes")
    for mapping in existing.get("clientMappings", {}).values():
        if mapping["id"] != owner or {r["name"] for r in mapping["mappings"]} - allowed:
            raise Refused("Service client has unexpected client role scopes")

    defaults = call(client_path + "/default-client-scopes")
    if [scope["id"] for scope in defaults] != [roles_scope_id] or call(client_path + "/optional-client-scopes"):
        raise Refused("Service client has unexpected inherited client scopes")
    inherited = call("client-scopes/" + defaults[0]["id"] + "/scope-mappings")
    if inherited.get("realmMappings") or inherited.get("clientMappings"):
        raise Refused("Service roles scope must not inherit additional role scopes")

    call(grants + owner, "POST", roles)
    call(scopes + "/clients/" + owner, "POST", roles)
    for path in (grants + owner, scopes + "/clients/" + owner):
        if {role["name"] for role in call(path + "/composite")} != expected:
            raise Refused("Service role assignment or scope readback failed")
