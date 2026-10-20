"""Keycloak session invalidation within an externally held maintenance window."""
from .common import Refused


def invalidate_realm_sessions(call, installation_id, cutoff):
    """Reconcile session invalidation and return the effective issuance floor.

    The caller serializes identity maintenance, persists its requested cutoff
    before dispatch, keeps access fenced on uncertainty, and durably applies
    the returned (possibly newer) floor to every API and rollback before
    releasing maintenance. Locally verified JWTs need that separate API floor.

    Keycloak logout-all replaces notBefore with its server clock. Reconcile
    that side effect without discarding either the requested or observed floor.
    Lost acknowledgements are uncertain. A newer observed floor requires
    persisting a revised intent before retrying while fenced.
    """
    if (not isinstance(installation_id, str) or not installation_id
            or type(cutoff) is not int or not 1577836800 <= cutoff < 2**31):
        raise Refused("Session invalidation requires an installation identity and canonical cutoff")
    realm = call("")
    identity = realm.get("id")
    if not isinstance(identity, str) or not identity:
        raise Refused("Session invalidation requires a realm identity")

    def inspect(observed):
        if (observed.get("id") != identity or observed.get("realm") != "nebulalog"
                or observed.get("attributes", {}).get("nebulalog.installation-id") != installation_id):
            raise Refused("Session invalidation ownership readback failed")
        floor = observed.get("notBefore")
        if type(floor) is not int or not 0 <= floor < 2**31:
            raise Refused("Session invalidation cutoff readback is malformed")
        return floor

    def write_verify(floor):
        call("", "PUT", {"notBefore": floor})
        if inspect(call("")) != floor:
            raise Refused("Session invalidation cutoff readback failed")

    previous = inspect(realm)
    if previous > cutoff:
        # Do not invoke logout with a stronger boundary known only in RAM:
        # the vendor can lower it and lose the response. The caller must first
        # persist a revised intent, then retry with at least this boundary.
        raise Refused("Session invalidation needs a durable intent for the newer realm cutoff")
    effective = cutoff
    write_verify(effective)
    call("logout-all", "POST")
    observed = inspect(call(""))
    # The vendor may move the floor forwards or backwards (clock skew or a
    # previously future-dated policy). Access remains fenced through repair.
    if observed < effective:
        write_verify(effective)
    else:
        effective = observed
    return {"realm_id": identity, "token_not_before": effective,
            "api_cutoff_required": True, "locally_verified_tokens_revoked": False}
