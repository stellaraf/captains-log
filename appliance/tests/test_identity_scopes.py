"""Refusal cases complement the real Keycloak service-account qualification."""
import unittest

from nebulalog_manager.common import Refused
from nebulalog_manager.identity_scopes import configure_service_roles


class ServiceScopeTests(unittest.TestCase):
    def setUp(self):
        self.writes = []
        self.role = {"name": "view-realm", "id": "role-id", "containerId": "management", "composite": False}
        self.responses = {
            "clients/service": {"enabled": False, "fullScopeAllowed": False},
            "client-scopes": [{"id": "roles-scope", "name": "roles"}],
            "clients?clientId=realm-management": [{"id": "management"}],
            "clients?clientId=nebulalog": [{"id": "application"}],
            "clients/service/service-account-user": {"id": "user"},
            "users/user/role-mappings/clients/management/composite": [self.role],
            "users/user/role-mappings/clients/application/composite": [],
            "clients/management/roles/view-realm": self.role,
            "clients/service/scope-mappings": {},
            "clients/service/default-client-scopes": [{"id": "roles-scope", "name": "roles"}],
            "clients/service/optional-client-scopes": [],
            "client-scopes/roles-scope/scope-mappings": {},
            "clients/service/scope-mappings/clients/management/composite": [self.role],
        }

    def call(self, path, method="GET", body=None):
        if method != "GET":
            self.writes.append((path, method, body))
            return None
        return self.responses[path]

    def configure(self):
        configure_service_roles(self.call, "service", {"view-realm"})

    def test_effective_privilege_escalation_refused_before_grants(self):
        self.responses["users/user/role-mappings/clients/management/composite"] += [{"name": "manage-users"}]
        with self.assertRaises(Refused):
            self.configure()
        self.assertFalse(any(method == "POST" for _, method, _ in self.writes))

    def test_inherited_role_scopes_are_not_implicitly_trusted(self):
        for mappings in ({"realmMappings": [{"name": "realm-admin"}]},
                         {"clientMappings": {"foreign": {"id": "foreign", "mappings": [{"name": "admin"}]}}}):
            with self.subTest(mappings=mappings):
                self.responses["client-scopes/roles-scope/scope-mappings"] = mappings
                with self.assertRaises(Refused):
                    self.configure()
                self.assertFalse(any(method == "POST" for _, method, _ in self.writes))

    def test_foreign_explicit_scope_is_refused(self):
        self.responses["clients/service/scope-mappings"] = {
            "clientMappings": {"other": {"id": "other", "mappings": [{"name": "view-realm"}]}}}
        with self.assertRaises(Refused):
            self.configure()
        self.assertFalse(any(method == "POST" for _, method, _ in self.writes))

    def test_vendor_role_becoming_composite_requires_review(self):
        self.role["composite"] = True
        with self.assertRaises(Refused):
            self.configure()
        self.assertFalse(any(method == "POST" for _, method, _ in self.writes))

    def view_clients(self):
        parent = {**self.role, "name": "view-clients", "composite": True}
        child = {**self.role, "name": "query-clients", "id": "child-id"}
        self.responses["clients/management/roles/view-clients"] = parent
        self.responses["clients/management/roles/view-clients/composites"] = [child]
        for path in ("users/user/role-mappings/clients/management/composite",
                     "clients/service/scope-mappings/clients/management/composite"):
            self.responses[path] = [parent, child]
        return child

    def test_known_read_only_composite_is_supported(self):
        self.view_clients()
        configure_service_roles(self.call, "service", {"view-clients"})

    def test_new_child_of_a_known_composite_requires_review(self):
        self.view_clients()
        self.responses["clients/management/roles/view-clients/composites"].append(
            {**self.role, "name": "manage-clients"})
        with self.assertRaisesRegex(Refused, "children changed"):
            configure_service_roles(self.call, "service", {"view-clients"})
        self.assertFalse(any(method == "POST" for _, method, _ in self.writes))

    def test_unacknowledged_scope_write_is_not_success(self):
        self.responses["clients/service/scope-mappings/clients/management/composite"] = []
        with self.assertRaisesRegex(Refused, "readback"):
            self.configure()
        self.assertEqual(sum(method == "POST" for _, method, _ in self.writes), 2)

    def test_enabled_or_broad_client_is_never_configured(self):
        for client in ({"enabled": True, "fullScopeAllowed": False},
                       {"enabled": False, "fullScopeAllowed": True}):
            with self.subTest(client=client):
                self.responses["clients/service"] = client
                with self.assertRaises(Refused):
                    self.configure()
                self.assertEqual(self.writes, [])


if __name__ == "__main__":
    unittest.main()
