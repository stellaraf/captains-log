"""Identity ownership and monotonicity boundaries; live tokens are tested separately."""
import copy
import unittest

from nebulalog_manager.common import Refused
from nebulalog_manager.identity_sessions import invalidate_realm_sessions


class SessionInvalidationTests(unittest.TestCase):
    def setUp(self):
        self.realm = {"id": "realm-id", "realm": "nebulalog", "notBefore": 0,
                      "attributes": {"nebulalog.installation-id": "owned"}}
        self.writes = []
        self.cutoff = 1792480000

    def call(self, path, method="GET", body=None):
        if method == "GET":
            return copy.deepcopy(self.realm)
        self.writes.append((path, method, body))
        if method == "PUT":
            self.realm.update(body)

    def invoke(self, call=None, identity="owned", cutoff=None):
        return invalidate_realm_sessions(call or self.call, identity,
                                         self.cutoff if cutoff is None else cutoff)

    def test_foreign_identity_refused_without_writes(self):
        with self.assertRaises(Refused):
            self.invoke(identity="foreign")
        self.assertEqual(self.writes, [])

    def test_invalid_cutoff_refused_without_writes(self):
        for value in (True, "1792480000", -1, 0, 1577836799, 2**31):
            with self.subTest(value=value), self.assertRaises(Refused):
                self.invoke(cutoff=value)
        self.assertEqual(self.writes, [])

    def test_malformed_server_floor_refused(self):
        for previous in (None, "0", False, -1, 2**31):
            self.realm["notBefore"] = previous
            with self.subTest(previous=previous), self.assertRaises(Refused):
                self.invoke()
        self.assertEqual(self.writes, [])

    def test_unacknowledged_cutoff_is_not_session_invalidation(self):
        def ignored(path, method="GET", body=None):
            if method == "GET":
                return self.call(path)
            self.writes.append((path, method, body))
        with self.assertRaisesRegex(Refused, "readback"):
            self.invoke(ignored)
        self.assertEqual([method for _, method, _ in self.writes], ["PUT"])

    def test_changed_owner_after_write_never_logs_out_foreign_realm(self):
        def changed(path, method="GET", body=None):
            result = self.call(path, method, body)
            if method == "PUT":
                self.realm["attributes"]["nebulalog.installation-id"] = "foreign"
            return result
        with self.assertRaisesRegex(Refused, "readback"):
            self.invoke(changed)
        self.assertEqual([method for _, method, _ in self.writes], ["PUT"])

    def test_lost_write_acknowledgement_can_retry_same_floor(self):
        def lost(path, method="GET", body=None):
            result = self.call(path, method, body)
            if method == "PUT":
                raise OSError("Lost response after committed write")
            return result
        with self.assertRaises(OSError):
            self.invoke(lost)
        result = self.invoke()
        self.assertTrue(result["api_cutoff_required"])
        self.assertFalse(result["locally_verified_tokens_revoked"])
        self.assertEqual(result["token_not_before"], self.cutoff)

    def test_lost_logout_acknowledgement_is_not_reported_as_success(self):
        def lost(path, method="GET", body=None):
            result = self.call(path, method, body)
            if path == "logout-all":
                raise OSError("Lost logout acknowledgement")
            return result
        with self.assertRaises(OSError):
            self.invoke(lost)
        self.assertEqual(self.invoke()["token_not_before"], self.cutoff)

    def test_newer_policy_requires_replanned_durable_intent(self):
        self.realm["notBefore"] = self.cutoff + 20
        with self.assertRaisesRegex(Refused, "durable intent"):
            self.invoke()
        self.assertEqual(self.writes, [])
        self.assertEqual(self.invoke(cutoff=self.cutoff + 20)["token_not_before"], self.cutoff + 20)

    def test_vendor_logout_clock_advances_effective_api_floor(self):
        def server(path, method="GET", body=None):
            result = self.call(path, method, body)
            if path == "logout-all":
                self.realm["notBefore"] = self.cutoff + 10
            return result
        self.assertEqual(self.invoke(server)["token_not_before"], self.cutoff + 10)
        self.assertEqual(self.realm["notBefore"], self.cutoff + 10)

    def test_vendor_logout_cannot_leave_a_lower_floor_on_success(self):
        def server(path, method="GET", body=None):
            result = self.call(path, method, body)
            if path == "logout-all":
                self.realm["notBefore"] = self.cutoff - 10
            return result
        self.assertEqual(self.invoke(server)["token_not_before"], self.cutoff)
        self.assertEqual(self.realm["notBefore"], self.cutoff)
        self.assertEqual([method for _, method, _ in self.writes], ["PUT", "POST", "PUT"])

    def test_lost_logout_ack_with_advanced_clock_reconciles_on_retry(self):
        def lost(path, method="GET", body=None):
            result = self.call(path, method, body)
            if path == "logout-all":
                self.realm["notBefore"] = self.cutoff + 10
                raise OSError("Lost logout acknowledgement")
            return result
        with self.assertRaises(OSError):
            self.invoke(lost)
        with self.assertRaisesRegex(Refused, "durable intent"):
            self.invoke()
        self.assertEqual(self.invoke(cutoff=self.cutoff + 10)["token_not_before"], self.cutoff + 10)

    def test_owner_change_during_logout_prevents_repair_write(self):
        def changed(path, method="GET", body=None):
            result = self.call(path, method, body)
            if path == "logout-all":
                self.realm["notBefore"] = 0
                self.realm["attributes"]["nebulalog.installation-id"] = "foreign"
            return result
        with self.assertRaises(Refused):
            self.invoke(changed)
        self.assertEqual([method for _, method, _ in self.writes], ["PUT", "POST"])


if __name__ == "__main__":
    unittest.main()
