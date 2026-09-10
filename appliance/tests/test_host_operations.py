"""Pure host wire-schema tests; no host, service, executor or socket is used."""
import copy
import unittest

from nebulalog_manager.common import Refused
from nebulalog_manager.host_operations import parameters


RESOURCE = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"
OTHER = "03e32832-7874-4aa6-b1b2-a18f187e5943"
REVISION = "a" * 64
SCHEDULE = {
    "weekday": 6, "start": "03:00", "end": "05:00", "timezone": "UTC",
    "automatic_os_updates": True, "automatic_application_updates": False,
}
VALID = {
    "storage.grow": {"pool_id": RESOURCE},
    "storage.add_disk": {"pool_id": RESOURCE, "disk_id": OTHER},
    "updates.check": {"channel": "stable"},
    "updates.install": {"release_id": RESOURCE},
    "updates.rollback": {"transaction_id": RESOURCE},
    "updates.finalize": {"transaction_id": RESOURCE},
    "updates.schedule": SCHEDULE,
    "os.apply": {"policy_revision": REVISION},
    "reboot.complete": {"transaction_id": RESOURCE},
    "backup.create": {"recipient_id": RESOURCE, "scope": "configuration"},
    "restore.apply": {"backup_id": RESOURCE},
    "baseline.scan": {"selection_id": RESOURCE},
    "baseline.review": {"assessment_id": RESOURCE, "review_id": OTHER},
    "baseline.select": {"policy_id": RESOURCE, "baseline": "cis-level2"},
    "settings.network": {"network_configuration_id": RESOURCE},
    "settings.time": {"ntp_servers": ["time.example.invalid", "192.0.2.1", "2001:db8::123"], "timezone": "UTC"},
    "certificates.activate": {"certificate_id": RESOURCE, "target": "https"},
}


class HostOperationSchemaTests(unittest.TestCase):
    def test_supported_contract_examples_accept_only_data(self):
        for operation, values in VALID.items():
            original = copy.deepcopy(values)
            with self.subTest(operation=operation):
                self.assertEqual(parameters(operation, values), original)
                self.assertEqual(values, original)

    def test_unregistered_operations_cannot_be_used_as_command_dispatch(self):
        for operation in (None, True, 1, [], {}, "", "Storage.Grow", "storage.grow ",
                          "baseline.remediate", "shell", "systemctl restart httpd",
                          "../storage.grow", "/usr/bin/reboot", "updates.install;reboot"):
            with self.subTest(operation=operation), self.assertRaisesRegex(Refused, "operation_not_registered"):
                parameters(operation, {})

    def test_every_operation_rejects_missing_and_extra_fields(self):
        for operation, values in VALID.items():
            for omitted in values:
                candidate = {key: value for key, value in values.items() if key != omitted}
                with self.subTest(operation=operation, omitted=omitted), self.assertRaises(Refused):
                    parameters(operation, candidate)
            for extra in ("command", "script", "path", "url", "password", "token", "private_key", "secret_handle"):
                candidate = {**values, extra: "PRIVATE-FIXTURE-MUST-NOT-APPEAR-IN-ERROR"}
                with self.subTest(operation=operation, extra=extra), self.assertRaises(Refused) as caught:
                    parameters(operation, candidate)
                self.assertNotIn(candidate[extra], str(caught.exception))
            for candidate in (None, False, [], "{}", 1):
                with self.subTest(operation=operation, candidate=candidate), self.assertRaises(Refused):
                    parameters(operation, candidate)

    def test_resource_fields_require_canonical_opaque_uuid_not_paths_or_secrets(self):
        invalid = (RESOURCE.upper(), RESOURCE.replace("-", ""), "{" + RESOURCE + "}",
                   "urn:uuid:" + RESOURCE, " " + RESOURCE, RESOURCE + "\n", "", None,
                   True, 123, [], {}, "/etc/nebulalog/release-public.pem", "../backup",
                   "https://publisher.invalid/release", "registry.invalid/app:latest",
                   "-----BEGIN PRIVATE KEY-----\nTEST-ONLY-SECRET\n-----END PRIVATE KEY-----")
        for operation, values in VALID.items():
            for field in (key for key in values if key.endswith("_id")):
                for value in invalid:
                    with self.subTest(operation=operation, field=field, value=value), self.assertRaisesRegex(Refused, "invalid_resource_id"):
                        parameters(operation, {**values, field: value})

    def test_policy_revision_is_lowercase_sha256_not_an_arbitrary_revision(self):
        for value in (None, True, 1, {}, [], "", "a" * 63, "a" * 65, "A" * 64,
                      "g" * 64, "sha256:" + REVISION, "/etc/policy.json", REVISION + "\n"):
            with self.subTest(value=value), self.assertRaisesRegex(Refused, "invalid_digest"):
                parameters("os.apply", {"policy_revision": value})

    def test_choice_fields_do_not_expand_update_channel_backup_scope_or_target(self):
        cases = (
            ("updates.check", "channel", ("beta", "STABLE", "stable ", "https://release.invalid")),
            ("backup.create", "scope", ("all", "clickhouse", "configuration ", "/var/lib/nebulalog")),
            ("baseline.select", "baseline", ("cis-level1", "disabled", "CIS-LEVEL2", "../../profile")),
            ("certificates.activate", "target", ("all", "httpd", "https ", "/etc/pki/server.pem")),
        )
        for operation, field, values in cases:
            for value in (*values, True, 1, None, [], {}):
                with self.subTest(operation=operation, field=field, value=value), self.assertRaisesRegex(Refused, "invalid_choice"):
                    parameters(operation, {**VALID[operation], field: value})
        for baseline in ("cis-level2", "stig", "unified"):
            self.assertEqual(parameters("baseline.select", {"policy_id": RESOURCE, "baseline": baseline})["baseline"], baseline)
        for target in ("https", "syslog", "internal"):
            self.assertEqual(parameters("certificates.activate", {"certificate_id": RESOURCE, "target": target})["target"], target)

    def test_schedule_weekday_rejects_bool_float_and_out_of_range(self):
        for day in (0, 6):
            self.assertEqual(parameters("updates.schedule", {**SCHEDULE, "weekday": day})["weekday"], day)
        for day in (False, True, -1, 7, 1.0, "1", None, [], {}):
            with self.subTest(day=day), self.assertRaisesRegex(Refused, "invalid_weekday"):
                parameters("updates.schedule", {**SCHEDULE, "weekday": day})

    def test_schedule_flags_require_json_booleans(self):
        for field in ("automatic_os_updates", "automatic_application_updates"):
            for value in (0, 1, "true", "false", "yes", None, [], {}):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(Refused, "invalid_boolean"):
                    parameters("updates.schedule", {**SCHEDULE, field: value})

    def test_wall_times_are_exact_and_empty_window_refused_but_overnight_allowed(self):
        for field in ("start", "end"):
            for value in ("3:00", "24:00", "23:60", "00:00:00", "12:00Z", "12:00 ",
                          "12:00\n", "-1:00", "", None, True, 300, [], {}):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(Refused, "invalid_wall_time"):
                    parameters("updates.schedule", {**SCHEDULE, field: value})
        with self.assertRaisesRegex(Refused, "empty_maintenance_window"):
            parameters("updates.schedule", {**SCHEDULE, "start": "00:00", "end": "00:00"})
        overnight = {**SCHEDULE, "start": "23:59", "end": "00:00"}
        self.assertEqual(parameters("updates.schedule", overnight), overnight)

    def test_timezones_reject_paths_offsets_unknown_names_and_wrong_types(self):
        for operation in ("settings.time", "updates.schedule"):
            for value in ("/etc/localtime", "../UTC", "Etc/../../etc/passwd", "UTC\n", "UTC ",
                          "UTC+03:00", "NoSuch/HostJobTimezone", "A" * 129, None, True, 0, [], {}):
                with self.subTest(operation=operation, value=value), self.assertRaisesRegex(Refused, "invalid_timezone"):
                    parameters(operation, {**VALID[operation], "timezone": value})
            for value in ("UTC", "America/Phoenix"):
                self.assertEqual(parameters(operation, {**VALID[operation], "timezone": value})["timezone"], value)

    def test_ntp_requires_bounded_nonempty_list_of_strings(self):
        for value in (None, {}, (), "time.example.invalid", [], ["time.example.invalid"] * 9):
            with self.subTest(value=value), self.assertRaisesRegex(Refused, "invalid_time_servers"):
                parameters("settings.time", {"ntp_servers": value, "timezone": "UTC"})
        for value in (True, False, 0, 123, 2**32, 1.0, None, b"\xc0\x00\x02\x01", [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(Refused, "invalid_time_server"):
                parameters("settings.time", {"ntp_servers": [value], "timezone": "UTC"})
        eight = ["time%d.example.invalid" % index for index in range(8)]
        self.assertEqual(parameters("settings.time", {"ntp_servers": eight, "timezone": "UTC"})["ntp_servers"], eight)

    def test_ntp_refuses_duplicates_and_hostname_option_path_or_url_injection(self):
        with self.assertRaisesRegex(Refused, "duplicate_time_server"):
            parameters("settings.time", {"ntp_servers": ["192.0.2.1", "192.0.2.1"], "timezone": "UTC"})
        for value in ("", "https://time.example.invalid", "/etc/chrony.conf", "../pool",
                      "--config=malicious", "time.example.invalid iburst", "time.example.invalid\nserver other",
                      "time.example.invalid;reboot", "-time.example.invalid", "time-.example.invalid",
                      "time..example.invalid", "a" * 64 + ".example.invalid", ".".join(["a" * 63] * 4)):
            with self.subTest(value=value), self.assertRaises(Refused):
                parameters("settings.time", {"ntp_servers": [value], "timezone": "UTC"})

    def test_scoped_ipv6_cannot_smuggle_configuration_tokens(self):
        valid = {"ntp_servers": ["fe80::1%eth0"], "timezone": "UTC"}
        self.assertEqual(parameters("settings.time", valid), valid)
        for scope in ("eth0\nserver injected.example.invalid", "eth0 iburst", "eth0\tprefer",
                      "eth0\rserver injected.example.invalid", "eth0;reboot", "eth0#comment",
                      "eth0\x00extra", "../../etc/chrony.conf", "$(id)"):
            value = "fe80::1%" + scope
            with self.subTest(scope=scope), self.assertRaisesRegex(Refused, "invalid_time_server") as caught:
                parameters("settings.time", {"ntp_servers": [value], "timezone": "UTC"})
            self.assertNotIn(value, str(caught.exception))

    def test_validated_ntp_list_is_detached_from_request(self):
        requested = {"ntp_servers": ["time.example.invalid"], "timezone": "UTC"}
        validated = parameters("settings.time", requested)
        requested["ntp_servers"].append("changed.example.invalid")
        self.assertEqual(validated["ntp_servers"], ["time.example.invalid"])
        validated["ntp_servers"].append("validated.example.invalid")
        self.assertEqual(requested["ntp_servers"], ["time.example.invalid", "changed.example.invalid"])


if __name__ == "__main__":
    unittest.main()
