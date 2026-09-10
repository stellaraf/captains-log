"""AIDE report/configuration contract tests; no executable or host is used."""
import copy
import json
import unittest
from unittest.mock import patch

from nebulalog_manager.aide_report import parse_report, render_config
from nebulalog_manager.common import Refused


DATABASE = "/var/lib/nebulalog/manager/aide/baseline.db.gz"
CANDIDATE = "/var/lib/nebulalog/manager/aide/candidate.db.gz"
SECRET = "PRIVATE-REPORT-FIXTURE-MUST-NOT-APPEAR"
POLICY = """# Fixed appliance policy.
NEBULA = p+ftype+l+u+g+s+m+c+sha512+acl+selinux+xattrs
/etc NEBULA
/usr NEBULA
-/var/lib/nebulalog/manager/aide(/.*)?
"""


def report(mask=0, action="check"):
    value = {
        "aide_version": "0.19.2", "start_time": "2026-09-07 10:00:00 +0000",
        "end_time": "2026-09-07 10:00:02 +0000", "run_time_seconds": 2,
        "outline": "AIDE found NO differences between database and filesystem. Looks okay!!",
        "number_of_entries": {"total": 12},
        "databases": {DATABASE: {"sha512": "a" * 128}},
    }
    if mask:
        value["outline"] = "AIDE found differences between database and filesystem!!"
        for name, bit in (("added", 1), ("removed", 2), ("changed", 4)):
            count = 1 if mask & bit else 0
            value["number_of_entries"][name] = count
            if count:
                value[name] = {"/etc/" + name: "f+++++++++++++++"}
    if action == "init":
        value["outline"] = "AIDE successfully initialized database."
        value["new_database"] = CANDIDATE
        value["databases"] = {CANDIDATE: {"sha512": "b" * 128}}
    return value


class AideReportTests(unittest.TestCase):
    def parse(self, value, code=0, action="check", expected=None):
        return parse_report(json.dumps(value), "", code, action, expected)

    def test_clean_report_omits_change_counts_and_returns_only_sanitized_fields(self):
        value = report()
        value["private_extra"] = SECRET
        actual = self.parse(value, expected=DATABASE)
        self.assertEqual(actual, {"state": "clean", "exit_code": 0,
                                 "counts": {"total": 12, "added": 0, "removed": 0, "changed": 0},
                                 "aide_version": "0.19.2"})
        self.assertNotIn(SECRET, json.dumps(actual))
        self.assertNotIn(DATABASE, json.dumps(actual))

    def test_every_finding_exit_mask_matches_counts_and_groups(self):
        for mask in range(1, 8):
            with self.subTest(mask=mask):
                value = report(mask)
                result = self.parse(value, mask)
                self.assertEqual(result["state"], "differences")
                self.assertEqual(result["counts"], value["number_of_entries"])
                self.assertEqual(result["exit_code"], mask)

    def test_initialization_requires_matching_new_database(self):
        value = report(action="init")
        self.assertEqual(self.parse(value, action="init", expected=CANDIDATE)["state"], "initialized")
        for expected in (None, DATABASE):
            with self.subTest(expected=expected), self.assertRaises(Refused):
                self.parse(value, action="init", expected=expected)
        value["new_database"] = SECRET
        with self.assertRaises(Refused) as caught:
            self.parse(value, action="init", expected=CANDIDATE)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_operational_exits_and_non_integer_codes_refuse(self):
        for code in (-15, -1, 8, 13, *range(14, 26), 255, True, False, 0.0, "0", None):
            with self.subTest(code=code), self.assertRaisesRegex(Refused, "did not complete"):
                self.parse(report(), code)
        with self.assertRaisesRegex(Refused, "initialization did not complete"):
            self.parse(report(1), 1, "init", CANDIDATE)

    def test_stderr_diagnostics_never_become_clean_and_are_redacted(self):
        for diagnostic in (SECRET, "WARNING: " + SECRET, "\x1b[31m" + SECRET, None, 0):
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(Refused, "diagnostics") as caught:
                parse_report(json.dumps(report()), diagnostic, 0, "check")
            self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(parse_report(json.dumps(report()), " \n\t", 0, "check")["state"], "clean")

    def test_malformed_json_duplicate_keys_constants_and_wrong_types_refuse(self):
        cases = ("", SECRET, "null", "[]", "true", "{} {}", '{"aide_version":"0.19.2","aide_version":"0.19.2"}',
                 json.dumps(report())[:-1], json.dumps(report())[:-1] + ',"private":NaN}',
                 json.dumps(report())[:-1] + ',"private":' + "9" * 1000 + '}',
                 "[" * 1500 + "]" * 1500, None, {}, b"{}")
        for raw in cases:
            with self.subTest(raw=str(raw)[:70]), self.assertRaises(Refused) as caught:
                parse_report(raw, "", 0, "check")
            self.assertNotIn(SECRET, str(caught.exception))
        with patch("nebulalog_manager.aide_report.MAX_REPORT_CHARS", 8), self.assertRaises(Refused):
            self.parse(report())

    def test_required_metadata_and_pinned_version(self):
        for field in ("aide_version", "number_of_entries", "start_time", "end_time", "outline", "run_time_seconds"):
            value = report()
            del value[field]
            with self.subTest(field=field), self.assertRaises(Refused):
                self.parse(value)
        for version in ("0.16", "0.19.3", "0.19.2-custom", None, 192, True):
            value = report()
            value["aide_version"] = version
            with self.subTest(version=version), self.assertRaises(Refused):
                self.parse(value)

    def test_counts_are_strict_nonnegative_integers_and_total_is_positive(self):
        for field in ("total", "added", "removed", "changed"):
            for bad in (True, False, -1, 0.1, "1", None, 1 << 63):
                value = report(7)
                value["number_of_entries"][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(Refused):
                    self.parse(value, 7)
        for action in ("check", "init"):
            value = report(action=action)
            value["number_of_entries"]["total"] = 0
            with self.subTest(action=action), self.assertRaisesRegex(Refused, "no monitored"):
                self.parse(value, action=action, expected=CANDIDATE if action == "init" else None)

    def test_partial_or_unknown_counts_and_exit_disagreement_refuse(self):
        for counts in (None, [], {"total": 12, "added": 0}, {"total": 12, "unknown": 0}):
            value = report()
            value["number_of_entries"] = counts
            with self.subTest(counts=counts), self.assertRaises(Refused):
                self.parse(value)
        for report_mask in range(8):
            for exit_mask in range(8):
                if report_mask != exit_mask:
                    with self.subTest(report_mask=report_mask, exit_mask=exit_mask), self.assertRaises(Refused):
                        self.parse(report(report_mask), exit_mask)

    def test_finding_groups_must_be_complete_and_match_fixed_rendered_format(self):
        for change in (None, [], ["/etc/added"], {}, {"relative": "f+++"}, {"/etc/added": 1},
                       {"/etc/added": ""}, {"/etc/added": "f+++", "/etc/extra": "f+++"}):
            value = report(1)
            value["added"] = change
            with self.subTest(change=change), self.assertRaises(Refused):
                self.parse(value, 1)
        value = report(1)
        del value["added"]
        with self.assertRaises(Refused):
            self.parse(value, 1)
        value = report(3)
        value["removed"] = copy.deepcopy(value["added"])
        with self.assertRaises(Refused):
            self.parse(value, 3)

    def test_wrong_action_or_unexpected_output_database_refuse(self):
        for action in ("update", "compare", "config-check", "CHECK", None, [], True):
            with self.subTest(action=action), self.assertRaises(Refused):
                self.parse(report(), action=action)
        with self.assertRaises(Refused):
            self.parse(report(action="init"), expected=DATABASE)
        with self.assertRaises(Refused):
            self.parse(report(), expected=CANDIDATE)
        value = report()
        value["entries"] = {}
        with self.assertRaises(Refused):
            self.parse(value)

    def test_changed_attribute_selection_cannot_be_reported_as_clean(self):
        value = report()
        value["different_attributes"] = {"/etc/private": "sha512-sha256"}
        with self.assertRaisesRegex(Refused, "monitored attributes differ"):
            self.parse(value)


class AideConfigTests(unittest.TestCase):
    def test_fixed_modern_config_and_report_options_precede_destination(self):
        config = render_config(POLICY, DATABASE, CANDIDATE)
        self.assertEqual(config, render_config(POLICY, DATABASE, CANDIDATE))
        lines = config.splitlines()
        for directive in ("database_in=file:" + DATABASE, "database_out=file:" + CANDIDATE,
                          "gzip_dbout=yes", "database_attrs=sha512", "report_format=json",
                          "report_level=list_entries", "report_grouped=yes", "report_summarize_changes=yes",
                          "report_quiet=no", "report_append=no"):
            self.assertIn(directive, lines)
        destination = lines.index("report_url=stdout")
        self.assertEqual(sum(line.startswith("report_url=") for line in lines), 1)
        self.assertTrue(all(i < destination for i, line in enumerate(lines)
                            if line.startswith("report_") and not line.startswith("report_url=")))
        self.assertNotIn("database=", config)
        self.assertNotIn("@@", config)
        self.assertTrue(config.endswith(POLICY))

    def test_database_paths_cannot_inject_config_or_select_nonlocal_urls(self):
        for path in (None, True, "", "relative", "file:/path", "https://example.invalid/db", "/a/../b",
                     "/a/./b", "/a//b", "/a/", "/", "/a\nreport_url=stdout", "/a b", "/a@@{V}",
                     "/a\\b", "/a%20b", "/a#b", "/a?b"):
            for incoming in (True, False):
                with self.subTest(path=path, incoming=incoming), self.assertRaises(Refused):
                    render_config(POLICY, path if incoming else DATABASE, CANDIDATE if incoming else path)
        with self.assertRaises(Refused):
            render_config(POLICY, DATABASE, DATABASE)

    def test_policy_cannot_override_reports_paths_or_execute_includes(self):
        for suffix in ("@@include /etc/other", "@@x_include /usr/bin/program", "database_out=file:/tmp/leak",
                       "report_url=file:/tmp/leak", "root_prefix=/tmp", "report_format=plain", "/etc NEBULA\\",
                       "SECRET = expression with spaces", "/etc NEBULA\r", "/etc NEBULA\0"):
            with self.subTest(suffix=suffix), self.assertRaises(Refused):
                render_config(POLICY + suffix, DATABASE, CANDIDATE)
        for policy in (None, True, "", "# comments only", "-/tmp", "NEBULA = sha512"):
            with self.subTest(policy=policy), self.assertRaises(Refused):
                render_config(policy, DATABASE, CANDIDATE)


if __name__ == "__main__":
    unittest.main()
