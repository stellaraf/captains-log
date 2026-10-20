"""AIDE acceptance/recovery with real files and vendor-format retained DB bytes.

Scans, native restore admission, storage and SELinux metadata are injected.
The production DB parser and retained-history validator are not mocked.
"""
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from nebulalog_manager import aide_updates as updates, ordinary_boot_metadata as database
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import digest
import test_aide_updates as fixture
import test_ordinary_boot_metadata as db_fixture


class IdentityCutoffAideTests(unittest.TestCase):
    for _name, _method in fixture.AuthorizedAideTests.__dict__.items():
        if callable(_method) and not _name.startswith(("test_", "__")):
            locals()[_name] = _method

    def snapshot_files(self):
        result = {}
        for path in self.monitored:
            if not path.exists():
                continue
            info = path.lstat()
            row = db_fixture.fixture_row(str(path))
            directory = stat.S_ISDIR(info.st_mode)
            raw = b"" if directory else path.read_bytes()
            row.update(perm=format(info.st_mode, "o"), uid=str(info.st_uid), gid=str(info.st_gid),
                       size="0" if directory else str(len(raw)), inode=str(info.st_ino),
                       ctime=str(int(info.st_ctime)), mtime=str(int(info.st_mtime)),
                       lcount="0" if directory else "1",
                       sha512="0" if directory else base64.b64encode(hashlib.sha512(raw).digest()).decode())
            if directory:
                row.update(attr=str(database.EFI_DIRECTORY_MASK), acl="0")
            else:
                row["acl"] = "POSIX," + db_fixture.b64(b"user::rw-\ngroup::---\nother::---\n") + ",0"
            row.update(getattr(self, "row_overrides", {}).get(str(path), {}))
            result[str(path)] = row
        return result

    def encode_snapshot(self, value):
        return db_fixture.compressed(db_fixture.text_database([value[path] for path in sorted(value)]))

    def decode_snapshot(self, raw):
        # The fake scanner compares rows. Production history later reparses
        # these bytes with its bounded header/spec/row/EOF validator.
        lines = gzip.decompress(raw).splitlines()
        return {row["name"]: row for row in
                (dict(zip(database.FIELDS, line.decode().split(" "))) for line in lines[4:-1])}

    def cutoff_fixture(self):
        p = patch.object(updates, "CONFIGURATION", self.root / "configuration")
        p.start(); self.addCleanup(p.stop)
        self.authorized_fixture(api=True)
        self.api = self.unrelated
        self.original_api = self.api.read_bytes()
        self.after_api = self.original_api + b"OIDC_TOKEN_NOT_BEFORE=1800000000\n"
        self.prepare_update()
        self.original_prepared = {p: p.read_bytes() for p in (self.state / "authorized/prepared").glob("*.json")}
        self.write_private(self.stage / "adapter-database-restore-complete.json", b"{}\n")
        self.native_calls = []

        def verified(life, stage, before, after):
            self.native_calls.append((stage, before, after))
            self.assertEqual(stage, self.stage)
            self.assertEqual(life.data, self.identity.root)
            self.assertEqual(life.configuration, updates.CONFIGURATION)
            # This fixture injects only native restore admission. File
            # descriptors and hashes still derive from the actual API bytes.
            self.assertEqual(before, self.plan["preserved"][0])
            self.assertEqual(after, {"path": str(self.api), **self.desc(self.api)})
            return {"schema": 1, "kind": "restored-api-cutoff-v1",
                    "operation": hashlib.sha256((str(stage) + "/identity/rollback").encode()).hexdigest(),
                    "installation_id": self.identity.installation_id, "before": before, "after": after,
                    "before_sha512": hashlib.sha512(self.original_api).hexdigest(),
                    "after_sha512": hashlib.sha512(self.after_api).hexdigest(),
                    "configuration_sha256": hashlib.sha256(self.original_api).hexdigest(),
                    "token_not_before": 1800000000, "completion_sha256": "a" * 64,
                    "maintenance_release_authorized": False}
        p = patch("nebulalog_adapters.identity_maintenance.verify_restore_api_preservation", side_effect=verified)
        self.verifier = p.start(); self.addCleanup(p.stop)

    def restore(self):
        self.runtime.write_bytes(b"old managed\n")
        self.selection.write_bytes(b"restored selection highwater\n")
        replacement = self.api.with_suffix(".new")
        self.write_private(replacement, self.after_api)
        replacement.replace(self.api)

    def latest(self):
        pointer = json.loads((self.state / "authorized/head.json").read_text())
        path = self.state / "authorized/entries" / (pointer["id"] + ".json")
        return path, json.loads(path.read_text())

    def test_cutoff_acceptance_preserves_preparation_and_replays_without_live_journal(self):
        self.cutoff_fixture(); self.restore()
        result = self.accept_update("rollback")
        self.assertTrue(result["ok"])
        path, entry = self.latest()
        self.assertEqual(entry["api_cutoff"]["proof"]["after"]["sha256"], hashlib.sha256(self.after_api).hexdigest())
        self.assertNotIn(self.original_api.decode(), path.read_text())
        self.assertFalse(self.accept_update("rollback")["baseline_changed"])
        self.assertEqual(self.scan_calls.count("update"), 1)
        for p, raw in self.original_prepared.items(): self.assertEqual(p.read_bytes(), raw)
        self.verifier.side_effect = AssertionError("Historical verification cannot consult live restore state")
        self.assertEqual(self.manager.check()["state"], "clean")
        self.assert_original()

    def test_forward_cannot_claim_cutoff_and_unrelated_file_is_not_authorized(self):
        self.cutoff_fixture(); self.activate()
        self.api.write_bytes(self.after_api)
        with self.assertRaisesRegex(Refused, "live_file_not_authorized"): self.accept_update()
        self.assertEqual(self.native_calls, [])
        self.restore()
        extra = self.root / "unrelated-extra"; self.write_private(extra, b"foreign\n"); self.monitored.append(extra)
        with self.assertRaisesRegex(Refused, "unrelated_integrity_change"): self.accept_update("rollback")
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)

    def test_live_admission_failure_and_incomplete_restore_do_not_scan(self):
        self.cutoff_fixture(); self.restore()
        self.verifier.side_effect = Refused("Foreign restore receipt")
        with self.assertRaisesRegex(Refused, "Foreign restore"): self.accept_update("rollback")
        (self.stage / "adapter-database-restore-complete.json").unlink()
        with self.assertRaisesRegex(Refused, "cutoff_restore_incomplete"): self.accept_update("rollback")
        self.assertEqual(self.scan_calls.count("update"), 0)

    def test_wrong_api_bytes_cannot_be_accepted_with_claimed_cutoff_hash(self):
        self.cutoff_fixture(); self.restore()
        self.api.write_bytes(self.after_api.replace(b"nebulalog", b"foreign"))
        with self.assertRaisesRegex(Refused, "cutoff_database_content_changed"): self.accept_update("rollback")
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)

    def test_retained_output_metadata_change_is_rejected_even_if_scan_claims_clean(self):
        self.cutoff_fixture(); self.restore()
        self.row_overrides = {str(self.api): {"acl": "POSIX," + db_fixture.b64(b"user::r--\ngroup::---\nother::---\n") + ",0"}}
        with self.assertRaisesRegex(Refused, "cutoff_database_metadata_changed"): self.accept_update("rollback")
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)

    def test_interruption_after_database_replacement_reuses_same_authorization(self):
        self.cutoff_fixture(); self.restore()
        replace = updates._replace_current
        def lost(*args):
            replace(*args)
            raise OSError("Lost database replacement acknowledgement")
        with patch.object(updates, "_replace_current", lost), self.assertRaises(OSError):
            self.accept_update("rollback")
        pending = json.loads((self.state / "authorized/pending.json").read_text())
        self.assertEqual(pending["state"], "ready")
        self.assertEqual(pending["api_cutoff"], pending["proposed_entry"]["api_cutoff"])
        self.assertTrue(self.accept_update("rollback")["ok"])
        self.assertEqual(self.latest()[1]["api_cutoff"], pending["api_cutoff"])
        self.assertEqual(self.scan_calls.count("update"), 1)
        self.assertEqual(self.manager.check()["state"], "clean")

    def test_scanning_retry_refuses_changed_authorization_before_another_scan(self):
        self.cutoff_fixture(); self.restore()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError("scan lost")) if action == "update" else None
        with self.assertRaises(OSError): self.accept_update("rollback")
        self.scan_hook = None
        original = self.verifier.side_effect
        self.verifier.side_effect = lambda *a: {**original(*a), "completion_sha256": "b" * 64}
        with self.assertRaisesRegex(Refused, "pending_cutoff_changed"): self.accept_update("rollback")
        self.assertEqual(self.scan_calls.count("update"), 1)
        self.verifier.side_effect = original
        self.assertTrue(self.accept_update("rollback")["ok"])

    def test_forward_then_rollback_and_lost_forward_publication_keep_correct_lineage(self):
        self.cutoff_fixture(); self.activate()
        replace = updates._replace_current
        def lost(*args):
            replace(*args)
            raise OSError("Lost forward publication")
        with patch.object(updates, "_replace_current", lost), self.assertRaises(OSError):
            self.accept_update()
        self.restore()
        self.assertTrue(self.accept_update("rollback")["ok"])
        entries = [json.loads(p.read_text()) for p in (self.state / "authorized/entries").glob("*.json")]
        self.assertEqual(len(entries), 2)
        self.assertNotIn("api_cutoff", next(e for e in entries if e["direction"] == "forward"))
        self.assertIn("api_cutoff", next(e for e in entries if e["direction"] == "rollback"))
        self.assertEqual(self.manager.check()["state"], "clean")

    def test_history_rejects_forged_cutoff_even_with_rehashed_entry(self):
        self.cutoff_fixture(); self.restore(); self.accept_update("rollback")
        path, saved = self.latest()
        head = self.state / "authorized/head.json"
        for change in ("before", "after_sha512", "prepared", "installation", "stage", "phase", "null"):
            with self.subTest(change=change):
                entry = copy.deepcopy(saved)
                value = entry["api_cutoff"]
                if change == "before": value["proof"]["before"]["sha256"] = "b" * 64
                if change == "after_sha512": value["proof"]["after_sha512"] = "b" * 128
                if change == "prepared": value["prepared"]["sha256"] = "b" * 64
                if change == "installation": value["installation_id"] = "00000000-0000-4000-8000-000000000000"
                if change == "stage": value["stage"] = str(self.stage / "foreign")
                if change == "phase": entry["direction"] = "forward"
                if change == "null": entry["api_cutoff"] = None
                self.write_private(path, json.dumps(entry).encode())
                self.write_private(head, json.dumps(updates._pointer(entry)).encode())
                with self.assertRaises(Refused): updates._chain(self.manager, self.state, self.identity, self.base)
        self.write_private(path, json.dumps(saved).encode())
        self.write_private(head, json.dumps(updates._pointer(saved)).encode())
        self.assertEqual(self.manager.check()["state"], "clean")
