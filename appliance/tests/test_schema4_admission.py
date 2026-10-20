"""A source identity is not permission to package or activate schema 4."""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import assemble_release
import prepare_provenance
import stage_sources
from nebulalog_manager import update_enrollment
from nebulalog_manager.common import Refused
from nebulalog_manager.image_bundle import ApplicationSchema, RestoredAuthContract


class SchemaFourAdmissionTests(unittest.TestCase):
    def descriptor(self, source):
        return {"schema": 1, "product": "nebulalog", "sequence": 1, "schema_revision": "4",
                "source_commit": "a" * 40, "source_dirty": False,
                "source_snapshot_sha256": hashlib.sha256(source).hexdigest(), "bundle_manifest_sha256": "b" * 64,
                "qualification_status": "pending", "publisher": {"mode": "private-unsealed"}}

    def test_factory_capture_refuses_before_source_scan_or_output(self):
        for private in (True, False):
            with self.subTest(private=private), patch.object(prepare_provenance, "source_snapshot") as scan:
                with self.assertRaisesRegex(ValueError, "Schema 4 packaging"):
                    prepare_provenance.capture(Path("/not-read"), Path("/not-read"), Path("/not-written"),
                                               sequence=1, schema_revision="4", private_unsealed=private)
                scan.assert_not_called()

    def test_staging_cannot_adopt_manually_prepared_four_descriptor(self):
        source = b'{"schema":1,"files":{"example":"' + b'a' * 64 + b'"}}'
        for auth in (False, True):
            descriptor = self.descriptor(source)
            if auth:
                descriptor["restore_auth"] = {}
            with self.subTest(auth=auth), patch.object(stage_sources, "read_bounded",
                    side_effect=[source, json.dumps(descriptor).encode()]):
                with self.assertRaisesRegex(ValueError, "Schema 4 packaging"):
                    stage_sources.captured(Path("/fixture"))

    def test_release_recipe_refuses_four_before_artifacts(self):
        recipe = {"schema": 1, "repository": assemble_release.REPOSITORY, "sequence": 2, "version": "1.0.1",
                  "issued_at": "2026-10-19T00:00:00Z", "expires_at": "2026-10-20T00:00:00Z",
                  "schema_revision": "4", "source_commit": "a" * 40, "components": {}, "evidence_artifacts": []}
        with self.assertRaisesRegex(Refused, "Schema 4 packaging"):
            assemble_release.validate_recipe(recipe)

    def test_enrollment_refuses_before_bootstrap_can_read_schema_four(self):
        manager = update_enrollment.UpdateEnrollment(share=Path("/fixture"), runner=lambda *a, **kw: "")
        raw = json.dumps(self.descriptor(b"fixture")).encode()
        with patch.object(update_enrollment, "_read", return_value=raw) as read:
            with self.assertRaisesRegex(Refused, "Schema 4 activation"):
                manager._descriptor()
            self.assertEqual(read.call_count, 1)

    def qualification_descriptor(self):
        source = json.dumps({"schema": 1, "files": ApplicationSchema.SCHEMAS["4"]}).encode()
        value = self.descriptor(source)
        value.update(private_qualification=True, restore_auth={
            "schema": 1, "contract": RestoredAuthContract.CONTRACT, "version": "1.0.0",
            "artifacts": {name: {"bytes": 2, "sha256": "c" * 64} for name in RestoredAuthContract.EVIDENCE}})
        return source, value

    def test_private_capture_requires_opt_in_and_evidence_before_scanning(self):
        with patch.object(prepare_provenance, "source_snapshot") as scan:
            for revision, evidence, flag in (("4", None, True), ("3", Path("/not-read"), True),
                                              ("4", Path("/not-read"), 1)):
                with self.subTest(revision=revision, flag=flag), self.assertRaises(ValueError):
                    prepare_provenance.capture(Path("/not-read"), Path("/not-read"), Path("/not-written"),
                        sequence=1, schema_revision=revision, restore_auth_evidence=evidence, private_qualification=flag)
            scan.assert_not_called()

    def test_explicit_private_inputs_stage_but_do_not_authorize_sealing_or_default_admission(self):
        source, value = self.qualification_descriptor()
        raw = json.dumps(value).encode()
        with patch.object(stage_sources, "read_bounded", side_effect=[source, raw]):
            self.assertEqual(stage_sources.captured(Path("/fixture"))[1], value)
        manager = update_enrollment.UpdateEnrollment(share=Path("/fixture"), runner=lambda *a, **kw: "")
        with patch.object(update_enrollment, "_read", side_effect=[raw, source]):
            self.assertEqual(manager._descriptor(_qualification=True)[0], value)
        for call in (manager._descriptor, lambda: manager.verify_build_inputs(require_factory=True)):
            with patch.object(update_enrollment, "_read", return_value=raw) as reader:
                with self.assertRaisesRegex(Refused, "Schema 4 activation"):
                    call()
                self.assertEqual(reader.call_count, 1)

    def test_false_nonboolean_or_missing_evidence_private_marker_refuses(self):
        source, original = self.qualification_descriptor()
        for marker in (False, 1, "true", None):
            value = {**original, "private_qualification": marker}
            raw = json.dumps(value).encode()
            with self.subTest(marker=marker):
                with patch.object(stage_sources, "read_bounded", side_effect=[source, raw]), self.assertRaises(ValueError):
                    stage_sources.captured(Path("/fixture"))
                manager = update_enrollment.UpdateEnrollment(share=Path("/fixture"))
                with patch.object(update_enrollment, "_read", return_value=raw), self.assertRaises(Refused):
                    manager._descriptor(_qualification=True)
        del original["restore_auth"]
        with patch.object(stage_sources, "read_bounded", side_effect=[source, json.dumps(original).encode()]), self.assertRaises(ValueError):
            stage_sources.captured(Path("/fixture"))


if __name__ == "__main__":
    unittest.main()
