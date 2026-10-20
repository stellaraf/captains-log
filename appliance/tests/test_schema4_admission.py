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


if __name__ == "__main__":
    unittest.main()
