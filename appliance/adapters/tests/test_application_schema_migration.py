"""Actual PG17 catalog/transaction tests; Podman/systemd are injected transport.

Every test creates a unique database in the explicitly selected, labelled test
container. This does not qualify native Podman execution or an appliance update.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch

from nebulalog_adapters import lifecycle
from nebulalog_manager.image_bundle import ApplicationSchema
from nebulalog_manager.common import Refused


class FixedSchemaSQLTests(unittest.TestCase):
    def test_exact_source_bytes_and_tamper_refusal(self):
        old, suffix, stepup = ApplicationSchema.reviewed_sql()
        root = Path(__file__).resolve().parents[3]
        self.assertEqual((old + suffix).encode(), (root / 'migrations/postgres.sql').read_bytes())
        self.assertEqual(stepup.encode(), (root / 'migrations/host_stepup.sql').read_bytes())
        with patch.object(ApplicationSchema, 'ADDITIVE_POSTGRES_SQL', suffix + '\n'):
            with self.assertRaises(Refused): ApplicationSchema.reviewed_sql()


@unittest.skipUnless(os.environ.get('CAPTAINSLOG_GATE_TEST_CONTAINER'), 'isolated PostgreSQL fixture not selected')
class ApplicationSchemaPostgresTests(unittest.TestCase):
    def setUp(self):
        self.container = os.environ['CAPTAINSLOG_GATE_TEST_CONTAINER']
        labels = json.loads(subprocess.check_output(['docker', 'inspect', '--format', '{{json .Config.Labels}}', self.container]))
        self.assertEqual(labels.get('captainslog.fixture'), 'emergency-destructive')
        self.database = 'captainslog_schema_' + uuid.uuid4().hex
        self.psql('CREATE DATABASE ' + self.database, database='emergency_test')
        self.addCleanup(lambda: self.psql('DROP DATABASE ' + self.database + ' WITH (FORCE)', database='emergency_test'))
        self.psql(ApplicationSchema.reviewed_sql()[0])
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.stage = self.root / 'manager/updates/releases/1-schema'
        self.stage.mkdir(parents=True)
        self.configuration = self.root / 'configuration'
        (self.configuration / 'runtime').mkdir(parents=True)
        (self.configuration / 'runtime/postgresql.env').write_text('POSTGRES_PASSWORD=synthetic-unused\n')
        (self.configuration / 'runtime/postgresql.env').chmod(0o600)
        self.release = {'components': {'nebulalog': {'schema_revision': '2',
            'schema_sha256': ApplicationSchema.schema_digest('2'), 'rollback_safe': True,
            'database_migration': ApplicationSchema.ADDITIVE_UPGRADE}}, 'artifacts': []}
        self.write(self.stage / 'manifest.json', self.release)
        self.write(self.stage.parent.parent / 'transaction.json', {'release': str(self.stage),
            'manifest_sha256': self.sha(self.stage / 'manifest.json')})
        (self.stage / 'recovery').mkdir()
        self.write(self.stage / 'adapter-backup-inventory.json', {'owners': {'nebulalog': 'emergency_test'}, 'files': []})
        self.write(self.stage / 'adapter-backup.json', {'inventory_sha256': self.sha(self.stage / 'adapter-backup-inventory.json')})
        self.gate = self.root / 'manager/storage-maintenance/gate.json'; self.gate.parent.mkdir(mode=0o755)
        self.operation = hashlib.sha256(str(self.stage.resolve()).encode()).hexdigest()
        gate = {'schema': 1, 'held': True, 'delivery_held': True, 'operation': self.operation}
        self.write(self.gate, gate); self.gate.chmod(0o644)
        self.psql("INSERT INTO settings(key,value) VALUES('storage_emergency_maintenance','" + json.dumps(gate) + "')")
        self.calls = []; self.dispatched = 0; self.exists = False; self.unit = 'not-found'; self.running_writer = False
        self.identity = 'c' * 64; self.image = 'sha256:' + 'd' * 64
        self.quadlets = self.root / 'quadlets'; self.quadlets.mkdir()
        (self.quadlets / 'nebulalog-postgresql.container').write_text('Image=registry.example/postgres@sha256:' + 'd' * 64 + '\n')
        self.manager = lifecycle.Lifecycle({'schema_revision': '1'}, self.command,
            state=self.stage.parent.parent, data=self.root, configuration=self.configuration, quadlets=self.quadlets, guard=lambda: None)
        for mock in (patch.object(lifecycle, 'trusted_file', side_effect=lambda p: p),
                     patch.object(lifecycle, 'STORAGE_OWNER_UID', os.getuid()),
                     patch.object(lifecycle, 'STORAGE_OWNER_GID', os.getgid())):
            mock.start(); self.addCleanup(mock.stop)

    @staticmethod
    def write(path, value): path.write_text(json.dumps(value))

    @staticmethod
    def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

    def prefix(self, database=None):
        return ['docker', 'exec', '-i', self.container, 'psql', '-X', '--username=emergency_test',
            '--dbname=' + (database or self.database), '--quiet', '--tuples-only', '--no-align', '--set=ON_ERROR_STOP=1']

    def psql(self, text, database=None):
        result = subprocess.run(self.prefix(database), input=text.encode(), capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr.decode())
        return result.stdout.decode().strip()

    def execute(self, raw):
        result = subprocess.run(self.prefix() + ['--single-transaction'], input=raw, capture_output=True)
        if result.returncode:
            raise Refused(result.stderr.decode())
        return result.stdout.decode().strip()

    def command(self, argv, *, input=None, timeout=120):
        self.calls.append(argv)
        if argv[0] == 'systemctl':
            if argv[1] == 'stop': self.unit = 'not-found'; return ''
            if '--property=LoadState' in argv: return self.unit
            if 'nebulalog-schema-' in argv[-1]: return 'inactive'
            return 'active' if self.running_writer else 'inactive'
        if argv[:2] == ['podman', 'inspect']: return self.image
        if argv[:3] == ['podman', 'image', 'inspect']: return self.image
        if argv[:2] == ['podman', 'create']:
            self.assertFalse(self.exists); self.exists = True; return self.identity
        if argv[:2] == ['podman', 'ps']: return self.identity if self.exists else ''
        if argv[:2] == ['podman', 'rm']: self.exists = False; return self.identity
        if argv[0] == 'systemd-run':
            self.assertTrue(self.exists); self.dispatched += 1; self.unit = 'loaded'
            return self.execute(input)
        self.assertEqual(argv[:2], ['podman', 'exec'])
        self.assertIn('--dbname=nebulalog', argv)
        self.assertIn('--single-transaction', argv)
        if b'pg_hba_file_rules' in input:
            # Fixture transport is local trust; native client configuration is a
            # separately tested host boundary, never a catalog/transaction mock.
            return json.dumps({'listen':'*','rules':[{'type':'host','database':['all'],'user_name':['all'],
                'address':'127.0.0.1','netmask':'255.255.255.255','auth_method':'scram-sha-256','options':None,'error':None}]})
        return self.execute(input)

    def migrate(self): return self.manager.application_schema_migrate(self.stage)

    def test_real_additive_migration_preserves_rows_settings_and_exact_owner(self):
        self.psql("UPDATE settings SET value='{" + '"global_days":17' + "}' WHERE key='retention'; INSERT INTO firewalls(serial,notes) VALUES('sentinel','preserve me')")
        result = self.migrate()
        self.assertEqual(result['schema_revision'], '2')
        self.assertEqual(result['state'], 'complete')
        self.assertEqual(self.dispatched, 1)
        self.assertEqual(self.psql("SELECT notes FROM firewalls WHERE serial='sentinel'"), 'preserve me')
        self.assertEqual(json.loads(self.psql("SELECT value FROM settings WHERE key='retention'")), {'global_days': 17})
        self.assertEqual(self.psql("SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'captainslog_probe_%'"), '0')
        self.assertEqual(self.psql("SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relowner<>(SELECT oid FROM pg_roles WHERE rolname='emergency_test')"), '0')
        self.assertEqual(self.manager.application_schema_verify(self.stage), result)
        self.assertEqual(self.migrate(), result)
        self.assertEqual(self.dispatched, 1)

    def test_optional_exact_host_stepup_profile_is_preserved(self):
        self.psql(ApplicationSchema.reviewed_sql()[2])
        self.assertEqual(self.migrate()['profile'], 'host-stepup')

    def test_unknown_commit_readback_never_replays_sql(self):
        original = self.command
        def lost(argv, **kwargs):
            value = original(argv, **kwargs)
            if argv[0] == 'systemd-run': raise TimeoutError('lost acknowledgement after actual COMMIT')
            return value
        self.manager.cmd = lost
        with self.assertRaises(TimeoutError): self.migrate()
        self.assertFalse((self.stage / 'adapter-application-schema.json').exists())
        self.manager.cmd = original
        self.assertEqual(self.migrate()['state'], 'complete')
        self.assertEqual(self.dispatched, 1)
        self.assertEqual(self.psql("SELECT count(*) FROM audit_events WHERE action='application.schema.migrate'"), '1')

    def test_intent_before_dispatch_is_aborted_and_not_replayed(self):
        original = self.command
        def interrupted(argv, **kwargs):
            if argv[0] == 'systemd-run': raise TimeoutError('before dispatch')
            return original(argv, **kwargs)
        self.manager.cmd = interrupted
        with self.assertRaises(TimeoutError): self.migrate()
        self.manager.cmd = original
        result = self.migrate()
        self.assertEqual(result['state'], 'aborted'); self.assertFalse(result['replay_permitted'])
        self.assertEqual(self.dispatched, 0)
        self.assertEqual(self.psql("SELECT to_regclass('public.storage_emergency_actions') IS NULL"), 't')

    def test_malformed_preexisting_new_object_refuses_before_intent(self):
        self.psql('CREATE TABLE storage_emergency_actions(id text)')
        with self.assertRaises(Refused): self.migrate()
        self.assertFalse((self.stage / 'adapter-application-schema-intent.json').exists())
        self.assertEqual(self.dispatched, 0)

    def test_changed_legacy_constraint_refuses(self):
        self.psql('ALTER TABLE saved_filters DROP CONSTRAINT saved_filters_name_check')
        with self.assertRaises(Refused): self.migrate()
        self.assertEqual(self.dispatched, 0)

    def test_wrong_owner_and_active_writer_refuse(self):
        self.running_writer = True
        with self.assertRaises(Refused): self.migrate()
        self.assertFalse(any(x[0] == 'podman' for x in self.calls))
        self.running_writer = False
        backup = self.stage / 'adapter-backup-inventory.json'
        self.write(backup, {'owners': {'nebulalog': 'postgres'}, 'files': []})
        self.write(self.stage / 'adapter-backup.json', {'inventory_sha256': self.sha(backup)})
        with self.assertRaises(Refused): self.migrate()
        self.assertEqual(self.dispatched, 0)

    def test_changed_marker_refuses_recovery_and_preserves_host_gate(self):
        self.migrate()
        self.psql("UPDATE settings SET value=jsonb_set(value,'{backup_sha256}','\"foreign\"') WHERE key LIKE 'application_schema_migration:%'")
        with self.assertRaises(Refused): self.migrate()
        self.assertTrue(json.loads(self.gate.read_text())['delivery_held'])
        self.assertEqual(self.dispatched, 1)

    def test_pending_or_unknown_clickhouse_evidence_blocks_recovery(self):
        self.migrate()
        self.psql("INSERT INTO storage_emergency_actions(id,state,plan) VALUES(gen_random_uuid(),'uncertain','{}')")
        with self.assertRaises(Refused): self.manager.application_schema_recover(self.stage)
        self.assertTrue(json.loads(self.gate.read_text())['delivery_held'])

    def test_server_executor_is_terminated_before_abort_readback(self):
        original = self.command
        def interrupted(argv, **kwargs):
            if argv[0] == 'systemd-run': raise TimeoutError('before dispatch')
            return original(argv, **kwargs)
        self.manager.cmd = interrupted
        with self.assertRaises(TimeoutError): self.migrate()
        self.manager.cmd = original
        intent = json.loads((self.stage / 'adapter-application-schema-intent.json').read_text())
        app = intent['executor']['application_name']
        prefix = self.prefix()
        prefix[2:2] = ['--env', 'PGAPPNAME=' + app]
        client = subprocess.Popen(prefix, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            client.stdin.write('BEGIN; SELECT pg_advisory_xact_lock(%d);\n\\echo LOCKED\nSELECT pg_sleep(60);\n' % lifecycle.STORAGE_LOCK)
            client.stdin.flush()
            while client.stdout.readline().strip() != 'LOCKED': self.assertIsNone(client.poll())
            self.assertEqual(self.manager.application_schema_recover(self.stage)['state'], 'aborted')
            client.communicate(timeout=10)
            self.assertNotEqual(client.returncode, 0)
            self.assertEqual(self.psql("SELECT count(*) FROM pg_stat_activity WHERE application_name='" + app + "'"), '0')
        finally:
            if client.poll() is None: client.terminate(); client.communicate(timeout=10)

    def test_actual_mid_migration_failure_rolls_back_new_catalog_and_marker(self):
        original = self.command
        def failed(argv, **kwargs):
            if argv[0] == 'systemd-run':
                query = kwargs['input'].replace(b"  INSERT INTO public.settings(key,value) VALUES('application_schema_migration:",
                    b"  RAISE EXCEPTION 'isolated failure after actual DDL';\n  INSERT INTO public.settings(key,value) VALUES('application_schema_migration:")
                kwargs['input'] = query
            return original(argv, **kwargs)
        self.manager.cmd = failed
        with self.assertRaisesRegex(Refused, 'isolated failure'): self.migrate()
        self.manager.cmd = original
        self.assertEqual(self.migrate()['state'], 'aborted')
        self.assertEqual(self.dispatched, 1)
        self.assertEqual(self.psql("SELECT to_regclass('public.storage_emergency_actions') IS NULL"), 't')
        self.assertEqual(self.psql("SELECT count(*) FROM settings WHERE key LIKE 'application_schema_migration:%'"), '0')

    def test_changed_backup_intent_refuses_before_any_new_executor(self):
        self.migrate()
        inventory = self.stage / 'adapter-backup-inventory.json'
        value = json.loads(inventory.read_text()); value['extra'] = 'changed'
        self.write(inventory, value)
        self.write(self.stage / 'adapter-backup.json', {'inventory_sha256': self.sha(inventory)})
        with self.assertRaises(Refused): self.migrate()
        self.assertEqual(self.dispatched, 1)

    def test_rls_and_extra_public_function_refuse_before_creation(self):
        self.psql('ALTER TABLE firewalls ENABLE ROW LEVEL SECURITY')
        with self.assertRaises(Refused): self.migrate()
        self.psql("ALTER TABLE firewalls DISABLE ROW LEVEL SECURITY; CREATE FUNCTION public.shadow() RETURNS integer LANGUAGE sql AS 'SELECT 1'")
        with self.assertRaises(Refused): self.migrate()
        self.assertFalse(self.exists)

    def test_host_gate_or_executor_fence_failure_cannot_advance(self):
        self.migrate()
        original = self.command
        self.exists = True
        def remains(argv, **kwargs):
            if argv[:2] == ['podman', 'rm']: return ''
            return original(argv, **kwargs)
        self.manager.cmd = remains
        with self.assertRaisesRegex(Refused, 'client can still execute'):
            self.manager.application_schema_fence(self.stage)
        self.manager.cmd = original
        self.gate.unlink()
        with self.assertRaises(FileNotFoundError): self.manager.application_schema_recover(self.stage)

    def test_unqualified_authentication_refuses_before_client_creation(self):
        original = self.command
        def trust(argv, **kwargs):
            result = original(argv, **kwargs)
            if kwargs.get('input') and b'pg_hba_file_rules' in kwargs['input']:
                value = json.loads(result); value['rules'][0]['auth_method'] = 'trust'; return json.dumps(value)
            return result
        self.manager.cmd = trust
        with self.assertRaisesRegex(Refused, 'SCRAM profile'): self.migrate()
        self.assertFalse(self.exists)

    def test_public_namespace_foreign_create_grant_refuses(self):
        self.psql('GRANT CREATE ON SCHEMA public TO emergency_test')
        with self.assertRaisesRegex(Refused, 'namespace privileges'): self.migrate()
        self.assertEqual(self.dispatched, 0)

    def test_foreign_schema_inheritance_child_refuses(self):
        self.psql('CREATE SCHEMA foreign_child; CREATE TABLE foreign_child.records() INHERITS(public.firewalls)')
        with self.assertRaisesRegex(Refused, 'inheritance'): self.migrate()
        self.assertEqual(self.dispatched, 0)

    def test_static_receipt_and_database_proof_survive_new_owned_operation(self):
        result = self.migrate()
        other = self.stage.parent / '2-next'; other.mkdir()
        self.write(self.stage.parent.parent / 'transaction.json', {'release': str(other)})
        count = len(self.calls)
        self.assertEqual(self.manager.application_schema_receipt(self.stage), result)
        self.assertEqual(len(self.calls), count)
        operation = hashlib.sha256(str(other).encode()).hexdigest()
        gate = {'schema':1,'held':True,'delivery_held':True,'operation':operation}
        self.write(self.gate, gate)
        self.psql("UPDATE settings SET value='" + json.dumps(gate) + "' WHERE key='storage_emergency_maintenance'")
        self.assertEqual(self.manager.application_schema_verify(self.stage, maintenance_stage=other), result)
        self.assertEqual(self.dispatched, 1)

    def test_old_catalog_with_foreign_marker_is_not_a_clean_abort(self):
        original = self.command
        def interrupted(argv, **kwargs):
            if argv[0] == 'systemd-run': raise TimeoutError('before dispatch')
            return original(argv, **kwargs)
        self.manager.cmd = interrupted
        with self.assertRaises(TimeoutError): self.migrate()
        self.manager.cmd = original
        self.psql("INSERT INTO settings(key,value) VALUES('application_schema_migration:" + 'f' * 64 + "','{}')")
        with self.assertRaises(Refused): self.migrate()
        self.assertFalse((self.stage / 'adapter-application-schema-recovery.json').exists())

    def test_running_image_must_match_protected_immutable_pin(self):
        original = self.command
        def different(argv, **kwargs):
            if argv[:3] == ['podman','image','inspect']: return 'sha256:' + 'e' * 64
            return original(argv, **kwargs)
        self.manager.cmd = different
        with self.assertRaisesRegex(Refused, 'Quadlet pin'): self.migrate()
        self.assertFalse(self.exists)

    def test_fixed_factory_catalog_observation_never_creates_migration_authority(self):
        old = self.manager.application_schema_catalog(self.stage, '1')
        self.assertEqual(old['schema_revision'], '1'); self.assertEqual(old['markers'], [])
        self.psql(ApplicationSchema.reviewed_sql()[1])
        new = self.manager.application_schema_catalog(self.stage, '2')
        self.assertEqual(new['schema_revision'], '2'); self.assertEqual(new['markers'], [])
        self.assertFalse((self.stage / 'adapter-application-schema.json').exists())
        with self.assertRaises(Refused): self.migrate()
        self.assertEqual(self.dispatched, 0)

    def test_real_backup_restore_retains_host_hold_and_rearms_database_gate(self):
        self.psql("INSERT INTO firewalls(serial,notes) VALUES('restore-sentinel','before')")
        archive = subprocess.check_output(['docker','exec',self.container,'pg_dump','--username=emergency_test','--format=custom','--dbname='+self.database])
        self.migrate()
        self.manager.application_schema_fence(self.stage)
        self.psql('DROP DATABASE ' + self.database + ' WITH (FORCE)', database='emergency_test')
        self.psql('CREATE DATABASE ' + self.database, database='emergency_test')
        subprocess.run(['docker','exec','-i',self.container,'pg_restore','--username=emergency_test','--dbname='+self.database,
            '--single-transaction','--exit-on-error'], input=archive, capture_output=True, check=True)
        self.assertTrue(json.loads(self.gate.read_text())['delivery_held'])
        self.manager.storage_maintenance(self.stage, held=True, delivery_held=True)
        observed = self.manager.application_schema_catalog(self.stage, '1')
        self.assertEqual(observed['markers'], [])
        self.assertEqual(self.psql("SELECT notes FROM firewalls WHERE serial='restore-sentinel'"), 'before')
        self.assertEqual(self.dispatched, 1)

    def test_malformed_settings_view_is_not_executed_before_catalog_validation(self):
        self.psql("""CREATE SCHEMA hostile_view;
CREATE FUNCTION hostile_view.fail(jsonb) RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'UNSAFE VIEW EXECUTED'; END $$;
ALTER TABLE settings RENAME TO saved_settings;
CREATE VIEW settings AS SELECT key,hostile_view.fail(value) AS value FROM saved_settings;""")
        with self.assertRaises(Refused) as failed: self.migrate()
        self.assertIn('catalog differs before reading', str(failed.exception))
        self.assertNotIn('UNSAFE VIEW EXECUTED', str(failed.exception))
        self.assertEqual(self.dispatched, 0)
