import hashlib
import io
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.storage import Identity, Snapshot, growth_plan, blank_disk_plan, apply_growth
from nebulalog_manager.sizing import Measurement, forecast
from nebulalog_manager.security import summarize_xccdf
from nebulalog_manager.updates import verify_release, in_maintenance_window, REQUIRED_CHECKS, UpdateManager
from nebulalog_manager.backup import unpack_backup

GIB = 1024**3
IDENTITY = Identity("/dev/disk/by-id/scsi-data", "data-serial", "/dev/disk/by-id/scsi-data-part1", "part-uuid", "luks-uuid", "nebulalog-data", "pv-uuid", "vg-uuid", "lv-uuid")
BASE = Snapshot(IDENTITY, 1000*GIB, 1000*GIB-2*1024**2, 1024**2, 1000*GIB-18*1024**2,
                1000*GIB-20*1024**2, 1000*GIB-20*1024**2, 1000*GIB-20*1024**2, 0)

class StorageTests(unittest.TestCase):
    def test_noop(self):
        self.assertEqual(growth_plan(BASE)["stages"], [])

    def test_larger_preboot_disk_has_full_sequence(self):
        plan = growth_plan(replace(BASE, disk_bytes=5000*GIB))
        self.assertEqual(plan["stages"], ["partition", "luks", "pv", "lv", "xfs"])
        self.assertTrue(plan["requires_unlock_credential"])

    def test_resume_after_partition_growth(self):
        p = growth_plan(replace(BASE, disk_bytes=5000*GIB, partition_bytes=5000*GIB-2*1024**2))
        self.assertEqual(p["stages"], ["luks", "pv", "lv", "xfs"])

    def test_changed_identity_changes_confirmation(self):
        self.assertNotEqual(BASE.fingerprint, replace(BASE, identity=replace(IDENTITY, serial="replacement")).fingerprint)

    def test_reject_unsafe_topologies(self):
        for changes in ({"system_disk": True}, {"read_only": True}, {"removable": True}, {"mounted": False},
                        {"last_partition": False}, {"linear": False}, {"filesystem": "ext4"}, {"luks_version": 1},
                        {"disk_bytes": 500*GIB}, {"sector_size": 2048}):
            with self.subTest(changes=changes), self.assertRaises(Refused):
                growth_plan(replace(BASE, **changes))

    def test_reject_arbitrary_paths(self):
        for disk in ("/dev/sdb", "/dev/disk/by-id/../../sda", "/dev/disk/by-id/data;reboot"):
            with self.subTest(disk=disk), self.assertRaises(Refused):
                growth_plan(replace(BASE, identity=replace(IDENTITY, disk=disk)))

    def test_unknown_blank_disk_needs_explicit_confirmation(self):
        result = blank_disk_plan("/dev/disk/by-id/new", "new-serial", 4*GIB, [], [], [], False, False, False)
        self.assertEqual(len(result["confirmation"]), 64)
        self.assertTrue(result["destructive"])

    def test_reject_disk_in_use(self):
        for signatures, children, holders, mounted in [(["ext4"], [], [], False), ([], ["sdc1"], [], False), ([], [], ["dm-0"], False), ([], [], [], True)]:
            with self.assertRaises(Refused):
                blank_disk_plan("/dev/disk/by-id/new", "s", GIB, signatures, children, holders, mounted, False, False)

    def test_stale_plan_runs_no_disk_commands(self):
        with tempfile.TemporaryDirectory() as temp, patch("nebulalog_manager.storage.require_linux_root"):
            calls = []
            with self.assertRaisesRegex(Refused, "changed since review"):
                apply_growth(IDENTITY, "wrong", state=Path(temp), inspector=lambda _:BASE, runner=lambda args:calls.append(args))
            self.assertEqual(calls, [])

    def test_missing_key_fails_before_mutation(self):
        expanded = replace(BASE, disk_bytes=5000*GIB)
        with tempfile.TemporaryDirectory() as temp, patch("nebulalog_manager.storage.require_linux_root"):
            calls = []
            with self.assertRaisesRegex(Refused, "credential"):
                apply_growth(IDENTITY, expanded.fingerprint, state=Path(temp), inspector=lambda _:expanded, runner=lambda args:calls.append(args))
            self.assertEqual(calls, [])

    def test_successful_resume_only_grows_filesystem(self):
        before = replace(BASE, lv_bytes=BASE.lv_bytes+32*1024**2, pv_bytes=BASE.pv_bytes+32*1024**2,
                         mapping_bytes=BASE.mapping_bytes+32*1024**2, partition_bytes=BASE.partition_bytes+32*1024**2, disk_bytes=BASE.disk_bytes+32*1024**2)
        after = replace(before, filesystem_bytes=before.lv_bytes)
        observations = iter([before, before, after])
        with tempfile.TemporaryDirectory() as temp, patch("nebulalog_manager.storage.require_linux_root"):
            calls = []
            result = apply_growth(IDENTITY, before.fingerprint, state=Path(temp), inspector=lambda _:next(observations), runner=lambda args:calls.append(args))
            self.assertEqual(calls, [["xfs_growfs", "/var/lib/nebulalog"]])
            self.assertEqual(result["status"], "complete")
            self.assertIn("storage.grow.complete", (Path(temp)/"audit.jsonl").read_text())

class SizingTests(unittest.TestCase):
    def test_measured_projection(self):
        result = forecast(10**12, 500*10**9, [Measurement(24, 34*10**9, 22_896_000)])
        self.assertAlmostEqual(result["average_eps"], 265)
        self.assertAlmostEqual(result["estimated_retention_days"], 25)
        self.assertEqual(result["required_capacity_bytes"]["30"], 1_200_000_000_000)

    def test_unknown_growth_is_not_zero_retention(self):
        for samples in ([], [Measurement(24,0,0)]):
            r = forecast(1000,100,samples)
            self.assertIsNone(r["estimated_retention_days"])
            self.assertEqual(r["required_capacity_bytes"], {})

    def test_negative_or_nan_measurements_rejected(self):
        for sample in (Measurement(0,0,0), Measurement(float("nan"),0,0), Measurement(1,-1,1)):
            with self.assertRaises(ValueError): forecast(100,1,[sample])

    def test_thresholds(self):
        for used, level in [(69,"normal"),(70,"information"),(80,"warning"),(90,"critical"),(95,"emergency")]:
            self.assertEqual(forecast(100,used,[])["level"],level)

class ComplianceTests(unittest.TestCase):
    def report(self, outcomes):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"report.xml"
            p.write_text('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult>'+''.join('<rule-result><result>'+x+'</result></rule-result>' for x in outcomes)+'</TestResult></Benchmark>')
            return summarize_xccdf(p)

    def test_pass_only_assessment(self):
        self.assertTrue(self.report(["pass","pass"])["automated_assessment_passed"])

    def test_notapplicable_never_reports_compliant(self):
        for values in ([],["notapplicable"],["pass","notchecked"],["pass","error"],["pass","fail"]):
            self.assertFalse(self.report(values)["automated_assessment_passed"])
            self.assertTrue(self.report(values)["requires_review"])

    def test_external_entity_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"report.xml"
            p.write_text('<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>')
            with self.assertRaises(Refused): summarize_xccdf(p)

class MaintenanceTests(unittest.TestCase):
    def test_phoenix_default(self):
        self.assertTrue(in_maintenance_window(datetime(2026,9,6,10,30,tzinfo=timezone.utc),zone="America/Phoenix"))
        self.assertFalse(in_maintenance_window(datetime(2026,9,6,12,0,tzinfo=timezone.utc),zone="America/Phoenix"))

    def test_overnight(self):
        self.assertTrue(in_maintenance_window(datetime(2026,9,7,1,0,tzinfo=timezone.utc),start="23:00",end="02:00"))
        self.assertFalse(in_maintenance_window(datetime(2026,9,8,1,0,tzinfo=timezone.utc),start="23:00",end="02:00"))

@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for real cryptographic verification")
class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir=tempfile.TemporaryDirectory()
        cls.private=Path(cls.keydir.name)/"private.pem"
        cls.public=Path(cls.keydir.name)/"public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:3072","-out",str(cls.private)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["openssl","pkey","-in",str(cls.private),"-pubout","-out",str(cls.public)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    @classmethod
    def tearDownClass(cls): cls.keydir.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name); (self.path/"app.tar").write_bytes(b"real artifact bytes")
        self.manifest={"schema":1,"product":"nebulalog","channel":"stable","version":"0.1.1","sequence":2,
                       "issued_at":"2026-09-01T00:00:00Z","expires_at":"2026-10-01T00:00:00Z",
                       "artifacts":[{"name":"app.tar","sha256":hashlib.sha256(b"real artifact bytes").hexdigest(),"bytes":19}],
                       "components":{"nebulalog":{"version":"0.1.1","artifact":"app.tar","from_versions":["0.1.0"],"rollback_safe":True}}}
        self.sign()
    def sign(self):
        (self.path/"manifest.json").write_text(json.dumps(self.manifest))
        subprocess.run(["openssl","dgst","-sha256","-sign",str(self.private),"-sigopt","rsa_padding_mode:pss","-sigopt","rsa_pss_saltlen:32","-out",str(self.path/"manifest.sig"),str(self.path/"manifest.json")],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def verify(self,**kwargs):
        return verify_release(self.path/"manifest.json",self.path/"manifest.sig",self.public,self.path,
                              now=datetime(2026,9,7,tzinfo=timezone.utc),**kwargs)
    def test_valid_signature(self): self.assertEqual(self.verify(current_sequence=1,current_versions={"nebulalog":"0.1.0"})["sequence"],2)
    def test_modified_manifest(self):
        with (self.path/"manifest.json").open("a") as f:f.write(" ")
        with self.assertRaises(Refused):self.verify()
    def test_modified_artifact(self):
        (self.path/"app.tar").write_bytes(b"fake artifact bytes")
        with self.assertRaises(Refused):self.verify()
    def test_replay(self):
        with self.assertRaisesRegex(Refused,"Replay"):self.verify(current_sequence=2)
    def test_expiry(self):
        self.manifest["expires_at"]="2026-09-02T00:00:00Z";self.sign()
        with self.assertRaisesRegex(Refused,"expired"):self.verify()
    def test_expired_retained_finalization_still_requires_signature_and_valid_timestamps(self):
        self.manifest["expires_at"]="2026-09-02T00:00:00Z";self.sign()
        self.assertEqual(self.verify(allow_expired=True)["sequence"],2)
        self.manifest["issued_at"]="2026-10-01T00:00:00Z";self.sign()
        with self.assertRaises(Refused):self.verify(allow_expired=True)
        with (self.path/"manifest.json").open("a") as stream:stream.write(" ")
        with self.assertRaises(Refused):self.verify(allow_expired=True)
    def test_unknown_component(self):
        self.manifest["components"]["arbitrary-shell"]={};self.sign()
        with self.assertRaisesRegex(Refused,"Unknown"):self.verify()
    def test_upgrade_path(self):
        with self.assertRaisesRegex(Refused,"upgrade path"):self.verify(current_versions={"nebulalog":"0.0.1"})
    def test_signed_clickhouse_measured_vendor_version_is_accepted(self):
        change={"version":"25.3.8.30001.altinityfips","artifact":"app.tar",
                "from_versions":["25.3.8.30001.altinityfips"],"rollback_safe":True,
                "family":"25.3","tested_minimum":"25.3.8.30001","tested_maximum":"25.3.8.30001"}
        self.manifest["components"]={"clickhouse":change};self.sign()
        self.assertEqual(self.verify(current_versions={"clickhouse":"25.3.8.30001.altinityfips"})["components"]["clickhouse"],change)
    def test_signed_clickhouse_invalid_ranges_family_and_vendor_refuse(self):
        original={"version":"25.3.8.30001.altinityfips","artifact":"app.tar",
                  "from_versions":["25.3.8.30001.altinityfips"],"rollback_safe":True,
                  "family":"25.3","tested_minimum":"25.3.8.30001","tested_maximum":"25.3.8.30001"}
        for changes in ({"family":"25.4"},{"version":"25.4.1.1.altinityfips"},
                        {"version":"25.3.9.1.altinityfips"},{"from_versions":["25.3.7.1.altinityfips"]},
                        {"from_versions":["25.3.8.30001"]},{"version":"25.3.8.30001.unrecognized"},
                        {"tested_minimum":"25.3.9.1"},{"tested_maximum":""},
                        {"tested_maximum":"25.3.8.30001.altinityfips"},{"from_versions":[None]}):
            self.manifest["components"]={"clickhouse":{**original,**changes}};self.sign()
            for metadata_only in (False,True):
                with self.subTest(changes=changes,metadata_only=metadata_only),self.assertRaisesRegex(Refused,"ClickHouse"):
                    self.verify(metadata_only=metadata_only)
    def test_traversal(self):
        self.manifest["artifacts"][0]["name"]="../app.tar";self.sign()
        with self.assertRaisesRegex(Refused,"unsafe"):self.verify()
    def test_symlink_artifact(self):
        (self.path/"app.tar").rename(self.path/"real.tar");(self.path/"app.tar").symlink_to(self.path/"real.tar")
        with self.assertRaisesRegex(Refused,"regular"):self.verify()

class BackupTests(unittest.TestCase):
    def make(self,path,unsafe=None,tampered=False):
        data=b"configuration bytes"
        manifest={"schema":1,"product":"nebulalog","kind":"configuration","files":[{"path":"configuration/app.json","bytes":len(data),"sha256":hashlib.sha256(b"wrong" if tampered else data).hexdigest()}]}
        with tarfile.open(path,"w") as tar:
            for name,value in [("backup.json",json.dumps(manifest).encode()),("configuration/app.json",data)]:
                item=tarfile.TarInfo(name);item.size=len(value);tar.addfile(item,io.BytesIO(value))
            if unsafe:
                tar.addfile(unsafe)
    def test_valid_restore_and_private_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);self.make(p/"backup.tar")
            self.assertEqual(unpack_backup(p/"backup.tar",p/"restore")["product"],"nebulalog")
            self.assertEqual((p/"restore/configuration/app.json").stat().st_mode & 0o777,0o600)
    def test_path_traversal_and_links(self):
        for name,kind in [("../../escape",tarfile.REGTYPE),("configuration/key",tarfile.SYMTYPE),("configuration/dev",tarfile.CHRTYPE)]:
            with tempfile.TemporaryDirectory() as temp:
                p=Path(temp);item=tarfile.TarInfo(name);item.type=kind;item.linkname="/etc/passwd";self.make(p/"backup.tar",item)
                with self.assertRaises(Refused):unpack_backup(p/"backup.tar",p/"restore")
                self.assertFalse((p/"restore").exists())
    def test_integrity_mismatch_cleans_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);self.make(p/"backup.tar",tampered=True)
            with self.assertRaises(Refused):unpack_backup(p/"backup.tar",p/"restore")
            self.assertFalse((p/"restore").exists())
    def test_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);self.make(p/"backup.tar")
            with self.assertRaises(Refused):unpack_backup(p/"backup.tar",p/"restore",max_bytes=2)

if __name__ == "__main__":unittest.main()

class EnrollmentSafetyTests(unittest.TestCase):
    def test_no_stable_identity_refuses_before_probe(self):
        from nebulalog_manager.enrollment import probe_blank
        calls=[]
        for disk in ("/dev/sdb","/dev/disk/by-id/../sda","/dev/disk/by-id/new;reboot"):
            with self.assertRaises(Refused):probe_blank(disk,runner=lambda args:calls.append(args))
        self.assertEqual(calls,[])

    def test_stale_confirmation_performs_no_disk_mutation(self):
        from nebulalog_manager.enrollment import add_disk
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);identity=p/"identity.json";atomic_json(identity,{**replace(IDENTITY).__dict__})
            key=p/"key";key.write_bytes(b"unit-test-only");key.chmod(0o600)
            calls=[]
            with patch("nebulalog_manager.enrollment.require_linux_root"),patch("nebulalog_manager.enrollment.trusted_file",side_effect=lambda x:x):
                with self.assertRaisesRegex(Refused,"stale"):
                    add_disk(identity,"/dev/disk/by-id/new","wrong",key,Path("/run/nebulalog/unit-test-recovery"),state=p/"state",runner=lambda args,**kw:calls.append(args),inspector=lambda _:BASE,prober=lambda _: {"confirmation":"expected"})
            self.assertEqual(calls,[])

@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
class TransactionTests(unittest.TestCase):
    setUpClass = classmethod(SignatureTests.setUpClass.__func__)
    tearDownClass = classmethod(SignatureTests.tearDownClass.__func__)
    setUp = SignatureTests.setUp
    sign = SignatureTests.sign
    def setup_manager(self,fail=None):
        # Exercise the signed fixture within its declared validity interval.
        # Production expiry checks stay enabled; wall-clock drift must not make
        # transaction/rollback tests stop before reaching their intended gates.
        clock = patch("nebulalog_manager.updates.datetime", wraps=datetime)
        frozen = clock.start()
        frozen.now.return_value = datetime(2026, 9, 7, tzinfo=timezone.utc)
        self.addCleanup(clock.stop)
        state=self.path/"state";hooks=self.path/"hooks";hooks.mkdir()
        current={"sequence":1,"version":"0.1.0","components":{name:{"version":version} for name,version in
                 (("nebulalog","0.1.0"),("postgresql","17.11"),("clickhouse","25.3.9.100"),("keycloak","26.7.3"))}}
        atomic_json(state/"current.json",current)
        # Temporary filesystem fixtures retain real enrolled-key byte binding;
        # only appliance-root ownership/ancestry is replaced by test ownership.
        def fixture_file(path):
            info = path.lstat()
            if (not path.is_relative_to(self.path) or path.is_symlink() or not path.is_file()
                    or info.st_uid != os.getuid() or info.st_mode & 0o022):
                raise Refused("Hook evidence is outside the protected test fixture")
            return path
        for mocker in (patch("nebulalog_manager.update_enrollment._tree"), patch("nebulalog_manager.update_enrollment.ROOT_UID",os.getuid()),
                       patch("nebulalog_manager.host_payload._OWNER_UID", os.getuid()),
                       patch("nebulalog_manager.host_dispatch.trusted_file", side_effect=fixture_file)):
            mocker.start();self.addCleanup(mocker.stop)
        atomic_json(state/"initial-enrollment.json",{"schema":1,"state":"enrolled","installation_id":"458a08e3-ef3b-4cd1-83e5-b402a2c1e913","current":current})
        atomic_json(state/"publisher-trust.json",{"schema":1,"state":"enrolled","installation_id":"458a08e3-ef3b-4cd1-83e5-b402a2c1e913","algorithm":"RSA-PSS-SHA256","rsa_bits":3072,
                    "public_key":str(self.public),"spki_sha256":"a"*64,"pem_sha256":hashlib.sha256(self.public.read_bytes()).hexdigest(),
                    "initial_enrollment_sha256":hashlib.sha256((state/"initial-enrollment.json").read_bytes()).hexdigest()})
        for name in ("update-preflight","update-backup","update-prepare","update-activate","update-health","update-rollback","update-finalize"):(hooks/name).write_text("unit test hook")
        calls=[];health_count=0
        from nebulalog_manager.common import run
        def runner(argv,**kwargs):
            nonlocal health_count
            if argv[0]=="openssl":return run(argv,**kwargs)
            name=Path(argv[0]).name;calls.append(name)
            from nebulalog_manager.host_dispatch import HookJournal
            journal=HookJournal(Path(argv[1]),json.loads((state/"transaction.json").read_text()))
            ticket=journal.enter(name)
            def result(value):
                journal.finish(ticket,"success",result=value)
                return json.dumps(value)
            if name==fail:
                journal.finish(ticket,"failed")
                raise Refused("simulated adapter failure")
            if name=="update-backup":return result({"ok":True,"postgresql":True,"configuration":True})
            if name=="update-health":
                health_count+=1
                checks={k:True for k in REQUIRED_CHECKS}
                if fail=="health-once" and health_count==1:checks["ingestion"]=False
                return result({"ok":True,"checks":checks})
            return result({"ok":True})
        return UpdateManager(state,hooks,runner),calls
    def install(self,manager):
        with patch("nebulalog_manager.updates.require_linux_root"),patch("nebulalog_manager.updates.trusted_file",side_effect=lambda p:p):
            return manager.install(self.path/"manifest.json",self.path/"manifest.sig",self.path,self.public)
    def test_transaction_commits_only_after_all_health_gates(self):
        manager,calls=self.setup_manager()
        self.assertEqual(self.install(manager)["state"],"committed")
        self.assertLess(calls.index("update-backup"),calls.index("update-activate"))
        self.assertEqual(manager.status()["current"]["sequence"],2)
    def test_failed_backup_never_activates(self):
        manager,calls=self.setup_manager("update-backup")
        with self.assertRaises(Refused):self.install(manager)
        self.assertNotIn("update-activate",calls)
        self.assertEqual(manager.status()["transaction"]["state"],"preflight_failed")
    def test_failed_backup_with_unrecovered_writers_is_recovery_required(self):
        manager,calls=self.setup_manager("update-backup")
        atomic_json(manager.state.parent/"maintenance.json", {"active":True})
        with self.assertRaises(Refused):self.install(manager)
        self.assertNotIn("update-activate",calls)
        self.assertEqual(manager.status()["transaction"]["state"],"recovery_required")
        self.assertIs(manager.status()["transaction"]["activation_started"], False)
    def test_activation_journal_is_durable_before_candidate_hook(self):
        manager,calls=self.setup_manager()
        runner=manager.runner
        def observe(argv, **kwargs):
            name=Path(argv[0]).name
            if name in ("update-backup", "update-prepare", "update-activate"):
                transaction=json.loads((manager.state/"transaction.json").read_text())
                self.assertIs(transaction["activation_started"], name == "update-activate")
            return runner(argv, **kwargs)
        manager.runner=observe
        self.assertEqual(self.install(manager)["state"], "committed")

    def interrupted_preflight(self):
        manager, calls = self.setup_manager()
        # This interruption occurs before dispatch publication, not inside a
        # running adapter. Only that zero-dispatch window can recapture proof.
        with patch.object(manager, "_hook", side_effect=KeyboardInterrupt("before first dispatch")):
            with self.assertRaises(KeyboardInterrupt): self.install(manager)
        self.assertEqual(manager.status()["transaction"]["state"], "preflight")
        return manager, calls

    def recover(self, manager):
        def trusted(path):
            if not path.is_file():
                raise FileNotFoundError(path)
            return path
        with patch("nebulalog_manager.updates.require_linux_root"), \
                patch("nebulalog_manager.updates.trusted_file", side_effect=trusted):
            return manager.recover(self.public)

    def test_recovery_rechecks_undispatched_preflight_before_restoring_host_or_stopping_services(self):
        manager, calls = self.interrupted_preflight()
        runner = manager.runner
        def preflight(argv, **kwargs):
            if Path(argv[0]).name == "update-preflight":
                self.assertEqual(manager.status()["transaction"]["state"], "preflight")
                atomic_json(Path(argv[1]) / "adapter-backup-intent.json", {"fixture": True})
            return runner(argv, **kwargs)
        manager.runner = preflight
        result = self.recover(manager)
        self.assertEqual(result["state"], "rolled_back")
        self.assertEqual(calls, ["update-preflight", "update-rollback", "update-health", "update-finalize"])
        self.assertEqual(manager.status()["current"]["components"]["nebulalog"]["version"], "0.1.0")

    def test_missing_preflight_intent_never_recaptures_after_possible_effects(self):
        manager, calls = self.interrupted_preflight()
        stage = Path(manager.status()["transaction"]["release"])
        for path in (stage / "recovery", stage / "host-activation.json", stage / "adapter-storage-maintenance.json",
                     manager.state.parent / "maintenance.json"):
            with self.subTest(path=path.name):
                path.write_text("inert possible-effect marker")
                with self.assertRaisesRegex(Refused, "possible runtime effects"): self.recover(manager)
                self.assertEqual(calls, [])
                path.unlink()
        gate = manager.state.parent / "storage-maintenance/gate.json"
        for value in ({"schema": 1, "held": True, "delivery_held": True, "operation": "a" * 64},
                      {"schema": True, "held": False, "delivery_held": False, "operation": None}):
            atomic_json(gate, value)
            with self.assertRaisesRegex(Refused, "possible runtime effects"): self.recover(manager)
            self.assertEqual(calls, [])
        gate.unlink()
        transaction = manager.status()["transaction"]; transaction["state"] = "preparing"
        atomic_json(manager.state / "transaction.json", transaction)
        with self.assertRaisesRegex(Refused, "possible runtime effects"): self.recover(manager)
        self.assertEqual(calls, [])
    def test_health_failure_rolls_back_and_keeps_high_watermark(self):
        manager,calls=self.setup_manager("health-once")
        with self.assertRaisesRegex(Refused,"previous application restored"):self.install(manager)
        self.assertIn("update-rollback",calls)
        self.assertEqual(manager.status()["transaction"]["state"],"rolled_back")
        self.assertEqual(manager.status()["current"]["components"]["nebulalog"]["version"],"0.1.0")
        self.assertEqual(manager.status()["current"]["sequence"],2)

    def test_operator_rollback_checks_retained_signed_release(self):
        manager,calls=self.setup_manager()
        self.install(manager)
        with patch("nebulalog_manager.updates.require_linux_root"),patch("nebulalog_manager.updates.trusted_file",side_effect=lambda p:p):
            result=manager.rollback(self.public)
        self.assertEqual(result["state"],"rolled_back")
        self.assertEqual(manager.status()["current"]["sequence"],2)
        self.assertEqual(manager.status()["current"]["components"]["nebulalog"]["version"],"0.1.0")

    def test_failed_finalization_preserves_committed_component_and_gates_next_update(self):
        manager,calls=self.setup_manager("update-finalize")
        with self.assertRaisesRegex(Refused,"maintenance release failed"):
            self.install(manager)
        self.assertNotIn("update-rollback",calls)
        status=manager.status()
        self.assertEqual(status["transaction"]["state"],"committed")
        self.assertEqual(status["transaction"]["finalization"],"failed")
        self.assertEqual(status["current"]["components"]["nebulalog"]["version"],"0.1.1")
        self.assertTrue(status["maintenance_release_pending"])
        before=list(calls)
        with self.assertRaisesRegex(Refused,"pending maintenance"):
            self.install(manager)
        self.assertEqual(calls,before)

    def test_finalization_retry_rechecks_health_without_activation_or_restore(self):
        manager,calls=self.setup_manager("update-finalize")
        with self.assertRaises(Refused):self.install(manager)
        original=manager.runner
        def recovered(argv,**kwargs):
            if Path(argv[0]).name=="update-finalize":
                calls.append("update-finalize")
                self.assertEqual(manager.status()["transaction"]["state"],"committed")
                from nebulalog_manager.host_dispatch import HookJournal
                journal=HookJournal(Path(argv[1]),manager.status()["transaction"])
                ticket=journal.enter("update-finalize")
                journal.finish(ticket,"success",result={"ok":True})
                return '{"ok":true}'
            return original(argv,**kwargs)
        manager.runner=recovered
        before=len(calls)
        with patch("nebulalog_manager.updates.require_linux_root"),patch("nebulalog_manager.updates.trusted_file",side_effect=lambda p:p):
            self.assertEqual(manager.finalize(self.public)["finalization"],"complete")
        self.assertEqual(calls[before:],["update-health","update-finalize"])
        self.assertEqual(manager.status()["current"]["components"]["nebulalog"]["version"],"0.1.1")
        self.assertFalse(manager.status()["maintenance_release_pending"])

    def test_finalization_retry_does_not_open_maintenance_when_local_auth_failed(self):
        manager,calls=self.setup_manager("update-finalize")
        with self.assertRaises(Refused):self.install(manager)
        original=manager.runner
        def unhealthy(argv,**kwargs):
            if Path(argv[0]).name=="update-health":
                calls.append("update-health")
                return json.dumps({"ok":True,"checks":{key:key!="local_auth" for key in REQUIRED_CHECKS}})
            return original(argv,**kwargs)
        manager.runner=unhealthy
        before=len(calls)
        with patch("nebulalog_manager.updates.require_linux_root"),patch("nebulalog_manager.updates.trusted_file",side_effect=lambda p:p),self.assertRaisesRegex(Refused,"health verification failed"):
            manager.finalize(self.public)
        self.assertEqual(calls[before:],["update-health"])
        self.assertEqual(manager.status()["transaction"]["state"],"committed")
        self.assertEqual(manager.status()["transaction"]["finalization"],"failed")

    def test_global_manager_lock_serializes_component_and_storage_os_work(self):
        from nebulalog_manager.common import locked
        manager,calls=self.setup_manager()
        with locked(manager.state.parent/"transaction.lock"),self.assertRaisesRegex(Refused,"Another appliance"):
            self.install(manager)
        self.assertEqual(calls,[])

    def test_pending_os_reboot_blocks_component_update_before_any_hook(self):
        manager,calls=self.setup_manager()
        atomic_json(manager.state.parent/"os-transaction.json",{"state":"reboot_requested"})
        with self.assertRaisesRegex(Refused,"OS maintenance"):
            self.install(manager)
        self.assertEqual(calls,[])

    def test_os_hold_or_kernel_recovery_blocks_every_component_mutation_after_healthy_fallback(self):
        manager, calls = self.setup_manager()
        phases_by_field = {field: ("pending", "failed", "recovery_required", "unknown")
                           for field in ("kernel_finalization", "kernel_retention", "kernel_rollback")}
        phases_by_field["storage_maintenance"] = ("held", "release_pending")
        for field, phases in phases_by_field.items():
            for phase in phases:
                operation = {"state": "complete", "finalization": "complete", field: phase}
                path = manager.state.parent / "os-transaction.json"
                atomic_json(path, operation)
                before = path.read_bytes()
                for action, state, finalization in (("install", "committed", "complete"),
                        ("rollback", "committed", "complete"), ("recover", "activating", "pending"),
                        ("finalize", "committed", "failed")):
                    with self.subTest(field=field, phase=phase, action=action):
                        atomic_json(manager.state / "transaction.json", {"state": state, "finalization": finalization})
                        with patch("nebulalog_manager.updates.require_linux_root"), \
                                patch("nebulalog_manager.updates.trusted_file", side_effect=lambda p: p), \
                                self.assertRaisesRegex(Refused, "OS"):
                            if action == "install":
                                self.install(manager)
                            else:
                                getattr(manager, action)(self.public)
                        self.assertEqual(path.read_bytes(), before)
                self.assertEqual(calls, [])
                self.assertIsNone(manager.status()["recovery_action"])
                self.assertEqual(manager.status()["recovery_blocked_by"], "os_update")
