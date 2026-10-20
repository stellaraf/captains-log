"""Small read-only sizing fixtures; no guest, service, dump or database executes."""
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import recovery_plans as plans
from nebulalog_manager.common import Refused
from nebulalog_manager.log_backup import VERSION

INSTALLATION = "e5cd13f8-ea47-4c23-8748-46509c04e5f1"
TABLE = "598e8b24-4ab6-4680-9467-1ddde081f89f"
NOW = 1792454400
G = plans.GIB
M = plans.MIB
PIN = "registry.example/image@sha256:"+"a"*64


def observation(shared=False):
    fs = lambda name: {"id": name*64, "revision": "e"*64, "total_bytes": 1000*G,
                       "free_bytes": 500*G, "free_inodes": 1000000, "block_bytes": 4096}
    return {"schema": 1, "installation_id": INSTALLATION,
        "runtime": {"images": {k:PIN for k in plans.IMAGE_KEYS}, "schema_revision": "3"},
        "policy": {"revision": 7, "normalization": "stored", "raw_policy_sha256": "a"*64},
        "configuration": {"bytes": M, "files": 10, "revision": "b"*64},
        "postgresql": {"bytes": G, "server_version": "17.6", "revision": "c"*64},
        "clickhouse": {"table_bytes": 2*G, "table_uuid": TABLE, "definition_sha256": "d"*64,
                       "server_version": VERSION, "instance_revision": "e"*64, "gate_revision": "f"*64},
        "recipient": {"sha256": "f"*64, "bytes": 1000},
        "storage": {"identity_sha256": "c"*64, "destination_revision": "d"*64, "data": "a"*64, "output": ("a" if shared else "b")*64,
                    "filesystems": [fs("a")] if shared else [fs("a"), fs("b")]},
        "observed_at": NOW, "sampling_ms": 20, "planner_revision": "d"*64}


def full_budgets():
    return {"maximum_archive_bytes": 3*G, "growth_reserve_bytes": G,
            "minimum_free_bytes": 100*G, "deadline_seconds": 600}


class PlanArithmeticTests(unittest.TestCase):
    def build(self, value=None, scope="full", budgets=None, **kwargs):
        value = value or observation()
        if scope == "config": value["clickhouse"] = None
        return plans.build_backup_plan(value, scope, budgets or (full_budgets() if scope == "full" else {"minimum_free_bytes": G}),
                                       now=NOW, expires_at=NOW+300, **kwargs)

    def test_exact_existing_admission_math_and_no_implicit_eta(self):
        result = self.build()
        data = next(fs for fs in result["filesystems"] if "data" in fs["roles"])
        self.assertEqual(data["existing_admission_floor_bytes"], 2*3*G+2*G+G)
        self.assertEqual(result["configuration"]["measured_bytes"], G+M)
        self.assertFalse(result["configuration"]["measurement_is_dump_upper_bound"])
        self.assertTrue(result["ready"])
        self.assertTrue(all(v == {"status":"unknown", "seconds":None} for v in result["estimates"].values()))
        self.assertFalse(result["space_reserved"] or result["execution_authorized"] or result["native_qualified"])

    def test_shared_filesystem_sums_simultaneous_components_not_unrelated_maxima(self):
        shared, separate = self.build(observation(True)), self.build(observation(False))
        row = shared["filesystems"][0]
        for phase in row["phase_peak_bytes"]:
            self.assertEqual(row["phase_peak_bytes"][phase], sum(f["phase_peak_bytes"][phase] for f in separate["filesystems"]))
        self.assertEqual(row["peak_additional_bytes"], max(row["existing_admission_floor_bytes"], *row["phase_peak_bytes"].values()))
        self.assertLess(row["peak_additional_bytes"], sum(row["phase_peak_bytes"].values()))

    def test_configuration_scope_does_not_require_or_claim_native_capture(self):
        result = self.build(scope="config")
        self.assertIsNone(result["clickhouse"])
        self.assertNotIn("native_backup", result["estimates"])
        self.assertEqual(result["configuration"]["plaintext_limit_bytes"], plans.MAX_BYTES)
        data = next(fs for fs in result["filesystems"] if "data" in fs["roles"])
        self.assertEqual(data["existing_admission_floor_bytes"], 3*(G+M))

    def test_capacity_and_inode_shortage_report_not_ready_without_clamping(self):
        value = observation(True); value["storage"]["filesystems"][0]["free_bytes"] = 101*G
        self.assertFalse(self.build(value)["ready"])
        value = observation(); value["storage"]["filesystems"][1]["free_inodes"] = 1
        self.assertFalse(self.build(value)["ready"])

    def test_native_archive_margin_and_ten_percent_reserve_match_adapter(self):
        budgets = full_budgets(); budgets["maximum_archive_bytes"] = 2*G
        self.assertIn("native_archive_budget_below_observed_table_margin", self.build(budgets=budgets)["reasons"])
        budgets = full_budgets(); budgets["minimum_free_bytes"] = 10*G
        self.assertIn("native_reserve_below_ten_percent", self.build(budgets=budgets)["reasons"])

    def test_runtime_policy_recipient_and_free_space_change_resource_digest(self):
        base = self.build()
        for section, field, replacement in (("recipient","sha256","1"*64),("policy","revision",8),
                                            ("configuration","revision","2"*64)):
            value = observation(); value[section][field] = replacement
            self.assertNotEqual(self.build(value)["resource_revision"], base["resource_revision"])
        value = observation(); value["storage"]["filesystems"][0]["free_bytes"] -= 4096
        self.assertNotEqual(self.build(value)["resource_revision"], base["resource_revision"])

    def test_strict_bounds_and_no_arbitrary_request_fields(self):
        for key, replacement in (("maximum_archive_bytes",True),("minimum_free_bytes",0),("deadline_seconds",86401)):
            budgets = full_budgets(); budgets[key] = replacement
            with self.subTest(key=key), self.assertRaises(Refused): self.build(budgets=budgets)
        value = observation(); value["private_key"] = "/tmp/key"
        with self.assertRaises(Refused): self.build(value)
        value = observation(); value["runtime"]["images"]["NEBULALOG_IMAGE"] = "latest"
        with self.assertRaises(Refused): self.build(value)
        with self.assertRaises(Refused): plans.build_backup_plan(observation(),"full",full_budgets(),now=NOW,expires_at=NOW)

    def test_only_compatible_measured_throughput_produces_estimate(self):
        base = self.build()
        sample = {"phase":"native_backup","scope":"full","bytes":G,"duration_ms":10000,"measured_at":NOW-20,
                  "runtime_revision":base["runtime_revision"],"storage_revision":base["storage_revision"],"evidence_sha256":"e"*64}
        result = self.build(throughput=[sample])
        self.assertEqual(result["estimates"]["native_backup"]["seconds"],20)
        self.assertIsNone(result["estimates"]["transfer"]["seconds"])
        for key,replacement in (("runtime_revision","f"*64),("storage_revision","f"*64),("measured_at",NOW+1),("duration_ms",True)):
            with self.subTest(key=key), self.assertRaises(Refused): self.build(throughput=[{**sample,key:replacement}])
        sample["duration_ms"] = 400000
        self.assertIn("measured_native_duration_exceeds_deadline", self.build(throughput=[sample])["reasons"])

    def test_duplicate_filesystems_and_unmatched_roles_refuse(self):
        value = observation(); value["storage"]["filesystems"][1] = copy.deepcopy(value["storage"]["filesystems"][0])
        with self.assertRaises(Refused): self.build(value)
        value = observation(); value["storage"]["output"] = "f"*64
        with self.assertRaises(Refused): self.build(value)


@dataclass
class FixtureIdentity:
    installation_id: str = INSTALLATION


class ObservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.data = self.root/"data"; self.output = self.root/"output"
        for path in (self.data/"manager",self.data/"configuration",self.output): path.mkdir(mode=0o700,parents=True)
        (self.data/"configuration/secret.pem").write_bytes(b"private configuration must never be read by sizing")
        (self.data/"configuration/secret.pem").chmod(0o600)
        self.cert = self.root/"recipient.pem"; self.cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n"); self.cert.chmod(0o600)
        self.calls=[]; self.host={"host_ready":True,"setup_complete":True,"installation_id":INSTALLATION}
        self.runtime=observation()["runtime"]; self.policy=observation()["policy"]
        self.storage_gate={"schema":1,"held":False,"delivery_held":False,"operation":None}
        self.storage_row={"gate":copy.deepcopy(self.storage_gate),"engine":{"schema":1,"mode":"partition","table_uuid":TABLE},"pending":0}
        self.gate_path=self.data/"manager/storage-maintenance/gate.json"
        self.gate_path.parent.mkdir(mode=0o700)
        self.gate_path.write_text(json.dumps(self.storage_gate)); self.gate_path.chmod(0o600)
        life=SimpleNamespace(cmd=self.command,_schema_psql=lambda query:json.dumps(self.storage_row))
        self.backup=SimpleNamespace(data=self.data,configuration=self.data/"configuration",manager=self.data/"manager",lifecycle=life,cmd=self.command,
            gate=lambda:copy.deepcopy(self.host),_pending=Mock(),_active=Mock(),_runtime_metadata=lambda:copy.deepcopy(self.runtime),
            _log_policy=lambda:copy.deepcopy(self.policy),_metadata=lambda:{"server_version":"17.6","image":PIN,
                "databases":{"nebulalog":{"bytes":G},"keycloak":{"bytes":G}}})
        self.subject=plans.RecoveryPlanner(self.backup,output_parent=self.output,recipient_certificate=self.cert,clock=lambda:NOW)
        self.native=SimpleNamespace(_instance=lambda pin:{"pin":pin,"pid":5},
            _table=lambda value:{"bytes_on_disk":G,"table_uuid":TABLE,"table_definition_sha256":"a"*64,"server_version":VERSION})
        for item in (patch.object(plans,"require_linux_root"),patch.object(plans,"DATA",self.data),patch.object(plans,"ROOT_UID",os.getuid()),
                     patch.object(plans,"_directory",side_effect=self.directory),patch.object(plans,"LogBackupAdapter",return_value=self.native),
                     patch("nebulalog_manager.host_plans.read_identity",return_value=FixtureIdentity()),
                     patch.object(plans.os,"statvfs",return_value=SimpleNamespace(f_blocks=1000*G//4096,f_bavail=500*G//4096,f_frsize=4096,f_favail=1000000))):
            item.start(); self.addCleanup(item.stop)

    def directory(self,path,*,private=False):
        if not path.is_relative_to(self.root): raise Refused("outside fixture")
        for current in [path,*path.parents]:
            if current==self.root.parent: break
            info=current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o022: raise Refused("unsafe fixture directory")
        if private and path.stat().st_mode&0o077: raise Refused("not private")

    def command(self,argv,**kwargs):
        self.calls.append((argv,kwargs))
        if argv[0]=="findmnt": return json.dumps({"filesystems":[{"target":str(self.data),"source":"/dev/mapper/data","fstype":"xfs"}]})
        if argv[0]=="lsblk": return json.dumps({"blockdevices":[{"name":"data","type":"lvm","fstype":"xfs","children":[{"fstype":"crypto_LUKS"}]}]})
        if argv[:2]==["openssl","x509"]: return "Certificate will not expire"
        raise AssertionError(argv)

    def snapshot(self):
        return {p.relative_to(self.root).as_posix():(p.lstat().st_mode,p.lstat().st_size,p.read_bytes() if p.is_file() else None)
                for p in self.root.rglob("*")}

    def test_configuration_observation_is_read_only_and_contains_no_paths_or_secrets(self):
        before=self.snapshot(); command=self.backup.cmd
        result=self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        self.assertEqual(before,self.snapshot()); self.assertIs(self.backup.cmd,command)
        raw=json.dumps(result)
        self.assertNotIn(str(self.root),raw); self.assertNotIn("secret.pem",raw); self.assertNotIn("private configuration",raw)
        self.assertEqual(result["configuration"]["measured_bytes"],2*G+(self.data/"configuration/secret.pem").stat().st_size)
        self.assertTrue(all(call[0][0] in ("findmnt","lsblk","openssl") for call in self.calls))
        self.assertFalse(any("BACKUP" in str(call) or "pg_dump" in str(call) for call in self.calls))

    def test_full_observation_binds_fixed_native_table_without_native_job(self):
        before=self.snapshot()
        result=self.subject.plan(scope="full",budgets=full_budgets())
        self.assertEqual(result["clickhouse"]["table_uuid"],TABLE)
        self.assertEqual(before,self.snapshot())
        self.assertEqual(len(result["filesystems"]),1)

    def test_changed_policy_or_host_identity_refuses_and_restores_runner(self):
        original=self.backup.cmd
        self.backup._log_policy=Mock(side_effect=[self.policy,{**self.policy,"revision":8}])
        with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        self.assertIs(self.backup.cmd,original)

    def test_missing_output_symlink_and_private_key_recipient_never_create_state(self):
        self.subject.output=self.root/"missing"
        with self.assertRaises((Refused,FileNotFoundError)): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        self.assertFalse(self.subject.output.exists())
        self.subject.output=self.output
        self.cert.write_bytes(b"-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----\n")
        with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        self.assertFalse(self.calls)

    def test_configuration_symlink_special_and_hardlink_refuse_without_content_reads(self):
        path=self.data/"configuration/secret.pem"; original=path.read_bytes()
        path.unlink(); path.symlink_to(self.cert)
        with self.assertRaises(Refused): plans.configuration_measurement(path.parent)
        path.unlink(); os.mkfifo(path)
        with self.assertRaises(Refused): plans.configuration_measurement(path.parent)
        path.unlink(); path.write_bytes(original); path.chmod(0o600); os.link(path,self.root/"hardlink")
        with self.assertRaises(Refused): plans.configuration_measurement(path.parent)

    def test_inventory_bound_and_timeout_fail_closed(self):
        with patch.object(plans,"MAX_FILES",0),self.assertRaises(Refused): plans.configuration_measurement(self.data/"configuration")
        with self.assertRaises(Refused): plans.configuration_measurement(self.data/"configuration",lambda:(_ for _ in ()).throw(Refused("expired")))
        self.subject.monotonic=Mock(side_effect=[0,121])
        with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})

    def test_configuration_cross_device_entry_is_refused(self):
        original=plans.os.stat
        def changed(path, *args, **kwargs):
            info=original(path,*args,**kwargs)
            if path=="secret.pem" and kwargs.get("dir_fd") is not None:
                return SimpleNamespace(st_dev=info.st_dev+1,st_mode=info.st_mode,st_uid=info.st_uid,st_gid=info.st_gid)
            return info
        with patch.object(plans.os,"stat",side_effect=changed),self.assertRaises(Refused):
            plans.configuration_measurement(self.backup.configuration)

    def test_corrupt_mount_ancestry_and_destination_overlap_refuse(self):
        original=self.command
        self.backup.cmd=lambda argv,**kw:json.dumps({"blockdevices":[{"fstype":"xfs"}]}) if argv[0]=="lsblk" else original(argv,**kw)
        with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        self.subject.output=self.backup.configuration
        with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})

    def test_destination_is_bound_but_throughput_storage_is_device_based(self):
        first=self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        other=self.root/"another-output"; other.mkdir(mode=0o700)
        self.subject.output=other
        second=self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        self.assertNotEqual(first["destination_revision"],second["destination_revision"])
        self.assertNotEqual(first["resource_revision"],second["resource_revision"])
        self.assertEqual(first["storage_revision"],second["storage_revision"])

    def test_destination_replacement_during_observation_refuses(self):
        def metadata():
            self.output.rename(self.root/"original-output"); self.output.mkdir(mode=0o700)
            return {"server_version":"17.6","databases":{"nebulalog":{"bytes":G},"keycloak":{"bytes":G}}}
        self.backup._metadata=metadata
        with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})

    def test_full_plan_refuses_pending_foreign_and_changed_gates(self):
        for mutation in (lambda:self.storage_row.update(pending=1),
                         lambda:self.storage_row["engine"].update(table_uuid=INSTALLATION),
                         lambda:self.storage_row["gate"].update(held=True,operation="e"*64)):
            original=copy.deepcopy(self.storage_row); mutation()
            with self.assertRaises(Refused): self.subject.plan(scope="full",budgets=full_budgets())
            self.storage_row=original
        before=copy.deepcopy(self.storage_row)
        self.backup.lifecycle._schema_psql=Mock(side_effect=[json.dumps(before),json.dumps({**before,"pending":1})])
        with self.assertRaises(Refused): self.subject.plan(scope="full",budgets=full_budgets())

    def test_changed_native_instance_or_definition_refuses_but_growth_is_measured(self):
        table=self.native._table(None)
        self.native._instance=Mock(side_effect=[{"pin":PIN,"pid":5},{"pin":PIN,"pid":6}])
        with self.assertRaises(Refused): self.subject.plan(scope="full",budgets=full_budgets())
        self.native._instance=lambda pin:{"pin":pin,"pid":5}
        self.native._table=Mock(side_effect=[table,{**table,"table_definition_sha256":"b"*64}])
        with self.assertRaises(Refused): self.subject.plan(scope="full",budgets=full_budgets())
        self.native._table=Mock(side_effect=[table,{**table,"bytes_on_disk":2*G}])
        self.assertEqual(self.subject.plan(scope="full",budgets=full_budgets())["clickhouse"]["table_bytes"],2*G)

    def test_missing_or_oversized_gate_and_mount_option_source_refuse(self):
        self.gate_path.write_bytes(b" "*4097)
        with self.assertRaises(Refused): self.subject.plan(scope="full",budgets=full_budgets())
        self.gate_path.unlink()
        with self.assertRaises(FileNotFoundError): self.subject.plan(scope="full",budgets=full_budgets())
        self.backup.cmd=lambda argv,**kw:json.dumps({"filesystems":[{"target":str(self.data),"source":"--unsafe-option","fstype":"xfs"}]}) if argv[0]=="findmnt" else self.command(argv,**kw)
        with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        self.assertFalse(any(call[0][0]=="lsblk" for call in self.calls))

    def test_one_observer_cannot_swap_command_adapters_concurrently(self):
        self.subject._busy.acquire()
        try:
            with self.assertRaises(Refused): self.subject.plan(scope="config",budgets={"minimum_free_bytes":G})
        finally: self.subject._busy.release()
        self.assertFalse(self.calls)
