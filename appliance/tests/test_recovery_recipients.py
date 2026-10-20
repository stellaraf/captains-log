"""Tiny real OpenSSL3 and protected-file fixtures, never live authorization."""
from dataclasses import replace
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from nebulalog_manager import recovery_recipients as recipients
from nebulalog_manager import host_job_storage as storage
from nebulalog_manager.common import CommandFailed, Refused
from nebulalog_manager.host_challenges import ChallengeRecords
from nebulalog_manager.host_job_storage import StorageIdentity, digest

INSTALLATION = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"


class RecipientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = os.environ.get("CAPTAINS_LOG_TEST_OPENSSL") or shutil.which("openssl")
        if not cls.openssl or not subprocess.check_output([cls.openssl,"version"],text=True).startswith("OpenSSL 3."):
            raise unittest.SkipTest("Real OpenSSL3 is required; no crypto acceptance without it")
        cls.temporary = tempfile.TemporaryDirectory(); cls.directory = Path(cls.temporary.name)
        cls.key = cls.directory/"fixture-only.key"
        cls.cli(["genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:3072","-out",str(cls.key)])
        cls.key.chmod(0o600)
        cls.certificates = {}
        options = {"valid":("critical,CA:FALSE","critical,keyEncipherment"),
                   "digital":("critical,CA:FALSE","critical,digitalSignature,keyEncipherment"),
                   "ca":("critical,CA:TRUE","critical,keyEncipherment"),
                   "signing":("critical,CA:FALSE","critical,digitalSignature"),
                   "missing_usage":("critical,CA:FALSE",None),
                   "missing_constraints":(None,"critical,keyEncipherment"),
                   "extended":("critical,CA:FALSE","critical,keyEncipherment"),
                   "unknown_critical":("critical,CA:FALSE","critical,keyEncipherment"),
                   "sha1":("critical,CA:FALSE","critical,keyEncipherment")}
        # Empty config prevents distro/user default CA extensions changing fixtures.
        config=cls.directory/"empty.cnf"; config.write_text("")
        for name,(basic,usage) in options.items():
            argv=["req","-new","-x509","-config",str(config),"-key",str(cls.key),"-days","2",
                  "-sha1" if name=="sha1" else "-sha256","-subj","/CN=Public recovery fixture"]
            if basic: argv += ["-addext","basicConstraints="+basic]
            if usage: argv += ["-addext","keyUsage="+usage]
            if name=="extended": argv += ["-addext","extendedKeyUsage=emailProtection"]
            if name=="unknown_critical": argv += ["-addext","1.2.3.4=critical,DER:04:01:01"]
            cls.certificates[name]=cls.cli(argv)
        weak=cls.directory/"weak.key"
        cls.cli(["genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out",str(weak)]);weak.chmod(0o600)
        cls.certificates["weak"]=cls.cli(["req","-new","-x509","-config",str(config),"-key",str(weak),"-days","2","-sha256","-subj","/CN=Weak fixture",
                                        "-addext","basicConstraints=critical,CA:FALSE","-addext","keyUsage=critical,keyEncipherment"])
        ec=cls.directory/"ec.key"
        cls.cli(["genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",str(ec)]);ec.chmod(0o600)
        cls.certificates["ec"]=cls.cli(["req","-new","-x509","-config",str(config),"-key",str(ec),"-days","2","-sha256","-subj","/CN=Unqualified EC fixture",
                                      "-addext","basicConstraints=critical,CA:FALSE","-addext","keyUsage=critical,keyAgreement"])
        large=cls.directory/"rsa4096.key"
        cls.cli(["genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:4096","-out",str(large)]);large.chmod(0o600)
        cls.certificates["rsa4096"]=cls.cli(["req","-new","-x509","-config",str(config),"-key",str(large),"-days","2","-sha384","-subj","/CN=Public RSA4096 fixture",
                                           "-addext","basicConstraints=critical,CA:FALSE","-addext","keyUsage=critical,keyEncipherment"])

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    @classmethod
    def cli(cls, argv, data=None):
        proc=subprocess.run([cls.openssl,*argv],input=data,capture_output=True,timeout=15)
        if proc.returncode: raise RuntimeError("Fixture OpenSSL failed: "+proc.stderr.decode())
        return proc.stdout

    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.identity=StorageIdentity(INSTALLATION,self.root,self.root.stat().st_dev)
        self.now=int(time.time());self.calls=[];self.probe=None
        owner=patch.object(storage,"ROOT_UID",os.getuid());owner.start();self.addCleanup(owner.stop)
        self.records=ChallengeRecords(lambda:self.identity)
        self.subject=recipients.RecoveryRecipients(records=self.records,commands=self.command,clock=lambda:self.now)
        self.subject.initialize();self.state=self.root/"manager/jobs"
        self.request=str(uuid.uuid4());self.pem=self.certificates["valid"]

    def command(self, argv, *, input=None, timeout=5):
        self.assertEqual(argv[0],"openssl");self.assertLessEqual(timeout,5)
        self.calls.append(argv)
        proc=subprocess.run([self.openssl,*argv[1:]],input=input,capture_output=True,timeout=timeout)
        if proc.returncode: raise CommandFailed("openssl",proc.returncode)
        if argv[1]=="cms": self.probe=proc.stdout
        return proc.stdout.decode("utf-8").strip()

    def body(self, pem=None, revision=0, ack=True):
        return {"certificate_sha256":hashlib.sha256(pem or self.pem).hexdigest(),"escrow_acknowledged":ack,"expected_registry_revision":revision}

    def binding(self, action, body, request=None):
        return recipients.RecipientBinding(INSTALLATION,"a"*64,"b"*64,action,recipients.request_digest(action,request or self.request,body))

    def enroll(self, pem=None, revision=0, request=None):
        body=self.body(pem,revision);return self.subject.enroll(self.binding("recipient.enroll",body,request),
            request_id=request or self.request,certificate_pem=pem or self.pem,escrow_acknowledged=True,expected_registry_revision=revision)

    def disable(self, enrolled, request=None, revision=1):
        request=request or str(uuid.uuid4())
        body={k:enrolled[k] for k in ("recipient_id","revision","certificate_sha256")};body["expected_registry_revision"]=revision
        return self.subject.disable(self.binding("recipient.disable",body,request),request_id=request,**body)

    def lookup(self, value):return self.subject.lookup(*(value[k] for k in ("recipient_id","revision","certificate_sha256")))
    def ledger(self):return json.loads((self.state/recipients.LEDGER).read_text())
    def raw(self):return (self.state/recipients.LEDGER).read_bytes()

    def test_genesis_is_explicit_idempotent_and_does_not_initialize_jobs(self):
        before=self.raw();first=self.subject.initialize()
        self.assertEqual(first,self.subject.initialize());self.assertEqual(before,self.raw())
        self.assertFalse((self.state/"ledger.json").exists())
        self.assertFalse((self.state.parent/"host-jobs-identity.json").exists())

    def test_real_openssl_profile_inspection_has_no_persistence_or_key_possession_claim(self):
        before=self.raw();value=self.subject.inspect(self.pem)
        self.assertEqual(before,self.raw());self.assertEqual(value["facts"]["public_key_bits"],3072)
        self.assertFalse(value["authorization"] or value["key_possession_proven"])
        text=self.cli(["cms","-cmsout","-print","-inform","PEM"],self.probe).decode()
        self.assertIn("rsaesOaep",text);self.assertIn("aes-256-gcm",text);self.assertGreaterEqual(text.count("sha256"),2)
        self.assertIn("rsa_padding_mode:oaep",self.calls[-1]);self.assertIn("rsa_mgf1_md:sha256",self.calls[-1])

    def test_real_rsa4096_sha384_certificate_uses_same_fixed_cms_profile(self):
        found=self.subject.inspect(self.certificates["rsa4096"])
        self.assertEqual(found["facts"]["public_key_bits"],4096)
        self.assertEqual(found["facts"]["cms_profile"],recipients.RECOVERY_CRYPTO_PROFILE)
        text=self.cli(["cms","-cmsout","-print","-inform","PEM"],self.probe).decode()
        self.assertIn("rsaesOaep",text);self.assertGreaterEqual(text.count("sha256"),2)

    def test_enroll_retains_exact_public_identity_and_stable_retry(self):
        value=self.enroll();before=self.raw();calls=len(self.calls)
        self.assertEqual(value,self.enroll());self.assertEqual(before,self.raw());self.assertEqual(calls,len(self.calls))
        found=self.lookup(value);self.assertEqual(found["certificate_pem"],self.pem)
        self.assertEqual(found["facts"]["certificate_sha256"],hashlib.sha256(self.pem).hexdigest())
        self.assertFalse(found["authorization"] or found["key_possession_proven"])
        self.assertNotIn(b"PRIVATE KEY",before)

    def test_disable_preserves_history_and_blocks_new_lookup_without_replacing_bytes(self):
        enrolled=self.enroll();request=str(uuid.uuid4());disabled=self.disable(enrolled,request)
        before=self.raw()
        self.assertEqual(disabled,self.disable(enrolled,request));self.assertEqual(before,self.raw())
        with self.assertRaisesRegex(Refused,"unavailable"):self.lookup(enrolled)
        self.assertEqual(self.ledger()["events"][0]["certificate_pem"].encode(),self.pem)
        self.assertEqual(enrolled,self.enroll()) # Historical acknowledgement, never a new enabled lookup.
        replacement=self.enroll(revision=2,request=str(uuid.uuid4()))
        self.assertNotEqual(replacement["recipient_id"],enrolled["recipient_id"])
        self.assertEqual(self.lookup(replacement)["certificate_pem"],self.pem)

    def test_wrong_action_actor_installation_digest_or_stale_review_refuses(self):
        body=self.body();binding=self.binding("recipient.enroll",body);before=self.raw()
        for change in ({"installation_id":str(uuid.uuid4())},{"request_digest":"c"*64},{"action":"recipient.disable"}):
            with self.subTest(change=change),self.assertRaises(Refused):
                self.subject.enroll(replace(binding,**change),request_id=self.request,certificate_pem=self.pem,
                                    escrow_acknowledged=True,expected_registry_revision=0)
        self.assertEqual(before,self.raw());self.enroll()
        with self.assertRaisesRegex(Refused,"stale"):self.enroll(request=str(uuid.uuid4()))
        with self.assertRaisesRegex(Refused,"reused"):self.enroll(self.certificates["digital"])

    def test_unacknowledged_escrow_is_rejected_but_acknowledgement_is_not_a_proof(self):
        with self.assertRaisesRegex(Refused,"acknowledgement"):self.binding("recipient.enroll",self.body(ack=False))
        for bad in (1,"true",None):
            with self.subTest(bad=bad),self.assertRaises(Refused):self.binding("recipient.enroll",self.body(ack=bad))
        enrolled=self.enroll();self.assertFalse(self.lookup(enrolled)["key_possession_proven"])

    def test_single_public_pem_boundary_rejects_keys_chains_suffixes_and_oversize(self):
        before=self.raw()
        for bad in (self.pem+self.key.read_bytes(),self.key.read_bytes(),self.pem+self.pem,self.pem+b"junk",self.pem+b"\nPRIVATE KEY",
                    b"x"*65537,self.pem.decode(),b"-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n"):
            with self.subTest(size=len(bad)),self.assertRaises(Refused):self.subject.inspect(bad)
        self.assertEqual(self.raw(),before);self.assertFalse(self.calls)

    def test_constraints_usage_algorithms_and_extensions_fail_before_crypto(self):
        for name in ("ca","signing","missing_usage","missing_constraints","extended","unknown_critical","sha1","weak","ec"):
            with self.subTest(name=name),self.assertRaises(Refused):self.subject.inspect(self.certificates[name])
        self.assertFalse(self.calls)
        self.assertEqual(self.subject.inspect(self.certificates["digital"])["facts"]["public_key_bits"],3072)

    def test_current_validity_exclusive_expiry_and_future_certificate(self):
        facts=recipients._facts(self.pem);before=self.raw()
        self.now=facts["not_before"]-1
        with self.assertRaisesRegex(Refused,"not_current"):self.subject.inspect(self.pem)
        self.now=facts["not_after"]
        with self.assertRaisesRegex(Refused,"not_current"):self.enroll()
        self.assertEqual(self.raw(),before);self.assertFalse(self.calls)

    def test_expired_enrolled_recipient_cannot_be_used_for_new_backup(self):
        enrolled=self.enroll();self.now=recipients._facts(self.pem)["not_after"]
        with self.assertRaisesRegex(Refused,"not_current"):self.lookup(enrolled)
        self.assertEqual(enrolled,self.enroll())

    def test_crypto_failure_or_wrong_openssl_never_commits(self):
        original=self.command;before=self.raw()
        for stage in ("version","x509","pkey","cms"):
            def failing(argv,**kwargs):
                if argv[1]==stage:
                    if stage=="version":return "OpenSSL 4.0.3"
                    raise CommandFailed("openssl",1)
                return original(argv,**kwargs)
            with self.subTest(stage=stage),patch.object(self.subject,"commands",side_effect=failing),self.assertRaises(Refused):self.enroll()
            self.assertEqual(before,self.raw())

    def test_lost_enroll_and_disable_acknowledgement_preserve_original_events(self):
        original=self.records.write
        def lost(path,value,identity):
            original(path,value,identity)
            if path.name==recipients.LEDGER and value["revision"]:raise OSError("lost ack")
        with patch.object(self.records,"write",side_effect=lost),self.assertRaises(Refused):self.enroll()
        first=self.ledger()["events"][0]["result"];before=self.raw()
        self.assertEqual(first,self.enroll());self.assertEqual(before,self.raw())
        request=str(uuid.uuid4())
        with patch.object(self.records,"write",side_effect=lost),self.assertRaises(Refused):self.disable(first,request)
        expected=self.ledger()["events"][1]["result"];before=self.raw()
        self.assertEqual(expected,self.disable(first,request));self.assertEqual(before,self.raw())

    def test_failed_precommit_does_not_publish_recipient(self):
        original=self.records.write;before=self.raw()
        def failed(path,value,identity):
            if path.name==recipients.LEDGER and value["revision"]:raise OSError("before commit")
            return original(path,value,identity)
        with patch.object(self.records,"write",side_effect=failed),self.assertRaises(Refused):self.enroll()
        self.assertEqual(before,self.raw());self.assertEqual(len(self.ledger()["events"]),0)

    def test_genesis_ack_loss_preserves_registry_and_exact_marker_types(self):
        root=self.root/"fresh";root.mkdir(mode=0o700)
        identity=StorageIdentity(INSTALLATION,root,root.stat().st_dev)
        records=ChallengeRecords(lambda:identity)
        subject=recipients.RecoveryRecipients(records=records,commands=self.command,clock=lambda:self.now)
        original=records.write
        def lost(path,value,identity):
            original(path,value,identity)
            if path.name==recipients.MARKER:raise OSError("marker ack lost")
        with patch.object(records,"write",side_effect=lost),self.assertRaises(Refused):subject.initialize()
        path=root/"manager"/recipients.MARKER;marker=json.loads(path.read_text())
        self.assertEqual(subject.initialize()["registry_id"],marker["registry_id"])
        marker["schema"]=True
        with records.locked() as (_,identity):records.write(path,marker,identity)
        with self.assertRaisesRegex(Refused,"marker_schema"):subject.initialize()

    def test_registry_and_history_are_bounded_without_deleting_disabled_records(self):
        first=self.enroll();self.disable(first);before=self.raw()
        with patch.object(recipients,"MAX_RECIPIENTS",1),self.assertRaisesRegex(Refused,"registry_full"):
            self.enroll(revision=2,request=str(uuid.uuid4()))
        with patch.object(recipients,"MAX_EVENTS",2),self.assertRaisesRegex(Refused,"history_full"):
            self.enroll(revision=2,request=str(uuid.uuid4()))
        self.assertEqual(before,self.raw())

    def test_shared_owned_lock_lookup_has_no_recursive_acquisition_or_consumption(self):
        first=self.enroll();args=[first[k] for k in ("recipient_id","revision","certificate_sha256")];before=self.raw()
        with self.assertRaisesRegex(Refused,"owned_lock"):self.subject.lookup_locked(*args)
        with self.records.locked():
            self.assertEqual(self.subject.lookup_locked(*args)["certificate_pem"],self.pem)
            with self.assertRaisesRegex(Refused,"manager_busy"):self.lookup(first)
        self.assertEqual(before,self.raw())

    def test_storage_corruption_symlink_permissions_and_missing_state_refuse(self):
        self.enroll();path=self.state/recipients.LEDGER;saved=path.read_bytes()
        value=self.ledger();value["events"][0]["facts"]["public_key_bits"]=4096
        value["digest"]=digest({k:v for k,v in value.items() if k!="digest"})
        with self.records.locked() as (_,identity):self.records.write(path,value,identity)
        with self.assertRaises(Refused):self.subject.initialize()
        path.write_bytes(saved);path.chmod(0o644)
        with self.assertRaises(Refused):self.subject.initialize()
        path.chmod(0o600);path.unlink()
        with self.assertRaises(Refused):self.subject.initialize()
        self.assertFalse(path.exists())
        other=self.root/"elsewhere";other.write_bytes(saved);other.chmod(0o600);path.symlink_to(other)
        with self.assertRaises(Refused):self.subject.initialize()

    def test_wrong_revision_fingerprint_and_clock_refuse_lookup(self):
        first=self.enroll()
        for args in ((first["recipient_id"],True,first["certificate_sha256"]),(first["recipient_id"],2,first["certificate_sha256"]),
                     (first["recipient_id"],1,"f"*64)):
            with self.subTest(args=args),self.assertRaises(Refused):self.subject.lookup(*args)
        self.now-=1
        with self.assertRaisesRegex(Refused,"clock_regressed"):self.lookup(first)

    def test_crypto_expiry_during_probe_refuses_before_commit(self):
        original=self.command;before=self.raw()
        def expire(argv,**kwargs):
            result=original(argv,**kwargs)
            if argv[1]=="cms":self.now=recipients._facts(self.pem)["not_after"]
            return result
        with patch.object(self.subject,"commands",side_effect=expire),self.assertRaisesRegex(Refused,"not_current"):self.enroll()
        self.assertEqual(before,self.raw())


if __name__ == "__main__": unittest.main()
