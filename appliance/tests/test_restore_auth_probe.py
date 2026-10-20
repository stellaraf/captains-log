"""Source tests for the publisher probe; no application image is executed here."""
import base64
import copy
import http.server
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

PACKER=Path(__file__).resolve().parents[1]/"packer"
sys.path.insert(0,str(PACKER))
import probe_restore_auth as probe
from nebulalog_manager.common import Refused


IMAGE={"config_digest":"sha256:"+"a"*64,"reference":"nebulalog/application@sha256:"+"b"*64,
       "application_source_sha256":"c"*64}


def target(cutoff=1700000000):
    values={"OIDC_TOKEN_NOT_BEFORE":str(cutoff),"REQUIRE_FIPS":"true","OIDC_ISSUER":probe.ISSUER,
        "OIDC_CLIENT_ID":probe.CLIENT,"OIDC_BACKCHANNEL_URL":"",
        "PG_DSN":"postgresql://fixture@127.0.0.1:1/fixture?sslmode=disable&connect_timeout=1",
        "CH_URL":"http://127.0.0.1:1","STORAGE_MAINTENANCE_PATH":probe.GATE+"/gate.json","API_LISTEN":":8080"}
    return {"Id":"container-id","Image":IMAGE["config_digest"],"Path":"nebulalog","Args":["serve"],"State":{"Running":True},
        "Config":{"Image":IMAGE["config_digest"],"Entrypoint":["nebulalog"],"Cmd":["serve"],"User":"10001:10001",
                  "Labels":{probe.LABEL:"owned"},"Env":[key+"="+value for key,value in values.items()]},
        "HostConfig":{"ReadonlyRootfs":True,"Privileged":False,"NetworkMode":"isolated","PidsLimit":64,"Memory":256*1024**2,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"]},
        "NetworkSettings":{"Networks":{"isolated":{}},"Ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"43123"}]}},
        "Mounts":[{"Type":"volume","Name":"gate","Destination":probe.GATE,"RW":False}]}


class IdentityTests(unittest.TestCase):
    def test_exact_normal_entrypoint_cutoff_and_loopback_bindings(self):
        self.assertEqual(probe.target_identity(target(),IMAGE,"isolated",1700000000,"owned","gate"),(43123,1700000000))
        variants=[]
        for key,value in (("Args",["api"]),("Image","sha256:"+"d"*64),("Path","/bin/sh")):
            got=target();got[key]=value;variants.append(got)
        got=target();got["Config"]["Env"].append("OIDC_TOKEN_NOT_BEFORE=1");variants.append(got)
        got=target();got["Config"]["Env"][1]="REQUIRE_FIPS=false";variants.append(got)
        got=target();got["HostConfig"]["Privileged"]=True;variants.append(got)
        got=target();got["Mounts"][0]["RW"]=True;variants.append(got)
        got=target();got["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostIp"]="0.0.0.0";variants.append(got)
        got=target();got["NetworkSettings"]["Networks"]["outside"]={};variants.append(got)
        for item in variants:
            with self.subTest(item=item),self.assertRaises(Refused):
                probe.target_identity(item,IMAGE,"isolated",1700000000,"owned","gate")

    def test_capacity_refuses_before_oci_or_runtime_access(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(Path,"is_mount",return_value=True),patch.object(probe.shutil,"disk_usage",return_value=Mock(free=probe.RESERVE-1)), \
                 patch.object(probe,"Docker") as runtime,patch.object(probe,"verify_oci_archive") as archive:
                with self.assertRaisesRegex(Refused,"150 GiB"):
                    probe.execute("unused","unused","unused","unused",Path(folder)/"out",folder)
                runtime.assert_not_called();archive.assert_not_called()
                self.assertFalse((Path(folder)/"out").exists())

    def test_remote_transport_is_refused_without_a_cli_call(self):
        runtime=probe.Docker()
        with patch.dict(os.environ,{"DOCKER_HOST":"tcp://fixture.invalid:2375"}),patch.object(runtime,"call") as call:
            with self.assertRaisesRegex(Refused,"remote"):
                runtime.local()
            call.assert_not_called()

    def test_local_context_is_pinned_for_subsequent_operations(self):
        runtime=probe.Docker()
        item={"Name":"local-fixture","Endpoints":{"docker":{"Host":"unix:///fixture.sock"}}}
        with patch.dict(os.environ,{"DOCKER_HOST":"","DOCKER_TLS_VERIFY":"","DOCKER_CERT_PATH":""}), \
             patch.object(runtime,"call",return_value=Mock(stdout=json.dumps([item]).encode())):
            runtime.local()
        with patch.object(probe.subprocess,"run",return_value=Mock(returncode=0,stdout=b"[]",stderr=b"")) as call:
            runtime.call(["image","inspect","fixture"])
            self.assertEqual(call.call_args.args[0][:3],["docker","--context","local-fixture"])
        item["Endpoints"]["docker"]["Host"]="unix:///changed.sock"
        with patch.dict(os.environ,{"DOCKER_HOST":"","DOCKER_TLS_VERIFY":"","DOCKER_CERT_PATH":""}), \
             patch.object(runtime,"call",return_value=Mock(stdout=json.dumps([item]).encode())):
            with self.assertRaisesRegex(Refused,"changed"):
                runtime.local()

    def test_absence_is_exact_resource_evidence_not_a_daemon_or_context_error(self):
        for kind,message in (("container","No such container: owned"),("network","network owned not found"),
                             ("volume","get owned: no such volume")):
            self.assertTrue(probe.absent(kind,"owned",Mock(returncode=1,stderr=message.encode())))
            for wrong in ("Cannot connect to Docker daemon","context owned: context not found",message.replace("owned","foreign"),message.replace("owned","owned-extra")):
                self.assertFalse(probe.absent(kind,"owned",Mock(returncode=1,stderr=wrong.encode())))

    def test_remote_refusal_does_not_attempt_cleanup_on_that_transport(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime=Mock(calls=[]);runtime.local.side_effect=Refused("remote transport")
            with patch.object(probe,"reserve"),patch.object(probe,"verify_oci_archive",return_value=IMAGE), \
                 patch.object(probe.host_payload,"read_regular",return_value=b'{"requested_version":"1.0.0"}'), \
                 patch.object(probe.host_payload,"source_manifest",return_value={"files":{}}), \
                 patch.object(probe.Contract,"_build"),patch.object(probe,"Docker",return_value=runtime):
                out=Path(folder)/"output"
                with self.assertRaisesRegex(Refused,"qualification failed"):
                    probe.execute("unused",IMAGE["reference"],"unused","unused",out,folder)
            runtime.call.assert_not_called();runtime.inspect.assert_not_called()
            self.assertEqual(json.loads((out/"execution.json").read_bytes())["status"],"failed")
            self.assertFalse((out/probe.Contract.BEHAVIOR).exists())

    def test_changed_context_at_cleanup_preserves_unknown_resources_without_calls(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime=Mock(calls=[])
            runtime.local.side_effect=[None,Refused("pinned context changed")]
            runtime.inspect.side_effect=Refused("interrupted preflight")
            with patch.object(probe,"reserve"),patch.object(probe,"verify_oci_archive",return_value=IMAGE), \
                 patch.object(probe.host_payload,"read_regular",return_value=b'{"requested_version":"1.0.0"}'), \
                 patch.object(probe.host_payload,"source_manifest",return_value={"files":{}}), \
                 patch.object(probe.Contract,"_build"),patch.object(probe,"Docker",return_value=runtime):
                out=Path(folder)/"output"
                with self.assertRaisesRegex(Refused,"qualification failed"):
                    probe.execute("unused",IMAGE["reference"],"unused","unused",out,folder)
            runtime.call.assert_not_called()
            self.assertEqual(runtime.inspect.call_count,1)
            receipt=json.loads((out/"execution.json").read_bytes())
            self.assertTrue(receipt["cleanup"][0]["resource_calls_skipped"])
            self.assertFalse((out/probe.Contract.BEHAVIOR).exists())


class HTTPAndCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory()
        cls.signer=probe.Signer(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_rsa_tokens_and_wrong_signature_control(self):
        self.assertEqual(self.signer.jwk["kty"],"RSA")
        for wrong in (False,True):
            token=self.signer.token({"sub":"fixture"},wrong)
            header,payload,signature=token.split(".")
            self.assertEqual(json.loads(base64.urlsafe_b64decode(payload+"==")),{"sub":"fixture"})
            path=Path(self.temporary.name)/"signature.bin"
            path.write_bytes(base64.urlsafe_b64decode(signature+"=="))
            result=subprocess.run(["openssl","dgst","-sha256","-verify",str(self.signer.public),"-signature",str(path)],
                                  input=(header+"."+payload).encode(),capture_output=True,timeout=10)
            self.assertEqual(result.returncode==0,not wrong)
        with self.assertRaises(Refused):probe.rsa_jwk(b"not DER")

    def server(self, responses):
        seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                seen.append((self.path,self.headers.get("Authorization")))
                status,body=responses[len(seen)-1]
                raw=json.dumps(body).encode();self.send_response(status)
                self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(raw)))
                self.end_headers();self.wfile.write(raw)
        server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(thread.join);self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return server.server_port,seen

    def test_collection_uses_real_loopback_http_and_only_hashes_tokens(self):
        # A synthetic responder tests the harness's wire/report path, not Go auth.
        responses=[(status,{"id":"fixture-viewer","name":"fixture-viewer","role":"VIEWER"} if status==200 else {"error":"denied"})
                   for status in probe.Contract.CASES.values()]
        port,seen=self.server(responses)
        observations=[];cutoff=int(time.time())-120
        report=probe.collect(port,self.signer,IMAGE,cutoff,cutoff,observations)
        self.assertEqual(len(seen),8);self.assertEqual(len(observations),8)
        self.assertEqual(report["command"],["serve"])
        raw=json.dumps(report)+json.dumps(observations)
        for path,authorization in seen:
            self.assertEqual(path,"/api/me");self.assertTrue(authorization.startswith("Bearer "))
            self.assertNotIn(authorization[7:],raw)
        self.assertEqual(set(report["cases"]),set(probe.Contract.CASES))

    def test_bad_http_result_never_becomes_a_passing_report(self):
        for status,body in ((200,{"role":"VIEWER"}),(503,{"error":"unavailable"}),(302,{"location":"elsewhere"})):
            port,seen=self.server([(status,body)])
            with self.subTest(status=status),self.assertRaises(Refused):
                probe.collect(port,self.signer,IMAGE,1700000000,1700000000,[])
            self.assertEqual(len(seen),1)

    def test_claim_controls_do_not_confuse_cutoff_with_expiry(self):
        cutoff,now=1700000000,1700000120
        values={name:probe.claims_for(name,cutoff,now) for name in probe.Contract.CASES}
        self.assertEqual(values["before_cutoff"]["iat"],cutoff-1)
        self.assertGreater(values["before_cutoff"]["exp"],now+30)
        self.assertLess(values["expired"]["exp"],now)
        self.assertNotIn("iat",values["missing_iat"])
        compile(probe.ISSUER_CODE,"isolated_issuer.py","exec")


if __name__=="__main__":unittest.main()
