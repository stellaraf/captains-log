#!/usr/bin/env python3
"""Execute the restored-token boundary against one captured, already loaded image.

This publisher-side fixture does not qualify a native appliance. It never pulls
or imports images, connects to a real identity provider/database, or changes an
existing container. A passing contract report is published only after all HTTP
cases and owned-resource cleanup succeed. Signing/promoting it requires review.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nebulalog_manager.common import Refused
from nebulalog_manager import host_payload
from nebulalog_manager.image_bundle import RestoredAuthContract as Contract, verify_oci_archive
from build_application import write_receipt

RESERVE = 150 * 1024**3
LABEL = "io.captains-log.restore-auth-probe"
GATE = "/run/nebulalog-storage-maintenance"
ISSUER = "http://issuer:8081"
CLIENT = "nebulalog"
MAX_RESPONSE = 65536

# Executed by a separate fixture container from the SAME application image. The
# target keeps its normal entrypoint/user; the helper only serves public keys.
ISSUER_CODE = '''import http.server,json,os
from pathlib import Path
p=json.loads(Path('/fixture/public.json').read_text())
root=Path('/gate');root.chmod(0o755)
with (root/'gate.json').open('x') as f:
 json.dump(p['gate'],f);f.flush();os.fsync(f.fileno())
(root/'gate.json').chmod(0o644)
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  values={'/.well-known/openid-configuration':p['discovery'],'/jwks':p['jwks']}
  if self.path not in values:self.send_error(404);return
  raw=json.dumps(values[self.path]).encode();self.send_response(200)
  self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
  self.end_headers();self.wfile.write(raw)
server=http.server.ThreadingHTTPServer(('0.0.0.0',8081),Handler)
print(json.dumps({'fixture_ready':True,'gate_uid':(root/'gate.json').stat().st_uid}),flush=True)
server.serve_forever()
'''


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def reserve(storage, output):
    storage = Path(storage).resolve(strict=True)
    parent = Path(output).parent.resolve(strict=True)
    if storage == Path("/") or not storage.is_mount() or not parent.is_relative_to(storage):
        raise Refused("Probe output must be on the explicitly mounted development storage volume")
    if shutil.disk_usage(storage).free < RESERVE:
        raise Refused("Probe requires the preserved 150 GiB free-space reserve before runtime access")
    return storage


def rsa_jwk(der):
    """Read only the bounded OpenSSL RSA SubjectPublicKeyInfo structure."""
    def part(raw, tag):
        if len(raw) < 2 or raw[0] != tag:
            raise Refused("Unexpected RSA public key encoding")
        size, at = raw[1], 2
        if size & 128:
            count = size & 127
            if not 1 <= count <= 4 or len(raw) < at + count:
                raise Refused("Invalid RSA public key length")
            size = int.from_bytes(raw[at:at+count], "big"); at += count
        if size < 1 or at+size > len(raw):
            raise Refused("Truncated RSA public key")
        return raw[at:at+size], raw[at+size:]
    if not isinstance(der, bytes) or len(der) > 8192:
        raise Refused("Invalid RSA public key size")
    outer, tail = part(der, 0x30)
    algorithm, outer = part(outer, 0x30)
    bits, end = part(outer, 0x03)
    if tail or end or bits[:1] != b"\0" or algorithm != bytes.fromhex("06092a864886f70d0101010500"):
        raise Refused("Unexpected RSA public key algorithm")
    key, end = part(bits[1:], 0x30)
    n, key = part(key, 0x02); e, key = part(key, 0x02)
    if end or key or int.from_bytes(e, "big") != 65537 or int.from_bytes(n, "big").bit_length() != 2048:
        raise Refused("Fixture requires a fresh RSA-2048 public key")
    return {"kty":"RSA", "kid":"fixture", "use":"sig", "alg":"RS256",
            "n":b64(n.lstrip(b"\0")), "e":b64(e.lstrip(b"\0"))}


class Signer:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.keys = [self.directory / name for name in ("issuer.key", "wrong.key")]
        for key in self.keys:
            self.openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)])
            key.chmod(0o600)
        self.public = self.directory / "issuer-public.pem"
        self.openssl(["pkey", "-in", str(self.keys[0]), "-pubout", "-out", str(self.public)])
        self.jwk = rsa_jwk(self.openssl(["pkey", "-in", str(self.keys[0]), "-pubout", "-outform", "DER"]))

    @staticmethod
    def openssl(args, data=None):
        result = subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=30)
        if result.returncode:
            raise Refused("Fixture OpenSSL operation failed")
        return result.stdout

    def token(self, claims, wrong_signature=False):
        message = (b64(encoded({"alg":"RS256", "kid":"fixture", "typ":"JWT"})) + "." + b64(encoded(claims))).encode()
        signature = self.openssl(["dgst", "-sha256", "-sign", str(self.keys[int(wrong_signature)])], message)
        return message.decode() + "." + b64(signature)


def claims_for(name, cutoff, now):
    claims = {"iss":ISSUER, "aud":CLIENT, "sub":"fixture-viewer", "preferred_username":"fixture-viewer",
              "iat":cutoff + (-1 if name=="before_cutoff" else 1 if name=="after_cutoff" else 0),
              "exp":now+600, "resource_access":{CLIENT:{"roles":["VIEWER"]}}}
    if name == "missing_iat": del claims["iat"]
    if name == "wrong_issuer": claims["iss"] = ISSUER + "/other"
    if name == "wrong_audience": claims["aud"] = "other-client"
    if name == "expired": claims["exp"] = now-30
    return claims


def request(port, token=None):
    """Fixed loopback endpoint, no proxies, redirects, caller URLs or mutations."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise Refused("Invalid loopback port")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/api/me", headers={} if token is None else {"Authorization":"Bearer " + token})
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE+1)
        if len(raw) > MAX_RESPONSE or response.getheader("Content-Type", "").split(";")[0] != "application/json":
            raise Refused("API returned an unbounded or non-JSON response")
        value = host_payload.strict_json(raw)
        if not isinstance(value, dict): raise Refused("API response is not an object")
        return response.status, value, {"bytes":len(raw), "sha256":hashlib.sha256(raw).hexdigest()}
    finally:
        connection.close()


def internal_request(runtime, container, port, token=None):
    code = """import sys,json,http.client,hashlib
v=json.load(sys.stdin)
c=http.client.HTTPConnection('api',v['port'],timeout=5)
try:
 c.request('GET','/api/me',headers={} if v['token'] is None else {'Authorization':'Bearer '+v['token']})
 r=c.getresponse(); raw=r.read(65537)
 assert len(raw)<=65536 and r.getheader('Content-Type','').split(';')[0]=='application/json'
 body=json.loads(raw); assert isinstance(body,dict)
 print(json.dumps([r.status,body,{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}]))
finally: c.close()
"""
    result = runtime.call(["container","exec","-i",container,"/usr/bin/python3","-c",code],
                          check=False,input=encoded({"port":port,"token":token}))
    if result.returncode:
        raise OSError("Isolated HTTP client could not reach the normal API")
    value = host_payload.strict_json(result.stdout)
    if not isinstance(value,list) or len(value)!=3:
        raise Refused("Isolated HTTP client returned an invalid response")
    return tuple(value)


def collect(port, signer, image, cutoff, observed_cutoff, observations, requester=None):
    requester = requester or request
    report = {"schema":1, "kind":"captains-log-restored-token-boundary", "method":"isolated-image-normal-api-http",
              "application_image":image["reference"], "application_config_digest":image["config_digest"],
              "application_source_sha256":image["application_source_sha256"], "command":["serve"],
              "http_method":"GET", "path":"/api/me", "issuer_mode":"isolated-fixture",
              "cutoff":cutoff, "observed_cutoff":observed_cutoff, "cases":{}}
    for name, wanted in Contract.CASES.items():
        now = int(time.time())
        claims = claims_for(name, cutoff, now)
        token = signer.token(claims, name == "wrong_signature")
        observed = int(time.time())
        status, body, identity = requester(port, token)
        role = body.get("role")
        observations.append({"case":name, "http_status":status, "observed_at":observed, "response":identity})
        if status != wanted or (wanted == 200 and body != {"id":"fixture-viewer", "name":"fixture-viewer", "role":"VIEWER"}):
            raise Refused("Normal API JWT boundary case failed: " + name)
        report["cases"][name] = {"iat":claims.get("iat"), "exp":claims["exp"], "observed_at":observed,
            "issuer_match":claims["iss"] == ISSUER, "audience_match":claims["aud"] == CLIENT,
            "signature_valid":name != "wrong_signature", "http_status":status, "api_role":role,
            "token_sha256":hashlib.sha256(token.encode()).hexdigest()}
    Contract._behavior(report, {"image":image["reference"]}, image, image["application_source_sha256"])
    return report


def env_value(environment, key):
    values = [item.split("=",1)[1] for item in environment if item.startswith(key+"=")]
    if len(values) != 1: raise Refused("Runtime must have one exact " + key)
    return values[0]


def target_identity(value, image, network, cutoff, run_id, volume):
    runtime_id = image.get("runtime_image_id", image["config_digest"])
    config, host = value.get("Config", {}), value.get("HostConfig", {})
    environment = config.get("Env", [])
    bindings = value.get("NetworkSettings", {}).get("Ports", {})
    mounts = value.get("Mounts", [])
    if (value.get("Image") != runtime_id or config.get("Image") != runtime_id
            or config.get("Entrypoint") != ["nebulalog"] or config.get("Cmd") != ["serve"]
            or config.get("User") != "10001:10001" or config.get("Labels", {}).get(LABEL) != run_id
            or value.get("Path") != "nebulalog" or value.get("Args") != ["serve"]
            or value.get("State", {}).get("Running") is not True or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False or host.get("NetworkMode") != network
            or host.get("PidsLimit") != 64 or host.get("Memory") != 256*1024**2
            or set(value.get("NetworkSettings", {}).get("Networks", {})) != {network}
            or {str(x).upper() for x in host.get("CapDrop", [])} != {"ALL"}
            or "no-new-privileges" not in host.get("SecurityOpt", [])
            or not any(m.get("Type")=="volume" and m.get("Name")==volume and m.get("Destination")==GATE and m.get("RW") is False for m in mounts)
            or any(bindings.values()) or host.get("PortBindings")
            or host.get("PublishAllPorts") is True):
        raise Refused("Normal API container identity or isolation differs from the fixture plan")
    expected = {"OIDC_TOKEN_NOT_BEFORE":str(cutoff), "REQUIRE_FIPS":"true", "OIDC_ISSUER":ISSUER,
                "OIDC_CLIENT_ID":CLIENT, "OIDC_BACKCHANNEL_URL":"", "PG_DSN":"postgresql://fixture@127.0.0.1:1/fixture?sslmode=disable&connect_timeout=1",
                "CH_URL":"http://127.0.0.1:1", "STORAGE_MAINTENANCE_PATH":GATE+"/gate.json", "API_LISTEN":":8080"}
    for key, wanted in expected.items():
        if env_value(environment,key) != wanted: raise Refused("Runtime environment mismatch: " + key)
    return 8080, int(env_value(environment,"OIDC_TOKEN_NOT_BEFORE"))


class Docker:
    def __init__(self):
        self.deadline = time.monotonic()+300
        self.calls = []
        self.context, self.transport = None, None

    def call(self, args, *, check=True, input=None):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0: raise Refused("Probe runtime deadline exhausted")
        prefix=["docker", "--context", self.context] if self.context else ["docker"]
        result = subprocess.run([*prefix, *args], input=input, capture_output=True, timeout=min(30,remaining))
        if len(result.stdout)+len(result.stderr) > 8*1024**2:
            raise Refused("Runtime response exceeded its bounded evidence size")
        self.calls.append({"operation":args[:2], "returncode":result.returncode,
                           "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256":hashlib.sha256(result.stderr).hexdigest()})
        if check and result.returncode:
            # Fixture CLI arguments contain no tokens or passwords. Keep bounded
            # daemon diagnostics in the private receipt so failed starts can be
            # distinguished from image, mount and network errors.
            diagnostic = result.stderr.decode("utf-8", errors="replace")[:2048]
            raise Refused("Local fixture runtime operation failed: " + " ".join(args[:2]) + ": " + diagnostic)
        return result

    def inspect(self, kind, name):
        value = host_payload.strict_json(self.call([kind,"inspect",name]).stdout)
        if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],dict):
            raise Refused("Runtime returned ambiguous resource identity")
        return value[0]

    def local(self):
        if any(os.environ.get(name) for name in ("DOCKER_HOST","DOCKER_TLS_VERIFY","DOCKER_CERT_PATH")):
            raise Refused("Probe refuses remote or overridden Docker transport")
        context = host_payload.strict_json(self.call(["context","inspect",*([self.context] if self.context else [])]).stdout)
        if (not isinstance(context,list) or len(context)!=1
                or not isinstance(context[0].get("Name"),str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",context[0]["Name"])
                or not context[0].get("Endpoints",{}).get("docker",{}).get("Host","").startswith("unix:///")):
            raise Refused("Probe requires a local Unix-socket Docker context")
        name,host=context[0]["Name"],context[0]["Endpoints"]["docker"]["Host"]
        if self.context is not None and (name,host)!=(self.context,self.transport):
            raise Refused("Pinned local Docker context changed during the probe")
        self.context,self.transport=name,host


def absent(kind, name, result):
    if result.returncode == 0: return False
    text=result.stderr.decode("utf-8",errors="replace").lower()
    patterns={"container":("no such container: "+name,"no such object: "+name),
              "network":("network "+name+" not found","no such network: "+name),
              "volume":("get "+name+": no such volume","no such volume: "+name)}
    return any(re.search(re.escape(value.lower())+r"(?:\s|$)",text) for value in patterns[kind])


def loaded_image(runtime, image):
    """Resolve only digests cryptographically bound by the verified OCI archive."""
    allowed = (image["config_digest"], image["manifest_digest"])
    for digest in allowed:
        result = runtime.call(["image", "inspect", digest], check=False)
        if result.returncode:
            message = result.stderr.decode("utf-8", errors="replace").lower()
            if not re.search(r"no such image: " + re.escape(digest) + r"(?:\s|$)", message):
                raise Refused("Loaded image lookup failed without confirmed absence")
            continue
        values = host_payload.strict_json(result.stdout)
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise Refused("Loaded image identity is ambiguous")
        installed = values[0]
        if (installed.get("Id") not in allowed or installed.get("Architecture") != "amd64"
                or installed.get("Os") != "linux"
                or installed.get("Config", {}).get("Entrypoint") != ["nebulalog"]
                or installed.get("Config", {}).get("User") != "10001:10001"
                or installed.get("Config", {}).get("Labels", {}).get("io.nebulalog.application-source-sha256") != image["application_source_sha256"]):
            raise Refused("Already loaded application differs from verified OCI configuration")
        return installed
    raise Refused("Verified application image is not loaded")


def fixture_network(value):
    if value is None:
        return None
    try:
        network = ipaddress.ip_network(value, strict=True)
        if network.version == 4 and network.prefixlen in (28, 29) and network.subnet_of(ipaddress.ip_network("198.18.0.0/15")):
            return str(network)
    except ValueError:
        pass
    raise Refused("Fixture subnet must be an aligned /28 or /29 in the isolated benchmark range 198.18.0.0/15")


def execute(archive, reference, source, build, output, storage, fixture_subnet=None):
    fixture_subnet = fixture_network(fixture_subnet)
    # This check precedes image hashing, CLI access and any resource creation.
    reserve(storage, output)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink(): raise Refused("Probe output must be a new directory")
    image = {**verify_oci_archive(archive, reference), "reference":reference}
    snapshot_raw = host_payload.read_regular(Path(source), Contract.MAX_RECEIPT)
    snapshot = host_payload.source_manifest(snapshot_raw)
    build_raw = host_payload.read_regular(Path(build), Contract.MAX_RECEIPT)
    built = host_payload.strict_json(build_raw)
    Contract._build(built, snapshot["files"], {"version":built.get("requested_version")}, image)
    output.mkdir(mode=0o700)
    runtime, run_id = Docker(), uuid.uuid4().hex
    network, volume = "cl-auth-net-"+run_id, "cl-auth-gate-"+run_id
    names = ["cl-auth-issuer-"+run_id, "cl-auth-api-"+run_id]
    probe_digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    record = {"schema":1, "run_id":run_id, "status":"started", "image":image,"probe_sha256":probe_digest,
              "source_snapshot_sha256":hashlib.sha256(snapshot_raw).hexdigest(),
              "build_receipt_sha256":hashlib.sha256(build_raw).hexdigest(), "observations":[], "cleanup":[],
              "native_qualified":False, "normal_entrypoint":["nebulalog","serve"]}
    write_receipt(output/"intent.json", {**record,"network":network,"volume":volume,"containers":names})
    failure, report, runtime_ready = None, None, False
    try:
        runtime.local()
        runtime_ready = True
        installed = loaded_image(runtime, image)
        image["runtime_image_id"] = installed["Id"]
        record["installed_image"] = installed
        reserve(storage,output)
        runtime.call(["network","create","--internal","--label",LABEL+"="+run_id,
                      *(["--subnet",fixture_subnet] if fixture_subnet else []),network])
        net = runtime.inspect("network",network)
        if net.get("Internal") is not True or net.get("Labels",{}).get(LABEL)!=run_id:
            raise Refused("Fixture network is not owned and internal")
        if fixture_subnet and [x.get("Subnet") for x in net.get("IPAM",{}).get("Config",[])] != [fixture_subnet]:
            raise Refused("Fixture network subnet differs from the requested isolated range")
        record["fixture_subnet"] = fixture_subnet
        runtime.call(["volume","create","--label",LABEL+"="+run_id,volume])
        fixture = output/"public-fixture"; fixture.mkdir(mode=0o755)
        with tempfile.TemporaryDirectory(prefix="private-keys-", dir=output) as keys:
            signer = Signer(keys)
            cutoff = int(time.time())-120
            material = {"gate":{"schema":1,"held":True,"delivery_held":True,"operation":hashlib.sha256(run_id.encode()).hexdigest()},
                "discovery":{"issuer":ISSUER,"jwks_uri":ISSUER+"/jwks","authorization_endpoint":ISSUER+"/unused",
                             "token_endpoint":ISSUER+"/unused","response_types_supported":["code"],"subject_types_supported":["public"],
                             "id_token_signing_alg_values_supported":["RS256"]}, "jwks":{"keys":[signer.jwk]}}
            for name, raw in (("issuer.py",ISSUER_CODE.encode()),("public.json",encoded(material))):
                (fixture/name).write_bytes(raw); (fixture/name).chmod(0o444)
            common = ["--pull=never","--label",LABEL+"="+run_id,"--network",network,"--read-only","--cap-drop=ALL",
                      "--security-opt=no-new-privileges","--pids-limit=64","--memory=256m",
                      "--log-driver=local","--log-opt=max-size=1m","--log-opt=max-file=1","--log-opt=compress=false"]
            runtime.call(["container","create","--name",names[0],*common,"--network-alias=issuer","--user=0:0","--entrypoint=/usr/bin/python3",
                          "--mount","type=bind,src="+str(fixture)+",dst=/fixture,readonly",
                          "--mount","type=volume,src="+volume+",dst=/gate",image["runtime_image_id"],"/fixture/issuer.py"])
            runtime.call(["container","start",names[0]])
            until = time.monotonic()+45
            while True:
                logs = runtime.call(["container","logs","--tail=5",names[0]]).stdout
                if b'"fixture_ready": true' in logs and b'"gate_uid": 0' in logs: break
                if time.monotonic()>=until: raise Refused("Fixture Python/server/root-owned gate did not become ready")
                if not runtime.inspect("container",names[0]).get("State",{}).get("Running"): raise Refused("Fixture issuer stopped")
                time.sleep(.25)
            environment = {"OIDC_ISSUER":ISSUER,"OIDC_CLIENT_ID":CLIENT,"OIDC_BACKCHANNEL_URL":"","OIDC_TOKEN_NOT_BEFORE":str(cutoff),
                "PG_DSN":"postgresql://fixture@127.0.0.1:1/fixture?sslmode=disable&connect_timeout=1","CH_URL":"http://127.0.0.1:1",
                "REQUIRE_FIPS":"true","STORAGE_MAINTENANCE_PATH":GATE+"/gate.json","API_LISTEN":":8080"}
            args=["container","create","--name",names[1],*common,"--network-alias=api",
                  "--tmpfs=/var/lib/nebulalog/exports:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700",
                  "--mount","type=volume,src="+volume+",dst="+GATE+",readonly"]
            for key,value in environment.items(): args.extend(["--env",key+"="+value])
            reserve(storage,output)
            runtime.call([*args,image["runtime_image_id"],"serve"])
            runtime.call(["container","start",names[1]])
            target = runtime.inspect("container",names[1])
            record["target_before"] = target
            port, observed = target_identity(target,image,network,cutoff,run_id,volume)
            def client(port, token=None):
                return internal_request(runtime,names[0],port,token)
            until=time.monotonic()+60
            while True:
                try:
                    status, _, _ = client(port)
                    if status != 401: raise Refused("Normal API did not require authentication")
                    break
                except (OSError,http.client.HTTPException):
                    if time.monotonic()>=until: raise Refused("Normal API did not become ready")
                    time.sleep(.25)
            report=collect(port,signer,image,cutoff,observed,record["observations"],requester=client)
            record["http_client"] = "same-image-isolated-network-stdin"
            after=runtime.inspect("container",names[1])
            if target_identity(after,image,network,cutoff,run_id,volume)!=(port,observed) or after.get("Id")!=target.get("Id"):
                raise Refused("Normal API identity changed during HTTP cases")
            record["target_after"] = after
            runtime.local()
            record["docker_context"]={"name":runtime.context,"transport":runtime.transport}
            record["fixture_code_sha256"] = hashlib.sha256(ISSUER_CODE.encode()).hexdigest()
            record["public_fixture_sha256"] = hashlib.sha256(encoded(material)).hexdigest()
            if hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=probe_digest:
                raise Refused("Probe source changed during execution")
    except BaseException as exc:
        failure = type(exc).__name__ + ": " + str(exc)
    finally:
        runtime.deadline = time.monotonic()+90
        if runtime_ready:
            try:
                # Context inspection reads local metadata. Never send resource
                # requests after a context mutation, even for owned-name cleanup.
                runtime.local()
            except Exception as exc:
                runtime_ready=False
                record["cleanup"].append({"kind":"runtime-context","error":type(exc).__name__+": "+str(exc),
                                          "resource_calls_skipped":True})
                failure=failure or "Cleanup transport no longer matches the pinned local context"
        resources=[("container",names[1]),("container",names[0]),("network",network),("volume",volume)] if runtime_ready else []
        for kind,name in resources:
            try:
                seen=runtime.call([kind,"inspect",name],check=False)
                if seen.returncode:
                    # Distinguish a known missing name from an unreachable daemon.
                    if not absent(kind,name,seen): raise Refused("Cleanup identity is unknown")
                    record["cleanup"].append({"kind":kind,"name":name,"absent":True});continue
                value=host_payload.strict_json(seen.stdout)
                if not isinstance(value,list) or len(value)!=1: raise Refused("Cleanup identity is ambiguous")
                labels=value[0].get("Config",{}).get("Labels",{}) if kind=="container" else value[0].get("Labels",{})
                if labels.get(LABEL)!=run_id or kind=="container" and value[0].get("Image")!=image.get("runtime_image_id"):
                    raise Refused("Cleanup refuses a foreign resource")
                runtime.call([kind,"rm",*(["--force"] if kind=="container" else []),name])
                check=runtime.call([kind,"inspect",name],check=False)
                if not absent(kind,name,check):
                    raise Refused("Cleanup removal was not confirmed")
                record["cleanup"].append({"kind":kind,"name":name,"removed":True})
            except Exception as exc:
                record["cleanup"].append({"kind":kind,"name":name,"error":type(exc).__name__+": "+str(exc)})
                failure = failure or "Owned-resource cleanup was not confirmed"
        record.update(status="failed" if failure else "passed",error=failure,calls=runtime.calls)
        write_receipt(output/"execution.json",record)
    if failure: raise Refused("HTTP qualification failed; inspect the private execution receipt")
    write_receipt(output/Contract.BEHAVIOR,report)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("archive","reference","source-manifest","build-receipt","output"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--storage-root",default="/Volumes/T9")
    parser.add_argument("--fixture-subnet",help="Optional unused /28 or /29 in 198.18.0.0/15 for the internal test network")
    args=parser.parse_args()
    try:
        execute(args.archive,args.reference,args.source_manifest,args.build_receipt,args.output,args.storage_root,args.fixture_subnet)
    except (Refused,OSError,ValueError) as exc:
        parser.exit(1,str(exc)+"\n")
    print("Normal API HTTP boundary cases passed; native restore/update/rollback acceptance remains pending.")


if __name__=="__main__":main()
