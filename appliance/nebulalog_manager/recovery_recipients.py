"""Inactive public recovery-recipient storage, never an authorization service.

Only a future qualified host controller may call these persistence methods after
independently approving the exact typed action. Bindings and escrow assertions
are not grants, proof of private-key possession, or a recovery test. No routes,
default verifier, exporter integration or historical-registry adoption exists.
Replacement always allocates a new ID. Disable preserves every certificate and
event, and blocks new lookups; already-started jobs retain their pinned copy.

The admitted profile is RSA-OAEP/SHA256/MGF1-SHA256 with AES256-GCM. The
configuration and log exporters now select it through the shared command helper;
registry-to-controller/exporter integration remains absent. Historical RSA
transport defaults are not qualification evidence. Local OpenSSL success proves
compatibility only, never FIPS certification.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import os
import re
import time
import uuid

from .common import Refused
from .backup import RECOVERY_CRYPTO_PROFILE, cms_encrypt_command
from .host_challenges import ChallengeRecords
from .host_job_storage import digest, exact
from .host_operations import digest_value, uuid_value

MAX_CERTIFICATE_BYTES = 65536
MAX_RECIPIENTS = 64
MAX_EVENTS = 128
MAX_TIME = 253402300799
PROFILE = RECOVERY_CRYPTO_PROFILE
LEDGER = "recipients.json"
GENESIS = "recipients-initial.json"
MARKER = "recovery-recipients-identity.json"
ACTIONS = ("recipient.enroll", "recipient.disable")


def _integer(value, minimum=0, maximum=MAX_TIME):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Refused("invalid_recipient_integer")
    return value


def _uuid(value):
    if type(value) is not str or uuid_value(value) != value or uuid.UUID(value).int == 0:
        raise Refused("invalid_recipient_id")
    return value


def _seal(value):
    return {**value, "digest": digest(value)}


class _DER:
    """Bounded canonical TLV framing; OpenSSL independently parses the X.509."""
    def __init__(self, data):
        self.data, self.offset = data, 0

    def item(self, wanted):
        p = self.offset
        if p + 2 > len(self.data) or self.data[p] != wanted:
            raise Refused("unsupported_recipient_certificate")
        n, p = self.data[p+1], p+2
        if n & 128:
            width = n & 127
            raw = self.data[p:p+width]
            if not 1 <= width <= 3 or len(raw) != width or not raw[0]:
                raise Refused("invalid_recipient_der_length")
            n, p = int.from_bytes(raw, "big"), p+width
            if n < 128: raise Refused("noncanonical_recipient_der")
        if p+n > len(self.data): raise Refused("truncated_recipient_certificate")
        self.offset = p+n
        return self.data[p:p+n]

    def sequence(self): return _DER(self.item(0x30))
    def more(self): return self.offset < len(self.data)
    def peek(self): return self.data[self.offset] if self.more() else None
    def end(self):
        if self.more(): raise Refused("trailing_recipient_der")


def _positive(raw):
    if (not raw or raw[0] & 128 or len(raw) > 1 and raw[0] == 0 and not raw[1] & 128):
        raise Refused("noncanonical_recipient_integer")
    value = int.from_bytes(raw, "big")
    if value == 0: raise Refused("zero_recipient_integer")
    return value


def _date(container):
    tag = container.peek()
    if tag not in (0x17, 0x18): raise Refused("unsupported_recipient_date")
    raw = container.item(tag)
    if not re.fullmatch(rb"[0-9]{12}Z" if tag == 0x17 else rb"[0-9]{14}Z", raw):
        raise Refused("invalid_recipient_date")
    text = raw.decode("ascii")
    if tag == 0x17: text = ("19" if int(text[:2]) >= 50 else "20") + text
    try: return int(datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, OverflowError): raise Refused("invalid_recipient_date") from None


def _facts(pem):
    if type(pem) is not bytes or not 1 <= len(pem) <= MAX_CERTIFICATE_BYTES:
        raise Refused("invalid_recipient_certificate_size")
    match = re.fullmatch(rb"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?", pem)
    if not match: raise Refused("one_public_certificate_only")
    try: der = base64.b64decode(match[1].replace(b"\r", b"").replace(b"\n", b""), validate=True)
    except ValueError: raise Refused("invalid_recipient_pem") from None
    top = _DER(der); cert = top.sequence(); top.end()
    tbs = cert.sequence()
    version = _DER(tbs.item(0xa0)); value = version.item(2); version.end()
    if value != b"\x02": raise Refused("recipient_requires_x509_v3")
    if len(tbs.item(2)) > 21: raise Refused("oversized_recipient_serial")
    signed_algorithm = tbs.item(0x30)
    algorithm = _DER(signed_algorithm); signature_oid = algorithm.item(6)
    allowed_signatures = {bytes.fromhex(x) for x in ("2a864886f70d01010b", "2a864886f70d01010c", "2a864886f70d01010d", "2a8648ce3d040302", "2a8648ce3d040303", "2a8648ce3d040304")}
    if signature_oid not in allowed_signatures: raise Refused("unsupported_recipient_signature_algorithm")
    if algorithm.more() and algorithm.item(5) != b"": raise Refused("invalid_recipient_signature_parameters")
    algorithm.end()
    tbs.item(0x30)  # Issuer is not an authority or endpoint selection.
    validity = tbs.sequence(); before, after = _date(validity), _date(validity); validity.end()
    if not 0 < before < after <= MAX_TIME: raise Refused("invalid_recipient_validity")
    tbs.item(0x30)  # Subject is never interpreted as identity or authorization.
    spki = tbs.sequence(); key_algorithm = spki.sequence()
    if key_algorithm.item(6) != bytes.fromhex("2a864886f70d010101") or key_algorithm.item(5) != b"":
        raise Refused("recipient_requires_rsa_encryption_key")
    key_algorithm.end()
    bitkey = spki.item(3); spki.end()
    if not bitkey or bitkey[0] != 0: raise Refused("invalid_recipient_public_key")
    key = _DER(bitkey[1:]); numbers = key.sequence(); key.end()
    modulus = _positive(numbers.item(2)); exponent = _positive(numbers.item(2)); numbers.end()
    bits = modulus.bit_length()
    if bits not in (3072, 4096) or exponent != 65537 or modulus % 2 != 1:
        raise Refused("unsupported_recipient_rsa_parameters")
    extensions = _DER(tbs.item(0xa3)); items = extensions.sequence(); extensions.end(); tbs.end()
    seen = set(); constraints = usage = False
    while items.more():
        extension = items.sequence(); oid = extension.item(6)
        if oid in seen: raise Refused("duplicate_recipient_extension")
        seen.add(oid)
        critical = False
        if extension.peek() == 1:
            flag = extension.item(1)
            if flag != b"\xff": raise Refused("noncanonical_recipient_extension")
            critical = True
        content = _DER(extension.item(4)); extension.end()
        if oid == bytes.fromhex("551d13"):
            basic = content.sequence(); content.end()
            if basic.more(): raise Refused("recipient_must_not_be_ca")
            constraints = True
        elif oid == bytes.fromhex("551d0f"):
            bits_usage = content.item(3); content.end()
            if len(bits_usage) != 2 or bits_usage[0] != 5 or bits_usage[1] not in (0x20, 0xa0):
                raise Refused("recipient_requires_key_encipherment_usage")
            usage = True
        elif critical or oid == bytes.fromhex("551d25"):
            # No guessed semantics for critical or extended-purpose constraints.
            raise Refused("unsupported_recipient_extension")
    if not constraints or not usage: raise Refused("recipient_constraints_and_usage_required")
    if cert.item(0x30) != signed_algorithm: raise Refused("recipient_signature_algorithm_mismatch")
    signature = cert.item(3); cert.end()
    if len(signature) < 2 or signature[0] != 0: raise Refused("invalid_recipient_signature")
    return {"certificate_sha256":hashlib.sha256(pem).hexdigest(), "fingerprint_sha256":hashlib.sha256(der).hexdigest(),
            "public_key_algorithm":"RSA", "public_key_bits":bits, "public_exponent":exponent,
            "not_before":before, "not_after":after, "cms_profile":PROFILE}


@dataclass(frozen=True)
class RecipientBinding:
    installation_id: str
    subject_digest: str
    session_digest: str
    action: str
    request_digest: str

    def validate(self):
        _uuid(self.installation_id)
        for v in (self.subject_digest, self.session_digest, self.request_digest): digest_value(v)
        if type(self.action) is not str or self.action not in ACTIONS: raise Refused("unsupported_recipient_action")


def request_digest(action, request_id, body):
    """Deterministic request binding only; hashing a request never approves it."""
    _uuid(request_id)
    if action not in ACTIONS: raise Refused("unsupported_recipient_action")
    if action == "recipient.enroll":
        exact(body, ("certificate_sha256", "escrow_acknowledged", "expected_registry_revision"))
        digest_value(body["certificate_sha256"])
        if body["escrow_acknowledged"] is not True: raise Refused("recipient_escrow_acknowledgement_required")
    else:
        exact(body, ("recipient_id", "revision", "certificate_sha256", "expected_registry_revision"))
        _uuid(body["recipient_id"]); digest_value(body["certificate_sha256"])
        if type(body["revision"]) is not int or body["revision"] != 1: raise Refused("unsupported_recipient_revision")
    _integer(body["expected_registry_revision"], 0, MAX_EVENTS)
    return digest({"domain":"nebulalog.recovery-recipient.request.v1", "action":action, "request_id":request_id, "body":body})


class RecoveryRecipients:
    def __init__(self, *, records=None, commands=None, clock=None):
        self.records = records if records is not None else ChallengeRecords()
        if not isinstance(self.records, ChallengeRecords): raise Refused("recipient_owned_lock_required")
        if commands is None:
            from nebulalog_adapters.commands import Commands
            commands = Commands()
        self.commands = commands
        self.clock = clock if clock is not None else lambda:int(time.time())

    def _now(self): return _integer(self.clock(), 1)

    def _confirm(self, state, identity):
        for path in (state/LEDGER, state/GENESIS, state.parent/MARKER):
            self.records.read(path, identity)
            fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try: self.records._file(os.fstat(fd), identity); os.fsync(fd)
            finally: os.close(fd)
        for path in (state, state.parent, identity.root):
            self.records.directory(path, identity)
            fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)

    def initialize(self):
        with self.records.locked(initialize=True) as (state, identity):
            _uuid(identity.installation_id)
            if os.path.lexists(state.parent/MARKER):
                value = self._load(state, identity)
            else:
                if not os.path.lexists(state/GENESIS):
                    if os.path.lexists(state/LEDGER): raise Refused("orphan_recipient_ledger")
                    self.records.write(state/GENESIS, _seal({"schema":1,"installation_id":identity.installation_id,
                        "registry_id":str(uuid.uuid4()),"revision":0,"last_at":0,"events":[]}), identity)
                value = self.records.read(state/GENESIS, identity)
                self._validate(value, identity)
                if value["revision"] != 0: raise Refused("invalid_recipient_genesis")
                if os.path.lexists(state/LEDGER):
                    if self.records.read(state/LEDGER, identity) != value: raise Refused("unbound_recipient_ledger")
                else: self.records.write(state/LEDGER, value, identity)
                self.records.write(state.parent/MARKER,{"schema":1,"installation_id":identity.installation_id,
                    "registry_id":value["registry_id"],"genesis_digest":value["digest"]},identity)
            self._confirm(state, identity)
            return {k:value[k] for k in ("schema","installation_id","registry_id","revision")}

    def _validate(self, value, identity):
        exact(value, ("schema","installation_id","registry_id","revision","last_at","events","digest"))
        if type(value["schema"]) is not int or value["schema"] != 1 or value["installation_id"] != identity.installation_id:
            raise Refused("recipient_installation_changed")
        _uuid(value["registry_id"])
        if value["digest"] != digest({k:v for k,v in value.items() if k != "digest"}): raise Refused("recipient_journal_changed")
        if type(value["events"]) is not list or len(value["events"]) > MAX_EVENTS or type(value["revision"]) is not int or value["revision"] != len(value["events"]):
            raise Refused("invalid_recipient_journal_size")
        recipients, requests, latest = {}, set(), 0
        for revision,event in enumerate(value["events"],1):
            exact(event, ("request_id","binding","body","at","result","certificate_pem","facts"))
            exact(event["binding"], RecipientBinding.__dataclass_fields__)
            binding = RecipientBinding(**event["binding"]); binding.validate()
            if binding.installation_id != identity.installation_id: raise Refused("recipient_installation_changed")
            if request_digest(binding.action,event["request_id"],event["body"]) != binding.request_digest:
                raise Refused("recipient_request_binding_changed")
            if event["body"]["expected_registry_revision"] != revision-1: raise Refused("recipient_revision_changed")
            index = (binding.subject_digest,binding.session_digest,event["request_id"])
            if index in requests: raise Refused("duplicate_recipient_request")
            requests.add(index)
            timestamp = _integer(event["at"],1)
            if timestamp < latest: raise Refused("recipient_clock_regressed")
            latest = timestamp
            result = event["result"]
            exact(result,("recipient_id","revision","certificate_sha256","registry_revision","status"))
            _uuid(result["recipient_id"])
            if type(result["revision"]) is not int or result["revision"] != 1 or type(result["registry_revision"]) is not int or result["registry_revision"] != revision:
                raise Refused("recipient_revision_changed")
            if binding.action == "recipient.enroll":
                if type(event["certificate_pem"]) is not str: raise Refused("invalid_recipient_public_copy")
                facts = _facts(event["certificate_pem"].encode("ascii"))
                if facts != event["facts"] or facts["certificate_sha256"] != event["body"]["certificate_sha256"] or result["certificate_sha256"] != facts["certificate_sha256"]:
                    raise Refused("recipient_certificate_changed")
                if not facts["not_before"] <= timestamp < facts["not_after"]: raise Refused("recipient_not_valid_at_enrollment")
                if result["status"] != "enrolled" or result["recipient_id"] in recipients: raise Refused("duplicate_recipient_id")
                recipients[result["recipient_id"]] = {"event":event,"disabled":False}
            else:
                prior = recipients.get(result["recipient_id"])
                if not prior or prior["disabled"] or event["facts"] is not None or event["certificate_pem"] is not None:
                    raise Refused("invalid_recipient_disable")
                for key in ("recipient_id","revision","certificate_sha256"):
                    if event["body"][key] != prior["event"]["result"][key] or result[key] != event["body"][key]:
                        raise Refused("recipient_disable_binding_changed")
                if result["status"] != "disabled": raise Refused("invalid_recipient_disable")
                prior["disabled"] = True
        if len(recipients) > MAX_RECIPIENTS or type(value["last_at"]) is not int or value["last_at"] != latest:
            raise Refused("invalid_recipient_registry")
        return recipients

    def _load(self, state, identity):
        marker = self.records.read(state.parent/MARKER,identity)
        exact(marker,("schema","installation_id","registry_id","genesis_digest"))
        if type(marker["schema"]) is not int or marker["schema"] != 1:
            raise Refused("invalid_recipient_marker_schema")
        genesis = self.records.read(state/GENESIS,identity)
        self._validate(genesis,identity)
        if marker != {"schema":1,"installation_id":identity.installation_id,"registry_id":genesis["registry_id"],"genesis_digest":genesis["digest"]} or genesis["revision"] != 0:
            raise Refused("recipient_genesis_changed")
        value = self.records.read(state/LEDGER,identity); self._validate(value,identity)
        if value["registry_id"] != marker["registry_id"]: raise Refused("recipient_registry_changed")
        return value

    def _inspect(self, pem, now):
        facts = _facts(pem)
        if not facts["not_before"] <= now < facts["not_after"]: raise Refused("recipient_certificate_not_current")
        def command(argv, data=None):
            result = self.commands(["openssl",*argv],input=data,timeout=5)
            if type(result) is not str or len(result.encode()) > 65536: raise Refused("invalid_recipient_crypto_result")
            return result
        if not command(["version"]).startswith("OpenSSL 3."): raise Refused("recipient_requires_openssl3")
        public = command(["x509","-pubkey","-noout"],pem)
        if not public.startswith("-----BEGIN PUBLIC KEY-----"): raise Refused("invalid_recipient_public_key")
        command(["pkey","-pubin","-pubcheck","-noout"],public.encode())
        probe_argv = cms_encrypt_command("/dev/null", "/dev/stdout", "/dev/stdin")
        # Only the framing changes for the text-only runner; cryptography comes
        # from the same fixed helper used by configuration and log exporters.
        probe_argv[probe_argv.index("-outform")+1] = "PEM"
        probe = command(probe_argv[1:],pem)
        if not probe.startswith("-----BEGIN CMS-----") or not probe.endswith("-----END CMS-----"):
            raise Refused("recipient_cms_profile_unavailable")
        return facts

    def inspect(self, certificate_pem):
        with self.records.locked() as (state,identity):
            value = self._load(state,identity); now = self._now()
            if now < value["last_at"]: raise Refused("recipient_clock_regressed")
            facts = self._inspect(certificate_pem,now)
            if not facts["not_before"] <= self._now() < facts["not_after"]: raise Refused("recipient_certificate_not_current")
            return {"facts":facts,"registry_revision":value["revision"],"authorization":False,"key_possession_proven":False}

    def _mutate(self,binding,request_id,body,pem):
        if type(binding) is not RecipientBinding: raise Refused("typed_recipient_binding_required")
        binding.validate()
        if request_digest(binding.action,request_id,body) != binding.request_digest: raise Refused("recipient_request_binding_changed")
        with self.records.locked() as (state,identity):
            value = self._load(state,identity); now = self._now()
            if binding.installation_id != identity.installation_id: raise Refused("recipient_installation_changed")
            if now < value["last_at"]: raise Refused("recipient_clock_regressed")
            for event in value["events"]:
                if event["request_id"] == request_id and all(event["binding"][k] == getattr(binding,k) for k in ("subject_digest","session_digest")):
                    if event["binding"] != asdict(binding) or event["body"] != body or event["certificate_pem"] != (pem.decode("ascii") if pem else None):
                        raise Refused("recipient_request_reused")
                    self._confirm(state,identity)
                    return copy.deepcopy(event["result"])
            if body["expected_registry_revision"] != value["revision"]: raise Refused("recipient_review_stale")
            if len(value["events"]) >= MAX_EVENTS: raise Refused("recipient_history_full")
            recipients = self._validate(value,identity)
            if binding.action == "recipient.enroll":
                if len(recipients) >= MAX_RECIPIENTS: raise Refused("recipient_registry_full")
                facts = self._inspect(pem,now); identifier = str(uuid.uuid4())
                if identifier in recipients: raise Refused("recipient_id_collision")
                now = self._now()
                if now < value["last_at"] or not facts["not_before"] <= now < facts["not_after"]: raise Refused("recipient_certificate_not_current")
                result = {"recipient_id":identifier,"revision":1,"certificate_sha256":facts["certificate_sha256"],
                          "registry_revision":value["revision"]+1,"status":"enrolled"}
            else:
                facts = None; prior = recipients.get(body["recipient_id"])
                if not prior or prior["disabled"]: raise Refused("recipient_unavailable")
                if any(prior["event"]["result"][k] != body[k] for k in ("recipient_id","revision","certificate_sha256")):
                    raise Refused("recipient_disable_binding_changed")
                result = {k:body[k] for k in ("recipient_id","revision","certificate_sha256")}
                result.update(registry_revision=value["revision"]+1,status="disabled")
            value["events"].append({"request_id":request_id,"binding":asdict(binding),"body":body,"at":now,"result":result,
                                    "certificate_pem":pem.decode("ascii") if pem else None,"facts":facts})
            value.update(revision=value["revision"]+1,last_at=now)
            value = _seal({k:v for k,v in value.items() if k != "digest"}); self._validate(value,identity)
            self.records.write(state/LEDGER,value,identity)
            if self._load(state,identity) != value: raise Refused("recipient_readback_changed")
            self._confirm(state,identity)
            return copy.deepcopy(result)

    def enroll(self,binding,*,request_id,certificate_pem,escrow_acknowledged,expected_registry_revision):
        # Reject hidden keys before persistence, including retry paths.
        facts = _facts(certificate_pem)
        if type(binding) is not RecipientBinding or binding.action != "recipient.enroll": raise Refused("recipient_action_mismatch")
        body = {"certificate_sha256":facts["certificate_sha256"],"escrow_acknowledged":escrow_acknowledged,
                "expected_registry_revision":expected_registry_revision}
        return self._mutate(binding,request_id,body,certificate_pem)

    def disable(self,binding,*,request_id,recipient_id,revision,certificate_sha256,expected_registry_revision):
        if type(binding) is not RecipientBinding or binding.action != "recipient.disable": raise Refused("recipient_action_mismatch")
        body = {"recipient_id":recipient_id,"revision":revision,"certificate_sha256":certificate_sha256,
                "expected_registry_revision":expected_registry_revision}
        return self._mutate(binding,request_id,body,None)

    def lookup(self,recipient_id,revision,certificate_sha256):
        with self.records.locked(): return self.lookup_locked(recipient_id,revision,certificate_sha256)

    def lookup_locked(self,recipient_id,revision,certificate_sha256):
        """Public pinned bytes for new work; caller must separately authorize it."""
        _uuid(recipient_id); digest_value(certificate_sha256)
        if type(revision) is not int or revision != 1: raise Refused("unsupported_recipient_revision")
        state,identity = self.records.owned(); value = self._load(state,identity)
        now = self._now()
        if now < value["last_at"]: raise Refused("recipient_clock_regressed")
        prior = self._validate(value,identity).get(recipient_id)
        if not prior or prior["disabled"]: raise Refused("recipient_unavailable")
        event = prior["event"]
        if event["facts"]["certificate_sha256"] != certificate_sha256: raise Refused("recipient_certificate_changed")
        if not event["facts"]["not_before"] <= now < event["facts"]["not_after"]: raise Refused("recipient_certificate_not_current")
        return {"recipient_id":recipient_id,"revision":1,"certificate_sha256":certificate_sha256,
                "certificate_pem":event["certificate_pem"].encode("ascii"),"facts":copy.deepcopy(event["facts"]),
                "registry_revision":value["revision"],"authorization":False,"key_possession_proven":False}
