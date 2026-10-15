"""Provision and verify the installed runtime on enrolled encrypted guest storage.

No Docker development endpoints are used. Image selection is an installed release
input; only immutable digests and fixed templates/services are accepted.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .common import CommandFailed, Refused, atomic_json, audit, locked, run, trusted_file
from .firstboot import FirstBoot, Locations, FINAL_CHECKS, RUNTIME_CHECKS, _private_dir, _private_file, _write_bytes

IMAGES = {"NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE"}
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}")
ENV_NAMES = ("postgresql", "clickhouse", "keycloak", "api", "ingest")
MANAGER_ROLES = {"manage-identity-providers", "view-identity-providers", "view-realm"}
INSPECTOR_ROLES = {"view-users", "view-clients", "view-realm"}
SYSTEM_CA = Path("/etc/pki/tls/certs/ca-bundle.crt")
ROCKY_PACKAGE_KEY = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9")
ROCKY_9_FINGERPRINT = "21CB256AE16FC54C6E652949702D426D350D275D"
EDGE_TEMPLATE = Path("/usr/share/nebulalog/httpd/nebulalog.conf.in")
EDGE_CONFIG = Path("/etc/httpd/conf.d/nebulalog.conf")
INITIAL_RELEASE = Path("/usr/share/nebulalog/initial-release.json")
ENROLL_RELEASE = Path("/usr/libexec/nebulalog/enroll-installed-release")


def image_pins(value):
    if not isinstance(value, dict) or set(value) != IMAGES or any(not isinstance(ref, str) or not IMAGE.fullmatch(ref) for ref in value.values()):
        raise Refused("Release images must contain exactly four immutable SHA256 references")
    return value


def environment(values):
    """Systemd/Podman env-file encoding with no substitutions or multiline data."""
    if any(not re.fullmatch(r"[A-Z][A-Z0-9_]+", key) or not isinstance(value, str) or any(c in value for c in "\n\r\0") for key, value in values.items()):
        raise Refused("Invalid runtime environment value")
    return "".join(key + "=" + value + "\n" for key, value in sorted(values.items())).encode()


def realm_config(template, setup, runtime):
    realm = copy.deepcopy(template)
    if realm.get("realm") != "nebulalog":
        raise Refused("Installed realm template has the wrong realm")
    hostname = setup["hostname"]
    origin = "https://" + hostname
    realm.update(sslRequired="all", registrationAllowed=False, passwordPolicy="length(14) and hashAlgorithm(pbkdf2-sha512)")
    realm["attributes"] = {**realm.get("attributes", {}), "nebulalog.installation-id": setup["installation_id"]}
    clients = [client for client in realm.get("clients", []) if client.get("clientId") == "nebulalog"]
    if len(clients) != 1:
        raise Refused("Installed realm template must have one application client")
    clients[0].update(redirectUris=[origin + "/*"], webOrigins=[origin], directAccessGrantsEnabled=False)
    clients[0]["attributes"] = {**clients[0].get("attributes", {}), "pkce.code.challenge.method": "S256", "post.logout.redirect.uris": origin + "/*"}
    flows = {flow["alias"]: flow for flow in realm["authenticationFlows"]}
    forms = flows["nebulalog-forms"]
    forms["authenticationExecutions"] = [entry for entry in forms["authenticationExecutions"] if entry.get("authenticator") == "auth-username-password-form"]
    forms["authenticationExecutions"].append({"flowAlias": "nebulalog-second-factor", "requirement": "REQUIRED", "priority": 20, "authenticatorFlow": True})
    realm["authenticationFlows"].append({"alias": "nebulalog-second-factor", "providerId": "basic-flow", "topLevel": False, "builtIn": False,
        "authenticationExecutions": [{"authenticator": provider, "requirement": "ALTERNATIVE", "priority": priority, "authenticatorFlow": False}
                                     for provider, priority in (("auth-otp-form", 10), ("auth-recovery-authn-code-form", 20))]})
    realm["requiredActions"] = [{"alias": alias, "name": label, "providerId": alias, "enabled": True, "defaultAction": False, "priority": priority}
                                for alias, label, priority in (("CONFIGURE_TOTP", "Configure OTP", 10), ("CONFIGURE_RECOVERY_AUTHN_CODES", "Recovery Authentication Codes", 20))]
    realm["users"] = [{"username": "nebulalog-health", "enabled": True, "emailVerified": True,
                       "firstName": "NebulaLog", "lastName": "Health", "email": "health@localhost.invalid",
                       "attributes": {"nebulalog-installation": [setup["installation_id"]], "nebulalog-purpose": ["health-probe"]},
                       "requiredActions": [], "clientRoles": {"nebulalog": ["VIEWER"]},
                       "credentials": [{"type": "password", "value": runtime["health_password"], "temporary": False},
                                       {"type": "otp", "userLabel": "Appliance lifecycle health",
                                        "secretData": json.dumps({"value": runtime["health_totp"]}),
                                        "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0, "period": 30, "algorithm": "HmacSHA256", "secretEncoding": "BASE32"})}]}]
    return realm


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Bootstrap:
    def __init__(self, paths=Locations(), *, runner=run, firstboot=None):
        self.paths = paths
        # FirstBoot's read-only gate runs before temporary image storage exists.
        # Runtime tools use a subprocess-local encrypted TMPDIR after that gate.
        from .image_bundle import run_private
        self.runner = (lambda argv, **kwargs: run_private(argv, temp=paths.data / "tmp", **kwargs)) if runner is run else runner
        self.firstboot = firstboot or FirstBoot(paths, runner=runner)
        self.configuration = paths.data / "configuration"
        self.bootstrap = self.configuration / "bootstrap"
        self.tls = self.configuration / "tls"
        self.state_path = self.bootstrap / "runtime-state.json"
        self.state = {}
        self.setup = {}
        self.secret = {}
        self.runtime = {}

    def _read(self, path):
        return json.loads(_private_file(path, maximum=1024 * 1024))

    def _load(self, setup_path, secrets_path=None):
        gate = self.firstboot.gate()
        if setup_path != self.bootstrap / "setup.json" or secrets_path not in (None, self.bootstrap / "secrets.json"):
            raise Refused("Runtime bootstrap accepts only the enrolled encrypted setup files")
        self.setup = self._read(setup_path)
        if self.setup.get("installation_id") != gate["installation_id"]:
            raise Refused("Runtime setup belongs to another installation")
        self.secret = self._read(self.bootstrap / "secrets.json")
        expected = {"postgresql_admin", "postgresql_app", "postgresql_keycloak", "clickhouse", "keycloak_bootstrap", "identity_service"}
        if set(self.secret) != expected or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in self.secret.values()):
            raise Refused("Installation secret bundle is incomplete or malformed")
        if self.state_path.exists():
            self.state = self._read(self.state_path)
            if self.state.get("installation_id") != gate["installation_id"]:
                raise Refused("Runtime journal belongs to another installation")
        else:
            self.state = {"schema": 1, "installation_id": gate["installation_id"], "completed": []}
        runtime_path = self.bootstrap / "runtime-secrets.json"
        if runtime_path.exists():
            self.runtime = self._read(runtime_path)
        elif self.state["completed"] or secrets_path is None:
            raise Refused("Existing runtime is missing its original secrets")
        else:
            self.runtime = {"health_password": secrets.token_urlsafe(36) + "Aa1!", "health_totp": base64.b32encode(secrets.token_bytes(32)).decode().rstrip("="), "inspector_service": secrets.token_hex(32)}
            atomic_json(runtime_path, self.runtime)

    def _stage(self, name, operation):
        self.state["active_stage"] = name
        atomic_json(self.state_path, self.state)
        result = operation()
        if name not in self.state["completed"]:
            self.state["completed"].append(name)
        self.state["active_stage"] = None
        atomic_json(self.state_path, self.state)
        audit(self.paths.bootstrap / "audit.jsonl", "bootstrap.stage", installation_id=self.setup["installation_id"], stage=name)
        return result

    def _directories(self):
        relabel = [str(self.paths.data)]
        for name, uid, gid, mode in (("postgresql", 999, 999, 0o700), ("clickhouse", 101, 101, 0o700), ("clickhouse-logs", 101, 101, 0o700), ("keycloak", 1000, 1000, 0o700), ("exports", 10001, 10001, 0o700), ("spool", 10001, 10001, 0o700), ("runtime", 10001, 10001, 0o700), ("containers", 0, 0, 0o700)):
            path = self.paths.data / name
            if path.is_symlink():
                raise Refused("Runtime storage destination is a symlink")
            if not path.exists():
                relabel.append(str(path))
            path.mkdir(mode=mode, exist_ok=True)
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        temporary = self.paths.data / "tmp"
        if not temporary.exists():
            relabel.append(str(temporary))
        _private_dir(temporary)
        # Existing :Z bind mounts carry private container MCS categories. A
        # recursive restore of the data tree on retry would revoke live access.
        self.runner(["restorecon", *relabel])
        info = json.loads(self.runner(["podman", "info", "--format", "json"]))
        if Path(info["store"]["graphRoot"]) != self.paths.data / "containers":
            raise Refused("Podman graphroot must be on the encrypted data mount before creating containers or secrets")

    def _storage_maintenance(self):
        """Create the fresh host fence once; retained gates are evidence, not defaults."""
        from .image_bundle import strict_json

        fresh = set(self.state.get("completed", [])) <= {"directories"}
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

        def directory(info, mode=None):
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_mode & 0o022 or mode is not None and stat.S_IMODE(info.st_mode) != mode):
                raise Refused("Storage maintenance directory must be root-owned with safe permissions")

        try:
            with ExitStack() as stack:
                def opened(name, flags, **kwargs):
                    fd = os.open(name, flags, **kwargs)
                    stack.callback(os.close, fd)
                    return fd

                data = opened(self.paths.data, directory_flags)
                directory(os.fstat(data))
                try:
                    manager = opened("manager", directory_flags, dir_fd=data)
                except FileNotFoundError:
                    if not fresh:
                        raise Refused("Existing runtime lost its storage maintenance evidence")
                    os.mkdir("manager", 0o700, dir_fd=data)
                    os.fsync(data)
                    manager = opened("manager", directory_flags, dir_fd=data)
                directory(os.fstat(manager))
                created = False
                try:
                    gate_dir = opened("storage-maintenance", directory_flags, dir_fd=manager)
                except FileNotFoundError:
                    if not fresh:
                        raise Refused("Existing runtime lost its storage maintenance evidence")
                    os.mkdir("storage-maintenance", 0o755, dir_fd=manager)
                    gate_dir = opened("storage-maintenance", directory_flags, dir_fd=manager)
                    os.fchmod(gate_dir, 0o755)
                    os.fchown(gate_dir, 0, 0)
                    os.fsync(manager)
                    created = True
                directory(os.fstat(gate_dir), 0o755)
                if created:
                    gate = {"schema": 1, "held": False, "delivery_held": False, "operation": None}
                    raw = (json.dumps(gate, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    output = opened("gate.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    dir_fd=gate_dir, mode=0o644)
                    os.fchmod(output, 0o644)
                    os.fchown(output, 0, 0)
                    with os.fdopen(os.dup(output), "wb") as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.fsync(gate_dir)
                source = opened("gate.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=gate_dir)
                before = os.fstat(source)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                        or stat.S_IMODE(before.st_mode) != 0o644 or before.st_nlink != 1
                        or not 1 <= before.st_size <= 4096):
                    raise Refused("Storage maintenance gate must be a bounded root-owned regular file with mode 0644")
                raw = os.read(source, 4097)
                after = os.fstat(source)
                if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key)
                        for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
                    raise Refused("Storage maintenance gate changed while being read")
                gate = strict_json(raw)
                if (not isinstance(gate, dict) or set(gate) != {"schema", "held", "delivery_held", "operation"}
                        or type(gate["schema"]) is not int or gate["schema"] != 1
                        or type(gate["held"]) is not bool or type(gate["delivery_held"]) is not bool
                        or gate["held"] and (not isinstance(gate["operation"], str)
                            or not re.fullmatch(r"[a-f0-9]{64}", gate["operation"]))
                        or not gate["held"] and (gate["delivery_held"] or gate["operation"] is not None)):
                    raise Refused("Storage maintenance gate has an invalid schema or operation owner")
        except OSError as exc:
            raise Refused("Storage maintenance evidence is missing or unsafe; bootstrap cannot reset it") from exc
        if created:
            self.runner(["restorecon", "-RF", str(self.paths.data / "manager/storage-maintenance")])
        return gate

    def _certificates(self):
        names = {self.setup["hostname"], "localhost", "keycloak", "clickhouse"}
        addresses = {"127.0.0.1", "::1"}
        # DHCP addresses can change. Only enrolled static management addresses
        # belong in this installation's certificate; never infer a live address.
        for family in (4, 6):
            network = self.setup.get("network", {}).get("ipv" + str(family), {})
            if network.get("method") == "manual":
                for configured in network.get("addresses", []):
                    try:
                        address = ipaddress.ip_interface(configured).ip
                        if address.version != family or "%" in str(address):
                            raise ValueError
                    except (ValueError, TypeError) as exc:
                        raise Refused("Invalid configured static TLS address") from exc
                    addresses.add(str(address))
        self.tls.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chown(self.tls, 0, 20001)
        os.chmod(self.tls, 0o750)
        ca_key, ca_cert = self.tls / "ca.key", self.tls / "ca.crt"
        server_key, server_cert = self.tls / "server.key", self.tls / "server.crt"
        if ca_cert.exists() and not ca_key.exists() or server_cert.exists() and not server_key.exists():
            raise Refused("An existing TLS certificate has lost its private key; preserve evidence rather than rotating it silently")
        if not ca_key.exists():
            private = self.runner(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"], timeout=180)
            _write_bytes(ca_key, (private + "\n").encode())
        if not ca_cert.exists():
            self.runner(["openssl", "req", "-new", "-x509", "-sha256", "-days", "3650", "-key", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=NebulaLog " + self.setup["installation_id"] + " local CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        if not server_key.exists():
            private = self.runner(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"], timeout=180)
            _write_bytes(server_key, (private + "\n").encode())
        if not server_cert.exists():
            hostname = self.setup["hostname"]
            sans = ["DNS:" + name for name in sorted(names)] + ["IP:" + address for address in sorted(addresses)]
            lines = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature,keyEncipherment", "extendedKeyUsage=serverAuth", "subjectAltName=" + ",".join(sans)]
            ext, csr = self.bootstrap / "server.ext", self.bootstrap / "server.csr"
            _write_bytes(ext, ("\n".join(lines) + "\n").encode())
            self.runner(["openssl", "req", "-new", "-sha256", "-key", str(server_key), "-out", str(csr), "-subj", "/CN=" + hostname])
            self.runner(["openssl", "x509", "-req", "-sha256", "-days", "397", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-set_serial", "0x" + secrets.token_hex(16), "-extfile", str(ext), "-out", str(server_cert)])
            csr.unlink(missing_ok=True)
            ext.unlink(missing_ok=True)
        if server_cert.read_bytes().count(b"-----BEGIN CERTIFICATE-----") == 1:
            _write_bytes(server_cert, server_cert.read_bytes() + ca_cert.read_bytes(), 0o644)
        for path in (ca_key, ca_cert, server_key, server_cert):
            trusted_file(path)
        os.chown(server_key, 0, 20001)
        os.chmod(server_key, 0o640)
        os.chmod(ca_key, 0o600)
        for path in (ca_cert, server_cert):
            os.chmod(path, 0o644)
        for name in sorted(names):
            self.runner(["openssl", "verify", "-CAfile", str(ca_cert), "-verify_hostname", name, str(server_cert)])
        for address in sorted(addresses):
            self.runner(["openssl", "verify", "-CAfile", str(ca_cert), "-verify_ip", address, str(server_cert)])
        for private, certificate in ((ca_key, ca_cert), (server_key, server_cert)):
            if self.runner(["openssl", "pkey", "-in", str(private), "-pubout"]) != self.runner(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"]):
                raise Refused("TLS certificate does not match its private key")
        self.runner(["openssl", "x509", "-in", str(server_cert), "-checkend", "86400", "-noout"])
        # Preserve normal public trust for external SAML metadata and other TLS.
        system_ca = SYSTEM_CA.read_bytes()
        _write_bytes(self.tls / "trust-bundle.pem", system_ca + b"\n" + ca_cert.read_bytes(), 0o644)
        self.runner(["restorecon", "-RF", str(self.tls)])

    def _images(self):
        pins = image_pins(json.loads(trusted_file(self.paths.etc / "images.json").read_text()))
        templates = Path("/usr/share/nebulalog/quadlet-templates")
        output = Path("/etc/containers/systemd")
        output.mkdir(parents=True, exist_ok=True)
        for name in ("nebulalog-api.container.in", "nebulalog-ingest.container.in", "nebulalog-postgresql.container.in", "nebulalog-clickhouse.container.in", "nebulalog-keycloak.container.in", "nebulalog.network"):
            content = trusted_file(templates / name).read_text()
            for key, value in pins.items():
                content = content.replace("@" + key + "@", value)
            if re.search(r"@[A-Z_]+@", content):
                raise Refused("Installed Quadlet template has an unresolved image pin")
            _write_bytes(output / name.removesuffix(".in"), content.encode(), 0o644)
        bundled = Path("/usr/share/nebulalog/images/manifest.json").exists()
        if bundled:
            loader = trusted_file(Path("/usr/libexec/nebulalog/load-image-bundle"))
            self.runner([str(loader)], timeout=1800)
        for reference in pins.values():
            try:
                self.runner(["podman", "image", "exists", reference])
            except CommandFailed as exc:
                if exc.returncode != 1:
                    raise
                if bundled:
                    raise Refused("Verified offline bundle did not load the required immutable image reference")
                self.runner(["podman", "pull", reference], timeout=1800)
        self.runner(["systemctl", "daemon-reload"])
        self.pins = pins

    def _environment(self):
        public = "https://" + self.setup["hostname"]
        shared = {"PG_DSN": "postgres://nebulalog:" + self.secret["postgresql_app"] + "@postgresql:5432/nebulalog?sslmode=disable", "CH_URL": "https://clickhouse:8443", "CH_USER": "nebulalog", "CH_PASSWORD": self.secret["clickhouse"], "SSL_CERT_FILE": "/etc/nebulalog/tls/trust-bundle.pem", "REQUIRE_FIPS": "true"}
        configs = {
            "postgresql": {"POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres", "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=trust"},
            "clickhouse": {"CLICKHOUSE_DB": "nebulalog", "CLICKHOUSE_USER": "nebulalog", "CLICKHOUSE_PASSWORD_FILE": "/run/secrets/nebulalog-ch-password"},
            "keycloak": {"KC_DB": "postgres", "KC_DB_URL": "jdbc:postgresql://postgresql:5432/keycloak", "KC_DB_USERNAME": "keycloak", "KC_DB_PASSWORD": self.secret["postgresql_keycloak"], "KC_BOOTSTRAP_ADMIN_USERNAME": "nlbootstrap", "KC_BOOTSTRAP_ADMIN_PASSWORD": self.secret["keycloak_bootstrap"], "KC_HOSTNAME": public, "KC_HOSTNAME_BACKCHANNEL_DYNAMIC": "true", "KC_PROXY_HEADERS": "xforwarded", "KC_HTTP_ENABLED": "false", "KC_HTTPS_CERTIFICATE_FILE": "/etc/nebulalog/tls/server.crt", "KC_HTTPS_CERTIFICATE_KEY_FILE": "/etc/nebulalog/tls/server.key", "KC_TRUSTSTORE_PATHS": "/etc/nebulalog/tls/ca.crt"},
            "api": {**shared, "COLLECTOR_TLS_CA_PATH": "/etc/nebulalog/tls/ca.crt", "COLLECTOR_TLS_CERT_PATH": "/etc/nebulalog/tls/server.crt", "OIDC_ISSUER": public + "/realms/nebulalog", "OIDC_BACKCHANNEL_URL": "https://keycloak:8443", "OIDC_URL": public, "OIDC_REALM": "nebulalog", "OIDC_CLIENT_ID": "nebulalog", "IDENTITY_ADMIN_URL": "https://keycloak:8443", "IDENTITY_CLIENT_ID": "nebulalog-identity-manager", "IDENTITY_CLIENT_SECRET": self.secret["identity_service"], "IDENTITY_ENABLE_WRITES": "true"},
            "ingest": {**shared, "SYSLOG_CERT": "/etc/nebulalog/tls/server.crt", "SYSLOG_KEY": "/etc/nebulalog/tls/server.key", "PANOS_TIMEZONE": self.setup["maintenance"]["timezone"]},
        }
        directory = self.configuration / "runtime"
        directory.mkdir(mode=0o700, exist_ok=True)
        for name, values in configs.items():
            destination = directory / (name + ".env")
            _write_bytes(destination, environment(values))
            link = self.paths.etc / destination.name
            if link.is_symlink():
                if link.resolve() != destination.resolve():
                    raise Refused("Runtime environment link points outside encrypted configuration")
            elif link.exists():
                raise Refused("Runtime environment destination already exists without the expected encrypted link")
            else:
                link.symlink_to(destination)
        self.runner(["podman", "secret", "create", "--replace", "nebulalog-pg-password", "-"], input=self.secret["postgresql_admin"].encode())
        self.runner(["podman", "secret", "create", "--replace", "nebulalog-ch-password", "-"], input=self.secret["clickhouse"].encode())
        client = self.configuration / "clickhouse-client.xml"
        _write_bytes(client, ("<clickhouse><user>nebulalog</user><password>" + self.secret["clickhouse"] + "</password><host>127.0.0.1</host><port>9440</port><secure>true</secure><openSSL><client><caConfig>/etc/nebulalog/tls/ca.crt</caConfig><verificationMode>strict</verificationMode><loadDefaultCAFile>false</loadDefaultCAFile><extendedVerification>true</extendedVerification></client></openSSL></clickhouse>\n").encode(), 0o640)
        os.chown(client, 0, 101)

    def _realm(self):
        directory = self.configuration / "keycloak/import"
        directory.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chown(directory.parent, 0, 1000)
        os.chmod(directory.parent, 0o750)
        os.chown(directory, 0, 1000)
        os.chmod(directory, 0o750)
        if self.state.get("identity_initialized"):
            return
        template = json.loads(trusted_file(Path("/usr/share/nebulalog/keycloak/realm.json")).read_text())
        realm = realm_config(template, self.setup, self.runtime)
        path = directory / "nebulalog-realm.json"
        atomic_json(path, realm)
        os.chown(path, 1000, 1000)
        os.chmod(path, 0o400)
        self.runner(["restorecon", "-RF", str(directory.parent)])

    def _wait(self, operation, timeout=180):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return operation()
            except (Refused, HTTPError, URLError, OSError):
                if time.monotonic() >= deadline:
                    raise Refused("A required application dependency did not become ready") from None
                time.sleep(2)

    def _postgres(self):
        self.runner(["systemctl", "start", "nebulalog-postgresql.service"], timeout=900)
        prefix = ["podman", "exec", "-i", "nebulalog-postgresql", "psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--username", "postgres", "--dbname", "postgres"]
        self._wait(lambda: self.runner(prefix + ["--tuples-only", "--command", "SELECT 1"]))
        statements = []
        for role, password_key in (("nebulalog", "postgresql_app"), ("keycloak", "postgresql_keycloak")):
            # Role names are fixed and passwords are validated hex, not arbitrary
            # operator SQL. Secret values travel only on stdin, never argv.
            statements += [f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} LOGIN PASSWORD '{self.secret[password_key]}'; END IF; END $$;",
                           f"SELECT 'CREATE DATABASE {role} OWNER {role}' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='{role}') \\gexec",
                           f"REVOKE ALL ON DATABASE {role} FROM PUBLIC;",
                           f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole) THEN RAISE EXCEPTION 'Unexpected database role privileges'; END IF; END $$;"]
        self.runner(prefix, input=("\n".join(statements) + "\n").encode())
        self.runner(["systemctl", "start", "nebulalog-clickhouse.service"], timeout=900)
        self._wait(lambda: self.runner(["podman", "exec", "--user", "101:101", "nebulalog-clickhouse", "clickhouse-client", "--config-file", "/etc/nebulalog/clickhouse-client.xml", "--secure", "--port", "9440", "--query", "SELECT 1"]))

    def _migrate(self):
        self.runner(["podman", "run", "--rm", "--name", "nebulalog-initial-migrate", "--network", "nebulalog", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--volume", str(self.tls / "trust-bundle.pem") + ":/etc/nebulalog/tls/trust-bundle.pem:ro,z", "--env-file", str(self.configuration / "runtime/api.env"), self.pins["NEBULALOG_IMAGE"], "migrate"], timeout=900)
        if "migrations" not in self.state["completed"]:
            sql = "UPDATE settings SET value=jsonb_set(value, '{global_days}', '" + str(self.setup["retention_days"]) + "'::jsonb) WHERE key='retention';"
            self.runner(["podman", "exec", "-i", "nebulalog-postgresql", "psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--username", "postgres", "--dbname", "nebulalog"], input=sql.encode())

    def _request(self, url, data=None, token=None, method=None, form=False):
        headers = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        body = None if data is None else urlencode(data).encode() if form else json.dumps(data).encode()
        context = ssl.create_default_context(cafile=str(self.tls / "ca.crt"))
        opener = build_opener(HTTPSHandler(context=context), NoRedirect())
        with opener.open(Request(url, body, headers, method=method), timeout=20) as response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise Refused("Oversized runtime administration response")
            return json.loads(raw) if raw else None

    def _token(self, bootstrap=False):
        realm = "master" if bootstrap else "nebulalog"
        body = {"grant_type": "password", "client_id": "admin-cli", "username": "nlbootstrap", "password": self.secret["keycloak_bootstrap"]} if bootstrap else {"grant_type": "client_credentials", "client_id": "nebulalog-appliance-inspector", "client_secret": self.runtime["inspector_service"]}
        return self._request("https://127.0.0.1:8443/realms/" + realm + "/protocol/openid-connect/token", body, form=True)["access_token"]

    def _kc(self, path, token, method="GET", body=None):
        return self._request("https://127.0.0.1:8443/admin/realms/nebulalog/" + path, body, token, method)

    def _service_identity(self, token, name, secret, allowed):
        clients = self._kc("clients?clientId=" + name, token)
        if clients and clients[0].get("attributes", {}).get("nebulalog-installation") != self.setup["installation_id"]:
            raise Refused("Existing service client is not owned by this installation")
        if not clients:
            self._kc("clients", token, "POST", {"clientId": name, "enabled": True, "protocol": "openid-connect", "publicClient": False, "secret": secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "defaultClientScopes": ["roles"], "fullScopeAllowed": True, "attributes": {"nebulalog-installation": self.setup["installation_id"], "nebulalog-managed": "true"}})
            clients = self._kc("clients?clientId=" + name, token)
        if len(clients) != 1:
            raise Refused("Service identity is ambiguous")
        user = self._kc("clients/" + clients[0]["id"] + "/service-account-user", token)
        management = self._kc("clients?clientId=realm-management", token)[0]
        path = "users/" + user["id"] + "/role-mappings/clients/" + management["id"]
        existing = self._kc(path, token)
        if {role["name"] for role in existing} - allowed:
            raise Refused("Service identity has unexpected administration privileges")
        self._kc(path, token, "POST", [self._kc("clients/" + management["id"] + "/roles/" + name, token) for name in sorted(allowed)])

    def _identity(self):
        self.runner(["systemctl", "start", "nebulalog-keycloak.service"], timeout=900)
        self._wait(lambda: self._request("https://127.0.0.1:8443/realms/nebulalog/.well-known/openid-configuration"), timeout=300)
        if self.state.get("identity_initialized"):
            self._token()
            self._disable_bootstrap()
            (self.bootstrap / "administrator-password").unlink(missing_ok=True)
            (self.configuration / "keycloak/import/nebulalog-realm.json").unlink(missing_ok=True)
            return
        token = self._wait(lambda: self._token(bootstrap=True))
        realm = self._kc("", token)
        if realm.get("attributes", {}).get("nebulalog.installation-id") != self.setup["installation_id"]:
            raise Refused("Existing realm was not created by this installation")
        username = self.setup["administrator"]["username"]
        users = self._kc("users?" + urlencode({"username": username, "exact": "true"}), token)
        if users and (users[0].get("attributes", {}).get("nebulalog-installation") != [self.setup["installation_id"]] or users[0].get("attributes", {}).get("nebulalog-local-operator") != ["true"]):
            raise Refused("Existing administrator belongs to another installation; password was not changed")
        if not users:
            password_path = Path(self.setup["administrator"]["password_file"])
            if password_path != self.bootstrap / "administrator-password":
                raise Refused("Administrator credential is outside encrypted bootstrap storage")
            password = _private_file(password_path, minimum=14, maximum=1024).decode()
            self._kc("users", token, "POST", {"username": username, "enabled": True, "firstName": "Captain’s Log", "lastName": "Administrator", "email": "administrator@localhost.invalid", "emailVerified": True, "requiredActions": ["CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES"], "attributes": {"nebulalog-installation": [self.setup["installation_id"]], "nebulalog-local-operator": ["true"]}, "credentials": [{"type": "password", "value": password, "temporary": False}]})
            users = self._kc("users?" + urlencode({"username": username, "exact": "true"}), token)
        if len(users) != 1:
            raise Refused("Initial administrator is ambiguous")
        application = self._kc("clients?clientId=nebulalog", token)[0]
        administrator_role = self._kc("clients/" + application["id"] + "/roles/ADMINISTRATOR", token)
        self._kc("users/" + users[0]["id"] + "/role-mappings/clients/" + application["id"], token, "POST", [administrator_role])
        self._service_identity(token, "nebulalog-identity-manager", self.secret["identity_service"], MANAGER_ROLES)
        self._service_identity(token, "nebulalog-appliance-inspector", self.runtime["inspector_service"], INSPECTOR_ROLES)
        self._token()
        self.state.update(identity_initialized=True, administrator_id=users[0]["id"])
        atomic_json(self.state_path, self.state)
        # Retrying setup never re-enables this temporary superuser. Inspector
        # credentials can read evidence but cannot reset users or configure IdPs.
        self._disable_bootstrap(token)
        (self.bootstrap / "administrator-password").unlink(missing_ok=True)
        (self.configuration / "keycloak/import/nebulalog-realm.json").unlink(missing_ok=True)

    def _disable_bootstrap(self, token=None):
        sql = "SELECT COALESCE(bool_and(NOT u.enabled), false) FROM user_entity u JOIN realm r ON r.id=u.realm_id WHERE r.name='master' AND u.username='nlbootstrap';"
        argv = ["podman", "exec", "-i", "nebulalog-postgresql", "psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--username", "postgres", "--dbname", "keycloak"]
        if self.runner(argv, input=sql.encode()).strip() == "t":
            return
        token = token or self._token(bootstrap=True)
        masters = self._request("https://127.0.0.1:8443/admin/realms/master/users?username=nlbootstrap&exact=true", token=token)
        if len(masters) != 1:
            raise Refused("Temporary bootstrap administrator is ambiguous")
        self._request("https://127.0.0.1:8443/admin/realms/master/users/" + masters[0]["id"], {"enabled": False}, token, "PUT")
        if self.runner(argv, input=sql.encode()).strip() != "t":
            raise Refused("Temporary bootstrap administrator did not become disabled")

    def _edge_certificates(self):
        # Container :z mounts relabel their TLS tree container_file_t. Apache's
        # host httpd_t domain needs a separate httpd_config_t tree on the same
        # encrypted mount. Copy the verified identity; never generate another.
        edge = self.configuration / "edge-tls"
        _private_dir(edge)
        material = {}
        for name in ("server.crt", "ca.crt", "server.key"):
            source = trusted_file(self.tls / name)
            if not 1 <= source.stat().st_size <= 65536:
                raise Refused("TLS material exceeds its permitted size")
            material[name] = source.read_bytes()
            destination = edge / name
            if destination.exists() or destination.is_symlink():
                trusted_file(destination)
                if destination.read_bytes() != material[name]:
                    raise Refused("Existing HTTPS edge TLS identity differs; firstboot cannot rotate it")
        for name, content in material.items():
            destination = edge / name
            mode = 0o600 if name == "server.key" else 0o644
            if not destination.exists():
                _write_bytes(destination, content, mode)
            os.chown(destination, 0, 0)
            os.chmod(destination, mode)
        self.runner(["openssl", "verify", "-CAfile", str(edge / "ca.crt"), "-verify_hostname", self.setup["hostname"], str(edge / "server.crt")])
        if self.runner(["openssl", "pkey", "-in", str(edge / "server.key"), "-pubout"]) != self.runner(["openssl", "x509", "-in", str(edge / "server.crt"), "-pubkey", "-noout"]):
            raise Refused("HTTPS edge certificate does not match its private key")
        self.runner(["restorecon", "-RF", str(edge)])
        return edge

    def _edge(self):
        edge_tls = self._edge_certificates()
        template = trusted_file(EDGE_TEMPLATE).read_text()
        for name, value in {"SERVER_NAME": self.setup["hostname"], "TLS_DIRECTORY": str(edge_tls), "MAINTENANCE_MARKER": "/run/nebulalog-public/maintenance.json"}.items():
            template = template.replace("@" + name + "@", value)
        if re.search(r"@[A-Z_]+@", template):
            raise Refused("HTTPS edge template has unresolved settings")
        _write_bytes(EDGE_CONFIG, template.encode(), 0o644)
        self.runner(["httpd", "-t"])
        self.runner(["systemctl", "start", "nebulalog-api.service", "nebulalog-ingest.service"], timeout=900)
        self.runner(["systemctl", "restart", "nebulalog-edge.service"], timeout=180)
        self._wait(lambda: self._request("https://localhost/api/health"), timeout=180)

    def _schema_revision(self):
        from .update_enrollment import UpdateEnrollment
        descriptor, _, _ = UpdateEnrollment(data=self.paths.data, etc=self.paths.etc,
            share=INITIAL_RELEASE.parent, runner=self.runner, firstboot=self.firstboot)._descriptor()
        return descriptor["schema_revision"]

    def _lifecycle(self):
        path = self.configuration / "lifecycle.json"
        from .image_bundle import strict_json
        trust_path = trusted_file(self.paths.etc / "trust.json")
        if trust_path.stat().st_size > 65536:
            raise Refused("Installed package trust record exceeds its size budget")
        trust = strict_json(trust_path.read_bytes())
        required = {"schema", "rocky_key_sha256", "rocky_key_fingerprint"}
        if not isinstance(trust, dict) or required - set(trust) or set(trust) - required - {"source", "key_source"} or type(trust["schema"]) is not int or trust["schema"] != 1 or not isinstance(trust["rocky_key_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", trust["rocky_key_sha256"]) or trust["rocky_key_fingerprint"] != ROCKY_9_FINGERPRINT:
            raise Refused("Installed Rocky package trust record is invalid or unqualified")
        for name in ("source", "key_source"):
            if name in trust:
                value = trust[name]
                if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
                    raise Refused("Invalid package trust provenance URL")
                url = urlsplit(value)
                if url.scheme != "https" or url.hostname not in ("rockylinux.org", "dl.rockylinux.org", "download.rockylinux.org") or url.username or url.password or url.port not in (None, 443) or url.query or url.fragment:
                    raise Refused("Package trust provenance must name an official Rocky HTTPS source")
        package_key = trusted_file(ROCKY_PACKAGE_KEY)
        if not 1 <= package_key.stat().st_size <= 65536 or hashlib.sha256(package_key.read_bytes()).hexdigest() != trust["rocky_key_sha256"]:
            raise Refused("Rocky package key differs from the trust verified at image installation")
        value = {"schema": 1, "api_url": "http://127.0.0.1:8080", "issuer": "https://" + self.setup["hostname"] + "/realms/nebulalog", "ca_file": str(self.tls / "ca.crt"), "schema_revision": self._schema_revision(), "compliance_policy": str(self.configuration / "security-policy.json"), "auth_probe": {"client_id": "nebulalog", "redirect_uri": "https://" + self.setup["hostname"] + "/health-oidc", "username": "nebulalog-health", "password": self.runtime["health_password"], "totp_secret": self.runtime["health_totp"], "totp_algorithm": "SHA256", "totp_digits": 6, "totp_period": 30}}
        value["rocky_key_sha256"] = trust["rocky_key_sha256"]
        if path.exists():
            current = self._read(path)
            if current.get("auth_probe") != value["auth_probe"]:
                raise Refused("Lifecycle identity configuration changed")
            if current.get("schema_revision") != value["schema_revision"]:
                raise Refused("Existing lifecycle schema differs; firstboot cannot perform an application upgrade")
            if current.get("rocky_key_sha256") not in (None, trust["rocky_key_sha256"]):
                raise Refused("Existing lifecycle package trust differs; firstboot cannot rotate or reset trust")
            # Preserve installed adapter settings and operator policy on retries.
            value = {**value, **current}
            value["rocky_key_sha256"] = trust["rocky_key_sha256"]
        # Apache is a host service and remains up to enforce maintenance mode;
        # it must not enter the adapter's container/Quadlet service inventory.
        value.pop("edge_service", None)
        atomic_json(path, value)

    def _installed_release(self):
        from .image_bundle import strict_json
        descriptor = trusted_file(INITIAL_RELEASE)
        if not 1 <= descriptor.stat().st_size <= 65536:
            raise Refused("Installed initial-release descriptor is missing or oversized")
        descriptor_bytes = descriptor.read_bytes()
        initial = strict_json(descriptor_bytes)
        if not isinstance(initial, dict) or type(initial.get("sequence")) is not int or initial["sequence"] < 0:
            raise Refused("Installed initial-release descriptor has no explicit release sequence")
        helper = trusted_file(ENROLL_RELEASE)
        if not os.access(helper, os.X_OK):
            raise Refused("Installed release-enrollment helper is not executable")
        output = self.runner([str(helper)], timeout=1800)
        if len(output.encode()) > 65536:
            raise Refused("Oversized installed-release enrollment receipt")
        receipt = strict_json(output.encode())
        if not isinstance(receipt, dict) or type(receipt.get("schema")) is not int or receipt["schema"] != 1 or receipt.get("ok") is not True or receipt.get("status") != "enrolled" or receipt.get("installation_id") != self.setup["installation_id"] or receipt.get("initial_release_sha256") != hashlib.sha256(descriptor_bytes).hexdigest() or receipt.get("publisher_trust") not in ("not_enrolled", "enrolled") or receipt.get("qualification_status") != "pending":
            raise Refused("Installed-release enrollment did not return matching candidate evidence")
        publisher = initial.get("publisher")
        if not isinstance(publisher, dict) or publisher.get("mode") not in ("factory", "private-unsealed"):
            raise Refused("Installed release has no explicit factory or private unsealed publisher mode")
        if receipt.get("build_mode") != publisher["mode"] or type(receipt.get("update_ready")) is not bool:
            raise Refused("Installed publisher readiness differs from the protected build descriptor")
        if publisher["mode"] == "factory" and (receipt["publisher_trust"] != "enrolled" or receipt["update_ready"] is not True):
            raise Refused("Factory publisher enrollment must complete before runtime bootstrap readiness")
        if publisher["mode"] == "private-unsealed" and (publisher != {"mode": "private-unsealed"} or receipt["update_ready"] is not False):
            raise Refused("Private unsealed candidates cannot claim factory update readiness")
        current = receipt.get("current")
        if not isinstance(current, dict) or type(current.get("sequence")) is not int or current["sequence"] != initial["sequence"]:
            raise Refused("Installed-release sequence differs from the protected build descriptor")
        expected = {"nebulalog": "NEBULALOG_IMAGE", "postgresql": "POSTGRESQL_IMAGE", "clickhouse": "CLICKHOUSE_IMAGE", "keycloak": "KEYCLOAK_FIPS_IMAGE"}
        components = current.get("components")
        # Initial runtime setup precedes reviewed policy selection. Content is
        # enrolled by the later typed bridge, never fabricated in this receipt.
        if not isinstance(components, dict) or set(components) != set(expected) | {"host"}:
            raise Refused("Installed-release component inventory is incomplete")
        from .update_enrollment import UpdateEnrollment
        host = UpdateEnrollment(data=self.paths.data, etc=self.paths.etc, share=INITIAL_RELEASE.parent,
                                runner=self.runner, firstboot=self.firstboot)._factory_host(initial)
        if components["host"] != host:
            raise Refused("Installed-release host generation differs from measured factory code")
        for name, image in expected.items():
            component = components[name]
            if not isinstance(component, dict) or component.get("image") != self.pins[image] or component.get("schema_revision") != self._schema_revision() or not isinstance(component.get("version"), str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}", component["version"]):
                raise Refused("Installed-release component evidence differs from the runtime candidate")
        if current.get("version") != components["nebulalog"]["version"]:
            raise Refused("Installed-release application version is inconsistent")
        return receipt

    def _publisher_readiness(self):
        from .update_enrollment import UpdateEnrollment
        return UpdateEnrollment(data=self.paths.data, etc=self.paths.etc, share=INITIAL_RELEASE.parent,
                                runner=self.runner, firstboot=self.firstboot).factory_status()

    def _evidence(self, final=False):
        self._publisher_readiness()
        from nebulalog_adapters.auth import local_auth
        token = self._token()
        admin = self._kc("users/" + self.state["administrator_id"], token)
        credentials = self._kc("users/" + self.state["administrator_id"] + "/credentials", token)
        credential_types = {credential["type"] for credential in credentials}
        realm = self._kc("", token)
        application = self._kc("clients?clientId=nebulalog", token)[0]
        roles = self._kc("users/" + self.state["administrator_id"] + "/role-mappings/clients/" + application["id"] + "/composite", token)
        health_config = self._read(self.configuration / "lifecycle.json")
        auth_token, _ = local_auth(health_config)
        health = self._request("https://localhost/api/health")
        discovery = self._request("https://127.0.0.1:8443/realms/nebulalog/.well-known/openid-configuration")
        required = set(admin.get("requiredActions", []))
        executions = self._kc("authentication/flows/nebulalog-forms/executions", token)
        factors = self._kc("authentication/flows/nebulalog-second-factor/executions", token)
        mfa_policy = (realm.get("browserFlow") == "nebulalog-browser" and realm.get("otpPolicyAlgorithm") == "HmacSHA256"
                      and any(item.get("providerId") == "auth-username-password-form" and item.get("requirement") == "REQUIRED" for item in executions)
                      and any(item.get("displayName") == "nebulalog-second-factor" and item.get("authenticationFlow") is True and item.get("requirement") == "REQUIRED" for item in executions)
                      and {item.get("providerId"): item.get("requirement") for item in factors} == {"auth-otp-form": "ALTERNATIVE", "auth-recovery-authn-code-form": "ALTERNATIVE"})
        checks = {"postgresql": health.get("postgresql") == "ok", "clickhouse": health.get("clickhouse") == "ok", "keycloak": discovery.get("issuer") == "https://" + self.setup["hostname"] + "/realms/nebulalog", "https": True,
                  "administrator_created": admin.get("enabled") is True and admin.get("attributes", {}).get("nebulalog-installation") == [self.setup["installation_id"]],
                  "administrator_mfa_required": mfa_policy and ("CONFIGURE_TOTP" in required or "otp" in credential_types),
                  "local_breakglass": not admin.get("federationLink") and "password" in credential_types and any(role["name"] == "ADMINISTRATOR" for role in roles)}
        if final:
            logs = self._request("https://localhost/api/logs?" + urlencode({"type": "unified", "limit": "100", "query": "(device neq NEBULALOG-HEALTH)"}), token=auth_token)
            checks.update(administrator_mfa_enrolled="otp" in credential_types and "CONFIGURE_TOTP" not in required,
                          administrator_recovery_enrolled="recovery-authn-codes" in credential_types and "CONFIGURE_RECOVERY_AUTHN_CODES" not in required,
                          syslog_received=any(event.get("serial") and event.get("parse_status") == "parsed" for event in logs.get("events", [])), baseline_assessed=False, baseline_review_complete=False, aide_enrolled=False, aide_checked_clean=False)
            from .baseline import firstboot_checks
            checks.update(firstboot_checks(self.configuration, self.setup["installation_id"], self.setup["baseline"]))
            # Completion holds firstboot/runtime locks. This read-only verifier
            # inspects a recent explicit AIDE check without reacquiring them.
            from .aide import firstboot_checks as integrity_checks
            checks.update(integrity_checks(self.setup["installation_id"]))
        fingerprints = {}
        for field, filename in (("tls_certificate_sha256", "server.crt"), ("tls_ca_certificate_sha256", "ca.crt")):
            fingerprint = self.runner(["openssl", "x509", "-in", str(self.tls / filename), "-noout", "-fingerprint", "-sha256"]).split("=", 1)[-1].replace(":", "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                raise Refused("Invalid public TLS certificate fingerprint")
            fingerprints[field] = fingerprint
        return {"schema": 1, "installation_id": self.setup["installation_id"], "state": "setup-complete" if final and all(checks.values()) else "runtime-ready" if all(checks.values()) else "verification-pending", "checks": checks, "https_url": "https://" + self.setup["hostname"], **fingerprints}

    def prepare(self, setup_path, secrets_path):
        self.firstboot.gate()
        with locked(self.bootstrap / "runtime.lock"):
            self._load(setup_path, secrets_path)
            for name, operation in (("directories", self._directories), ("storage-maintenance", self._storage_maintenance), ("certificates", self._certificates), ("images", self._images), ("environment", self._environment), ("realm", self._realm), ("postgresql", self._postgres), ("migrations", self._migrate), ("identity", self._identity), ("lifecycle", self._lifecycle), ("edge", self._edge), ("installed-release", self._installed_release)):
                self._stage(name, operation)
            result = self._evidence()
            if not all(result["checks"].get(key) is True for key in RUNTIME_CHECKS):
                raise Refused("Runtime preparation did not pass its live dependency/authentication checks")
            return result

    def verify(self, setup_path):
        self.firstboot.gate()
        with locked(self.bootstrap / "runtime.lock"):
            self._load(setup_path)
            if not self.state.get("identity_initialized"):
                raise Refused("Application identity has not been initialized")
            return self._evidence(final=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "verify"):
        command = actions.add_parser(name)
        command.add_argument("--setup", type=Path, required=True)
        if name == "prepare":
            command.add_argument("--secrets", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manager = Bootstrap()
        result = manager.prepare(args.setup, args.secrets) if args.action == "prepare" else manager.verify(args.setup)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (Refused, HTTPError, URLError, OSError, ValueError, KeyError) as exc:
        # HTTP exception URLs and response bodies may contain temporary codes;
        # only explicit, controlled refusal messages cross this boundary.
        print(json.dumps({"state": "refused", "error": str(exc) if isinstance(exc, Refused) else "Runtime bootstrap failed; inspect the current stage and local service health"}), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
