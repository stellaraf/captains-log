"""Fixed, journal-bound host resource reconciliation through a retained coordinator.

Generation code is selected by the separately installed fixed boot shim. This
module reconciles only catalogued package files, preserves customer/trust inputs,
and requires measured runtime and authorized integrity evidence before success.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import stat

from nebulalog_manager import aide, host_activation, host_dispatch, host_payload
from nebulalog_manager.common import Refused, atomic_json

SYSTEMD = Path("/etc/systemd/system")
SHARE = Path("/usr/share/nebulalog")
ETC = Path("/etc/nebulalog")
EDGE = Path("/etc/httpd/conf.d/nebulalog.conf")
SHIM = Path("/usr/libexec/nebulalog/host-boot")
ORIGIN_MODULES = ("nebulalog_manager.updates", "nebulalog_manager.github_updates", "nebulalog_adapters.lifecycle")
MIGRATION_ONLY = {"share/defaults/" + name for name in host_payload.DEFAULTS} | {
    "share/templates/keycloak/realm.json", "share/templates/quadlet/nebulalog.network"} | {
    item["path"] for item in host_payload.CATALOG if item["path"].startswith("bin/")}
IMAGE_KEYS = {"api": "NEBULALOG_IMAGE", "ingest": "NEBULALOG_IMAGE", "postgresql": "POSTGRESQL_IMAGE",
              "clickhouse": "CLICKHOUSE_IMAGE", "keycloak": "KEYCLOAK_FIPS_IMAGE"}
COMPONENT_FOR_SERVICE = {"api": "nebulalog", "ingest": "nebulalog", "postgresql": "postgresql",
                         "clickhouse": "clickhouse", "keycloak": "keycloak"}
MAX_FILES = 2000
MAX_CUSTOMER_BYTES = 64 * 1024**2
OWNER_UID = 0
OWNER_GID = 0
MUTABLE_CUSTOMER = {"baseline.lock", "baseline-assessment.json", "baseline-review.json", "baseline-attempt.json", "baseline-audit.jsonl"}


def description(raw, mode=0o644, uid=None, gid=None):
    uid = OWNER_UID if uid is None else uid
    gid = OWNER_GID if gid is None else gid
    return {"kind": "file", "uid": uid, "gid": gid, "mode": mode, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def checked_file(path, maximum=host_payload.MAX_FILE):
    host_payload._trusted_tree(path.parent)
    stream, before = host_payload.open_regular(path, maximum, trusted=True)
    with stream:
        raw = stream.read(maximum + 1)
        if len(raw) != before.st_size or not host_payload.same_file(before, os.fstat(stream.fileno())):
            raise Refused("Host runtime input changed while being measured")
    return raw, description(raw, stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid)


class HostRuntime:
    def __init__(self, lifecycle, stage):
        self.lifecycle, self.stage = lifecycle, stage
        if lifecycle.state != host_dispatch.STATE:
            raise Refused("Host lifecycle requires the fixed manager state")
        self.transaction, self.release = host_dispatch.transaction_binding(stage)
        self.pin = host_dispatch.coordinator_pin(stage)
        self.candidate, _ = host_activation._candidate_identity(self.release)
        self.previous = {key: self.pin[key] for key in self.candidate}
        self.old_root = host_payload.GENERATIONS / self.previous["generation"]
        self.new_root = host_payload.GENERATIONS / self.candidate["generation"]
        self.plan_path = stage / "host-runtime-plan.json"
        self.root = stage / "host-runtime"

    def source(self, root, name):
        if name not in host_payload.CATALOG_BY_PATH:
            raise Refused("Uncatalogued host resource")
        return checked_file(root / name)[0]

    def phase(self, action):
        # Revalidate the fixed hook and retained coordinator before any effect,
        # including when invoked directly through an installed adapter wrapper.
        host_dispatch.hook_command(self.pin, action, self.stage)
        transaction, _ = host_dispatch.transaction_binding(self.stage)
        candidate = action == "update-activate" or action in {"update-health", "update-finalize"} and transaction["state"] in {"checking", "committed"}
        expected = self.candidate if candidate else self.previous
        sequence = transaction["previous"]["sequence"] if action in {"update-preflight", "update-backup", "update-prepare"} else transaction["sequence"]
        if host_activation.selection() != {"schema": 1, "generation": expected["generation"], "sequence": sequence}:
            raise Refused("Host lifecycle phase differs from the durable selection")

    def fixed_targets(self):
        values = {"share/templates/systemd/" + name: SYSTEMD / name for name in host_payload.UNITS}
        values.update({"share/templates/quadlet/" + name: SHARE / "quadlet-templates" / name for name in host_payload.QUADLETS})
        values["share/templates/httpd/nebulalog.conf.in"] = SHARE / "httpd/nebulalog.conf.in"
        values["share/templates/keycloak/realm.json"] = SHARE / "keycloak/realm.json"
        return values

    def preserved(self):
        """Hash protected inputs only; never store credential values in a plan."""
        from .lifecycle import inventory
        entries = inventory(self.lifecycle.configuration)
        values, total = [], 0
        for item in entries:
            name = item["path"]
            if (name in MUTABLE_CUSTOMER or name.startswith("baseline-assessments/")
                    or name == "bootstrap/runtime.lock"):
                continue
            total += item["bytes"]
            values.append({**item, "kind": "file", "path": str(self.lifecycle.configuration / name)})
        if len(values) > MAX_FILES or total > MAX_CUSTOMER_BYTES:
            raise Refused("Customer configuration exceeds the bounded preservation inventory")
        fixed = [ETC / name for name in ("trust.json", "release-public.pem", "github-updates.json", "images.json", "bootstrap/setup.json")]
        fixed += [SHARE / name for name in ("publisher-public.spki", "publisher-trust.json", "initial-release.json", "source-manifest.json", "initial-host.json")]
        fixed += [self.lifecycle.state / name for name in ("publisher-trust.json", "initial-enrollment.json")]
        for path in fixed:
            _, record = checked_file(path, host_payload.MAX_SOURCE_MANIFEST)
            values.append({"path": str(path), **record})
        return values

    def _render_quadlet(self, root, name, image):
        text = self.source(root, "share/templates/quadlet/nebulalog-" + name + ".container.in").decode("utf-8")
        text = text.replace("@" + IMAGE_KEYS[name] + "@", image)
        if re.search(r"@[A-Z_]+@", text):
            raise Refused("Host Quadlet has an unresolved fixed image placeholder")
        return text.encode()

    def _render_edge(self, root):
        from urllib.parse import urlsplit
        hostname = urlsplit(self.lifecycle.config["issuer"]).hostname
        if not hostname or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", hostname):
            raise Refused("Existing edge identity is not a safe configured hostname")
        text = self.source(root, "share/templates/httpd/nebulalog.conf.in").decode("utf-8")
        for key, value in {"SERVER_NAME": hostname, "TLS_DIRECTORY": str(self.lifecycle.configuration / "edge-tls"),
                           "MAINTENANCE_MARKER": "/run/nebulalog-public/maintenance.json"}.items():
            text = text.replace("@" + key + "@", value)
        if re.search(r"@[A-Z_]+@", text):
            raise Refused("Host HTTPS template has an unresolved fixed placeholder")
        return text.encode()

    def _resources(self):
        from .lifecycle import image_from_quadlet, IMAGE
        resources = []
        for name in sorted(MIGRATION_ONLY):
            if self.source(self.old_root, name) != self.source(self.new_root, name):
                receipt = {"schema": 1, "reason": "qualified_migration_required", "resource": name,
                           "sequence": self.transaction["sequence"], "manifest_sha256": self.transaction["manifest_sha256"]}
                path = self.stage / "host-refusal.json"
                if path.exists():
                    if json.loads(checked_file(path)[0]) != receipt:
                        raise Refused("Retained host refusal differs from this transaction")
                else:
                    atomic_json(path, receipt)
                raise Refused("Host resource requires a qualified policy, boot, dispatcher, network or identity migration: " + name)
        for name, path in self.fixed_targets().items():
            old, new = self.source(self.old_root, name), self.source(self.new_root, name)
            resources.append((path, old, new))
        for service, component in COMPONENT_FOR_SERVICE.items():
            path = self.lifecycle.quadlets / ("nebulalog-" + service + ".container")
            current = checked_file(path)[0]
            image = image_from_quadlet(current.decode("utf-8"))
            new_image = self.release["components"].get(component, {}).get("image", image)
            if not IMAGE.fullmatch(new_image):
                raise Refused("Host reconciliation requires the retained or signed immutable image pin")
            resources.append((path, self._render_quadlet(self.old_root, service, image), self._render_quadlet(self.new_root, service, new_image)))
        if self.lifecycle.config.get("edge_service"):
            resources.append((EDGE, self._render_edge(self.old_root), self._render_edge(self.new_root)))
        return sorted(resources, key=lambda item: str(item[0]))

    def _generation_additions(self):
        host_dispatch.generation_info(self.candidate["generation"])
        entries = []
        for path in [self.new_root, *sorted(self.new_root.rglob("*"))]:
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                value = {"kind": "directory", "mode": 0o555, "uid": info.st_uid, "gid": info.st_gid}
            else:
                _, value = checked_file(path)
            entries.append({"path": str(path), **value})
        return entries

    def probe(self, *, imports=False):
        checked_file(SHIM)
        result = json.loads(self.lifecycle.cmd(["/usr/bin/python3", "-I", "-B", str(SHIM),
                                               "probe-selected" if imports else "verify-selected"], timeout=90))
        selected = host_activation.selection()
        identity = self.candidate if selected["generation"] == self.candidate["generation"] else self.previous
        if (not isinstance(result, dict) or type(result.get("schema")) is not int or result["schema"] != 1
                or type(result.get("abi")) is not int or result["abi"] != 1 or result.get("verified") is not True
                or any(result.get(key) != value for key, value in identity.items())
                or type(result.get("selection_sequence")) is not int or result["selection_sequence"] != selected["sequence"]):
            raise Refused("Fixed boot dispatcher did not verify the selected host identity")
        if imports:
            expected = {name: str(host_payload.GENERATIONS / identity["generation"] / "lib" / (name.replace(".", "/") + ".py")) for name in ORIGIN_MODULES}
            hashes = {name: hashlib.sha256(checked_file(Path(path))[0]).hexdigest() for name, path in expected.items()}
            if (result.get("origins") != expected or result.get("module_sha256") != hashes
                    or result.get("coordinator_generation") != self.pin["generation"]
                    or result.get("runtime_imported") is not True or result.get("coordinator_verified") is not True):
                raise Refused("Selected host runtime import provenance failed")
        return result

    def integrity(self, action, direction="forward"):
        function = getattr(aide.Aide(), "authorized_update_" + action, None)
        if function is None:
            raise Refused("Host update requires installed authorized-change AIDE integration")
        result = function(self.stage, self.plan_path, **({"direction": direction} if action != "prepare" else {}))
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise Refused("Authorized host integrity acceptance did not pass")
        return result

    def preflight(self):
        self.phase("update-preflight")
        self.probe()
        resources = self._resources()
        files = []
        for path, old, new in resources:
            actual, observed = checked_file(path)
            if actual != old or observed != description(old):
                raise Refused("Package-managed host resource has local changes; automatic reconciliation refused: " + str(path))
            files.append({"path": str(path), "before": description(old), "after": description(new)})
        selection = host_activation.selection()
        # Match atomic_json's canonical bytes without writing any selection.
        encode_selection = lambda value: (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        selected_new = {"schema": 1, "generation": self.candidate["generation"], "sequence": self.transaction["sequence"]}
        restored = {"schema": 1, "generation": self.previous["generation"], "sequence": self.transaction["sequence"]}
        plan = {"schema": 1, "sequence": self.transaction["sequence"], "manifest_sha256": self.transaction["manifest_sha256"],
                "coordinator_generation": self.previous["generation"], "candidate_generation": self.candidate["generation"],
                "files": files, "generation_additions": self._generation_additions(), "preserved": self.preserved(),
                "selection": {"path": str(host_activation.SELECTION), "before": description(encode_selection(selection), 0o600),
                              "after": description(encode_selection(selected_new), 0o600), "restored": description(encode_selection(restored), 0o600)},
                "migration_only": sorted(MIGRATION_ONLY)}
        if self.plan_path.exists() or self.plan_path.is_symlink():
            if host_dispatch.protected_json(self.plan_path) != plan:
                raise Refused("Existing host runtime plan differs")
        else:
            atomic_json(self.plan_path, plan)
        self.integrity("prepare")
        return self.evidence("update-preflight", {"dispatcher_ready", "reconciliation_supported", "rollback_supported", "provenance_supported"})

    def plan(self):
        value = host_dispatch.protected_json(self.plan_path)
        if (not isinstance(value, dict) or value.get("schema") != 1 or value.get("sequence") != self.transaction["sequence"]
                or value.get("manifest_sha256") != self.transaction["manifest_sha256"]
                or value.get("coordinator_generation") != self.previous["generation"] or value.get("candidate_generation") != self.candidate["generation"]):
            raise Refused("Host runtime plan differs from the retained transaction")
        return value

    def evidence(self, action, checks):
        selected = host_activation.selection()
        identity = self.candidate if selected["generation"] == self.candidate["generation"] else self.previous
        return {"schema": 1, "abi": 1, "generation": identity["generation"], "host_source_sha256": identity["host_source_sha256"],
                "coordinator_generation": self.previous["generation"], "candidate_generation": self.candidate["generation"],
                "plan_sha256": hashlib.sha256(checked_file(self.plan_path)[0]).hexdigest(),
                "checks": {key: True for key in checks}}

    def _target_paths(self):
        paths = set(self.fixed_targets().values())
        paths.update(self.lifecycle.quadlets / ("nebulalog-" + name + ".container") for name in IMAGE_KEYS)
        if self.lifecycle.config.get("edge_service"): paths.add(EDGE)
        return paths

    def checked_plan(self):
        value = self.plan()
        entries = value.get("files")
        expected = self._target_paths()
        if (not isinstance(entries, list) or len(entries) != len(expected)
                or {item.get("path") for item in entries if isinstance(item, dict)} != {str(path) for path in expected}):
            raise Refused("Host runtime plan contains an unexpected destination")
        for entry in entries:
            if set(entry) != {"path", "before", "after"}:
                raise Refused("Host runtime file plan is malformed")
            for phase in ("before", "after"):
                item = entry[phase]
                if (not isinstance(item, dict) or set(item) != {"kind", "uid", "gid", "mode", "bytes", "sha256"}
                        or item["kind"] != "file" or type(item["uid"]) is not int or item["uid"] != OWNER_UID
                        or type(item["gid"]) is not int or item["gid"] != OWNER_GID or type(item["mode"]) is not int or item["mode"] != 0o644
                        or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= host_payload.MAX_FILE
                        or not isinstance(item["sha256"], str) or not host_payload.SHA256.fullmatch(item["sha256"])):
                    raise Refused("Host runtime file metadata is outside its fixed contract")
        return value

    def _write_retained(self, path, raw):
        from .lifecycle import atomic_file
        host_payload._trusted_tree(path.parent)
        if path.exists() or path.is_symlink():
            actual, info = checked_file(path)
            if actual != raw or info["mode"] != 0o600:
                raise Refused("Retained host backup/preparation differs")
        else:
            atomic_file(path, raw, 0o600, (OWNER_UID, OWNER_GID))

    def _preserved(self, plan):
        if self.preserved() != plan["preserved"]:
            raise Refused("Customer configuration or enrolled trust changed during host maintenance")

    def backup(self, *, preactivation_recovery=False):
        if preactivation_recovery and self.transaction.get("activation_started") is not False:
            raise Refused("Host backup recovery requires a preactivation transaction")
        self.phase("update-rollback" if preactivation_recovery else "update-backup")
        plan = self.checked_plan()
        self._preserved(plan)
        for directory in (self.root, self.root / "old", self.root / "new"):
            directory.mkdir(mode=0o700, exist_ok=True)
            host_payload._trusted_tree(directory)
        for index, item in enumerate(plan["files"]):
            raw, observed = checked_file(Path(item["path"]))
            if observed != item["before"]:
                raise Refused("Host runtime changed before its protected backup")
            self._write_retained(self.root / "old" / str(index), raw)
        value = {"schema": 1, "plan_sha256": hashlib.sha256(checked_file(self.plan_path)[0]).hexdigest(), "files": len(plan["files"])}
        path = self.root / "backup.json"
        if path.exists() and host_dispatch.protected_json(path) != value:
            raise Refused("Host backup receipt changed")
        atomic_json(path, value)
        self.verify_backup()
        return self.evidence("update-backup", {"backup_verified", "customer_state_preserved", "trust_preserved"})

    def verify_backup(self):
        plan = self.checked_plan()
        receipt = host_dispatch.protected_json(self.root / "backup.json")
        expected = {"schema": 1, "plan_sha256": hashlib.sha256(checked_file(self.plan_path)[0]).hexdigest(), "files": len(plan["files"])}
        if receipt != expected:
            raise Refused("Host backup is not bound to the immutable runtime plan")
        for index, item in enumerate(plan["files"]):
            raw, info = checked_file(self.root / "old" / str(index))
            if info["mode"] != 0o600 or description(raw) != item["before"]:
                raise Refused("Retained host backup content changed")
        return plan

    def prepare(self, quadlets):
        self.phase("update-prepare")
        from .lifecycle import atomic_file
        plan = self.verify_backup()
        self._preserved(plan)
        resources = {str(path): (old, new) for path, old, new in self._resources()}
        for index, item in enumerate(plan["files"]):
            old, new = resources[item["path"]]
            if description(old) != item["before"] or description(new) != item["after"]:
                raise Refused("Prepared host bytes differ from their fixed preflight plan")
            self._write_retained(self.root / "new" / str(index), new)
            path = Path(item["path"])
            if path.parent == self.lifecycle.quadlets:
                atomic_file(quadlets / path.name, new, 0o644, (OWNER_UID, OWNER_GID))
        return self.evidence("update-prepare", {"prepared_files", "backup_verified", "customer_state_preserved", "trust_preserved"})

    def apply(self, *, rollback=False):
        self.phase("update-rollback" if rollback else "update-activate")
        from .lifecycle import atomic_file
        plan = self.verify_backup()
        self._preserved(plan)
        if not rollback:
            host_dispatch.generation_info(self.candidate["generation"])
        phase, retained = ("before", "old") if rollback else ("after", "new")
        for index, item in enumerate(plan["files"]):
            path = Path(item["path"])
            raw, info = checked_file(self.root / retained / str(index))
            if info["mode"] != 0o600 or description(raw) != item[phase] or raw != self.expected_resource(path, index, rollback=rollback):
                raise Refused("Retained host activation bytes changed")
            actual, observed = checked_file(path)
            if observed not in (item["before"], item["after"]):
                raise Refused("Host reconciliation refuses unrelated runtime file changes: " + str(path))
            if observed != item[phase]:
                atomic_file(path, raw, item[phase]["mode"], (OWNER_UID, OWNER_GID))
                self.lifecycle.cmd(["restorecon", str(path)])
            if checked_file(path)[1] != item[phase]:
                raise Refused("Host runtime file did not retain the selected bytes and mode")
        if self.lifecycle.config.get("edge_service"):
            self.lifecycle.cmd(["httpd", "-t"])
        self._preserved(plan)

    def runtime_evidence(self, action, *, accept_integrity=False):
        self.phase(action)
        plan = self.verify_backup()
        self._preserved(plan)
        selected = host_activation.selection()
        rollback = selected["generation"] == self.previous["generation"]
        phase = "before" if rollback else "after"
        for item in plan["files"]:
            if checked_file(Path(item["path"]))[1] != item[phase]:
                raise Refused("Live host runtime files differ from the selected generation")
        self.probe(imports=True)
        for name in self.lifecycle.services:
            if self.lifecycle.cmd(["systemctl", "show", "--property=ActiveState", "--value", "nebulalog-" + name + ".service"]) != "active":
                raise Refused("Selected runtime services have not reached active state")
        if accept_integrity:
            self.integrity("accept", "rollback" if rollback else "forward")
        checks = {"runtime_files", "runtime_processes", "services", "customer_state_preserved", "trust_preserved"}
        return self.evidence(action, checks)

    def expected_resource(self, path, index, *, rollback):
        """Derive bytes from catalog source, never from plan-selected contents."""
        root = self.old_root if rollback else self.new_root
        reverse = {target: name for name, target in self.fixed_targets().items()}
        if path in reverse:
            return self.source(root, reverse[path])
        if path == EDGE and self.lifecycle.config.get("edge_service"):
            return self._render_edge(root)
        if path.parent == self.lifecycle.quadlets:
            from .lifecycle import image_from_quadlet
            service = path.name.removeprefix("nebulalog-").removesuffix(".container")
            old = checked_file(self.root / "old" / str(index))[0]
            image = image_from_quadlet(old.decode("utf-8"))
            if not rollback:
                image = self.release["components"].get(COMPONENT_FOR_SERVICE[service], {}).get("image", image)
            return self._render_quadlet(root, service, image)
        raise Refused("Host resource is outside the fixed reconciliation map")
