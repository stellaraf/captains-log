"""Plan and verify build-history cleanup on an offline, sealed system-disk copy.

The caller supplies an isolated libguestfs handle, explicit filesystem mounts,
and trusted installed-payload hashes. No guest executable is invoked. This is
pathname cleanup only; copy-mode free-space zeroing and a final read-only audit
remain mandatory before packaging.
"""
from __future__ import annotations

import base64
import re
import stat
from pathlib import PurePosixPath

MAX_FILES = 4096
MAX_HISTORY_BYTES = 256 * 1024**2
LOG_README = "/var/log/README"
LOG_README_TARGET = "../../usr/share/doc/systemd/README.logs"
ACCOUNT_BACKUPS = tuple("/etc/" + name + "-" for name in ("passwd", "shadow", "group", "gshadow", "subuid", "subgid"))
KICKSTARTS = ("/root/anaconda-ks.cfg", "/root/original-ks.cfg", "/root/.bash_history")
KERNEL_IMAGE = re.compile(r"initramfs-[0-9][A-Za-z0-9_.+-]{1,160}kdump\.img\Z")


def _path(path):
    p = PurePosixPath(path)
    if not p.is_absolute() or str(p) != path or ".." in p.parts:
        raise ValueError("Noncanonical cleanup path")
    return p


def _parents(g, path):
    p = _path(path)
    for parent in reversed(p.parents):
        info = g.lstatns(str(parent))
        if not stat.S_ISDIR(info["st_mode"]) or info["st_uid"] != 0:
            raise ValueError("Cleanup path has an untrusted directory")
        # /tmp is the one expected sticky build directory; its children are
        # checked without following links, after the disposable user is gone.
        if info["st_mode"] & 0o022 and not (str(parent) == "/tmp" and info["st_mode"] & stat.S_ISVTX):
            raise ValueError("Cleanup directory is writable by another account")


def _regular(g, path):
    _parents(g, path)
    info = g.lstatns(path)
    if not stat.S_ISREG(info["st_mode"]) or info["st_uid"] != 0 or info["st_nlink"] != 1:
        raise ValueError("Cleanup target must be one root-owned regular file")
    if info["st_mode"] & 0o022 and not (path.startswith("/var/log/") and not info["st_mode"] & 0o002):
        raise ValueError("Cleanup target has unsafe writable permissions")
    return info


def _log_readme(g):
    _parents(g, LOG_README)
    info = g.lstatns(LOG_README)
    if not stat.S_ISLNK(info["st_mode"]) or info["st_uid"] != 0 or info["st_gid"] != 0 or info["st_nlink"] != 1:
        raise ValueError("Unexpected log documentation link metadata")
    target = g.readlink(LOG_README)
    if target != LOG_README_TARGET:
        raise ValueError("Unexpected log documentation link target")
    return {"target": target, "uid": 0, "gid": 0}


def _xattrs(g, path):
    return sorted([{"name": row["attrname"], "value_b64": base64.b64encode(
        row["attrval"] if isinstance(row["attrval"], bytes) else row["attrval"].encode()).decode()}
        for row in g.lgetxattrs(path)], key=lambda row: row["name"])


def record(g, path):
    info = _regular(g, path)
    return {"path": path, "bytes": info["st_size"], "sha256": g.checksum("sha256", path),
            "mode": stat.S_IMODE(info["st_mode"]), "uid": info["st_uid"],
            "gid": info["st_gid"], "xattrs": _xattrs(g, path)}


def _exists(g, path):
    return g.exists(path) or g.is_symlink(path)


def _text(g, path, maximum=1024**2):
    info = _regular(g, path)
    if info["st_size"] > maximum:
        raise ValueError("Build metadata exceeds the inspection bound")
    return g.read_file(path).decode("utf-8")


def _guard(g):
    if _text(g, "/etc/nebulalog/bootstrap/state", 64) != "unconfigured\n":
        raise ValueError("Cannot clean an initialized appliance")
    if _text(g, "/etc/nebulalog/bootstrap/image-state", 64) != "sealed\n":
        raise ValueError("Offline cleanup requires a completed seal")
    for path in ("/etc/nebulalog/bootstrap/unsealed-build", "/etc/nebulalog/bootstrap/private-build.json",
                 "/etc/nebulalog/bootstrap/firstboot.json", "/etc/nebulalog/storage.json", "/etc/nebulalog/configured",
                 "/home/packer", "/etc/sudoers.d/nebulalog-build"):
        if _exists(g, path):
            raise ValueError("Build or customer enrollment state remains")
    if g.ls("/var/lib/nebulalog"):
        raise ValueError("Cannot clean a disk containing appliance data")
    if "packer:" in _text(g, "/etc/passwd"):
        raise ValueError("Disposable account remains")
    roots = [line for line in _text(g, "/etc/shadow").splitlines() if line.startswith("root:")]
    if len(roots) != 1 or not roots[0].split(":")[1].startswith(("!", "*")):
        raise ValueError("Root account must remain locked")
    if _text(g, "/etc/machine-id", 64) or _text(g, "/etc/hostname", 256) != "captains-log\n":
        raise ValueError("Active build identity remains")
    if any(name.startswith("ssh_host_") for name in g.ls("/etc/ssh")):
        raise ValueError("Host SSH keys remain")


def _kdump_candidates(g):
    candidates = ["/boot/" + name for name in g.ls("/boot") if KERNEL_IMAGE.fullmatch(name)]
    if not candidates:
        return []
    enabled = [name for name in g.find("/etc/systemd/system")
               if PurePosixPath(name).name == "kdump.service" and (".wants/" in name or ".requires/" in name)]
    if enabled:
        raise ValueError("Kdump is enabled; refuse removing its boot image")
    references = []
    for name in g.ls("/boot/loader/entries"):
        if name.endswith(".conf"):
            references.append(_text(g, "/boot/loader/entries/" + name))
    for path in ("/boot/grub2/grub.cfg", "/boot/efi/EFI/rocky/grub.cfg"):
        if _exists(g, path):
            references.append(_text(g, path))
    if any(PurePosixPath(path).name in body for path in candidates for body in references):
        raise ValueError("A boot entry references the kdump image")
    return candidates


def create_plan(g, payload_hashes):
    """Capture all original metadata before any mutation; reject unsafe targets."""
    _guard(g)
    if not payload_hashes:
        raise ValueError("Trusted installed-payload hashes are required")
    controls = {}
    for path, expected in sorted(payload_hashes.items()):
        info = record(g, path)
        if info["sha256"] != expected:
            raise ValueError("Installed payload differs from the frozen input")
        controls[path] = info
    unlinks = [path for path in (*KICKSTARTS, *ACCOUNT_BACKUPS) if _exists(g, path)]
    unlinks += ["/tmp/" + name for name in g.ls("/tmp")
                if re.fullmatch(r"ks-script-[A-Za-z0-9_-]{1,80}", name)]
    unlinks += _kdump_candidates(g)
    logs = []
    preserved_links = {}
    for relative in g.find("/var/log"):
        path = "/var/log/" + relative.lstrip("/")
        _path(path)
        info = g.lstatns(path)
        if stat.S_ISREG(info["st_mode"]):
            logs.append(path)
        elif path == LOG_README and stat.S_ISLNK(info["st_mode"]):
            preserved_links[path] = _log_readme(g)
        elif not stat.S_ISDIR(info["st_mode"]):
            raise ValueError("Unexpected link or special file in sealed build logs")
    if len(unlinks) + len(logs) > MAX_FILES:
        raise ValueError("Too many build artifacts")
    actions = [{**record(g, path), "action": action}
               for action, paths in (("unlink", unlinks), ("truncate", logs)) for path in sorted(paths)]
    if sum(row["bytes"] for row in actions if not row["path"].startswith("/boot/")) > MAX_HISTORY_BYTES:
        raise ValueError("Build history exceeds the cleanup bound")
    for name in g.ls("/boot"):
        path = "/boot/" + name
        if name.startswith(("vmlinuz-", "initramfs-")) and path not in unlinks:
            controls[path] = record(g, path)
    if not any(path.startswith("/boot/initramfs-") for path in controls):
        raise ValueError("No retained normal boot image")
    return {"schema": 1, "actions": actions, "controls": controls, "preserved_symlinks": preserved_links,
            "free_space_zeroing_still_required": True}


def apply_plan(g, plan):
    """Apply only an unchanged approved plan to the caller's disposable copy."""
    _guard(g)
    # Validate the whole plan first so a later mismatch cannot authorize partial
    # cleanup. Source isolation and absence of concurrent guest writers are the
    # caller's responsibility.
    for row in plan["actions"]:
        current = record(g, row["path"])
        if current != {key: value for key, value in row.items() if key != "action"}:
            raise ValueError("Cleanup input changed after review")
        if row["action"] not in ("unlink", "truncate"):
            raise ValueError("Unsupported cleanup action")
    for path, expected in plan["controls"].items():
        if record(g, path) != expected:
            raise ValueError("Retained payload or boot file changed")
    allowed = create_plan(g, {path: row["sha256"] for path, row in plan["controls"].items()})
    if allowed["actions"] != plan["actions"] or allowed["preserved_symlinks"] != plan.get("preserved_symlinks", {}):
        raise ValueError("Cleanup action scope changed")
    for row in plan["actions"]:
        if row["action"] == "unlink":
            g.rm(row["path"])
        else:
            g.truncate(row["path"])
    g.sync()
    return verify_plan(g, plan)


def verify_plan(g, plan):
    """Verify retained modes, ownership, xattrs and control hashes after cleanup."""
    _guard(g)
    for path, expected in plan.get("preserved_symlinks", {}).items():
        if path != LOG_README or _log_readme(g) != expected:
            raise ValueError("Cleanup changed the log documentation link")
    after = []
    for row in plan["actions"]:
        path = row["path"]
        if row["action"] == "unlink":
            if _exists(g, path):
                raise ValueError("Build artifact was not removed")
            after.append({"path": path, "absent": True})
        else:
            current = record(g, path)
            if current["bytes"] != 0 or any(current[key] != row[key] for key in ("mode", "uid", "gid", "xattrs")):
                raise ValueError("Log cleanup failed to preserve metadata")
            after.append(current)
    for path, expected in plan["controls"].items():
        if record(g, path) != expected:
            raise ValueError("Cleanup changed a retained payload or boot file")
    return {"actions_verified": len(after), "controls_verified": len(plan["controls"]), "after": after}
