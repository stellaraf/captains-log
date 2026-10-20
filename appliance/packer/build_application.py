#!/usr/bin/env python3
"""Build the appliance application from its exact captured source, never cwd."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_provenance import application_hash, source_snapshot

CONTAINERFILE = "appliance/images/application/Containerfile"
REQUIRED = {CONTAINERFILE, "go.mod", "go.sum", "LICENSE", "cmd/nebulalog/main.go", "web/package.json", "web/package-lock.json"}
MAX_FILE = 128 * 1024**2
MAX_CONTEXT = 512 * 1024**2
MAX_FILES = 20000
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,100})?")
TAG = re.compile(r"nebulalog/[a-z0-9]+(?:[._-][a-z0-9]+)*:[a-z0-9][a-z0-9._-]{0,100}")
BUILDKIT_IMAGE = re.compile(r"moby/buildkit@sha256:[a-f0-9]{64}")
MINIMUM_FREE = 150 * 1024**3


def storage_admission(path, storage_root):
    root = storage_root.resolve()
    ancestor = path.resolve()
    while not ancestor.exists():
        ancestor = ancestor.parent
    if (not os.path.ismount(root) or not path.resolve().is_relative_to(root)
            or ancestor.stat().st_dev != root.stat().st_dev):
        raise ValueError("Application build storage must be on the selected mounted volume")
    if shutil.disk_usage(ancestor).free < MINIMUM_FREE:
        raise ValueError("Application builds require at least 150 GiB free on the selected volume")


def bounded_run(argv, *, timeout, check=True, reserve_path=None, **kwargs):
    """Reap the CLI process group; the owner separately settles daemon work."""
    # No Popen context manager: its implicit __exit__.wait() has no deadline.
    process = subprocess.Popen(argv, start_new_session=True, **kwargs)
    deadline = time.monotonic() + timeout
    try:
        while True:
            if reserve_path is not None:
                storage_admission(*reserve_path)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            try:
                stdout, stderr = process.communicate(timeout=min(5, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException as primary:
        try:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=10)
            if process.returncode is None:
                raise RuntimeError("CLI exit was not confirmed")
        except BaseException as settlement:
            primary.command_unsettled = True
            primary.command_pid = process.pid
            print("CLI settlement unconfirmed (" + type(settlement).__name__ + "); owned resources retained", file=sys.stderr)
        raise
    result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


class OwnedBuilder:
    """One private buildx configuration and one exactly identified cache volume."""

    def __init__(self, parent, docker_context, buildkit_image, runner):
        self.runner, self.image, self.parent = runner, buildkit_image, parent
        self.run_id = uuid.uuid4().hex
        self.name = "nebulalog-application-" + self.run_id
        self.node = self.name + "0"
        self.container = "buildx_buildkit_" + self.node
        self.volume = self.container + "_state"
        self.evidence = Path(tempfile.mkdtemp(prefix="application-build-evidence-", dir=parent))
        self.config = self.evidence / "buildx"
        self.config.mkdir(mode=0o700)
        scratch = self.config / "tmp"
        scratch.mkdir(mode=0o700)
        self.env = dict(os.environ, BUILDX_CONFIG=str(self.config), TMPDIR=str(scratch))
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "BUILDX_BUILDER", "BUILDKIT_HOST"):
            self.env.pop(key, None)
        self.prefix, self.ownership, self.attempted = None, None, False
    def prepare(self, docker_context):
        result = self.runner(["docker", "context", "inspect", docker_context], env=self.env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
        contexts = self.decode(result)
        endpoint = contexts[0]["Endpoints"]["docker"]["Host"] if len(contexts) == 1 else ""
        if not isinstance(endpoint, str) or not endpoint.startswith("unix:///") or len(endpoint) > 1024:
            raise ValueError("Use an explicit local Unix-socket Docker context")
        self.prefix = ["docker", "--host", endpoint]
        image = self.one("image", "inspect", self.image)
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image.get("Id", "")) or image.get("Os") != "linux":
            raise ValueError("BuildKit must already be cached as an immutable Linux image")
        self.image_id = image["Id"]
        write_receipt(self.evidence / "intent.json", {"schema": 1, "run_id": self.run_id,
            "builder": self.name, "node": self.node, "container": self.container, "volume": self.volume,
            "endpoint": endpoint, "buildkit_image": self.image, "buildkit_image_id": self.image_id})

    @staticmethod
    def decode(result):
        if not isinstance(result.stdout, bytes) or len(result.stdout) > 1024**2:
            raise ValueError("Oversized Docker metadata")
        return json.loads(result.stdout)

    def call(self, *args, **kwargs):
        return self.runner(self.prefix + list(args), env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, check=True, timeout=kwargs.pop("timeout", 30), **kwargs)

    def one(self, *args):
        value = self.decode(self.call(*args))
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise ValueError("Docker returned ambiguous resource identity")
        return value[0]

    def present(self, kind, name):
        args = [kind, "ls"] + (["--all", "--no-trunc"] if kind == "container" else [])
        result = self.call(*args, "--filter", "name=^" + ("/" if kind == "container" else "") + name + "$",
                           "--format", "{{.Names}}" if kind == "container" else "{{.Name}}")
        if len(result.stdout) > 1024:
            raise ValueError("Ambiguous owned-resource inventory")
        names = result.stdout.decode().splitlines()
        if names not in ([], [name]):
            raise ValueError("Unexpected owned-resource inventory")
        return bool(names)

    def volume_identity(self):
        volume = self.one("volume", "inspect", self.volume)
        if (volume.get("Name") != self.volume or volume.get("Driver") != "local"
                or volume.get("Scope") != "local" or volume.get("Options") not in (None, {})
                or volume.get("Labels", {}).get("io.nebulalog.application-build") != self.run_id
                or not isinstance(volume.get("CreatedAt"), str) or not volume["CreatedAt"]
                or not isinstance(volume.get("Mountpoint"), str) or not volume["Mountpoint"].startswith("/")):
            raise ValueError("Build cache volume ownership differs")
        return {key: volume[key] for key in ("Name", "Driver", "Scope", "CreatedAt", "Mountpoint", "Labels")}

    def container_identity(self):
        container = self.one("container", "inspect", self.container)
        mounts = container.get("Mounts", [])
        config = container.get("Config", {})
        if (not re.fullmatch(r"[a-f0-9]{64}", container.get("Id", ""))
                or container.get("Name") != "/" + self.container or container.get("Image") != self.image_id
                or config.get("Image") != self.image
                or "NEBULALOG_APPLICATION_BUILD=" + self.run_id not in config.get("Env", [])
                or len(mounts) != 1 or mounts[0].get("Type") != "volume" or mounts[0].get("Name") != self.volume
                or mounts[0].get("Destination") != "/var/lib/buildkit" or mounts[0].get("RW") is not True):
            raise ValueError("BuildKit container ownership or mounts differ")
        return container

    def start(self):
        if self.present("container", self.container) or self.present("volume", self.volume):
            raise ValueError("Unique builder resources already exist")
        self.attempted = True
        self.call("volume", "create", "--label", "io.nebulalog.application-build=" + self.run_id, self.volume)
        self.ownership = {"volume": self.volume_identity()}
        write_receipt(self.evidence / "volume.json", self.ownership)
        self.call("buildx", "create", "--name", self.name, "--node", self.node,
                  "--driver", "docker-container", "--driver-opt", "image=" + self.image,
                  "--driver-opt", "env.NEBULALOG_APPLICATION_BUILD=" + self.run_id,
                  "--driver-opt", "restart-policy=no", "--driver-opt", "memory=8g",
                  "--driver-opt", "cpu-period=100000", "--driver-opt", "cpu-quota=400000", self.prefix[2])
        self.call("buildx", "inspect", "--bootstrap", self.name, timeout=120)
        container = self.container_identity()
        self.ownership["container_id"] = container["Id"]
        write_receipt(self.evidence / "ownership.json", self.ownership)

    def cleanup(self):
        """Never ask buildx to remove names obtained from mutable builder config."""
        if self.attempted:
            if self.present("container", self.container):
                container = self.container_identity()
                if self.ownership and self.ownership.get("container_id", container["Id"]) != container["Id"]:
                    raise ValueError("BuildKit container was replaced")
                if self.volume_identity() != (self.ownership or {}).get("volume"):
                    raise ValueError("Build cache volume was replaced")
                self.call("container", "stop", "--time", "15", container["Id"], timeout=30)
                stopped = self.container_identity()
                state = stopped.get("State", {})
                if (stopped["Id"] != container["Id"] or state.get("Running") is not False
                        or state.get("Pid") != 0 or state.get("Status") != "exited"):
                    raise ValueError("BuildKit did not settle before cleanup")
                self.call("container", "rm", container["Id"])
            if self.present("container", self.container):
                raise ValueError("BuildKit container removal was not confirmed")
            if self.present("volume", self.volume):
                volume = self.volume_identity()
                if self.ownership is None or volume != self.ownership["volume"]:
                    raise ValueError("Build cache identity was not durably captured")
                references = self.call("container", "ls", "--all", "--filter", "volume=" + self.volume, "--format", "{{.ID}}")
                if references.stdout.strip():
                    raise ValueError("Build cache still has container references")
                self.call("volume", "rm", self.volume)
            if self.present("volume", self.volume):
                raise ValueError("Build cache removal was not confirmed")
        # This invocation exclusively created this directory. Evidence lives beside it.
        shutil.rmtree(self.config)

    def finish(self, primary):
        cleanup_error = None
        try:
            if getattr(primary, "command_unsettled", False):
                raise ValueError("CLI settlement is unconfirmed; cleanup is held")
            self.cleanup()
        except BaseException as error:
            cleanup_error = error
        try:
            write_receipt(self.evidence / "outcome.json", {"schema": 1, "run_id": self.run_id,
                "build_error": type(primary).__name__ if primary else None,
                "cleanup": "incomplete" if cleanup_error else "complete",
                "cleanup_error": type(cleanup_error).__name__ if cleanup_error else None,
                "unsettled_command_pid": getattr(primary, "command_pid", None) or getattr(cleanup_error, "command_pid", None),
                "output_images_removed": False})
        except BaseException:
            print("Cleanup outcome could not be recorded; inspect " + str(self.evidence), file=sys.stderr)
            if primary is None:
                raise
        if cleanup_error:
            print("Owned builder cleanup incomplete; inspect " + str(self.evidence), file=sys.stderr)
            if primary is None:
                raise cleanup_error


def selected_files(manifest):
    files = manifest["files"]
    selected = {path: sha for path, sha in files.items()
                if path.startswith(("cmd/", "internal/", "web/", "migrations/"))
                or path in ("go.mod", "go.sum", "LICENSE", CONTAINERFILE)}
    if (not REQUIRED <= set(selected) or not any(path.startswith("internal/") for path in selected)
            or not any(path.startswith("migrations/") for path in selected) or not 1 <= len(selected) <= MAX_FILES):
        raise ValueError("Captured application source is incomplete or exceeds the file limit")
    for path, sha in selected.items():
        parts = path.split("/")
        if (not re.fullmatch(r"[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@.-]+)*", path)
                or any(part in (".", "..", ".git", ".local", "node_modules", "dist", "test-results", "playwright-report") for part in parts)
                or any(part.startswith(".env") for part in parts)
                or any(part in (".npmrc", ".netrc", ".pypirc", ".git-credentials", ".ssh", ".aws") for part in parts)
                or Path(path).suffix.lower() in (".pem", ".key", ".p12", ".pfx", ".jks")
                or not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha)):
            raise ValueError("Captured application source contains an unsafe, generated or credential file")
    if application_hash({"files": selected}) != application_hash(manifest):
        raise ValueError("Application context selection no longer matches the provenance contract")
    return selected


def open_source(root, name):
    """Use directory descriptors so a symlink replacement cannot escape root."""
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_FILE:
        os.close(descriptor)
        raise ValueError("Captured source must remain a bounded regular file")
    return os.fdopen(descriptor, "rb"), info


class HashingReader:
    def __init__(self, source):
        self.source, self.digest, self.bytes = source, hashlib.sha256(), 0

    def read(self, size):
        value = self.source.read(size)
        self.digest.update(value)
        self.bytes += len(value)
        return value


def write_context(root: Path, selected: dict, destination: Path):
    """Finish the full, byte-verified context before Docker sees any input."""
    selected = selected_files({"files": selected})
    total = 0
    with destination.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, expected in sorted(selected.items()):
                source, before = open_source(root, name)
                with source:
                    total += before.st_size
                    if total > MAX_CONTEXT:
                        raise ValueError("Application context exceeds its byte limit")
                    item = tarfile.TarInfo(name)
                    item.size, item.mode = before.st_size, 0o644
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ""
                    reader = HashingReader(source)
                    archive.addfile(item, reader)
                    after = os.fstat(source.fileno())
                    if (reader.bytes != before.st_size or reader.digest.hexdigest() != expected or source.read(1)
                            or any(getattr(before, key) != getattr(after, key) for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
                        raise ValueError("Application source changed after capture or while creating context")
                    if output.tell() > MAX_CONTEXT:
                        raise ValueError("Application tar context exceeds its byte limit")
        if output.tell() > MAX_CONTEXT:
            raise ValueError("Application tar context exceeds its byte limit")
        output.flush()
        os.fsync(output.fileno())
    digest = hashlib.sha256()
    with destination.open("rb") as source:
        for chunk in iter(lambda: source.read(1024**2), b""):
            digest.update(chunk)
    return {"context_sha256": digest.hexdigest(), "context_bytes": destination.stat().st_size,
            "source_bytes": total, "source_files": len(selected)}


def write_receipt(path, receipt):
    """Publish once; a failed build never overwrites previous evidence."""
    raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    fd, name = tempfile.mkstemp(prefix=".application-build-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(name, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.unlink(name)


def build(source: Path, tag: str, receipt: Path, *, version="0.2.0-appliance-candidate",
          docker_context=None, buildkit_image=None, storage_root=None, runner=bounded_run):
    if not isinstance(tag, str) or len(tag) > 200 or not TAG.fullmatch(tag):
        raise ValueError("Use an explicit local nebulalog/name:tag; registry addresses and options are refused")
    if not isinstance(version, str) or len(version) > 128 or not VERSION.fullmatch(version):
        raise ValueError("Application version must be a bounded semantic version without shell characters")
    if not isinstance(docker_context, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", docker_context):
        raise ValueError("An explicit local Docker context is required")
    if not isinstance(buildkit_image, str) or not BUILDKIT_IMAGE.fullmatch(buildkit_image):
        raise ValueError("An explicit cached immutable moby/buildkit image is required")
    if not isinstance(storage_root, Path):
        raise ValueError("An explicit mounted build storage root is required")
    source, receipt = source.resolve(), receipt.absolute()
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("Build receipt must be a new file")
    storage_admission(receipt.parent, storage_root)
    receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest, commit, dirty = source_snapshot(source)
    selected = selected_files(manifest)
    source_sha = application_hash(manifest)
    # Docker receives a completed private tar as stdin, not the source directory.
    # No .dockerignore, live workspace files, SSH keys or secret flags are added.
    # Capture completes before any builder creation. The sidecar survives all outcomes.
    owner, primary = None, None
    try:
        with tempfile.TemporaryDirectory(prefix="nebulalog-application-build-", dir=receipt.parent) as temporary:
            stage = Path(temporary)
            context, iid = stage / "context.tar", stage / "image.id"
            evidence = write_context(source, selected, context)
            storage_admission(receipt.parent, storage_root)
            owner = OwnedBuilder(receipt.parent, docker_context, buildkit_image, runner)
            owner.prepare(docker_context)
            owner.start()
            command = owner.prefix + ["buildx", "build", "--builder", owner.name, "--load", "--platform=linux/amd64", "--progress=plain", "--tag", tag,
                       "--file", CONTAINERFILE, "--iidfile", str(iid), "--build-arg", "APPLICATION_SOURCE_SHA256=" + source_sha,
                       "--build-arg", "VERSION=" + version, "-"]
            with context.open("rb") as stream:
                runner(command, stdin=stream, stdout=sys.stderr, stderr=sys.stderr, check=True, timeout=3600,
                       env=owner.env, reserve_path=(receipt.parent, storage_root))
            if iid.is_symlink() or not iid.is_file() or iid.stat().st_size > 128:
                raise ValueError("Docker did not produce a bounded regular immutable image ID")
            image_id = iid.read_text().strip()
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
                raise ValueError("Docker did not produce a valid immutable image ID")
            result = owner.call("image", "inspect", image_id)
            if len(result.stdout) > 1024**2:
                raise ValueError("Oversized built image metadata")
            images = json.loads(result.stdout)
            if (not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict)
                    or images[0].get("Id") != image_id or images[0].get("Architecture") != "amd64" or images[0].get("Os") != "linux"
                    or not isinstance(images[0].get("Config"), dict) or not isinstance(images[0]["Config"].get("Labels"), dict)
                    or images[0].get("Config", {}).get("Labels", {}).get("io.nebulalog.application-source-sha256") != source_sha):
                raise ValueError("Built image identity, platform or source label differs from the captured context")
            result = {"schema": 1, "status": "built", "tag": tag, "local_image_id": image_id, "platform": "linux/amd64",
                      "requested_version": version, "application_source_sha256": source_sha, "source_commit": commit,
                      "source_dirty": dirty, "application_files": selected, **evidence,
                      "context_mode": "captured_source_tar_stdin", "runtime_executed": False, "signature_created": False}
    except BaseException as error:
        primary = error
        raise
    finally:
        if owner is not None:
            owner.finish(primary)
    result["cleanup_evidence"] = str(owner.evidence / "outcome.json")
    result["builder_cache_removed"] = True
    write_receipt(receipt, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--version", default="0.2.0-appliance-candidate")
    parser.add_argument("--storage-root", required=True, type=Path)
    parser.add_argument("--docker-context", required=True)
    parser.add_argument("--buildkit-image", required=True)
    args = parser.parse_args(argv)
    previous = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    try:
        print(json.dumps(build(args.source, args.tag, args.receipt, version=args.version,
                               docker_context=args.docker_context, buildkit_image=args.buildkit_image, storage_root=args.storage_root), sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError):
        print(json.dumps({"status": "refused", "error": "Application build or captured-source verification failed; no successful receipt was published"}), file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
