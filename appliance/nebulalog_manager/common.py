"""Narrow command runner and durable records shared by host workflows."""
from __future__ import annotations
import contextlib
import fcntl
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import tempfile
from datetime import datetime, timezone

class Refused(RuntimeError):
    """A safety precondition was not met. No automatic weakening is allowed."""


class CommandFailed(Refused):
    def __init__(self, program: str, returncode: int):
        self.returncode = returncode
        super().__init__(f"{program} failed with exit status {returncode}")


def run(argv: list[str], *, input: bytes | None = None, timeout: int = 120) -> str:
    proc = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={**os.environ, "LC_ALL": "C"}, check=False)
    if proc.returncode:
        # Do not copy stderr: tool output may include credentials or payload data.
        raise CommandFailed(Path(argv[0]).name, proc.returncode)
    return proc.stdout.decode("utf-8", "strict").strip()


def require_linux_root() -> None:
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise Refused("This operation requires root inside the Rocky appliance")


def trusted_file(path: Path) -> Path:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Refused(f"Expected a root-owned regular file without group/world write: {path}")
    return path


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump(value, out, sort_keys=True, indent=2, allow_nan=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        parentfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parentfd)
        finally:
            os.close(parentfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def audit(path: Path, action: str, **details: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a") as out:
        fcntl.flock(out, fcntl.LOCK_EX)
        out.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(),
                              "action": action, **details}, sort_keys=True) + "\n")
        out.flush()
        os.fsync(out.fileno())


@contextlib.contextmanager
def locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    except BlockingIOError as exc:
        raise Refused("Another appliance transaction is already running") from exc
    finally:
        os.close(fd)
