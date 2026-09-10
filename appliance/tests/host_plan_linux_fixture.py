"""Opt-in Linux socket integration fixture with synthetic storage evidence.

Run only in the isolated disposable container prepared by the integration test:
NEBULALOG_HOST_PLAN_FIXTURE=1 PYTHONPATH=/source/appliance python3 -u this_file.py
The container supplies writable /run and /tmp, no network, and read-only source.
No host storage inspection, LUKS proof, SELinux proof, or execution is performed.
The socket, SO_PEERCRED checks, private record permissions and flock are real.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile

from nebulalog_manager.common import Refused, require_linux_root
from nebulalog_manager.host_job_storage import PrivateRecords, StorageIdentity
from nebulalog_manager.host_plan_socket import PlanSocket, SOCKET_GROUP, SOCKET_PATH
from nebulalog_manager.host_plans import HostPlans, StorageObserver
from nebulalog_manager.storage import Identity, Snapshot, MIB

INSTALLATION_ID = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"
GIB = 1024**3
DISK = "/dev/disk/by-id/nebulalog-synthetic-fixture"
IDENTITY = Identity(DISK, "NEBULALOG-SYNTHETIC-FIXTURE", DISK + "-part1",
                    "fixture-part", "fixture-luks", "nebulalog-data", "fixture-pv", "fixture-vg", "fixture-lv")
SNAPSHOT = Snapshot(IDENTITY, 12*GIB, 8*GIB+18*MIB, MIB, 8*GIB+2*MIB,
                    8*GIB, 8*GIB, 8*GIB-64*MIB, 0, filesystem_geometry_bytes=8*GIB)


class StopFixture(BaseException):
    """Exit through cleanup even if a signal arrives during request handling."""


def stop_fixture(_number, _frame):
    raise StopFixture()


def require_opt_in():
    # Refuse before creating any directory, journal, or socket.
    if os.environ.get("NEBULALOG_HOST_PLAN_FIXTURE") != "1":
        raise Refused("explicit_fixture_opt_in_required")
    require_linux_root()


@contextlib.contextmanager
def control_directory():
    """Create a new protected directory; never adopt or repair existing state."""
    directory = SOCKET_PATH.parent
    for parent in directory.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("unsafe_fixture_socket_ancestry")
    parent_fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owned = None
    try:
        os.mkdir(directory.name, mode=0o750, dir_fd=parent_fd)
        info = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        owned = (info.st_dev, info.st_ino)
        os.chown(directory.name, 0, SOCKET_GROUP, dir_fd=parent_fd, follow_symlinks=False)
        os.chmod(directory.name, 0o750, dir_fd=parent_fd)
        yield
    finally:
        # rmdir refuses nonempty state. Only the exact directory we created may
        # be removed; PlanSocket independently removes only its own socket inode.
        try:
            if owned is not None:
                try:
                    info = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and (info.st_dev, info.st_ino) == owned:
                        os.rmdir(directory.name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(parent_fd)


def fixture_service(root):
    info = root.lstat()
    enrolled = (info.st_dev, info.st_ino)

    def guard():
        current = root.lstat()
        if (not root.is_absolute() or root.parent != Path("/tmp")
                or not root.name.startswith("nebulalog-host-plan-fixture-")
                or not stat.S_ISDIR(current.st_mode) or current.st_uid != 0
                or stat.S_IMODE(current.st_mode) != 0o700 or (current.st_dev, current.st_ino) != enrolled):
            raise Refused("invalid_fixture_storage")
        return StorageIdentity(INSTALLATION_ID, root, current.st_dev)

    def inspect(identity, *, runner):
        # Do not invoke the supplied runner. All geometry is synthetic.
        if identity != IDENTITY:
            raise Refused("unexpected_fixture_identity")
        return SNAPSHOT

    observer = StorageObserver(INSTALLATION_ID, identity_reader=lambda: IDENTITY, inspector=inspect)
    service = HostPlans(INSTALLATION_ID, records=PrivateRecords(guard), observer=observer)
    service.initialize()  # The fixture explicitly enrolls its empty private journal.
    return service


def main():
    previous = {}
    server = None
    try:
        require_opt_in()
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop_fixture)
        with tempfile.TemporaryDirectory(prefix="nebulalog-host-plan-fixture-", dir="/tmp") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            with control_directory():
                try:
                    server = PlanSocket(fixture_service(root)).bind()
                    print("READY", flush=True)
                    server.serve()
                finally:
                    if server is not None:
                        server.close()
    except StopFixture:
        return 0
    except Exception:
        print("Linux host plan fixture unavailable; explicit opt-in and isolated root environment required.", file=sys.stderr, flush=True)
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
