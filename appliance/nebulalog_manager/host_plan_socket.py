"""Opt-in root AF_UNIX read-only planning service. No boot/install integration.

One connection: uint32be request length, strict UTF-8 JSON, client write EOF;
then uint32be response length, JSON, server EOF. Serial dispatch, backlog eight.
Linux SO_PEERCRED authorizes the API process, not the peer-asserted human actor.
"""
from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path
import platform
import signal
import socket
import stat
import struct
import threading
import time

from .common import Refused, require_linux_root
from .host_job_storage import canonical, strict_json
from .host_plans import create_service, unavailable

SOCKET_PATH = Path("/run/nebulalog-control/plans.sock")
SOCKET_GROUP = 20002
ROOT_UID = 0
PEER_UID = 10001
PEER_GID = 10001
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 64 * 1024
REQUEST_SECONDS = 10.0
BACKLOG = 8


class DeadlineExceeded(BaseException):
    """Not swallowed by lower-level best-effort Exception handlers."""


@contextlib.contextmanager
def bounded_request(seconds):
    if threading.current_thread() is not threading.main_thread():
        raise Refused("host_unavailable")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise Refused("host_unavailable")
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_number, _frame):
        raise DeadlineExceeded()
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(seconds, 0.001))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def peer_credentials(connection):
    if platform.system() != "Linux" or not hasattr(socket, "SO_PEERCRED"):
        raise Refused("peer_not_authorized")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    if len(raw) != struct.calcsize("3i"):
        raise Refused("peer_not_authorized")
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid != PEER_UID or gid != PEER_GID:
        raise Refused("peer_not_authorized")
    return pid, uid, gid


def receive(connection, count, deadline, monotonic):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise DeadlineExceeded()
        connection.settimeout(remaining)
        part = connection.recv(count - len(result))
        if not part:
            raise Refused("invalid_request")
        result.extend(part)
    return bytes(result)


def handle_connection(connection, service, *, credentials=peer_credentials, monotonic=time.monotonic):
    deadline = monotonic() + REQUEST_SECONDS
    response = unavailable("host_unavailable")
    try:
        with bounded_request(REQUEST_SECONDS):
            peer = credentials(connection)
            # Test/integration injection still must return the exact API peer.
            if type(peer) is not tuple or len(peer) != 3 or any(type(v) is not int for v in peer) or peer[0] <= 0 or peer[1:] != (PEER_UID, PEER_GID):
                raise Refused("peer_not_authorized")
            size = struct.unpack("!I", receive(connection, 4, deadline, monotonic))[0]
            if not 1 <= size <= MAX_REQUEST:
                raise Refused("invalid_request")
            body = receive(connection, size, deadline, monotonic)
            connection.settimeout(max(0.001, deadline - monotonic()))
            if connection.recv(1) != b"":
                raise Refused("invalid_request")
            try:
                value = strict_json(body.decode("utf-8", "strict"))
            except (Refused, UnicodeError, ValueError):
                raise Refused("invalid_request") from None
            response = service.handle(value, deadline=deadline)
            if monotonic() >= deadline:
                raise DeadlineExceeded()
    except (DeadlineExceeded, TimeoutError, socket.timeout):
        response = unavailable("request_timeout")
    except Refused as exc:
        response = unavailable(str(exc))
    except Exception:
        response = unavailable("host_unavailable")
    # Do not prolong the 10-second connection lifetime to report a timeout.
    # A client that reaches its deadline closes instead of trusting late data.
    try:
        raw = canonical(response)
        if len(raw) > MAX_RESPONSE:
            raw = canonical(unavailable("host_unavailable"))
        remaining = deadline - monotonic()
        if remaining > 0:
            connection.settimeout(remaining)
            connection.sendall(struct.pack("!I", len(raw)) + raw)
    except (OSError, ValueError, TypeError):
        pass
    finally:
        # Linux resets AF_UNIX streams closed with unread request bytes. Drain
        # only already queued bytes, without parsing/dispatching them or waiting
        # for a hostile peer. This lets bounded malformed/unauthorized callers
        # receive the framed refusal while retaining the original time limit.
        try:
            connection.setblocking(False)
            remaining_bytes = MAX_REQUEST + 4
            while remaining_bytes and monotonic() < deadline:
                discarded = connection.recv(min(4096, remaining_bytes))
                if not discarded:
                    break
                remaining_bytes -= len(discarded)
        except OSError:
            pass
        finally:
            connection.close()


def verify_directory(path):
    if not path.is_absolute() or path != Path(os.path.normpath(path)) or len(os.fsencode(path)) > 100:
        raise Refused("host_unavailable")
    directory = path.parent
    for parent in (directory, *directory.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise Refused("host_unavailable")
        if parent == directory and (stat.S_IMODE(info.st_mode) != 0o750 or info.st_gid != SOCKET_GROUP):
            raise Refused("host_unavailable")
    return directory.stat()


class PlanSocket:
    def __init__(self, service, *, path=SOCKET_PATH):
        self.service, self.path = service, Path(path)
        self.socket = self.directory_fd = self.inode = None

    def bind(self):
        require_linux_root()
        if self.socket is not None:
            raise Refused("host_unavailable")
        before = verify_directory(self.path)
        self.directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        after = os.fstat(self.directory_fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            self.close()
            raise Refused("host_unavailable")
        try:
            try:
                os.stat(self.path.name, dir_fd=self.directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("host_unavailable")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket = listener
            previous = os.umask(0o077)
            try:
                listener.bind(str(self.path))
            finally:
                os.umask(previous)
            info = os.stat(self.path.name, dir_fd=self.directory_fd, follow_symlinks=False)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != ROOT_UID:
                raise Refused("host_unavailable")
            self.inode = (info.st_dev, info.st_ino)
            # Parents exclude non-root directory writers. Check the named inode
            # after ownership/mode changes and again before serving.
            os.chown(self.path.name, ROOT_UID, SOCKET_GROUP, dir_fd=self.directory_fd, follow_symlinks=False)
            # Linux Python versions differ in fchmodat no-follow support. The
            # pinned directory excludes all non-root writers, and the same
            # socket inode is independently checked immediately afterward.
            os.chmod(self.path.name, 0o660, dir_fd=self.directory_fd)
            self._verify_socket()
            listener.listen(BACKLOG)
            return self
        except BaseException:
            self.close()
            raise

    def _verify_socket(self):
        directory = verify_directory(self.path)
        anchored = os.fstat(self.directory_fd)
        if (directory.st_dev, directory.st_ino) != (anchored.st_dev, anchored.st_ino):
            raise Refused("host_unavailable")
        info = os.stat(self.path.name, dir_fd=self.directory_fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != self.inode or info.st_uid != ROOT_UID
                or info.st_gid != SOCKET_GROUP or stat.S_IMODE(info.st_mode) != 0o660):
            raise Refused("host_unavailable")

    def serve(self):
        if self.socket is None:
            raise Refused("host_unavailable")
        try:
            while True:
                self._verify_socket()
                connection, _ = self.socket.accept()
                try:
                    self._verify_socket()
                except BaseException:
                    connection.close()
                    raise
                handle_connection(connection, self.service)
        finally:
            self.close()

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.directory_fd is not None:
            try:
                info = os.stat(self.path.name, dir_fd=self.directory_fd, follow_symlinks=False)
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self.inode and info.st_uid == ROOT_UID:
                    os.unlink(self.path.name, dir_fd=self.directory_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(self.directory_fd)
                self.directory_fd = self.inode = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve",), help="Opt-in foreground read-only socket service; does not initialize state")
    parser.parse_args()
    server = None
    try:
        require_linux_root()
        server = PlanSocket(create_service()).bind()
        server.serve()
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("Read-only host planning service unavailable; no executor is enabled.")
        return 1
    finally:
        if server is not None:
            server.close()


if __name__ == "__main__":
    raise SystemExit(main())
