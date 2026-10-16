"""Bounded argv-only commands; binary database archives never pass through strings."""
import os
import fcntl
from pathlib import Path
import subprocess
import stat
from nebulalog_manager.common import CommandFailed, Refused

ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C",
               "TMPDIR": "/var/lib/nebulalog/tmp"}


class Commands:
    def __init__(self, *, inherited_locks=(), observer=None, failure_observer=None):
        # Only an exact protected lock already owned by this process may cross
        # exec. Children retain its flock if their lifecycle parent disappears.
        self.inherited_locks = tuple(inherited_locks)
        if observer is not None and not callable(observer):
            raise Refused("Lifecycle command observer must be callable")
        if failure_observer is not None and not callable(failure_observer):
            raise Refused("Lifecycle command failure observer must be callable")
        self.observer = observer
        self.failure_observer = failure_observer
        self._inherited_fds()

    def _inherited_fds(self):
        result = []
        for descriptor, path in self.inherited_locks:
            path = Path(path)
            try:
                opened, retained = os.fstat(descriptor), path.lstat()
                if (type(descriptor) is not int or descriptor in result
                        or not path.is_absolute() or path.resolve() != path
                        or not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(retained.st_mode)
                        or opened.st_uid != 0 or opened.st_gid != 0
                        or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                        or (opened.st_dev, opened.st_ino) != (retained.st_dev, retained.st_ino)):
                    raise Refused("Inherited lifecycle lock is not the exact protected file")
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, TypeError, ValueError) as exc:
                raise Refused("Inherited lifecycle lock is unavailable") from exc
            result.append(descriptor)
        return tuple(result)

    def __call__(self, argv, *, timeout=120, input=None):
        descriptors = self._inherited_fds()
        ticket = self.observer("dispatch", "call", argv=argv) if self.observer else None
        result = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False, env=ENVIRONMENT, pass_fds=descriptors)
        if result.returncode:
            if self.failure_observer:
                self.failure_observer("call", ticket=ticket, returncode=result.returncode)
            failure = CommandFailed(Path(argv[0]).name, result.returncode)
            failure.execution_ticket = ticket
            raise failure
        if self.observer:
            self.observer("complete", "call", ticket=ticket)
        if len(result.stdout) > 16 * 1024 * 1024:
            raise Refused("Oversized lifecycle command result")
        return result.stdout.decode("utf-8", "strict").strip()

    def capture(self, argv, target: Path, *, timeout=1800):
        descriptors = self._inherited_fds()
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                ticket = self.observer("dispatch", "capture", argv=argv) if self.observer else None
                result = subprocess.run(argv, stdout=output, stderr=subprocess.DEVNULL,
                                        timeout=timeout, check=False, env=ENVIRONMENT, pass_fds=descriptors)
                output.flush()
                os.fsync(output.fileno())
            if result.returncode:
                if self.failure_observer:
                    self.failure_observer("capture", ticket=ticket, returncode=result.returncode)
                raise CommandFailed(Path(argv[0]).name, result.returncode)
            if self.observer:
                self.observer("complete", "capture", ticket=ticket)
            if target.stat().st_size == 0:
                raise Refused("Database archive was empty")
        except BaseException:
            target.unlink(missing_ok=True)
            raise

    def feed(self, argv, source: Path, *, timeout=1800):
        descriptors = self._inherited_fds()
        with source.open("rb") as data:
            ticket = self.observer("dispatch", "feed", argv=argv) if self.observer else None
            result = subprocess.run(argv, stdin=data, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=timeout, check=False, env=ENVIRONMENT,
                                    pass_fds=descriptors)
        if result.returncode:
            if self.failure_observer:
                self.failure_observer("feed", ticket=ticket, returncode=result.returncode)
            raise CommandFailed(Path(argv[0]).name, result.returncode)
        if self.observer:
            self.observer("complete", "feed", ticket=ticket)
