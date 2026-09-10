"""Bounded argv-only commands; binary database archives never pass through strings."""
import os
from pathlib import Path
import subprocess
from nebulalog_manager.common import CommandFailed, Refused

ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C",
               "TMPDIR": "/var/lib/nebulalog/tmp"}


class Commands:
    def __call__(self, argv, *, timeout=120, input=None):
        result = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False, env=ENVIRONMENT)
        if result.returncode:
            raise CommandFailed(Path(argv[0]).name, result.returncode)
        if len(result.stdout) > 16 * 1024 * 1024:
            raise Refused("Oversized lifecycle command result")
        return result.stdout.decode("utf-8", "strict").strip()

    def capture(self, argv, target: Path, *, timeout=1800):
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                result = subprocess.run(argv, stdout=output, stderr=subprocess.DEVNULL,
                                        timeout=timeout, check=False, env=ENVIRONMENT)
                output.flush()
                os.fsync(output.fileno())
            if result.returncode:
                raise CommandFailed(Path(argv[0]).name, result.returncode)
            if target.stat().st_size == 0:
                raise Refused("Database archive was empty")
        except BaseException:
            target.unlink(missing_ok=True)
            raise

    def feed(self, argv, source: Path, *, timeout=1800):
        with source.open("rb") as data:
            result = subprocess.run(argv, stdin=data, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=timeout, check=False, env=ENVIRONMENT)
        if result.returncode:
            raise CommandFailed(Path(argv[0]).name, result.returncode)
