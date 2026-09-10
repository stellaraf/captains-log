"""Local virtual-console entry; never launches a shell or unlocks Linux root."""
from __future__ import annotations

import argparse
import os
import resource
import subprocess
import sys

from .common import Refused, require_linux_root, run, trusted_file
from .firstboot import FirstBoot, wizard

TTY = "/dev/tty1"


def local_console(streams=None, environment=None, ttyname=os.ttyname):
    """All three descriptors must be the actual virtual terminal, never a PTY."""
    require_linux_root()
    environment = os.environ if environment is None else environment
    if any(environment.get(name) for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")):
        raise Refused("Automatic setup is available only on the local virtual console")
    streams = (sys.stdin, sys.stdout, sys.stderr) if streams is None else streams
    try:
        if any(not stream.isatty() or ttyname(stream.fileno()) != TTY for stream in streams):
            raise Refused("Automatic setup requires stdin, stdout and stderr directly attached to /dev/tty1")
    except (OSError, ValueError, AttributeError):
        raise Refused("Automatic setup requires the appliance's local virtual console") from None


def sealed_state(manager):
    """A privileged console is allowed only on a sealed image with unfinished setup."""
    bootstrap = manager.paths.bootstrap
    unsealed = bootstrap / "unsealed-build"
    if unsealed.exists() or unsealed.is_symlink():
        return "unsealed"
    image = trusted_file(bootstrap / "image-state")
    if image.stat().st_mode & 0o077 or image.read_text().strip() != "sealed":
        raise Refused("Automatic setup requires the sealed appliance image marker")
    current = manager.status()
    configured = manager.paths.etc / "configured"
    if current.get("setup_complete"):
        return "complete"
    if configured.exists() or configured.is_symlink():
        raise Refused("The setup-complete marker is invalid; privileged setup will not restart")
    return "pending"


def safe_error(error):
    # Refusal messages are controlled by this package, while e.g. ValueError may
    # quote an entered credential. Never expose arbitrary exception text/traceback.
    if isinstance(error, Refused):
        return str(error)
    if isinstance(error, KeyboardInterrupt):
        return "Setup was interrupted. Completed stages and recovery material are retained."
    if isinstance(error, ValueError):
        return "An entered setting was invalid. Review the requested format and retry."
    if isinstance(error, (OSError, subprocess.SubprocessError)):
        return "A required local resource or service is unavailable. Existing setup state has been retained."
    return "Setup could not complete. Existing state has been retained for review."


def serve(manager=None, *, wizard_fn=wizard, guard=local_console, read=input, write=print, runner=run):
    manager = manager or FirstBoot()
    guard()
    state = sealed_state(manager)
    if state == "unsealed":
        write("This private build is unsealed. Automatic administrator enrollment is disabled.")
        return {"state": "unsealed", "wizard_started": False}
    if state == "complete":
        write("Captain’s Log setup is complete. Manage this appliance through its HTTPS application.")
        return {"state": "setup-complete", "wizard_started": False}
    write("Captain’s Log appliance console\nPress Enter to start or resume secure setup. No Linux login is required.")
    started = False
    while True:
        try:
            read("Press Enter to continue: ")
        except KeyboardInterrupt:
            write("Setup is waiting. No root shell is available. Press Enter when ready.")
            continue
        except EOFError:
            write("The virtual console input closed. Reopen the console and restart the appliance to resume.")
            return {"state": "console-closed", "wizard_started": started}
        # Re-check the terminal and sealed/completion markers after every wait;
        # another authenticated setup path could have completed in the meantime.
        guard()
        state = sealed_state(manager)
        if state == "unsealed":
            write("Automatic setup is disabled for this unsealed build.")
            return {"state": "unsealed", "wizard_started": started}
        if state == "complete":
            break
        try:
            started = True
            wizard_fn(manager)
            if sealed_state(manager) == "complete":
                break
            write("Setup remains in progress. Press Enter to resume file-integrity actions or final verification after the pending browser and security checks.")
        except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
            write("\n" + safe_error(error))
            write("Press Enter to retry the same guarded setup. No completed storage is erased.")
        except EOFError:
            write("The virtual console input closed. Existing setup state is retained.")
            return {"state": "console-closed", "wizard_started": started}
        except Exception:
            # An unexpected implementation error must not display secret-bearing
            # exception values or an interactive debugger on this privileged TTY.
            write("\nSetup stopped unexpectedly. Existing state is retained; restart the appliance to retry.")
            return {"state": "console-error", "wizard_started": started}
    write("\nCaptain’s Log setup is complete. Continue in the HTTPS application.\nAutomatic privileged setup has ended; the Linux root account remains locked.")
    # Queue the normal, protected getty only after a valid completion receipt.
    # No autologin, credentials, shell command or arbitrary service is accepted.
    runner(["systemctl", "--no-block", "start", "getty@tty1.service"])
    return {"state": "setup-complete", "wizard_started": started}


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    os.umask(0o077)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        serve()
        return 0
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(safe_error(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Console setup stopped without opening a shell.", file=sys.stderr)
        return 1
    except Exception:
        print("Console setup stopped unexpectedly without opening a shell. Existing state is retained.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
