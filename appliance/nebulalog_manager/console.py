"""Local virtual-console entry; never launches a shell or unlocks Linux root."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
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


def _recovery_answer(read, prompt):
    value = read(prompt)
    if (not isinstance(value, str) or len(value) > 4096
            or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value)):
        raise Refused("Enter one displayed action or an absolute local file path")
    return value.strip()


def _recovery_path(read, label):
    value = _recovery_answer(read, label + " (absolute local path, or CANCEL): ")
    if value.upper() == "CANCEL":
        return None
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise Refused("Recovery accepts normalized absolute local file paths; no URL, shell expansion or pasted key contents")
    return path


def _show_restore_status(value, write):
    if value["state"] == "not_started":
        write("No configuration restore has started. Runtime provisioning has not been requested by this menu.")
        return
    write("Configuration recovery: " + value["state"] + " | operation " + value["id"])
    write("Retained database acknowledgements: " + ", ".join(name + ": " + state for name, state in value["databases"].items()))
    write("Recorded runtime stage: " + (value["runtime_active_stage"] or "none in flight"))
    write("Status describes retained evidence, not current service health. Setup remains incomplete.")
    if value["state"] == "recovery_required":
        write("A listener hold was recorded; current health still needs verification." if value["listener_hold_recorded"]
              else "A listener hold is not established by this journal. Keep the target isolated and retain its evidence.")
    if value["resume_blocked"]:
        write("An action has an uncertain outcome. Automatic replay is refused. Preserve this target and use a new fresh target or qualified recovery review.")


def host_ready_console(manager, config, *, restore_only=False, recovery=None, read=input, write=print):
    """Choose provisioning or retained recovery on the existing protected tty1."""
    from .configuration_restore import ConfigurationRestore
    from .restore_runtime import FreshRestoreRuntime
    from .setup_integrity import pending_console, resume_runtime
    from .firstboot import _runtime_console, validate_config
    validate_config(config)
    pending_console(manager)
    gate = manager.gate()
    if gate.get("host_ready") is not True or gate.get("setup_complete") is not False:
        raise Refused("Recovery selection requires the unfinished host-enrolled appliance")
    recovery = recovery or ConfigurationRestore(runtime=FreshRestoreRuntime(paths=manager.paths, firstboot=manager))
    write("\nEncrypted storage and host configuration are ready.")
    write("NEW prepares a new application. MEDIA imports a configuration backup from an explicitly selected recovery ISO. RESTORE uses already protected local files.")
    write("Recovery retains source accounts, passwords and existing MFA; it does not reset them. ClickHouse log data is excluded.")
    while True:
        pending_console(manager)
        status = recovery.status()
        retained = status["state"] != "not_started"
        if restore_only and not retained:
            raise Refused("The retained restore pointer is unavailable; normal provisioning will not replace it")
        _show_restore_status(status, write)
        if retained:
            prompt = "STATUS, CONTINUE setup, or LATER: " if status["state"] == "runtime_ready" else "STATUS, RESUME recovery, or LATER: "
        else:
            prompt = "NEW application, MEDIA recovery ISO, RESTORE local configuration, STATUS, or LATER: "
        action = _recovery_answer(read, prompt).upper()
        pending_console(manager)  # Recheck the terminal/unfinished boundary after input.
        if action == "LATER":
            return {"state": status["state"] if retained else "host-ready", "setup_complete": False}
        if action == "STATUS":
            continue
        if retained:
            if action == "CONTINUE" and status["state"] == "runtime_ready":
                receipt = resume_runtime(manager, config)
                if receipt is None:
                    raise Refused("Restored runtime evidence is incomplete; setup cannot continue")
                return _runtime_console(manager, config, {**receipt, "restored": True})
            if action != "RESUME":
                write("This appliance belongs to its retained recovery. Choose a displayed action; NEW and replacement inputs are unavailable.")
                continue
            if status["resume_blocked"]:
                write("RESUME is unavailable for the recorded uncertain action; no restore command was dispatched.")
                continue
            confirmation = _recovery_answer(read, "Type the complete operation UUID to resume its retained inputs: ")
            if confirmation != status["id"]:
                write("Recovery was not resumed.")
                continue
            pending_console(manager)
            recovery.resume(status["id"])
            continue
        if action == "NEW":
            if _recovery_answer(read, "Type NEW to prepare a new application instead of restoring a backup: ") != "NEW":
                write("Application provisioning was not requested.")
                continue
            pending_console(manager)
            manager.runner(["systemctl", "start", "nebulalog-firstboot.service"], timeout=180)
            return _runtime_console(manager, config, manager.provision())
        if action not in {"RESTORE", "MEDIA"}:
            write("Choose NEW, MEDIA, RESTORE, STATUS, or LATER.")
            continue
        recovery.runtime.guard_fresh()
        write("Use the same immutable release/schema, source hostname, administrator username and baseline. Keep the source offline before reusing its address.")
        if action == "MEDIA":
            from .recovery_media import restore_from_media
            write("Attach your configuration recovery ISO through the hypervisor console. Only the device you select will be mounted, read-only; no media is selected automatically.")
            device = _recovery_answer(read, "Optical device (/dev/sr0, /dev/sr1, …), or CANCEL: ")
            if device.upper() == "CANCEL":
                write("Recovery media import was cancelled.")
                continue
            pending_console(manager)
            result = restore_from_media(recovery, Path(device), read=read, write=write,
                                        guard=lambda: pending_console(manager), target_confirmation="RESTORE " + config["hostname"])
            if result.get("state") == "cancelled":
                write("Recovery media import was cancelled before applying a backup.")
            continue
        write("Export the new target's disk recovery material. Stage the encrypted backup and certificate in root-controlled directories; keep the private recovery key root-only, preferably in /run/nebulalog.")
        write("Enter protected paths only; use MEDIA for an attached recovery ISO. Do not paste secrets here. This path does not download inputs, upload keys or start SSH.")
        paths = []
        for label in ("Encrypted configuration backup", "Recipient certificate", "Private recovery key"):
            value = _recovery_path(read, label)
            if value is None:
                break
            paths.append(value)
        if len(paths) != 3:
            write("Recovery was cancelled before applying any backup.")
            continue
        pending_console(manager)
        write("Authenticating recovery inputs for review. Application services remain stopped.")
        review = recovery.prepare(paths[0], paths[2], paths[1])
        from .configuration_restore import review_text
        write(review_text(review))
        confirm = "RESTORE " + config["hostname"]
        if _recovery_answer(read, "After isolating the source and exporting target disk recovery material, type " + confirm + ": ") != confirm:
            write("Recovery was not started.")
            continue
        pending_console(manager)
        write("Applying the authenticated review. Retained status is available when this operation finishes or after a restart.")
        recovery.apply_prepared(review["id"], review["review_digest"])


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
