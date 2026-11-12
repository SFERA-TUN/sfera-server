#!/usr/bin/python3
"""Replace the v1 server software without reinitializing the installation."""

import fcntl
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

import sferactl

ROOT = Path("/opt/sfera")
UNIT = Path("/etc/systemd/system/sfera-selfhost.service")
INSTALL_LOCK = Path("/run/sfera-selfhost-install.lock")
VERSION = "server-version"


def version_key(tag):
    match = re.fullmatch(r"server-v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})", tag)
    if not match:
        raise ValueError("Expected a stable SFERA server release tag")
    return tuple(map(int, match.groups()))


def replace_file(source, destination, mode):
    fd, name = tempfile.mkstemp(dir=destination.parent, prefix=".sfera-")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            os.fchmod(output.fileno(), mode)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(destination)
        sferactl.sync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def files():
    return {
        "sfera-net": (ROOT / "bin/sfera-net", 0o755),
        "sferactl.py": (ROOT / "bin/sferactl", 0o755),
        "network.sh": (ROOT / "bin/network", 0o755),
        "sfera-selfhost.service": (UNIT, 0o644),
    }


def restart():
    subprocess.run(["systemctl", "daemon-reload"], check=True, stdout=sys.stderr)
    sferactl.start_transport()
    subprocess.run(["systemctl", "is-active", "--quiet", sferactl.SERVICE], check=True)


def retire(journal, workspace):
    journal.replace(workspace / "completed")
    sferactl.sync_directory(ROOT)


def rollback(journal, workspace):
    for name, (destination, mode) in files().items():
        replace_file(journal / name, destination, mode)
    marker = ROOT / VERSION
    previous = journal / VERSION
    if previous.exists():
        replace_file(previous, marker, 0o644)
    else:
        marker.unlink(missing_ok=True)
        sferactl.sync_directory(ROOT)
    restart()
    retire(journal, workspace)


def upgrade(bundle, expected, target):
    target_key = version_key(target)
    if (bundle / VERSION).read_text().strip() != target:
        raise ValueError("The package version does not match the requested release")
    if not all((bundle / name).is_file() for name in files()):
        raise ValueError("Incomplete SFERA server package")
    with INSTALL_LOCK.open("a") as installer, (sferactl.STATE / "lock").open("a") as registry:
        fcntl.flock(installer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(registry, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = ROOT / VERSION
        journal = ROOT / ".upgrade-recovery"
        if journal.exists():
            with tempfile.TemporaryDirectory(prefix=".sfera-recovery-", dir=ROOT) as folder:
                rollback(journal, Path(folder))
        installed = marker.read_text().strip() if marker.exists() else "unversioned"
        if installed != expected:
            raise ValueError("Server version changed. Check for updates again")
        if installed != "unversioned" and target_key <= version_key(installed):
            raise ValueError("Select a release newer than the installed server")
        active = sferactl.STATE / "active"
        applied = sferactl.STATE / "applied"
        if (not active.is_symlink() or not applied.is_symlink() or
                os.readlink(active) != os.readlink(applied) or
                not (active / "users.json").is_file() or not (active / "peers").is_file()):
            raise ValueError("SFERA must have an active v1 user registry before upgrading")
        for unit in (sferactl.SERVICE, "nginx.service", "sfera-acme.timer"):
            subprocess.run(["systemctl", "is-active", "--quiet", unit], check=True)
        with tempfile.TemporaryDirectory(prefix=".sfera-upgrade-", dir=ROOT) as folder:
            workspace = Path(folder)
            backup = workspace / "backup"
            backup.mkdir()
            for name, (destination, mode) in files().items():
                replace_file(destination, backup / name, mode)
            if marker.exists():
                replace_file(marker, backup / VERSION, 0o644)
            backup.replace(journal)
            sferactl.sync_directory(ROOT)
            try:
                for name, (destination, mode) in files().items():
                    replace_file(bundle / name, destination, mode)
                restart()
                replace_file(bundle / VERSION, marker, 0o644)
            except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
                try:
                    rollback(journal, workspace)
                except (OSError, RuntimeError, subprocess.CalledProcessError) as failure:
                    raise RuntimeError(f"Update failed ({error}); rollback needs attention ({failure})") from error
                raise RuntimeError(f"Update failed; previous version restored ({error})") from error
            retire(journal, workspace)


def interrupted(_signum, _frame):
    raise RuntimeError("SFERA update interrupted")


if __name__ == "__main__":
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        if os.geteuid() != 0 or len(sys.argv) != 3:
            raise ValueError("Run upgrade.py as root with the expected and target versions")
        upgrade(Path(__file__).resolve().parent, *sys.argv[1:])
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
