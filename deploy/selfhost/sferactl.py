#!/usr/bin/python3
"""Local administrative interface. Invoke over SSH with root privileges."""
import fcntl
import grp
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

STATE = Path("/etc/sfera-selfhost")
SERVICE = "sfera-selfhost.service"
GROUP = "sfera-selfhost"
LIMIT = 16


def durable_write(path, text, mode=0o600, group=0):
    with path.open("x") as stream:
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), 0, group)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def set_pointer(name, generation):
    temporary = STATE / f".{name}-{uuid.uuid4()}"
    try:
        temporary.symlink_to(generation)
        temporary.replace(STATE / name)
        sync_directory(STATE)
    finally:
        temporary.unlink(missing_ok=True)


def apply_active(force=False):
    generation = os.readlink(STATE / "active")
    applied = STATE / "applied"
    if force or not applied.is_symlink() or os.readlink(applied) != generation:
        start_transport()
        set_pointer("applied", generation)


def start_transport():
    subprocess.run(["systemctl", "restart", SERVICE], check=True, stdout=sys.stderr)
    for _ in range(50):
        connection = http.client.HTTPConnection("127.0.0.1", 7443, timeout=0.5)
        try:
            connection.request("POST", "/api/session")
            if connection.getresponse().status == 404:
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(0.1)
    raise RuntimeError("SFERA did not open its local signaling listener")


def save(users, previous=None):
    generation = Path(tempfile.mkdtemp(prefix="peers-", dir=STATE))
    group = grp.getgrnam(GROUP).gr_gid
    os.chown(generation, 0, group)
    os.chmod(generation, 0o750)
    try:
        lines = "".join(f"{user['ip']} {user['token']}\n" for user in users)
        durable_write(generation / "peers", lines, 0o640, group)
        durable_write(generation / "users.json", json.dumps(users))
        sync_directory(generation)
        set_pointer("active", generation.name)
        if previous is not None:
            apply_active()
    except (OSError, RuntimeError, subprocess.CalledProcessError):
        active = STATE / "active"
        if active.is_symlink() and os.readlink(active) == generation.name:
            if previous is None:
                active.unlink()
            else:
                set_pointer("active", previous)
                start_transport()
                set_pointer("applied", previous)
        shutil.rmtree(generation)
        raise
    if previous is not None:
        shutil.rmtree(STATE / previous, ignore_errors=True)


def create_user(name, slot):
    return {"id": str(uuid.uuid4()), "name": name, "ip": f"10.203.0.{slot * 4 + 2}",
            "token": secrets.token_hex(32), "owner": slot == 0}


def dispatch(command, value):
    registry = STATE / "active" / "users.json"
    if command == "init":
        if not registry.exists():
            save([create_user("Этот Mac", 0)])
        return None
    if command == "apply":
        apply_active(force=True)
        return None

    apply_active()
    generation = os.readlink(STATE / "active")
    users = json.loads(registry.read_text())
    if command == "list":
        return [{k: v for k, v in user.items() if k != "token"} for user in users]

    host = str(ipaddress.IPv4Address((STATE / "public-ip").read_text().strip()))
    if command == "add":
        if not isinstance(value, str):
            raise ValueError("Enter a user name")
        name = value.strip()
        if not 1 <= len(name) <= 60 or not name.isprintable():
            raise ValueError("User names must be 1–60 printable characters")
        if any(user["name"] == name for user in users):
            raise ValueError("A user with this name already exists")
        if len(users) >= LIMIT:
            raise ValueError("This server supports up to 16 profiles")
        used = {user["ip"] for user in users}
        slot = next(slot for slot in range(1, LIMIT) if f"10.203.0.{slot * 4 + 2}" not in used)
        user = create_user(name, slot)
        save(users + [user], generation)
    else:
        user = next((user for user in users if user["id"] == value), None)
        if user is None:
            raise ValueError("User not found")
        if command == "revoke":
            if user["owner"]:
                raise ValueError("The server's primary profile is required")
            save([entry for entry in users if entry["id"] != value], generation)
            return None
    return {"version": 1, "name": user["name"], "host": host, "peerIP": user["ip"],
            "token": user["token"]}


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise ValueError("Run sferactl as root with one command")
    command = sys.argv[1]
    if command not in {"init", "apply", "list", "add", "profile", "revoke"}:
        raise ValueError("Unknown SFERA command")
    value = json.loads(sys.stdin.buffer.read(4096)) if command in {"add", "profile", "revoke"} else None
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        print(json.dumps(dispatch(command, value)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
