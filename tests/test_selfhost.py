"""Checks that access changes publish or restore the whole server generation."""
import grp
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest import mock


MODULE = Path(__file__).resolve().parents[1] / "deploy" / "selfhost" / "sferactl.py"
SPEC = importlib.util.spec_from_file_location("sferactl", MODULE)
ctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ctl)
UPGRADE_SPEC = importlib.util.spec_from_file_location("upgrade", MODULE.with_name("upgrade.py"))
updater = importlib.util.module_from_spec(UPGRADE_SPEC)
with mock.patch.dict(sys.modules, {"sferactl": ctl}):
    UPGRADE_SPEC.loader.exec_module(updater)



class SelfhostTests(unittest.TestCase):
    def setUp(self):
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        (self.state / "public-ip").write_text("1.1.1.1\n")
        for patch in (
            mock.patch.object(ctl, "STATE", self.state),
            mock.patch.object(ctl, "GROUP", grp.getgrgid(os.getgid()).gr_name),
            mock.patch.object(ctl.os, "chown"),
            mock.patch.object(ctl.os, "fchown"),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        transport = mock.patch.object(ctl, "start_transport")
        self.transport = transport.start()
        self.addCleanup(transport.stop)
        ctl.dispatch("init", None)
        ctl.dispatch("apply", None)

    def test_revoke_removes_only_the_named_users_credential(self):
        owner = ctl.dispatch("list", None)[0]
        original = ctl.dispatch("profile", owner["id"])
        profile = ctl.dispatch("add", "Телефон")
        users = ctl.dispatch("list", None)
        self.assertNotIn("token", users[1])
        self.assertNotEqual(original["token"], profile["token"])
        self.assertIn(profile["token"], (self.state / "active" / "peers").read_text())
        ctl.dispatch("revoke", users[1]["id"])
        self.assertEqual(ctl.dispatch("list", None), [owner])
        self.assertEqual((self.state / "active" / "peers").read_text(),
                         f"{original['peerIP']} {original['token']}\n")

    def prepare_update(self):
        root = self.state / "software"
        (root / "bin").mkdir(parents=True)
        unit = root / "sfera.service"
        bundle = self.state / "bundle"
        bundle.mkdir()
        for name, value in (("ROOT", root), ("UNIT", unit), ("INSTALL_LOCK", root / "install-lock")):
            patch = mock.patch.object(updater, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        for name, (destination, _mode) in updater.files().items():
            destination.write_text(f"old {name}")
            (bundle / name).write_text(f"new {name}")
        (bundle / updater.VERSION).write_text("server-v0.1.1\n")
        commands = mock.patch.object(updater.subprocess, "run")
        commands.start()
        self.addCleanup(commands.stop)
        return bundle, root

    def registry_snapshot(self):
        return (
            os.readlink(self.state / "active"),
            os.readlink(self.state / "applied"),
            (self.state / "active" / "users.json").read_bytes(),
            (self.state / "active" / "peers").read_bytes(),
        )

    def test_upgrade_from_unversioned_preserves_existing_profiles(self):
        ctl.dispatch("add", "Телефон")
        before = self.registry_snapshot()
        bundle, root = self.prepare_update()
        updater.upgrade(bundle, "unversioned", "server-v0.1.1")
        self.assertEqual(self.registry_snapshot(), before)
        self.assertEqual((root / updater.VERSION).read_text().strip(), "server-v0.1.1")
        self.assertFalse((root / ".upgrade-recovery").exists())
        for name, (destination, _mode) in updater.files().items():
            self.assertEqual(destination.read_text(), f"new {name}")

    def test_failed_upgrade_restores_binary_unit_and_version(self):
        ctl.dispatch("add", "Ноутбук")
        before = self.registry_snapshot()
        bundle, root = self.prepare_update()
        marker = root / updater.VERSION
        marker.write_text("server-v0.1.0\n")
        with mock.patch.object(updater, "restart", side_effect=[RuntimeError("not ready"), None]) as restart:
            with self.assertRaisesRegex(RuntimeError, "previous version restored"):
                updater.upgrade(bundle, "server-v0.1.0", "server-v0.1.1")
            self.assertEqual(restart.call_count, 2)
        self.assertEqual(self.registry_snapshot(), before)
        self.assertEqual(marker.read_text(), "server-v0.1.0\n")
        self.assertFalse((root / ".upgrade-recovery").exists())
        for name, (destination, _mode) in updater.files().items():
            self.assertEqual(destination.read_text(), f"old {name}")

    def test_retry_recovers_interrupted_update_before_applying_again(self):
        bundle, root = self.prepare_update()
        before = self.registry_snapshot()
        journal = root / ".upgrade-recovery"
        journal.mkdir()
        for name, (destination, _mode) in updater.files().items():
            (journal / name).write_bytes(destination.read_bytes())
            destination.write_text(f"partially updated {name}")
        (root / updater.VERSION).write_text("server-v0.1.1\n")
        with mock.patch.object(updater, "restart") as restart:
            updater.upgrade(bundle, "unversioned", "server-v0.1.1")
            self.assertEqual(restart.call_count, 2)
        self.assertFalse(journal.exists())
        self.assertEqual(self.registry_snapshot(), before)
        self.assertEqual((root / updater.VERSION).read_text().strip(), "server-v0.1.1")

    def test_concurrent_version_change_refuses_to_replace_files(self):
        bundle, root = self.prepare_update()
        (root / updater.VERSION).write_text("server-v0.2.0\n")
        with self.assertRaisesRegex(ValueError, "version changed"):
            updater.upgrade(bundle, "server-v0.1.0", "server-v0.1.1")
        with self.assertRaisesRegex(ValueError, "newer"):
            updater.upgrade(bundle, "server-v0.2.0", "server-v0.1.1")
        for name, (destination, _mode) in updater.files().items():
            self.assertEqual(destination.read_text(), f"old {name}")

    def test_failed_restart_restores_the_last_working_generation(self):
        users = ctl.dispatch("list", None)
        generation = (self.state / "active").resolve()
        self.transport.side_effect = [subprocess.CalledProcessError(1, "systemctl"), None]
        with self.assertRaises(subprocess.CalledProcessError):
            ctl.dispatch("add", "Ноутбук")
        self.assertEqual((self.state / "active").resolve(), generation)
        self.assertEqual((self.state / "applied").resolve(), generation)
        self.assertEqual(ctl.dispatch("list", None), users)
