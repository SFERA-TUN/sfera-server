"""Checks that access changes publish or restore the whole server generation."""
import grp
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


MODULE = Path(__file__).resolve().parents[1] / "deploy" / "selfhost" / "sferactl.py"
SPEC = importlib.util.spec_from_file_location("sferactl", MODULE)
ctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ctl)


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

    def test_failed_restart_restores_the_last_working_generation(self):
        users = ctl.dispatch("list", None)
        generation = (self.state / "active").resolve()
        self.transport.side_effect = [subprocess.CalledProcessError(1, "systemctl"), None]
        with self.assertRaises(subprocess.CalledProcessError):
            ctl.dispatch("add", "Ноутбук")
        self.assertEqual((self.state / "active").resolve(), generation)
        self.assertEqual((self.state / "applied").resolve(), generation)
        self.assertEqual(ctl.dispatch("list", None), users)
