"""Exercise the piped installer without network access or system changes."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"
DEPENDENCIES = ("wg", "wg-quick", "ip", "sysctl", "resolvconf", "iptables")

# Every downloaded asset and privileged operation is confined to the fixture.
MOCK = r'''
import hashlib, os, pathlib, shutil, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ["FIXTURE"])
with (root / "calls").open("a") as log:
    log.write(name + " " + " ".join(args) + "\n")
if name == "uname":
    print(os.environ.get("TEST_OS", "Linux") if args == ["-s"] else os.environ.get("TEST_ARCH", "x86_64"))
elif name == "curl":
    if os.environ.get("DOWNLOAD_FAIL"):
        sys.exit(22)
    output = args[args.index("--output") + 1]
    url = args[-1]
    if url.endswith("/latest"):
        print("https://github.com/mysteriumnetwork/mysteriumvpncli/releases/tag/v1.2.3", end="")
    elif url.endswith(".sha256"):
        digest = hashlib.sha256((root / "archive").read_bytes()).hexdigest()
        if os.environ.get("BAD_CHECKSUM"):
            digest = "0" * 64
        pathlib.Path(output).write_text(digest + "  archive\n")
    else:
        shutil.copyfile(root / "archive", output)
elif name == "sha256sum":
    print(hashlib.sha256(pathlib.Path(args[0]).read_bytes()).hexdigest() + "  " + args[0])
elif name == "sudo":
    if os.environ.get("SUDO_FAIL"):
        sys.exit(1)
    if args == ["-n", "true"]:
        sys.exit(0)
    os.execvp(args[1], args[1:])
elif name in ("apt-get", "dnf", "yum", "pacman", "zypper"):
    if "update" not in args:
        for dependency in ("wg", "wg-quick", "ip", "sysctl", "resolvconf", "iptables"):
            target = root / "bin" / dependency
            if not target.exists():
                target.symlink_to(root / "bin" / "uname")
'''


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.dest = self.root / "destination"
        self.dest.mkdir()
        self.env = dict(os.environ, FIXTURE=str(self.root), PATH=str(self.bin),
                        MYSTVPN_INSTALL_DIR=str(self.dest), TMPDIR=str(self.root))
        for name in ("tar", "gzip", "install", "mktemp", "rm", "env"):
            (self.bin / name).symlink_to(shutil.which(name))
        for name in ("uname", "curl", "sha256sum", "sudo", *DEPENDENCIES):
            self.mock(name)
        binary = b"#!/bin/sh\necho mystvpn v1.2.3\n"
        with tarfile.open(self.root / "archive", "w:gz") as archive:
            info = tarfile.TarInfo("mystvpn")
            info.size = len(binary)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(binary))

    def mock(self, name):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + MOCK)
        path.chmod(0o755)

    def run_installer(self, **env):
        return subprocess.run([shutil.which("bash")], input=INSTALLER.read_text(),
                              env=dict(self.env, **env), capture_output=True, text=True)

    def test_architectures_and_upgrade(self):
        for machine, arch in (("x86_64", "amd64"), ("aarch64", "arm64"),
                              ("armv7l", "arm32"), ("armv8l", "arm32")):
            with self.subTest(machine=machine):
                result = self.run_installer(TEST_ARCH=machine)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.dest / "mystvpn").stat().st_mode & 0o111)
                self.assertIn(f"/v1.2.3/mystvpn-linux-{arch}.tar.gz", (self.root / "calls").read_text())
        self.assertFalse(list(self.root.glob("tmp.*")))

    def test_package_managers_install_missing_dependencies(self):
        for manager, expected in (("apt-get", "iproute2"), ("dnf", "iproute"),
                                  ("yum", "iproute"), ("pacman", "iproute2"),
                                  ("zypper", "iproute")):
            with self.subTest(manager=manager):
                self.mock(manager)
                for dependency in DEPENDENCIES:
                    (self.bin / dependency).unlink()
                result = self.run_installer()
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = (self.root / "calls").read_text()
                self.assertIn(expected, calls)
                self.assertIn("wireguard-tools", calls)
                self.assertIn("resolvconf" if manager == "apt-get" else "openresolv", calls)
                (self.bin / manager).unlink()

    def test_dependencies_present_skip_package_manager(self):
        self.mock("apt-get")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("apt-get", (self.root / "calls").read_text())

    def test_checksum_failure_preserves_existing_install(self):
        target = self.dest / "mystvpn"
        target.write_text("existing binary")
        result = self.run_installer(BAD_CHECKSUM="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum verification failed", result.stderr)
        self.assertEqual(target.read_text(), "existing binary")
        self.assertFalse(list(self.root.glob("tmp.*")))

    def test_download_failure_does_not_install(self):
        result = self.run_installer(DOWNLOAD_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.dest / "mystvpn").exists())

    def test_unsupported_platforms(self):
        for env in ({"TEST_OS": "Darwin"}, {"TEST_ARCH": "armv6l"}, {"TEST_ARCH": "riscv64"}):
            result = self.run_installer(**env)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.dest / "mystvpn").exists())

    def test_relative_install_directory(self):
        result = self.run_installer(MYSTVPN_INSTALL_DIR="relative")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute path", result.stderr)

    def test_missing_dependency_without_package_manager(self):
        (self.bin / "wg").unlink()
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing wg", result.stderr)
        self.assertFalse((self.dest / "mystvpn").exists())

    def test_nft_satisfies_firewall_dependency(self):
        (self.bin / "iptables").unlink()
        self.mock("nft")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
