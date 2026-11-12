"""Build real packages and install/upgrade them only in a disposable Arch container.

Run as root after creating the unprivileged `builder` user (scripts/ci-arch.sh).
Package fixtures print a version; they never configure networking.
"""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


class ArchPackageTest(unittest.TestCase):
    def package(self, directory, tag, version, pkgrel="1"):
        directory.mkdir()
        directory.chmod(0o755)
        binary = directory / "binary"
        binary.write_text(f"#!/bin/sh\nprintf '%s\\n' 'mystvpn {tag}'\n")
        output = directory / "dist"
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        run("runuser", "-u", "builder", "--", "env", f"ARCH_PKGREL={pkgrel}",
            "bash", str(ROOT / "scripts/package-arch.sh"), str(binary), tag, "x86_64", str(output))
        package = output / f"mystvpn-{version}-{pkgrel}-x86_64.pkg.tar.zst"
        self.assertTrue(package.is_file())
        self.assertEqual(package.with_name(package.name + ".sha256").read_text(),
                         f"{hashlib.sha256(package.read_bytes()).hexdigest()}  {package.name}\n")
        info = run("bsdtar", "-xOf", str(package), ".PKGINFO")
        for field in ("pkgname = mystvpn", f"pkgver = {version}-{pkgrel}", "arch = x86_64"):
            self.assertIn(field + "\n", info)
        for dependency in ("ca-certificates", "wireguard-tools", "iproute2", "procps-ng", "openresolv", "nftables"):
            self.assertIn(f"depend = {dependency}\n", info)
        self.assertEqual(run("bsdtar", "-xOf", str(package), "usr/bin/mystvpn"), binary.read_text())
        listing = run("bsdtar", "--numeric-owner", "-tvf", str(package))
        self.assertTrue(all(line.split()[2:4] == ["0", "0"] for line in listing.splitlines()), listing)
        self.assertIn("usr/share/licenses/mystvpn/LICENSE", run("bsdtar", "-tf", str(package)))
        return package

    def test_versions_and_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            for index, (tag, version) in enumerate((
                ("v1.2.3", "1.2.3"), ("1.2.3-rc.1", "1.2.3pre.rc.1"),
                ("release/test", "release.test"),
            )):
                with self.subTest(tag=tag):
                    self.package(work / str(index), tag, version)
            self.assertLess(int(run("vercmp", "1.2.3pre.rc.1-1", "1.2.3-1")), 0)
            self.package(work / "pkgrel", "1.2.3", "1.2.3", pkgrel="2")

    def test_install_and_upgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            first = self.package(work / "first", "1.2.3", "1.2.3")
            second = self.package(work / "second", "1.2.4", "1.2.4")
            run("pacman", "-U", "--noconfirm", str(first))
            self.assertEqual(run("mystvpn", "version").strip(), "mystvpn 1.2.3")
            self.assertEqual(Path("/usr/bin/mystvpn").stat().st_mode & 0o777, 0o755)
            run("pacman", "-U", "--noconfirm", str(second))
            self.assertEqual(run("mystvpn", "version").strip(), "mystvpn 1.2.4")
            self.assertEqual(run("pacman", "-Q", "mystvpn").strip(), "mystvpn 1.2.4-1")

    def test_unsupported_architecture(self):
        result = subprocess.run(["bash", str(ROOT / "scripts/package-arch.sh"),
                                 "/nonexistent", "1.2.3", "aarch64", "/tmp"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported Arch architecture", result.stderr)


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run only inside a disposable Arch Linux container as root.")
    unittest.main(verbosity=2)
