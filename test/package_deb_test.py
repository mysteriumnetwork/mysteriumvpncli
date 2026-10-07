"""Inspect real Debian archives without installing them or changing networking."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DebianPackageTest(unittest.TestCase):
    def test_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            binary = work / "mystvpn"
            binary.write_bytes(b"test executable\n")
            for arch, tag, version in (
                ("amd64", "v1.2.3", "1.2.3"),
                ("armhf", "v1.2.3-rc.1", "1.2.3~rc.1"),
                ("arm64", "release/test", "0~release+test"),
            ):
                with self.subTest(arch=arch, tag=tag):
                    subprocess.run(
                        ["bash", str(ROOT / "scripts/package-deb.sh"),
                         str(binary), tag, arch, str(work)], check=True,
                    )
                    package = work / f"mystvpn_{version}_{arch}.deb"
                    def field(name):
                        return subprocess.check_output(
                            ["dpkg-deb", "--field", str(package), name], text=True,
                        ).strip()
                    self.assertEqual(field("Package"), "mystvpn")
                    self.assertEqual(field("Version"), version)
                    self.assertEqual(field("Architecture"), arch)
                    self.assertEqual(field("Depends"),
                                     "ca-certificates, wireguard-tools, iproute2, procps, "
                                     "resolvconf | openresolv, nftables | iptables")
                    extracted = work / arch
                    subprocess.run(["dpkg-deb", "--extract", str(package), str(extracted)],
                                   check=True)
                    installed = extracted / "usr/bin/mystvpn"
                    self.assertEqual(installed.read_bytes(), binary.read_bytes())
                    self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
                    listing = subprocess.check_output(
                        ["dpkg-deb", "--contents", str(package)], text=True,
                    )
                    self.assertIn("root/root", listing)
                    checksum = package.with_suffix(".deb.sha256").read_text()
                    self.assertEqual(checksum,
                                     f"{hashlib.sha256(package.read_bytes()).hexdigest()}  {package.name}\n")

    def test_rejects_unsupported_architecture(self):
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/package-deb.sh"), "/nonexistent", "v1", "arm32", "/tmp"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported Debian architecture", result.stderr)


if __name__ == "__main__":
    unittest.main()
