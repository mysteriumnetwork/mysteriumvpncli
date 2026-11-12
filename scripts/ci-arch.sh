#!/usr/bin/env bash
# Run in a disposable Arch Linux container as root; never on the host.
set -euo pipefail
[[ $# -eq 1 && ( $1 == test || $1 == release ) ]] || { echo "Usage: $0 <test|release>" >&2; exit 1; }
mode=$1
# QEMU cannot implement pacman's downloader seccomp sandbox. This opt-in is
# only for the disposable test container; package signature checks stay enabled.
if [[ ${MYSTVPN_TEST_DISABLE_SANDBOX:-0} == 1 ]]; then
    sed -i '/^\[options\]$/a DisableSandbox' /etc/pacman.conf
fi
pacman -Syu --noconfirm --needed base-devel python
useradd --create-home builder
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cp -a /src/. "$work/"
chown -R builder:builder "$work"
cd "$work"
if [[ $mode == test ]]; then
    python3 test/package_arch_test.py
else
    : "${VERSION:?Set the release tag}"
    # Reuse the tested amd64 release binary, without rebuilding or modifying it.
    tar -xzf /artifacts/mystvpn-linux-amd64.tar.gz -C "$work" mystvpn
    chown builder:builder "$work/mystvpn"
    runuser -u builder -- bash scripts/package-arch.sh "$work/mystvpn" "$VERSION" x86_64 "$work/arch-dist"
    pacman -U --noconfirm "$work"/arch-dist/*.pkg.tar.zst
    [[ $(mystvpn version) == "mystvpn $VERSION" ]]
    install -m 0644 "$work"/arch-dist/* /out/
fi
