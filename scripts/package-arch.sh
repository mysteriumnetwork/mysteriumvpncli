#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <binary> <tag> <x86_64> <output-directory>" >&2
    exit 1
fi
binary=$1
tag=$2
arch=$3
output=$4
[[ $arch == x86_64 ]] || { echo "Unsupported Arch architecture: $arch" >&2; exit 1; }
[[ -f $binary ]] || { echo "Binary not found: $binary" >&2; exit 1; }
(( EUID != 0 )) || { echo 'Run makepkg as an unprivileged user.' >&2; exit 1; }

# alpm compares 1.2.3pre.rc.1 before 1.2.3. A tilde separator does not
# provide Debian's prerelease ordering in pacman.
version=${tag#v}
if [[ $version =~ ^([0-9]+\.[0-9]+\.[0-9]+)-(.+)$ ]]; then
    version="${BASH_REMATCH[1]}pre.${BASH_REMATCH[2]}"
fi
version=$(printf '%s' "$version" | LC_ALL=C sed 's/[^A-Za-z0-9._+]/./g')
[[ -n $version ]] || { echo 'Empty Arch package version.' >&2; exit 1; }
pkgrel=${ARCH_PKGREL:-1}
[[ $pkgrel =~ ^[1-9][0-9]*(\.[1-9][0-9]*)?$ ]] || { echo 'Invalid ARCH_PKGREL.' >&2; exit 1; }

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$output"
output=$(cd -- "$output" && pwd)
staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
install -m 0755 "$binary" "$staging/mystvpn"
install -m 0644 "$root/LICENSE" "$staging/LICENSE"
cp "$root/packaging/arch/PKGBUILD" "$staging/PKGBUILD"
export MYSTVPN_PKGVER=$version MYSTVPN_PKGREL=$pkgrel
MYSTVPN_BINARY_SHA256=$(sha256sum "$staging/mystvpn")
MYSTVPN_LICENSE_SHA256=$(sha256sum "$staging/LICENSE")
export MYSTVPN_BINARY_SHA256=${MYSTVPN_BINARY_SHA256%% *}
export MYSTVPN_LICENSE_SHA256=${MYSTVPN_LICENSE_SHA256%% *}
# Pin the format independently of the build host's makepkg configuration.
printf "source /etc/makepkg.conf\nPKGEXT='.pkg.tar.zst'\n" > "$staging/makepkg.conf"
(
    cd "$staging"
    # Only package an existing binary: runtime dependencies are tested separately.
    PKGDEST="$output" makepkg --config "$staging/makepkg.conf" --nodeps --force --nosign --noconfirm
)
filename="mystvpn-${version}-${pkgrel}-${arch}.pkg.tar.zst"
(cd "$output" && sha256sum "$filename" > "$filename.sha256")
