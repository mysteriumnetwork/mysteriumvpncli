#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <binary> <tag> <amd64|armhf|arm64> <output-directory>" >&2
    exit 1
fi

binary=$1
tag=$2
arch=$3
output=$4
case "$arch" in
    amd64|armhf|arm64) ;;
    *) echo "Unsupported Debian architecture: $arch" >&2; exit 1 ;;
esac

# Keep arbitrary release tags usable, while sorting SemVer prereleases before
# their final release (v1.2.3-rc.1 becomes 1.2.3~rc.1).
version=${tag#v}
version=$(printf '%s' "$version" | LC_ALL=C sed 's/[^A-Za-z0-9.+~-]/+/g; s/-/~/g')
[[ $version =~ ^[0-9] ]] || version="0~${version}"
dpkg --validate-version "$version"

mkdir -p "$output"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/DEBIAN" "$staging/usr/bin"
install -m 0755 "$binary" "$staging/usr/bin/mystvpn"
cat > "$staging/DEBIAN/control" <<EOF
Package: mystvpn
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: Mysterium Network <support@mysterium.network>
Homepage: https://github.com/mysteriumnetwork/mysteriumvpncli
Depends: ca-certificates, wireguard-tools, iproute2, procps, resolvconf | openresolv, nftables | iptables
Description: Mysterium VPN command-line client
 Connect to Mysterium VPN using WireGuard from the Linux command line.
EOF
chmod 0755 "$staging"
chmod 0644 "$staging/DEBIAN/control"
filename="mystvpn_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "$staging" "$output/$filename"
(cd "$output" && sha256sum "$filename" > "$filename.sha256")
