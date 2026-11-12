#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: ARCH_REPO_UPLOAD_URL=https://host/api/arch/packages ARCH_REPO_UPLOAD_TOKEN=... $0 <package.pkg.tar.zst>..." >&2
    exit 1
fi
: "${ARCH_REPO_UPLOAD_URL:?Set the repository upload endpoint}"
: "${ARCH_REPO_UPLOAD_TOKEN:?Set the repository upload token}"
case "$ARCH_REPO_UPLOAD_URL" in
    https://*/api/arch/packages|http://127.0.0.1:*/api/arch/packages|http://localhost:*/api/arch/packages) ;;
    *) echo "Upload URL must use HTTPS (HTTP is allowed for localhost port-forwarding)." >&2; exit 1 ;;
esac
if [[ $ARCH_REPO_UPLOAD_TOKEN == *[$'\r\n']* ]]; then
    echo "Upload token must not contain newlines." >&2
    exit 1
fi
for package in "$@"; do
    [[ -f $package && $package == *.pkg.tar.zst ]] || { echo "Not a .pkg.tar.zst file: $package" >&2; exit 1; }
done

# Keep credentials out of curl's process arguments. Do not run this script with bash -x.
umask 077
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
printf 'Authorization: Bearer %s\nContent-Type: application/octet-stream\n' "$ARCH_REPO_UPLOAD_TOKEN" > "$headers"
unset ARCH_REPO_UPLOAD_TOKEN
for package in "$@"; do
    printf 'Publishing %s\n' "$package"
    curl --fail-with-body --silent --show-error \
        --connect-timeout 15 --max-time 600 --retry 3 --retry-all-errors \
        --header "@$headers" --data-binary "@$package" "$ARCH_REPO_UPLOAD_URL"
done
