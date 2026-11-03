#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: APT_REPO_UPLOAD_URL=https://host/api/packages APT_REPO_UPLOAD_TOKEN=... $0 <package.deb>..." >&2
    exit 1
fi
: "${APT_REPO_UPLOAD_URL:?Set the repository upload endpoint}"
: "${APT_REPO_UPLOAD_TOKEN:?Set the repository upload token}"
case "$APT_REPO_UPLOAD_URL" in
    https://*/api/packages|http://127.0.0.1:*/api/packages|http://localhost:*/api/packages) ;;
    *) echo "Upload URL must use HTTPS (HTTP is allowed for localhost port-forwarding)." >&2; exit 1 ;;
esac
if [[ $APT_REPO_UPLOAD_TOKEN == *[$'\r\n']* ]]; then
    echo "Upload token must not contain newlines." >&2
    exit 1
fi
for package in "$@"; do
    [[ -f $package && $package == *.deb ]] || { echo "Not a .deb file: $package" >&2; exit 1; }
done

# Keep credentials out of curl's process arguments. Do not run this script with bash -x.
umask 077
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
printf 'Authorization: Bearer %s\nContent-Type: application/vnd.debian.binary-package\n' "$APT_REPO_UPLOAD_TOKEN" > "$headers"
unset APT_REPO_UPLOAD_TOKEN
for package in "$@"; do
    printf 'Publishing %s\n' "$package"
    curl --fail-with-body --silent --show-error \
        --connect-timeout 15 --max-time 600 --retry 3 --retry-all-errors \
        --header "@$headers" --data-binary "@$package" "$APT_REPO_UPLOAD_URL"
done
