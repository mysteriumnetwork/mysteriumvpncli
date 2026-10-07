#!/usr/bin/env bash
# Install the latest mystvpn release. Safe to invoke with curl | bash.

main() (
    set -euo pipefail
    export PATH="${PATH}:/usr/local/sbin:/usr/sbin:/sbin"
    local repository=mysteriumnetwork/mysteriumvpncli
    local install_dir=${MYSTVPN_INSTALL_DIR:-/usr/local/bin}
    local arch manager command package temp_dir release_url download_url archive
    local debarch debversion debfile status
    local -a packages=() privilege=()

    fail() { printf 'mystvpn installer: %s\n' "$*" >&2; exit 1; }
    as_root() {
        if (( EUID != 0 )) && (( ${#privilege[@]} == 0 )); then
            command -v sudo >/dev/null || fail 'Root access is required; install sudo or run this script as root.'
            if ! sudo -n true 2>/dev/null; then
                sudo -v || fail 'Unable to obtain sudo access.'
            fi
            privilege=(sudo -n)
        fi
        "${privilege[@]}" "$@" </dev/null
    }

    [[ $(uname -s) == Linux ]] || fail 'Only Linux is supported.'
    case $(uname -m) in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        armv7l|armv8l) arch=arm32 ;;
        *) fail "Unsupported architecture: $(uname -m). ARM32 requires ARMv7 or later." ;;
    esac
    [[ $install_dir == /* ]] || fail 'MYSTVPN_INSTALL_DIR must be an absolute path.'

    manager=''
    for command in apt-get dnf yum pacman zypper; do
        if command -v "$command" >/dev/null; then
            manager=$command
            break
        fi
    done

    install_archive_dependencies() {
        # wg-quick also uses ip, resolvconf for DNS, and nft or iptables for routes.
        for command in curl tar gzip sha256sum install wg wg-quick ip sysctl resolvconf iptables; do
            command -v "$command" >/dev/null && continue
            if [[ $command == iptables ]] && command -v nft >/dev/null; then
                continue
            fi
            [[ -n $manager ]] || fail "Missing $command and no supported package manager found (apt-get, dnf, yum, pacman, zypper)."
            case $command in
                curl|tar|gzip|iptables) package=$command ;;
                sha256sum|install) package=coreutils ;;
                wg|wg-quick) package=wireguard-tools ;;
                ip)
                    case $manager in
                        apt-get|pacman) package=iproute2 ;;
                        *) package=iproute ;;
                    esac ;;
                sysctl)
                    case $manager in
                        apt-get|zypper) package=procps ;;
                        *) package=procps-ng ;;
                    esac ;;
                resolvconf)
                    case $manager in
                        apt-get) package=resolvconf ;;
                        *) package=openresolv ;;
                    esac ;;
            esac
            # Avoid requesting wireguard-tools or coreutils twice.
            case " ${packages[*]} " in
                *" $package "*) ;;
                *) packages+=("$package") ;;
            esac
        done

        if (( ${#packages[@]} )); then
            printf 'Installing dependencies: %s\n' "${packages[*]}"
            case $manager in
                apt-get)
                    as_root apt-get update
                    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" ca-certificates ;;
                dnf|yum) as_root "$manager" install -y "${packages[@]}" ca-certificates ;;
                pacman) as_root pacman -S --needed --noconfirm "${packages[@]}" ca-certificates ;;
                zypper) as_root zypper --non-interactive install "${packages[@]}" ca-certificates ;;
            esac
        fi
        for command in curl tar gzip sha256sum install wg wg-quick ip sysctl resolvconf; do
            command -v "$command" >/dev/null || fail "Dependency $command is still missing after installation."
        done
        command -v nft >/dev/null || command -v iptables >/dev/null || fail 'nft or iptables is required.'

    }

    verify_checksum() {
        local file=$1 checksum actual
        read -r checksum _ < "$temp_dir/${file}.sha256"
        [[ $checksum =~ ^[[:xdigit:]]{64}$ ]] || fail 'Invalid release checksum.'
        actual=$(sha256sum "$temp_dir/$file")
        [[ ${actual%% *} == "$checksum" ]] || fail 'Release checksum verification failed.'
    }

    # Bootstrap downloads before letting apt resolve packaged runtime dependencies.
    if [[ $manager == apt-get && -z ${MYSTVPN_INSTALL_DIR:-} ]]; then
        for command in curl sha256sum; do
            if ! command -v "$command" >/dev/null; then
                as_root apt-get update
                as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y curl coreutils ca-certificates
                break
            fi
        done
        command -v curl >/dev/null || fail 'Dependency curl is still missing after installation.'
        command -v sha256sum >/dev/null || fail 'Dependency sha256sum is still missing after installation.'
    fi

    if [[ $manager != apt-get || -n ${MYSTVPN_INSTALL_DIR:-} ]]; then
        install_archive_dependencies
    fi

    temp_dir=$(mktemp -d)
    trap 'rm -rf -- "$temp_dir"' EXIT
    printf 'Finding latest release for %s...\n' "$arch"
    release_url=$(curl --fail --silent --show-error --location --retry 3 \
        --proto '=https' --proto-redir '=https' --output /dev/null --write-out '%{url_effective}' \
        "https://github.com/${repository}/releases/latest") || fail 'Could not find the latest release.'
    case $release_url in
        "https://github.com/${repository}/releases/tag/"*) ;;
        *) fail "Unexpected latest release URL: $release_url" ;;
    esac
    download_url="${release_url/\/tag\//\/download\/}"

    if [[ $manager == apt-get && -z ${MYSTVPN_INSTALL_DIR:-} ]]; then
        debarch=$arch
        [[ $arch != arm32 ]] || debarch=armhf
        debversion=${release_url##*/}
        debversion=${debversion#v}
        debversion=$(printf '%s' "$debversion" | LC_ALL=C sed 's/[^A-Za-z0-9.+~-]/+/g; s/-/~/g')
        [[ $debversion =~ ^[0-9] ]] || debversion="0~${debversion}"
        debfile="mystvpn_${debversion}_${debarch}.deb"
        status=$(curl --fail --silent --show-error --location --retry 3 \
            --proto '=https' --proto-redir '=https' --write-out '%{http_code}' \
            --output "$temp_dir/$debfile" "$download_url/$debfile") || {
            [[ $status == 404 ]] || fail "Could not download $debfile."
        }
        if [[ $status == 200 ]]; then
            curl --fail --silent --show-error --location --retry 3 \
                --proto '=https' --proto-redir '=https' \
                --output "$temp_dir/${debfile}.sha256" "$download_url/${debfile}.sha256" \
                || fail "Could not download ${debfile}.sha256."
            verify_checksum "$debfile"
            # Allow apt's unprivileged download helper to read the local package.
            chmod 0755 "$temp_dir"
            chmod 0644 "$temp_dir/$debfile"
            as_root apt-get update
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$temp_dir/$debfile"
            printf 'Installed mystvpn to /usr/bin/mystvpn using apt.\n'
            if [[ -e /usr/local/bin/mystvpn ]]; then
                printf 'Remove the previous /usr/local/bin/mystvpn to use the packaged executable.\n'
            fi
            printf 'Run VPN commands with root privileges, using the same user for auth and connection state.\n'
            exit 0
        fi
        [[ $status == 404 ]] || fail "Unexpected download status for $debfile: $status"
        printf 'No Debian package in this release; installing the archive.\n'
        install_archive_dependencies
    fi

    archive="mystvpn-linux-${arch}.tar.gz"
    for package in "$archive" "${archive}.sha256"; do
        curl --fail --silent --show-error --location --retry 3 \
            --proto '=https' --proto-redir '=https' \
            --output "$temp_dir/$package" "$download_url/$package" || fail "Could not download $package."
    done
    # Check only the expected file, never paths supplied by the checksum file.
    verify_checksum "$archive"
    tar -xzf "$temp_dir/$archive" -C "$temp_dir" mystvpn
    [[ -f $temp_dir/mystvpn && ! -L $temp_dir/mystvpn ]] || fail 'Release archive does not contain a regular mystvpn binary.'

    if [[ -d $install_dir && -w $install_dir ]]; then
        install -m 0755 "$temp_dir/mystvpn" "$install_dir/mystvpn"
    else
        as_root install -d -m 0755 "$install_dir"
        as_root install -m 0755 "$temp_dir/mystvpn" "$install_dir/mystvpn"
    fi
    printf 'Installed mystvpn to %s/mystvpn\n' "$install_dir"
    printf 'Run VPN commands with root privileges, using the same user for auth and connection state.\n'
)

main "$@"
