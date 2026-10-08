# mystvpn

`mystvpn` is a Linux command-line client for connecting to Mysterium VPN with
WireGuard.

The MVP supports browser activation authentication, country discovery,
connection establishment, refresh, local status, disconnect, and logout.

## Requirements

- Go 1.27 or later to build from source
- `wg-quick` installed on the target Linux system
- Permission to create and remove WireGuard interfaces

`mystvpn` does not elevate privileges automatically. Run all commands that use
persisted credentials or connection state under the same operating-system user.

## Build

From the repository root:

```sh
go build ./cmd/mystvpn
```

This creates a `mystvpn` executable in the repository root.

## Install

On Debian or Ubuntu, download the `.deb` package for your architecture from
[GitHub Releases](https://github.com/mysteriumnetwork/mysteriumvpncli/releases)
and install it with apt, for example:

```sh
sudo apt install ./mystvpn_1.2.3_amd64.deb
```

Replace the example filename with the downloaded package. Packages are available
for amd64, armhf (ARMv7), and arm64 and install `mystvpn` to `/usr/bin`. Apt installs
the required CA certificates, WireGuard tools, iproute2, procps, resolvconf (or
openresolv), and nftables (or iptables). The Linux kernel must support WireGuard.
If switching from the shell installer, remove its `/usr/local/bin/mystvpn` first
so it does not take precedence over the packaged executable.

Install the latest GitHub release on Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/mysteriumnetwork/mysteriumvpncli/HEAD/install.sh | bash
```

The installer supports amd64, arm32 (ARMv7), and arm64. On apt-based systems it
prefers the release's Debian package, verifies its SHA-256 checksum, and uses
apt to install `mystvpn` to `/usr/bin` along with its dependencies. If the release
has no Debian package, or on other distributions, it verifies and installs the
archive to `/usr/local/bin`. Download, checksum, and apt failures stop installation.
Re-running it updates to the latest release. Override the destination with
`MYSTVPN_INSTALL_DIR` (an absolute path):

```sh
curl -fsSL https://raw.githubusercontent.com/mysteriumnetwork/mysteriumvpncli/HEAD/install.sh | MYSTVPN_INSTALL_DIR="$HOME/.local/bin" bash
```

Setting `MYSTVPN_INSTALL_DIR` selects archive installation even on apt-based
systems. When switching from an older archive installation, remove
`/usr/local/bin/mystvpn` so it does not shadow the Debian package's executable.

For archive installation, it checks for curl, tar, gzip, coreutils, WireGuard tools (`wg` and `wg-quick`),
iproute, sysctl, resolvconf, and either nftables or iptables. Missing dependencies are
installed using apt-get, dnf, yum, pacman, or zypper, with sudo when required.
On other distributions, install the missing dependencies manually and rerun.
The initial `curl` command and Bash must already be available. Your Linux kernel
must support WireGuard; the installer does not change or upgrade the kernel.

Use the same privileged user for authentication and VPN commands, for example
`sudo mystvpn auth` followed by `sudo mystvpn connect --country DE --ip-type residential`.

## Usage

```sh
./mystvpn help
./mystvpn version

./mystvpn auth
./mystvpn countries --ip-type residential
./mystvpn connect --country DE --ip-type residential
./mystvpn status
./mystvpn refresh
./mystvpn disconnect
./mystvpn logout
```

Running `mystvpn` without a command also prints the command overview.

### Authentication

```sh
./mystvpn auth
```

The command creates a short-lived activation and prints a browser URL. Open the
URL, sign in if needed, and approve access. The CLI does not open the browser
automatically; it polls the API until approval succeeds or the five-minute
activation expires. It securely stores the resulting access and refresh
tokens. The access token is attached automatically to later API calls; an
unauthorized response triggers one refresh-token exchange and retries the
request once.

### Countries

```sh
./mystvpn countries --ip-type residential
./mystvpn countries --ip-type hosting
```

The command prints available two-letter country codes alphabetically, with up
to ten codes per line.

### Connect

```sh
./mystvpn connect --country DE --ip-type residential
```

Both flags are required. The IP type must be `residential` or `hosting`, and the
country must be a two-letter code. The command creates or reuses the app-owned
WireGuard keypair, requests a configuration, and runs `wg-quick up`.

If a connection is already active, `connect` replaces it using the saved
WireGuard keypair. It requests the new configuration before bringing the
existing tunnel down, updates the managed configuration at the same path, and
then brings the tunnel back up. An explicit remote disconnect is not required
for this replacement flow.

Successful output contains only connection metadata:

```text
exit_ip: 1.2.3.4
country: DE
city: berlin
```

### Active session

`mystvpn status` reads local state without making an API request:

```text
connected: yes
IP address: 1.2.3.4
country: DE
city: berlin
```

When there is no active session it prints `connected: no`.

`mystvpn refresh` reconnects using the active session's saved country, IP type,
and WireGuard keypair. It replaces the managed configuration at the same path,
brings the tunnel back up, and prints the new connection metadata.

`mystvpn disconnect` closes the remote connection using the saved public key,
runs `wg-quick down`, removes the managed WireGuard configuration, and clears
the active session state.

### Logout

```sh
./mystvpn logout
```

If a tunnel is active, logout disconnects it locally and remotely before
removing the locally stored authentication and refresh tokens.

## Security

- Access and refresh tokens, along with pending browser activation state, are
  stored in owner-only files in the current user's configuration directory.
- The app-owned WireGuard keypair, active session, and generated WireGuard
  configuration are stored with owner-only permissions.
- WireGuard private keys and authentication tokens are never included in normal
  command output or debug HTTP logs.
- The generated WireGuard configuration contains the private key and should not
  be copied or made accessible to other users.
- Only WireGuard configuration paths managed by `mystvpn` are accepted by the
  refresh and disconnect commands.

## Tests

```sh
go test ./...
```

The test suite uses local mock APIs and a fake WireGuard runner. It does not
contact external services or modify real network interfaces.

## CI

GitHub Actions runs the test suite with the race detector for every pull request.
Pushing any tag runs the tests, then builds Linux binaries for amd64, arm32
(ARMv7), and arm64 with CGO disabled. The tag is embedded in `mystvpn version`.

After all builds succeed, CI publishes a GitHub release for the tag containing
the archives, Debian packages, and their `.sha256` files. New releases remain drafts until all
assets have been uploaded. The installer downloads from the latest release.

Download the `mystvpn-linux-<architecture>` artifacts from the tagged workflow
run. Each contains a `.tar.gz` archive with the executable's permissions
preserved; extract it with `tar -xzf mystvpn-linux-<architecture>.tar.gz`. Each
artifact also includes the matching `.deb` package and checksum. Debian package
versions omit the tag's leading `v` and use `~` for prerelease separators.
