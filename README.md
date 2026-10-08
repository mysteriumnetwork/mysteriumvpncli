# mystvpn

A Linux command-line client for connecting to Mysterium VPN with WireGuard.
Sign in through your browser, choose a country, and manage your VPN connection
from the terminal.

- [Quick start](#quick-start)
- [Installation](#installation)
- [Everyday use](#everyday-use)
- [Updating](#updating)
- [Advanced setup](#advanced-setup)
- [Security](#security)
- [Development](#development)

## Quick start

You need Linux with WireGuard kernel support, Bash, and curl. The installer
installs missing dependencies on supported distributions and requests sudo
access when needed. You do not need Go to use a release build.

**1. Install the latest release.**

```sh
curl -fsSL https://github.com/mysteriumnetwork/mysteriumvpncli/releases/latest/download/install.sh | bash
```

**2. Sign in.**

```sh
sudo mystvpn auth
```

Open the URL printed in the terminal, sign in, and approve access. The command
waits for approval; the link expires after five minutes.

**3. Choose a country and connect.**

```sh
sudo mystvpn countries --ip-type residential
sudo mystvpn connect --country DE --ip-type residential
```

Replace `DE` with a country code from the list. You can also use `hosting`
instead of `residential` for both commands.

**4. Check your connection or disconnect.**

```sh
sudo mystvpn status
sudo mystvpn disconnect
```

Use the same operating-system user for authentication and all VPN commands.
The examples use `sudo` consistently because creating WireGuard interfaces
requires privileges. If you are already root, omit `sudo`. The CLI does not
elevate privileges automatically.

## Installation

### Automatic installer (recommended)

The [quick start](#quick-start) command detects your architecture and chooses
an installation method:

| System | Installation method | Executable |
| --- | --- | --- |
| Debian, Ubuntu, or another apt-based system | Debian package, installed through apt | `/usr/bin/mystvpn` |
| Other supported Linux distributions | Standalone binary from the release archive | `/usr/local/bin/mystvpn` |

If the latest release has no Debian package, the installer falls back to the
standalone binary. It verifies SHA-256 checksums before installing either format.
Download, checksum, and apt failures stop installation.

For custom destinations and dependency details, see [Advanced setup](#advanced-setup).
If you previously installed a standalone binary on an apt-based system, see
[Switching from standalone to a Debian package](#switching-from-standalone-to-a-debian-package).

### Install a Debian package manually

Download the `.deb` for your system from
[GitHub Releases](https://github.com/mysteriumnetwork/mysteriumvpncli/releases).
Check your Debian architecture with:

```sh
dpkg --print-architecture
```

Install the downloaded file with apt. For example:

```sh
sudo apt install ./mystvpn_1.2.3_amd64.deb
```

Replace the example filename with the file you downloaded. Apt installs the
runtime dependencies and places the executable at `/usr/bin/mystvpn`.

### Supported architectures

The automatic installer selects the correct architecture for you. When
downloading files manually, use these names:

| Linux architecture (`uname -m`) | Archive filename | Debian architecture |
| --- | --- | --- |
| `x86_64` / `amd64` | `mystvpn-linux-amd64.tar.gz` | `amd64` |
| `aarch64` / `arm64` | `mystvpn-linux-arm64.tar.gz` | `arm64` |
| `armv7l` / `armv8l` (32-bit ARM, ARMv7 or later) | `mystvpn-linux-arm32.tar.gz` | `armhf` |

Debian filenames follow `mystvpn_<version>_<architecture>.deb`.

## Everyday use

### Command reference

| Command | What it does |
| --- | --- |
| `mystvpn help` | Show available commands. Running `mystvpn` alone also shows help. |
| `mystvpn version` | Show the installed version. |
| `sudo mystvpn auth` | Sign in through browser approval. |
| `sudo mystvpn countries --ip-type residential` | List available country codes for an IP type. |
| `sudo mystvpn connect --country DE --ip-type residential` | Connect to a country, replacing any active connection. |
| `sudo mystvpn status` | Show the locally saved connection status. |
| `sudo mystvpn refresh` | Reconnect with the current country and IP type. |
| `sudo mystvpn disconnect` | Disconnect the VPN. |
| `sudo mystvpn logout` | Disconnect and remove stored authentication tokens. |

### Choose or change a location

List countries for the IP type you want:

```sh
sudo mystvpn countries --ip-type residential
sudo mystvpn countries --ip-type hosting
```

Country codes are listed alphabetically, with up to ten codes per line.
To connect, provide both a two-letter country code and an IP type
(`residential` or `hosting`):

```sh
sudo mystvpn connect --country DE --ip-type residential
```

Run `connect` again with another country or IP type to replace the active
connection. You do not need to disconnect first. The client requests the new
configuration before bringing the existing tunnel down.

A successful connection prints:

```text
exit_ip: 1.2.3.4
country: DE
city: berlin
```

### Check or refresh a connection

```sh
sudo mystvpn status
```

Example output:

```text
connected: yes
IP address: 1.2.3.4
country: DE
city: berlin
```

Status reads local state without making an API request; it is not a live
connectivity check. With no active session, it prints `connected: no`.

To reconnect using the saved country and IP type:

```sh
sudo mystvpn refresh
```

Refresh reuses the saved WireGuard keypair and prints the new connection
metadata. It requires an active session.

### Disconnect or sign out

```sh
sudo mystvpn disconnect
```

Disconnect closes the remote connection, brings down the local WireGuard
tunnel, and removes the managed configuration and active session state.

To also remove your stored authentication tokens:

```sh
sudo mystvpn logout
```

Logout disconnects an active tunnel locally and remotely before removing tokens.

## Updating

### Update with the installer

Rerun the [quick start installation command](#quick-start) to install the latest
release. On apt-based systems, it upgrades the Debian package; for standalone
installations, it replaces the binary in the installation directory.

If you used `MYSTVPN_INSTALL_DIR`, use the same setting again when updating
(see [Custom installation directory](#custom-installation-directory)). The
installer chooses its method on each run rather than detecting how you
previously installed the program.

Check the installed version afterward:

```sh
mystvpn version
```

### Update a manually installed Debian package

Download the newer `.deb` from
[GitHub Releases](https://github.com/mysteriumnetwork/mysteriumvpncli/releases)
and run `sudo apt install ./<downloaded-filename>.deb` with its actual filename.
You can also use the automatic installer.

### Switching from standalone to a Debian package

An older `/usr/local/bin/mystvpn` can take precedence over the packaged
`/usr/bin/mystvpn`. The installer warns about this but leaves the old file in place.

After installing the Debian package, remove the previous standalone binary:

```sh
sudo rm /usr/local/bin/mystvpn
hash -r
mystvpn version
```

If you used a custom directory, remove that old copy instead. Use
`command -v mystvpn` to check which executable your shell finds.

## Advanced setup

### Custom installation directory

Set `MYSTVPN_INSTALL_DIR` to an absolute path:

```sh
curl -fsSL https://github.com/mysteriumnetwork/mysteriumvpncli/releases/latest/download/install.sh | MYSTVPN_INSTALL_DIR="$HOME/.local/bin" bash
```

This selects standalone installation even on apt-based systems. Add the
directory to your `PATH` or invoke the binary by its full path. If sudo does
not search your custom directory, use the full path for every command, for example:

```sh
sudo "$HOME/.local/bin/mystvpn" auth
sudo "$HOME/.local/bin/mystvpn" connect --country DE --ip-type residential
```

A writable installation directory avoids needing root to copy the binary,
but installing system dependencies and managing the VPN can still require privileges.

### Dependencies

All installation methods require a Linux kernel with WireGuard support.
The installer does not change or upgrade the kernel.

| Purpose | Required tools or packages |
| --- | --- |
| WireGuard tunnel | `wireguard-tools` (`wg` and `wg-quick`) |
| Network configuration | `iproute2` (called `iproute` on some distributions) and `sysctl` from `procps` / `procps-ng` |
| DNS configuration | `resolvconf` or `openresolv` |
| Routing rules | `nftables` or `iptables` |
| HTTPS downloads | `curl` and CA certificates |
| Standalone archive installation | Bash, `tar`, `gzip`, and `coreutils` |

The Debian package declares its runtime dependencies so apt can install them.
For standalone installation, the installer checks for required commands and
installs missing packages using `apt-get`, `dnf`, `yum`, `pacman`, or `zypper`.
On other distributions, install missing dependencies manually and rerun it.
Bash and curl must already be available to run the installation command.

## Security

- Authentication uses a browser approval URL; the CLI does not open the browser
  automatically. Access and refresh tokens are saved in owner-only files in the
  current user's configuration directory, along with pending activation state.
- Access tokens are attached automatically to API calls. An unauthorized response
  triggers one refresh-token exchange and one retry.
- The app-owned WireGuard keypair, active session, and generated configuration
  have owner-only permissions. Connection replacements and refreshes reuse the
  keypair and managed configuration path.
- WireGuard private keys and authentication tokens are never included in normal
  command output or debug HTTP logs.
- The generated WireGuard configuration contains the private key. Do not copy it
  or make it accessible to other users.
- Refresh and disconnect accept only WireGuard configuration paths managed by
  `mystvpn`.

## Development

### Build from source

Go 1.27 or later is required. From the repository root:

```sh
go build ./cmd/mystvpn
```

This creates `./mystvpn`. Running it on Linux requires the same runtime
dependencies and privileges as a release build.

### Run tests

```sh
go test ./...
```

The Go test suite uses local mock APIs and a fake WireGuard runner. It does not
contact external services or modify real network interfaces.

Installer and Debian packaging checks are also available:

```sh
python3 test/install_test.py
python3 test/package_deb_test.py
```

### CI and releases

GitHub Actions runs Go tests with the race detector, shell checks, and installer
and packaging tests for every pull request. Pushing any tag runs those checks,
then builds Linux binaries for amd64, arm32 (ARMv7), and arm64 with CGO disabled.
The tag is embedded in `mystvpn version`.

After all builds succeed, CI publishes release archives, Debian packages, and
their `.sha256` files. New releases remain drafts until all assets have been
uploaded. The installer downloads packages from the latest release.

Each tagged workflow also provides a `mystvpn-linux-<architecture>` artifact
containing the archive, matching Debian package, and checksums. Extract an
archive with `tar -xzf mystvpn-linux-<architecture>.tar.gz` to preserve the
executable's permissions.

Debian package versions omit the tag's leading `v` and use `~` for prerelease
separators.
