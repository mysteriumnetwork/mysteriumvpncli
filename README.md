# mystvpn

`mystvpn` is a Linux command-line client for connecting to Mysterium VPN with
WireGuard.

The MVP supports email magic-link authentication, country discovery,
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

## Usage

```sh
./mystvpn help
./mystvpn version

./mystvpn auth --email alice@example.com
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
./mystvpn auth --email alice@example.com
```

The command requests a magic link and securely stores the short-lived state,
nonce, and PKCE verifier needed to complete authentication. Browser callback
handling is not part of this foundation commit and will be added separately.

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

- Access and refresh tokens, along with pending magic-link PKCE state, are
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
