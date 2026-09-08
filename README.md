# mystvpn

`mystvpn` is a command-line client for Mysterium VPN on Linux.

This repository contains the early MVP command structure, authentication,
country discovery, and WireGuard connection flow.

## Requirements

- Go 1.27 or later
- `wg-quick` for establishing WireGuard connections

## Build

From the repository root, run:

```sh
go build ./cmd/mystvpn
```

The command creates a `mystvpn` executable in the repository root.

## Usage

```sh
./mystvpn
./mystvpn help
./mystvpn version
./mystvpn auth --username alice
./mystvpn countries --ip-type residential
./mystvpn countries --ip-type hosting
./mystvpn connect --country DE --ip-type residential
./mystvpn status
./mystvpn logout
```

The `auth` command signs in with a username and password and stores the returned
tokens in owner-only files under the user's configuration directory. If
`--password` is omitted, the command securely prompts for it when run in an
interactive terminal. The `logout` command removes the stored tokens.

The `countries` command prints the available country codes alphabetically, with
up to ten codes per line.

The `connect` command creates or reuses an app-owned WireGuard keypair, requests
a connection, and immediately runs `wg-quick up`. It does not elevate privileges;
run `mystvpn` with the permissions required by your system.

The `refresh`, `status`, and `disconnect` commands remain placeholders.
