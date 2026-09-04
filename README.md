# mystvpn

`mystvpn` is a command-line client for Mysterium VPN on Linux.

This repository currently contains the initial project skeleton. Authentication,
network communication, proxying, and WireGuard support are not implemented yet.

## Requirements

- Go 1.27 or later

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
./mystvpn connect
./mystvpn status
./mystvpn logout
```

The `auth` command signs in with a username and password and stores the returned
tokens in owner-only files under the user's configuration directory. If
`--password` is omitted, the command securely prompts for it when run in an
interactive terminal. The `logout` command removes the stored tokens.

The `countries`, `connect`, `refresh`, `status`, and `disconnect` commands remain
placeholders and do not perform API or VPN operations yet.
