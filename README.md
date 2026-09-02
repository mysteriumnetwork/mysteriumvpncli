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
./mystvpn --help
./mystvpn --version
```
