// Command mystvpn provides the Mysterium VPN command-line interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"golang.org/x/term"
)

var version = "dev"

var commands = []string{
	"auth",
	"countries",
	"connect",
	"refresh",
	"status",
	"disconnect",
	"logout",
	"help",
	"version",
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	return runWithConfig(args, stdin, stdout, stderr, config.Load())
}

func runWithConfig(args []string, stdin *os.File, stdout, stderr io.Writer, cfg config.Config) int {
	if len(args) == 0 {
		writeUsage(stdout)
		return 0
	}
	if !isCommand(args[0]) {
		fmt.Fprintf(stderr, "mystvpn: unknown command %q\n", args[0])
		return 2
	}

	switch args[0] {
	case "auth":
		return runAuth(args[1:], cfg, stdin, stdout, stderr)
	case "logout":
		return runLogout(args[1:], stdout, stderr)
	case "help":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "mystvpn help: unexpected argument %q\n", args[1])
			return 2
		}
		writeUsage(stdout)
		return 0
	case "version":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "mystvpn version: unexpected argument %q\n", args[1])
			return 2
		}
		fmt.Fprintf(stdout, "mystvpn %s\n", version)
		return 0
	}

	if len(args) > 1 {
		fmt.Fprintf(stderr, "mystvpn: unexpected argument %q\n\n", args[1])
		writeUsage(stderr)
		return 2
	}

	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn: %v\n", err)
		return 2
	}

	return runCommand(args[0], apiClient, stdout)
}

func runAuth(args []string, cfg config.Config, stdin *os.File, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("auth", flag.ContinueOnError)
	flags.SetOutput(stderr)
	username := flags.String("username", "", "account username")
	password := flags.String("password", "", "account password")
	flags.Usage = func() {}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, `mystvpn auth: help flags are not supported; use "mystvpn help"`)
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "mystvpn auth: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if strings.TrimSpace(*username) == "" {
		fmt.Fprintln(stderr, "mystvpn auth: --username is required")
		return 2
	}

	passwordProvided := false
	flags.Visit(func(option *flag.Flag) {
		if option.Name == "password" {
			passwordProvided = true
		}
	})
	if !passwordProvided {
		promptedPassword, err := promptPassword(stdin, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "mystvpn auth: %v\n", err)
			return 2
		}
		*password = promptedPassword
	}
	if *password == "" {
		fmt.Fprintln(stderr, "mystvpn auth: --password must not be empty")
		return 2
	}

	service, err := newAuthService(cfg)
	if err != nil {
		writeAuthenticationError(stderr, err)
		return 1
	}
	if err := service.Login(context.Background(), *username, *password); err != nil {
		writeAuthenticationError(stderr, err)
		return 1
	}

	fmt.Fprintln(stdout, "Authentication successful.")
	return 0
}

func writeAuthenticationError(output io.Writer, err error) {
	var statusErr *auth.HTTPStatusError
	if errors.As(err, &statusErr) {
		fmt.Fprintf(output, "mystvpn auth: HTTP status %d\n", statusErr.StatusCode)
		return
	}
	fmt.Fprintln(output, "mystvpn auth: authentication failed")
}

func runLogout(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "mystvpn logout: unexpected argument %q\n", args[0])
		return 2
	}

	store, err := auth.NewDefaultFileStore()
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn logout: %v\n", err)
		return 1
	}
	if err := store.ClearTokens(); err != nil {
		fmt.Fprintf(stderr, "mystvpn logout: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "Logout successful.")
	return 0
}

func newAuthService(cfg config.Config) (*auth.Service, error) {
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		return nil, err
	}
	sentinelClient, err := client.New(cfg.SentinelURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		return nil, err
	}
	return auth.NewService(sentinelClient, store, cfg.Pool), nil
}

func promptPassword(stdin *os.File, output io.Writer) (string, error) {
	if stdin == nil || !term.IsTerminal(int(stdin.Fd())) {
		return "", errors.New("password is required; provide --password when standard input is not interactive")
	}

	fmt.Fprint(output, "Password: ")
	password, err := term.ReadPassword(int(stdin.Fd()))
	fmt.Fprintln(output)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(password), nil
}

func runCommand(name string, _ *client.Client, stdout io.Writer) int {
	fmt.Fprintf(stdout, "mystvpn %s: not implemented yet\n", name)
	return 0
}

func isCommand(name string) bool {
	for _, command := range commands {
		if name == command {
			return true
		}
	}
	return false
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "mystvpn - Mysterium VPN CLI for Linux")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  mystvpn <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	for _, command := range commands {
		if command == "auth" {
			fmt.Fprintln(output, "  auth --username <name> [--password <value>]")
			continue
		}
		fmt.Fprintf(output, "  %s\n", command)
	}
}
