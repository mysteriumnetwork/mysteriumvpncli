// Command mystvpn provides the Mysterium VPN command-line interface.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
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
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	root := flag.NewFlagSet("mystvpn", flag.ContinueOnError)
	root.SetOutput(stderr)
	showVersion := root.Bool("version", false, "print version information")
	root.Usage = func() {
		writeUsage(stderr)
	}

	cfg, err := config.Load(root, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "mystvpn %s\n", version)
		return 0
	}

	commandArgs := root.Args()
	if len(commandArgs) == 0 {
		writeUsage(stdout)
		return 0
	}
	if len(commandArgs) > 1 {
		fmt.Fprintf(stderr, "mystvpn: unexpected argument %q\n\n", commandArgs[1])
		writeUsage(stderr)
		return 2
	}
	if !isCommand(commandArgs[0]) {
		fmt.Fprintf(stderr, "mystvpn: unknown command %q\n\n", commandArgs[0])
		writeUsage(stderr)
		return 2
	}

	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn: %v\n", err)
		return 2
	}

	return runCommand(commandArgs[0], apiClient, stdout)
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
	fmt.Fprintln(output, "  mystvpn [options]")
	fmt.Fprintln(output, "  mystvpn [options] <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	for _, command := range commands {
		fmt.Fprintf(output, "  %s\n", command)
	}
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Options:")
	fmt.Fprintf(output, "  --api-url <url>  base URL for the API (default %q)\n", config.DefaultAPIURL)
	fmt.Fprintln(output, "  --debug          enable debug logging")
	fmt.Fprintln(output, "  --help           print usage information")
	fmt.Fprintln(output, "  --version        print version information")
}
