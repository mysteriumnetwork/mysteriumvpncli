// Command mystvpn provides the Mysterium VPN command-line interface.
package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version information")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: mystvpn [options]\n\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("mystvpn %s\n", version)
		return
	}

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "mystvpn: unexpected argument %q\n\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}

	fmt.Println("mystvpn - Mysterium VPN CLI for Linux")
	fmt.Println(`Run "mystvpn --help" for usage.`)
}
