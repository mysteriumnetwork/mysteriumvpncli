package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

func runConfig(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {}
	profileName := flags.String("profile", "", "profile to read or update (defaults to active)")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(stderr, `mystvpn config: use "mystvpn help" for usage`)
		return 2
	}
	args = flags.Args()
	if len(args) > 0 && args[0] == "profile" {
		if *profileName != "" {
			fmt.Fprintln(stderr, "mystvpn config: --profile cannot be combined with config profile; pass the profile name after the action")
			return 2
		}
		return runConfigProfile(args[1:], stdout, stderr)
	}
	// Validate the command before reading a potentially broken file. In particular,
	// config path remains available to help locate a file that needs repair.
	action := "get"
	if len(args) > 0 {
		action = args[0]
	}
	valid := (action == "get" && len(args) <= 2) ||
		(action == "effective" && len(args) == 1) ||
		(action == "path" && len(args) == 1) ||
		(action == "set" && len(args) == 3) ||
		(action == "unset" && len(args) == 2)
	if !valid {
		fmt.Fprintln(stderr, "mystvpn config: usage: config [--profile <name>] [get [key] | effective | set <key> <value> | unset <key> | path]; config profile [list | current | create <name> | use <name> | delete <name>]")
		return 2
	}
	if len(args) >= 2 {
		if _, err := config.DefaultSettings().Get(args[1]); err != nil {
			fmt.Fprintf(stderr, "mystvpn config: %v\n", err)
			return 2
		}
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn config: %v\n", err)
		return 1
	}
	if action == "path" {
		fmt.Fprintln(stdout, store.Path())
		return 0
	}
	document, err := store.LoadDocument()
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn config: %v\n", err)
		return 1
	}
	if action == "set" || action == "unset" {
		if action == "set" {
			err = document.Set(*profileName, args[1], args[2])
		} else {
			err = document.Unset(*profileName, args[1])
		}
		if err != nil {
			fmt.Fprintf(stderr, "mystvpn config: %v\n", err)
			return 2
		}
		if err := store.SaveDocument(document); err != nil {
			fmt.Fprintf(stderr, "mystvpn config: %v\n", err)
			return 1
		}
		return 0
	}

	var output any
	if action == "get" && len(args) < 2 {
		// Saved overrides can be inspected even while their values need repair.
		output, err = document.Saved(*profileName)
	} else {
		var settings config.Settings
		settings, err = document.Effective(*profileName)
		if err != nil {
			fmt.Fprintf(stderr, "mystvpn config: %v\n", err)
			return 2
		}
		if action == "get" {
			output, err = settings.Get(args[1])
		} else {
			values := make(map[string]any)
			for _, key := range config.Keys() {
				value, valueErr := settings.Get(key)
				if valueErr != nil {
					fmt.Fprintf(stderr, "mystvpn config: %v\n", valueErr)
					return 2
				}
				values[key] = value
			}
			output = values
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn config: %v\n", err)
		return 2
	}
	if text, ok := output.(string); ok {
		fmt.Fprintln(stdout, text)
		return 0
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(stderr, "mystvpn config: write output: %v\n", err)
		return 1
	}
	return 0
}
