package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

type helpTopic struct {
	name        string
	usage       string
	summary     string
	description string
	flags       string
	examples    string
	children    []helpTopic
}

var helpTopics = []helpTopic{
	{
		name: "auth", usage: "auth", summary: "Sign in through browser approval.",
		description: "Open the printed URL, sign in, and approve access. This command waits for\napproval; the link expires after five minutes. Use the same operating-system\nuser for authentication and all VPN commands.",
		examples:    "sudo mystvpn auth",
	},
	{
		name: "config", usage: "config [--profile <name>] [command]", summary: "View or change connection settings and profiles.",
		description: "With no command, print the active profile's saved overrides as JSON.\nUse effective to include built-in defaults. Changes apply to the next connect\nor refresh; they do not change a running connection.",
		flags:       "--profile <name>  Profile to read or update (default: active profile).\n                   Place this flag before the config command.",
		examples:    "mystvpn config effective\nmystvpn config set country US\nmystvpn config --profile work set ip_type hosting\nmystvpn config profile create work",
		children: []helpTopic{
			{name: "get", usage: "get [key]", summary: "Print saved overrides, or the effective value of one key.",
				description: "Without a key, print saved overrides as JSON. With a key, include its built-in\ndefault if no override is saved. Use --profile before get to select a profile.",
				examples:    "mystvpn config get\nmystvpn config get country\nmystvpn config --profile work get ip_type"},
			{name: "effective", usage: "effective", summary: "Print all settings, including built-in defaults, as JSON.",
				description: "Use --profile before effective to select a profile.",
				examples:    "mystvpn config effective\nmystvpn config --profile work effective"},
			{name: "set", usage: "set <key> <value>", summary: "Validate and save a setting for the selected profile.",
				description: "Use --profile before set to select a profile. The change applies to the next\nconnect or refresh.",
				examples:    "mystvpn config set country DE\nmystvpn config --profile work set ip_type hosting"},
			{name: "unset", usage: "unset <key>", summary: "Remove an override and restore the built-in default.",
				description: "Use --profile before unset to select a profile.",
				examples:    "mystvpn config unset country"},
			{name: "path", usage: "path", summary: "Print the configuration file path, even if the file is invalid.",
				examples: "mystvpn config path"},
			{
				name: "profile", usage: "profile [command]", summary: "Create, select, inspect, or delete saved profiles.",
				description: "With no command, list profiles. An asterisk (*) marks the active profile.\nSelecting a profile affects the next connect or refresh. Use profile names\nafter the action; --profile is not supported for these commands.",
				examples:    "mystvpn config profile create work\nmystvpn config --profile work set country US\nmystvpn config profile use work",
				children: []helpTopic{
					{name: "list", usage: "list", summary: "List profiles; * marks the active selection.", examples: "mystvpn config profile list"},
					{name: "current", usage: "current", summary: "Print the active profile's name.", examples: "mystvpn config profile current"},
					{name: "create", usage: "create <name>", summary: "Create a profile using built-in defaults without selecting it.",
						description: "Names must start with a letter or digit and contain only letters, digits,\nunderscores, or hyphens (up to 64 characters).",
						examples:    "mystvpn config profile create work"},
					{name: "use", usage: "use <name>", summary: "Select a profile and save the selection for future commands.", examples: "mystvpn config profile use work"},
					{name: "delete", usage: "delete <name>", summary: "Delete an inactive profile.",
						description: "The default profile and the active profile cannot be deleted.",
						examples:    "mystvpn config profile delete work"},
				},
			},
		},
	},
	{
		name: "countries", usage: "countries --ip-type <residential|hosting>", summary: "List available countries for an IP address type.",
		description: "Requires authentication. Use a country code from this list with connect.\nThe IP type must be supplied explicitly; saved profile settings are not used.",
		flags:       "--ip-type <type>  Required: residential or hosting.",
		examples:    "sudo mystvpn countries --ip-type residential\nsudo mystvpn countries --ip-type hosting",
	},
	{
		name: "connect", usage: "connect [--profile <name>] [--country <code>] [--ip-type <residential|hosting>]", summary: "Connect to a country, replacing any active VPN connection.",
		description: "Requires authentication and permission to manage WireGuard interfaces.\nOmitted flags use the selected profile's settings, then built-in defaults.\nExplicit flags override the profile for this connection only. The new\nconfiguration is requested before the existing tunnel is brought down.",
		flags:       "--profile <name>  Profile to use (default: active profile).\n--country <code>  Two-letter country code, e.g. DE or US (case-insensitive).\n--ip-type <type>  residential or hosting.",
		examples:    "sudo mystvpn connect\nsudo mystvpn connect --country US --ip-type hosting\nsudo mystvpn connect --profile work",
	},
	{
		name: "refresh", usage: "refresh", summary: "Reconnect using the active profile and saved WireGuard keypair.",
		description: "Requires an active session and permission to manage WireGuard interfaces.\nUses the active profile's current country and IP type, including changes\nsaved since the connection was established.",
		examples:    "sudo mystvpn refresh",
	},
	{
		name: "status", usage: "status", summary: "Show the locally saved VPN connection status.",
		description: "Reads local session state without an API request or a live connectivity check.\nPrints connected: no when there is no saved session.",
		examples:    "sudo mystvpn status",
	},
	{
		name: "disconnect", usage: "disconnect", summary: "Close the VPN connection and remove local session state.",
		description: "Closes the remote connection, brings down the WireGuard tunnel, and removes\nthe managed configuration and session state. Requires an active session and\npermission to manage WireGuard interfaces. Authentication is kept for reuse.",
		examples:    "sudo mystvpn disconnect",
	},
	{
		name: "logout", usage: "logout", summary: "Disconnect the VPN and remove stored authentication tokens.",
		description: "If connected, closes the remote connection and local WireGuard tunnel before\nremoving authentication tokens. Use the same operating-system user that\nsigned in. An active tunnel requires permission to manage WireGuard interfaces.",
		examples:    "sudo mystvpn logout",
	},
	{
		name: "help", usage: "help [command [subcommand...]]", summary: "Show help for the CLI or a specific command.",
		description: "Use --help or -h after any command to show the same help. Help does not\nrequire authentication, network access, or a valid configuration file.",
		examples:    "mystvpn help connect\nmystvpn connect --help\nmystvpn help config profile create\nmystvpn config set --help",
	},
	{name: "version", usage: "version", summary: "Print the installed CLI version.", examples: "mystvpn version"},
}

// Resolve help before running commands so it never reads state or performs work.
// Skip flag values and honor -- so values named "--help" remain values.
func helpRequest(args []string) ([]string, bool) {
	if len(args) == 0 {
		return nil, true
	}
	if args[0] == "help" {
		if len(args) == 2 && isHelpFlag(args[1]) {
			return []string{"help"}, true
		}
		return args[1:], true
	}
	var path []string
	requested := false
	topics := helpTopics
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if isHelpFlag(arg) {
			requested = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			if !hasValue && (name == "country" || name == "ip-type" || name == "profile") {
				i++
			}
			continue
		}
		if len(topics) > 0 {
			path = append(path, arg)
			topic := findHelpTopic(topics, arg)
			if topic == nil {
				topics = nil
			} else {
				topics = topic.children
			}
		}
	}
	return path, requested
}

func isHelpFlag(arg string) bool {
	return arg == "--help" || arg == "-h" || arg == "-help"
}

func findHelpTopic(topics []helpTopic, name string) *helpTopic {
	for i := range topics {
		if topics[i].name == name {
			return &topics[i]
		}
	}
	return nil
}

func runHelp(path []string, stdout, stderr io.Writer) int {
	topic := &helpTopic{
		usage:       "<command> [flags]",
		summary:     "mystvpn - Mysterium VPN CLI for Linux",
		description: "Sign in, choose a country, and manage your WireGuard VPN connection.\nRun VPN commands as root (or with sudo) using the same user that signed in.",
		children:    helpTopics,
		examples:    "sudo mystvpn auth\nsudo mystvpn countries --ip-type residential\nsudo mystvpn connect --country DE --ip-type residential\nsudo mystvpn status\nsudo mystvpn disconnect",
	}
	for _, name := range path {
		topic = findHelpTopic(topic.children, name)
		if topic == nil {
			fmt.Fprintf(stderr, "mystvpn help: unknown command %q; use \"mystvpn help\" to list commands\n", strings.Join(path, " "))
			return 2
		}
	}
	fmt.Fprintln(stdout, topic.summary)
	if topic.description != "" {
		fmt.Fprintf(stdout, "\n%s\n", topic.description)
	}
	prefix := "mystvpn"
	if len(path) > 1 {
		prefix += " " + strings.Join(path[:len(path)-1], " ")
	}
	fmt.Fprintf(stdout, "\nUsage:\n  %s %s\n", prefix, topic.usage)
	if len(topic.children) > 0 {
		fmt.Fprintln(stdout, "\nCommands:")
		table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		for _, child := range topic.children {
			fmt.Fprintf(table, "  %s\t%s\n", child.name, child.summary)
		}
		_ = table.Flush()
	}
	fmt.Fprintln(stdout, "\nFlags:")
	if topic.flags != "" {
		fmt.Fprintln(stdout, "  "+strings.ReplaceAll(topic.flags, "\n", "\n  "))
	}
	fmt.Fprintln(stdout, "  -h, --help        Show help for this command.")
	if len(path) > 0 && (path[0] == "connect" || (path[0] == "config" && (len(path) == 1 || path[1] != "profile"))) {
		defaults := config.DefaultSettings()
		fmt.Fprintln(stdout, "\nSettings:")
		fmt.Fprintf(stdout, "  country  Two-letter country code (built-in default: %s).\n", defaults.Country)
		fmt.Fprintf(stdout, "  ip_type  residential or hosting (built-in default: %s).\n", defaults.IPType)
	}
	if topic.examples != "" {
		fmt.Fprintln(stdout, "\nExamples:\n  "+strings.ReplaceAll(topic.examples, "\n", "\n  "))
	}
	if len(topic.children) > 0 {
		target := strings.Join(path, " ")
		if target != "" {
			target += " "
		}
		fmt.Fprintf(stdout, "\nUse \"mystvpn help %s<command>\" for command details.\n", target)
	}
	return 0
}
