package main

import (
	"fmt"
	"io"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

func runConfigProfile(args []string, stdout, stderr io.Writer) int {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}
	valid := ((action == "list" || action == "current") && len(args) <= 1) ||
		((action == "create" || action == "use" || action == "delete") && len(args) == 2)
	if !valid {
		writeError(stderr, "mystvpn config profile: usage: config profile [list | current | create <name> | use <name> | delete <name>]")
		return 2
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		writeError(stderr, "mystvpn config profile: %v\n", err)
		return 1
	}
	document, err := store.LoadDocument()
	if err != nil {
		writeError(stderr, "mystvpn config profile: %v\n", err)
		return 1
	}
	switch action {
	case "list":
		for _, name := range document.Names() {
			marker := " "
			if name == document.ActiveProfile {
				marker = "*"
			}
			fmt.Fprintf(stdout, "%s %s\n", marker, name)
		}
		return 0
	case "current":
		fmt.Fprintln(stdout, document.ActiveProfile)
		return 0
	case "create":
		err = document.Create(args[1])
	case "use":
		err = document.Use(args[1])
	case "delete":
		err = document.Delete(args[1])
	}
	if err != nil {
		writeError(stderr, "mystvpn config profile: %v\n", err)
		return 2
	}
	if err := store.SaveDocument(document); err != nil {
		writeError(stderr, "mystvpn config profile: %v\n", err)
		return 1
	}
	switch action {
	case "use":
		writeSuccess(stdout, "Active profile: %s. Changes apply on the next connect or refresh.", document.ActiveProfile)
	case "create":
		writeSuccess(stdout, "Created profile %q. Select it with \"mystvpn config profile use %s\".", args[1], args[1])
	case "delete":
		writeSuccess(stdout, "Deleted profile %q.", args[1])
	}
	return 0
}
