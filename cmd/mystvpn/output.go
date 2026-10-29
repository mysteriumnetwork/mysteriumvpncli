package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Keep data output separate from status messages so config get/effective/path
// remain suitable for scripts. Color only the label, and only on terminals.
func writeSuccess(output io.Writer, format string, args ...any) {
	writeMessage(output, "SUCCESS", "32", format, args...)
}

func writeError(output io.Writer, format string, args ...any) {
	writeMessage(output, "ERROR", "31", format, args...)
}

func writeMessage(output io.Writer, label, color, format string, args ...any) {
	marker := "[" + label + "]"
	if colorEnabled(output) {
		marker = "\x1b[1;" + color + "m" + marker + "\x1b[0m"
	}
	fmt.Fprintf(output, "%s %s\n", marker, strings.TrimSuffix(fmt.Sprintf(format, args...), "\n"))
}

func colorEnabled(output io.Writer) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
