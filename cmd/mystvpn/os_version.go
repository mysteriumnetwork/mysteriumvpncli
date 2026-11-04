package main

import "strings"

// detectOSVersion reports the Linux distribution, falling back to the kernel
// release. Missing system metadata must not prevent a VPN connection.
func detectOSVersion(readFile func(string) ([]byte, error)) string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		values := make(map[string]string)
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok || strings.HasPrefix(key, "#") {
				continue
			}
			value = strings.TrimSpace(value)
			if len(value) >= 2 {
				if value[0] == '"' && value[len(value)-1] == '"' {
					value = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(value[1 : len(value)-1])
				} else if value[0] == '\'' && value[len(value)-1] == '\'' {
					value = value[1 : len(value)-1]
				}
			}
			values[key] = strings.TrimSpace(value)
		}
		if prettyName := values["PRETTY_NAME"]; prettyName != "" {
			return prettyName
		}
		if name := values["NAME"]; name != "" {
			return strings.TrimSpace(name + " " + values["VERSION_ID"])
		}
	}
	if data, err := readFile("/proc/sys/kernel/osrelease"); err == nil {
		if release := strings.TrimSpace(string(data)); release != "" {
			return "Linux " + release
		}
	}
	return "unknown"
}
