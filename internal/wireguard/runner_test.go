package wireguard

import "testing"

func TestIsMissingInterfaceOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "not WireGuard interface", output: "wg-quick: `wg0' is not a WireGuard interface", want: true},
		{name: "cannot find device", output: `Cannot find device "wg0"`, want: true},
		{name: "no such device", output: "Unable to access interface: No such device", want: true},
		{name: "device does not exist", output: `Device "wg0" does not exist.`, want: true},
		{name: "root required", output: "wg-quick must be run as root", want: false},
		{name: "missing config", output: "configuration file does not exist", want: false},
		{name: "invalid config", output: "Line unrecognized", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isMissingInterfaceOutput(test.output); got != test.want {
				t.Errorf("isMissingInterfaceOutput(%q) = %v, want %v", test.output, got, test.want)
			}
		})
	}
}
