package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

func TestRequestErrorsGiveActionsWithoutExposingDetails(t *testing.T) {
	var response map[string]string
	invalidJSON := json.Unmarshal([]byte(`{"message":"sensitive-value"`), &response)
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"missing credentials", fmt.Errorf("load token: %w", auth.ErrTokenNotFound), `run "mystvpn auth" first`},
		{"expired credentials", &auth.HTTPStatusError{StatusCode: 401}, "sign in again"},
		{"subscription", &client.APIError{StatusCode: 402, Message: "sensitive-value"}, "check your subscription"},
		{"bad request", &client.APIError{StatusCode: 400, Message: "sensitive-value"}, `"mystvpn help connect"`},
		{"invalid parameters", &client.APIError{StatusCode: 422, Message: "sensitive-value"}, `"mystvpn help connect"`},
		{"server error", fmt.Errorf("nested: %w", &client.APIError{StatusCode: 503, Message: "sensitive-value"}), "try again later"},
		{"unknown status", &client.APIError{StatusCode: 499, Details: "sensitive-value"}, "contact Mysterium VPN support"},
		{"timeout", context.DeadlineExceeded, "request timed out"},
		{"canceled", context.Canceled, "request canceled"},
		{"DNS", &net.DNSError{Name: "sensitive-value", Err: "lookup failed"}, "check your internet connection and DNS settings"},
		{"connection", &net.OpError{Op: "dial", Err: errors.New("sensitive-value")}, "could not reach the VPN service"},
		{"TLS", &tls.CertificateVerificationError{Err: errors.New("sensitive-value")}, "check your system clock and installed CA certificates"},
		{"permission", &os.PathError{Op: "open", Path: "sensitive-value", Err: os.ErrPermission}, "check file permissions"},
		{"invalid response", invalidJSON, "the VPN service returned an invalid response"},
		{"unknown", errors.New("sensitive-value"), "check your internet connection and try again"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			// HTTP transport errors commonly wrap the underlying cause and a URL
			// containing query parameters. Only the classified cause should print.
			err := &url.Error{Op: "Get", URL: "https://sensitive-value@service.test/?token=sensitive-value", Err: test.err}
			writeRequestError(&output, "connect", err)
			got := output.String()
			if !strings.HasPrefix(got, "[ERROR] mystvpn connect: ") || !strings.Contains(got, test.want) {
				t.Errorf("output = %q, want an error label and %q", got, test.want)
			}
			if strings.Contains(got, "sensitive-value") || strings.Contains(got, "\x1b") || strings.Contains(got, "[SUCCESS]") {
				t.Errorf("output contains sensitive details, color escapes, or a success label: %q", got)
			}
		})
	}
}

func TestInvalidCountryFailsBeforeRequestsOrStateChanges(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(fmt.Sprintf("connected=%v", connected), func(t *testing.T) {
			configureTestHome(t)
			var originalConfig []byte
			if connected {
				session := saveTestSession(t)
				var err error
				originalConfig, err = os.ReadFile(session.ConfigPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.Load()
			// Client construction would fail with exit 1 if local validation
			// did not reject this first. A nil runner catches tunnel operations.
			cfg.APIURL = "invalid-api-url"
			result := executeCLI([]string{"connect", "--country", "df"}, cfg, nil)
			assertCommandResult(t, result, 2, "", "[ERROR] mystvpn connect: unknown country code \"DF\"; use a valid two-letter country code (e.g. DE or US)\n")
			if connected {
				session := loadTestSession(t)
				data, err := os.ReadFile(session.ConfigPath)
				if err != nil || !bytes.Equal(originalConfig, data) {
					t.Fatalf("invalid country changed the active WireGuard configuration: %v", err)
				}
			} else if files, err := os.ReadDir(testConfigDirectory(t)); (err != nil && !os.IsNotExist(err)) || len(files) != 0 {
				t.Fatalf("invalid country created local state: %v, %v", files, err)
			}
		})
	}
}

func TestUsageErrorsHaveLabelsAndNoSuccessOutput(t *testing.T) {
	configureTestHome(t)
	for _, args := range [][]string{
		{"unknown"}, {"connect", "--unknown"}, {"connect", "--country"},
		{"countries", "--ip-type"}, {"config", "--profile"}, {"status", "extra"},
		{"help", "unknown"},
	} {
		result := executeCLI(args, config.Load(), nil)
		if result.exitCode != 2 || result.stdout != "" || !strings.HasPrefix(result.stderr, "[ERROR] ") {
			t.Errorf("%v: result = %+v, want a labeled argument error with no success output", args, result)
		}
	}
}

func TestTunnelPermissionErrorExplainsPrivileges(t *testing.T) {
	var output bytes.Buffer
	writeTunnelCommandError(&output, "connect", "/config/path", errors.New("wg-quick up failed: Operation not permitted"))
	if !strings.Contains(output.String(), "run with sudo") || !strings.Contains(output.String(), `config_path="/config/path"`) {
		t.Fatalf("missing privilege advice or config path: %s", output.String())
	}
}
