package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

func writeRequestError(output io.Writer, command string, err error) {
	writeError(output, "mystvpn %s: %s", command, requestErrorMessage(command, err))
}

// Describe known failure types without echoing response bodies or URL errors:
// either can contain credentials or other sensitive request information.
func requestErrorMessage(command string, err error) string {
	var authStatusErr *auth.HTTPStatusError
	var apiErr *client.APIError
	switch {
	case errors.As(err, &authStatusErr):
		return httpErrorMessage(command, authStatusErr.StatusCode)
	case errors.As(err, &apiErr):
		return httpErrorMessage(command, apiErr.StatusCode)
	case errors.Is(err, auth.ErrTokenNotFound):
		return `authentication required; run "mystvpn auth" first`
	case errors.Is(err, context.Canceled):
		return "request canceled; run the command again if needed"
	case errors.Is(err, os.ErrPermission):
		return "could not access local credentials; check file permissions and use the same operating-system user that signed in"
	}
	var networkErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkErr) && networkErr.Timeout()) {
		return "request timed out; check your internet connection and try again"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "could not resolve the VPN service address; check your internet connection and DNS settings"
	}
	var certificateErr *tls.CertificateVerificationError
	if errors.As(err, &certificateErr) {
		return "could not verify the VPN service certificate; check your system clock and installed CA certificates"
	}
	var connectionErr *net.OpError
	if errors.As(err, &connectionErr) {
		return "could not reach the VPN service; check your internet connection and try again"
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "the VPN service returned an invalid response; try again or check for a CLI update"
	}
	if command == "auth" {
		return `authentication failed; run "mystvpn auth" again and check that local credential storage is writable`
	}
	return "request failed; check your internet connection and try again"
}

func httpErrorMessage(command string, status int) string {
	var hint string
	switch {
	case status == http.StatusUnauthorized:
		hint = `authentication expired or was rejected; run "mystvpn auth" to sign in again`
	case status == http.StatusPaymentRequired:
		hint = "a VPN subscription is required; check your subscription in the Mysterium VPN app"
	case status == http.StatusForbidden:
		hint = "access denied; check your VPN account permissions and subscription"
	case status == http.StatusNotFound:
		hint = "the requested VPN resource was not found; retry or check for a CLI update"
	case status == http.StatusTooManyRequests:
		hint = "too many requests; wait a moment before trying again"
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		hint = fmt.Sprintf("the service rejected the request; check your options with \"mystvpn help %s\"", command)
	case status >= http.StatusInternalServerError:
		hint = "the VPN service is temporarily unavailable; try again later"
	default:
		hint = "the VPN service rejected the request; try again or contact Mysterium VPN support"
	}
	name := http.StatusText(status)
	if name == "" {
		name = "Unknown Status"
	}
	return fmt.Sprintf("HTTP status %d (%s): %s", status, name, hint)
}
