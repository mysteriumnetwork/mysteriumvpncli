package client

import (
	"net"
	"net/http"
	"time"
)

const defaultDialTimeout = 5 * time.Second

// newTransport bounds connection setup separately from the overall request.
// TLS handshakes remain bounded by the HTTP client's overall timeout.
func newTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}).DialContext
	// Disable the default transport's TLS-specific limit. The overall request
	// timeout still bounds the handshake.
	transport.TLSHandshakeTimeout = 0

	return transport
}
