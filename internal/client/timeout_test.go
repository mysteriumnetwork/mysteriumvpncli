package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStalledTLSUsesOverallTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept TCP but never respond to the TLS ClientHello.
		<-done
	}()
	c, err := New("https://"+listener.Addr().String(), 50*time.Millisecond, false)
	if err != nil {
		t.Fatal(err)
	}
	c.maxRetries = 0
	transport := c.HTTPClient.Transport.(*http.Transport)
	transport.Proxy = nil
	err = c.Get(context.Background(), "resource", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected overall request deadline, got %v", err)
	}
}

func TestSlowResponseUsesOverallTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	c, err := New(server.URL, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	c.maxRetries = 0
	transport := c.HTTPClient.Transport.(*http.Transport)
	transport.DialContext = (&net.Dialer{Timeout: 20 * time.Millisecond}).DialContext
	if err := c.Get(context.Background(), "resource", nil); err != nil {
		t.Fatalf("slow response should outlive connection timeouts: %v", err)
	}
}
