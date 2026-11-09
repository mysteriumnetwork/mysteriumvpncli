package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testAuthorizationURL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/healthcheck" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"status":"OK"}`)
	}))
	t.Cleanup(server.Close)
	return server.URL + "/oauth/authorize"
}
