package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestLoopbackCallbackExtractsCodeAndRejectsInvalidState(t *testing.T) {
	callback, err := NewLoopbackCallback()
	if err != nil {
		t.Fatalf("NewLoopbackCallback() error = %v", err)
	}
	defer callback.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultChannel := make(chan CallbackResult, 1)
	errorChannel := make(chan error, 1)
	go func() {
		result, err := callback.Wait(ctx, "expected-state", "expected-nonce")
		if err != nil {
			errorChannel <- err
			return
		}
		resultChannel <- result
	}()

	invalidResponse, err := http.Get(callbackRequestURL(t, callback.URL(), "code-value", "wrong-state", "expected-nonce"))
	if err != nil {
		t.Fatalf("invalid callback request: %v", err)
	}
	invalidResponse.Body.Close()
	if invalidResponse.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid callback status = %d, want 400", invalidResponse.StatusCode)
	}

	validResponse, err := http.Get(callbackRequestURL(t, callback.URL(), "code-value", "expected-state", "expected-nonce"))
	if err != nil {
		t.Fatalf("valid callback request: %v", err)
	}
	validResponse.Body.Close()
	if validResponse.StatusCode != http.StatusOK {
		t.Errorf("valid callback status = %d, want 200", validResponse.StatusCode)
	}

	select {
	case err := <-errorChannel:
		t.Fatalf("Wait() error = %v", err)
	case result := <-resultChannel:
		if result.AuthorizationCode != "code-value" || result.State != "expected-state" || result.Nonce != "expected-nonce" {
			t.Errorf("callback result = %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

func TestLoopbackCallbackTimesOut(t *testing.T) {
	callback, err := NewLoopbackCallback()
	if err != nil {
		t.Fatalf("NewLoopbackCallback() error = %v", err)
	}
	defer callback.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = callback.Wait(ctx, "expected-state", "expected-nonce")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait() error = %v, want context deadline exceeded", err)
	}
}

func callbackRequestURL(t *testing.T, callbackURL, code, state, nonce string) string {
	t.Helper()
	parsed, err := url.Parse(callbackURL)
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}
	query := parsed.Query()
	query.Set("code", code)
	query.Set("state", state)
	query.Set("nonce", nonce)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
