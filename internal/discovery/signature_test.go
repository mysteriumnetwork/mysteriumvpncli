package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// RFC 8032's public test seed, unrelated to the production trust anchor.
func testPrivateKey() ed25519.PrivateKey {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	return ed25519.NewKeyFromSeed(seed)
}

func testKeys() map[string]string {
	return map[string]string{"test-discovery": base64.StdEncoding.EncodeToString(testPrivateKey().Public().(ed25519.PublicKey))}
}

func signTestEnvelope(source string) string {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(source), &envelope); err != nil {
		panic(err)
	}
	payload, err := jsoncanonicalizer.Transform(envelope["signed"])
	if err != nil {
		panic(err)
	}
	signature := ed25519.Sign(testPrivateKey(), payload)
	envelope["signatures"], _ = json.Marshal([]map[string]string{{"key_id": "test-discovery", "alg": "Ed25519", "sig": base64.StdEncoding.EncodeToString(signature)}})
	data, _ := json.Marshal(envelope)
	return string(data)
}

func newTestLoader(path string) *Loader {
	l := New(path)
	l.keys = testKeys()
	return l
}

func TestProductionSignature(t *testing.T) {
	data, err := os.ReadFile("testdata/production.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(data, trustedKeys, true); err != nil {
		t.Fatal(err)
	}
	// Property order and whitespace do not affect the signature.
	var envelope map[string]any
	_ = json.Unmarshal(data, &envelope)
	reordered, _ := json.Marshal(envelope)
	if _, err := parse(reordered, trustedKeys, true); err != nil {
		t.Fatal(err)
	}
}

func TestPythonJCSInterop(t *testing.T) {
	data, err := os.ReadFile("testdata/python-jcs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Canonical string          `json:"canonical_base64"`
		Envelope  json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	expected, _ := base64.StdEncoding.DecodeString(fixture.Canonical)
	payload, err := verifiedPayload(fixture.Envelope, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(expected) {
		t.Fatalf("canonical bytes differ from Python JCS:\n%s\n%s", payload, expected)
	}
	if _, err := parse(fixture.Envelope, testKeys(), false); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureFailuresAndRotation(t *testing.T) {
	var envelope map[string]any
	_ = json.Unmarshal([]byte(sample), &envelope)
	signatures := envelope["signatures"].([]any)
	signature := signatures[0].(map[string]any)
	originalSig := signature["sig"].(string)
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unsigned", func(e map[string]any) { delete(e, "signatures") }},
		{"empty", func(e map[string]any) { e["signatures"] = []any{} }},
		{"unknown key", func(e map[string]any) {
			e["signatures"] = []any{map[string]any{"key_id": "unknown", "alg": "Ed25519", "sig": originalSig}}
		}},
		{"wrong algorithm", func(e map[string]any) {
			e["signatures"] = []any{map[string]any{"key_id": "test-discovery", "alg": "ed25519", "sig": originalSig}}
		}},
		{"bad base64", func(e map[string]any) {
			e["signatures"] = []any{map[string]any{"key_id": "test-discovery", "alg": "Ed25519", "sig": "!!!"}}
		}},
		{"invalid signature", func(e map[string]any) {
			e["signatures"] = []any{map[string]any{"key_id": "test-discovery", "alg": "Ed25519", "sig": base64.StdEncoding.EncodeToString(make([]byte, 64))}}
		}},
		{"modified payload", func(e map[string]any) { e["signed"].(map[string]any)["version"] = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var current map[string]any
			_ = json.Unmarshal([]byte(sample), &current)
			tc.change(current)
			encoded, _ := json.Marshal(current)
			if _, err := parse(encoded, testKeys(), false); err == nil {
				t.Fatal("untrusted configuration accepted")
			}
		})
	}
	// A signature over ordinary (non-JCS) JSON must not verify.
	var raw struct {
		Signed json.RawMessage `json:"signed"`
	}
	_ = json.Unmarshal([]byte(sample), &raw)
	pretty, _ := json.MarshalIndent(json.RawMessage(raw.Signed), "", "  ")
	signature["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(testPrivateKey(), pretty))
	wrong, _ := json.Marshal(envelope)
	if _, err := parse(wrong, testKeys(), false); err == nil {
		t.Fatal("non-JCS signature accepted")
	}
	signature["sig"] = originalSig
	envelope["signatures"] = []any{map[string]any{"key_id": "future", "alg": "Ed25519", "sig": "bad"}, map[string]any{"key_id": "test-discovery", "alg": "Ed25519", "sig": "bad"}, signature}
	multiple, _ := json.Marshal(envelope)
	if _, err := parse(multiple, testKeys(), false); err != nil {
		t.Fatal(err)
	}
}

func TestSignaturePrecedesSchemaAndExpiration(t *testing.T) {
	modified := strings.Replace(sample, `"schema_version":1`, `"schema_version":99`, 1)
	if _, err := parse([]byte(modified), testKeys(), false); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("error=%v", err)
	}
	if _, err := parse([]byte(signTestEnvelope(modified)), testKeys(), false); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("error=%v", err)
	}
	expired := signTestEnvelope(strings.Replace(strings.Replace(sample, "2026-10-27T00:00:00Z", "2000-01-01T00:00:00Z", 1), "2099-11-10T00:00:00Z", "2000-02-01T00:00:00Z", 1))
	if _, err := parse([]byte(expired), testKeys(), false); err == nil {
		t.Fatal("expired network config accepted")
	}
	if _, err := parse([]byte(expired), testKeys(), true); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidRefreshDoesNotReplaceVerifiedCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discovery.json")
	if err := os.WriteFile(path, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(sample, "app.mysterium.network", "attacker.example", 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, altered) }))
	defer server.Close()
	loader := newTestLoader(path)
	loader.Sources = []string{server.URL}
	loader.RefreshInterval = -time.Second
	if got := loader.Fallbacks(context.Background(), "app.mysteriumvpn.com"); len(got) != 2 || got[1] != "app.mysterium.network" {
		t.Fatalf("fallbacks=%v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != sample {
		t.Fatal("unverified response replaced cache")
	}
	if err := os.WriteFile(path, []byte(unsignedSample), 0600); err != nil {
		t.Fatal(err)
	}
	restarted := newTestLoader(path)
	restarted.Sources = []string{server.URL}
	if got := restarted.CachedFallbacks("app.mysteriumvpn.com"); len(got) != 0 {
		t.Fatal("unsigned cache was accepted")
	}
	if got := restarted.Fallbacks(context.Background(), "app.mysteriumvpn.com"); len(got) != 0 {
		t.Fatal("unsigned or modified config was applied")
	}
}

func TestRejectsDuplicateJSONProperties(t *testing.T) {
	duplicate := strings.Replace(sample, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
	if _, err := parse([]byte(duplicate), testKeys(), false); err == nil {
		t.Fatal("duplicate signed properties accepted")
	}
}
