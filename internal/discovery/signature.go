package discovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Keys are bundled with the client; discovery can never supply trust anchors.
var trustedKeys = map[string]string{
	"discovery-2026-11": "A06gWTPsthdi7mDhmSaOyyr3BbMvaN5A/1xFrYw8doA=",
}

func verifiedPayload(data []byte, keys map[string]string) ([]byte, error) {
	// Canonicalizing the envelope also rejects duplicate keys and invalid Unicode.
	canonical, err := jsoncanonicalizer.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("canonicalize discovery: %w", err)
	}
	var envelope struct {
		Signed     json.RawMessage   `json:"signed"`
		Signatures []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(canonical, &envelope); err != nil {
		return nil, fmt.Errorf("decode discovery envelope: %w", err)
	}
	if len(envelope.Signed) == 0 || envelope.Signed[0] != '{' {
		return nil, errors.New("missing signed discovery object")
	}
	for _, raw := range envelope.Signatures {
		var signature struct {
			KeyID     string `json:"key_id"`
			Algorithm string `json:"alg"`
			Value     string `json:"sig"`
		}
		if json.Unmarshal(raw, &signature) != nil || signature.Algorithm != "Ed25519" {
			continue
		}
		encodedKey, known := keys[signature.KeyID]
		if !known {
			continue
		}
		key, err := base64.StdEncoding.Strict().DecodeString(encodedKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			continue
		}
		value, err := base64.StdEncoding.Strict().DecodeString(signature.Value)
		if err != nil || len(value) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(value) != signature.Value {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(key), envelope.Signed, value) {
			return envelope.Signed, nil
		}
	}
	return nil, errors.New("discovery has no valid trusted Ed25519 signature")
}
