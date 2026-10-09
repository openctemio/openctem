package command

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func TestPayloadTemplateDigests(t *testing.T) {
	a, b := []byte("id: a\n"), []byte("id: b\n")
	digest := func(c []byte) string { s := sha256.Sum256(c); return "sha256:" + hex.EncodeToString(s[:]) }
	enc := base64.StdEncoding.EncodeToString
	payload, _ := json.Marshal(map[string]any{"scanner": "nuclei", "custom_templates": []map[string]string{
		{"name": "a", "content": enc(a)}, {"name": "b", "content": " " + enc(b) + "\n"}, {"name": "a2", "content": enc(a)},
	}})
	got, err := PayloadTemplateDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	// In payload order, duplicates kept, content trimmed before decoding.
	if want := []string{digest(a), digest(b), digest(a)}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, p := range []string{``, `null`, `{"scanner":"nuclei"}`, `{"custom_templates":[]}`} {
		if got, err := PayloadTemplateDigests(json.RawMessage(p)); err != nil || got != nil {
			t.Errorf("%q: %v %v", p, got, err)
		}
	}
	for _, p := range []string{`{"custom_templates":[{"content":"%%%"}]}`, `{"custom_templates":"x"}`} {
		if _, err := PayloadTemplateDigests(json.RawMessage(p)); !errors.Is(err, ErrTemplateContent) {
			t.Errorf("%q: %v", p, err)
		}
	}
}
