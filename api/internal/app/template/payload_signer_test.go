package template

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func testSigner(t *testing.T) (*PayloadSigner, *scannertemplate.Keyring) {
	t.Helper()
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(7 * i)
	}
	k, err := scannertemplate.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	return NewPayloadSigner(k, logger.New(logger.Config{Level: "error"})), k
}

func payloadWith(t *testing.T, extra map[string]any, bodies ...string) json.RawMessage {
	t.Helper()
	var tpls []map[string]any
	for i, b := range bodies {
		tpls = append(tpls, map[string]any{
			"id": "t" + string(rune('1'+i)), "name": "tpl" + string(rune('1'+i)) + ".yaml",
			"template_type": "nuclei", "content": base64.StdEncoding.EncodeToString([]byte(b)),
		})
	}
	doc := map[string]any{"scanner": "nuclei", "target": "https://203.0.113.10", "custom_templates": tpls}
	for k, v := range extra {
		doc[k] = v
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const goodNuclei = "id: probe\ninfo:\n  name: probe\n  author: x\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n"

func envelopeOf(t *testing.T, payload json.RawMessage) *scannertemplate.Envelope {
	t.Helper()
	var doc struct {
		Env *scannertemplate.Envelope `json:"custom_templates_envelope"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Env
}

func TestPayloadSignerSealsValidatedTemplates(t *testing.T) {
	s, keys := testSigner(t)
	out := s.SignTemplates("tenant-a", "sensor-1", "cmd-1", payloadWith(t, nil, goodNuclei, goodNuclei))
	env := envelopeOf(t, out)
	if env == nil {
		t.Fatalf("no envelope in %s", out)
	}
	pub, id, _ := keys.PublicKey("tenant-a")
	if env.Signatures[0].KeyID != id || !ed25519.Verify(pub, scannertemplate.PreAuthEncoding(env.PayloadType, env.Payload), env.Signatures[0].Sig) {
		t.Fatal("envelope does not verify with the tenant's key")
	}
	var m scannertemplate.Manifest
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		t.Fatal(err)
	}
	if m.TenantID != "tenant-a" || m.SensorID != "sensor-1" || m.CommandID != "cmd-1" || len(m.Templates) != 2 {
		t.Fatalf("manifest %+v", m)
	}
	if !m.ExpiresAt.After(time.Now()) || m.ExpiresAt.Sub(m.IssuedAt) != scannertemplate.ManifestTTL {
		t.Fatalf("manifest times %v .. %v", m.IssuedAt, m.ExpiresAt)
	}
	if m.Templates[0] != scannertemplate.NewManifestTemplate("t1", "tpl1.yaml", "nuclei", []byte(goodNuclei)) {
		t.Fatalf("template entry %+v", m.Templates[0])
	}
}

// A set with a template the validator refuses (code protocol here) is sent
// without a manifest, so the sensor refuses the whole command; an envelope
// the payload brought (forged, or stale) never survives.
func TestPayloadSignerRefusesToSignDangerousTemplates(t *testing.T) {
	s, _ := testSigner(t)
	code := "id: pwn\ninfo:\n  name: pwn\n  author: x\n  severity: info\ncode:\n  - engine: [sh]\n    source: id\n"
	forged := map[string]any{"custom_templates_envelope": map[string]any{"payloadType": "x", "payload": "e30=", "signatures": []any{}}}
	for name, payload := range map[string]json.RawMessage{
		"code template":         payloadWith(t, nil, goodNuclei, code),
		"code template, forged": payloadWith(t, forged, code),
		"not base64":            json.RawMessage(`{"custom_templates":[{"id":"t1","name":"a.yaml","template_type":"nuclei","content":"%%%"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if env := envelopeOf(t, s.SignTemplates("tenant-a", "sensor-1", "cmd-1", payload)); env != nil {
				t.Fatalf("signed: %+v", env)
			}
		})
	}
	// Valid templates with a forged envelope: replaced by a real one.
	out := s.SignTemplates("tenant-a", "sensor-1", "cmd-1", payloadWith(t, forged, goodNuclei))
	if env := envelopeOf(t, out); env == nil || env.PayloadType != scannertemplate.ManifestPayloadType {
		t.Fatalf("forged envelope kept: %s", out)
	}
	// No custom templates: the payload is untouched.
	plain := json.RawMessage(`{"scanner":"nuclei","target":"x"}`)
	if got := s.SignTemplates("tenant-a", "sensor-1", "cmd-1", plain); string(got) != string(plain) {
		t.Fatalf("payload changed: %s", got)
	}
}
