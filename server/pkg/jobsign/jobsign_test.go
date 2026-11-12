package jobsign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/vector.json")

// vector is the cross-implementation test vector: sdk-go's verifier must
// accept Envelope with PublicKey and produce the same statement, and must
// refuse it once a byte of the payload changes.
type vector struct {
	Seed       []byte          `json:"seed"`
	KeyID      string          `json:"keyid"`
	PublicKey  string          `json:"public_key"`
	Payload    string          `json:"payload"`
	CmdPayload string          `json:"command_payload"`
	Envelope   json.RawMessage `json:"envelope"`
}

func vectorStatement() (Statement, []byte) {
	cmdPayload := []byte(`{"scanner":"nuclei","targets":["203.0.113.10","app.example.com"]}`)
	issued := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	return Statement{
		Kind: Kind, TenantID: "11111111-1111-4111-8111-111111111111",
		SensorID: "22222222-2222-4222-8222-22222222abcd", CommandID: "33333333-3333-4333-8333-333333333333",
		CommandType: "scan", Tool: "nuclei", PayloadSHA256: PayloadDigest(cmdPayload),
		Targets: []string{"203.0.113.10", "app.example.com"}, LeaseEpoch: 2,
		IssuedAt: issued, ExpiresAt: issued.Add(time.Hour),
		Seq: 18, Nonce: "AAECAwQFBgcICQoLDA0ODw",
	}, cmdPayload
}

func TestVector(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	st, cmdPayload := vectorStatement()
	st.Signer = &SignerRef{KeyID: KeyID(pub)}
	payload, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(Sign(priv, payload))
	if err != nil {
		t.Fatal(err)
	}
	k := NewPublicKey(pub)
	got := vector{Seed: seed, KeyID: k.KeyID, PublicKey: k.PublicKey, Payload: string(payload), CmdPayload: string(cmdPayload), Envelope: env}
	path := filepath.Join("testdata", "vector.json")
	if *update {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want vector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if want.KeyID != got.KeyID || want.PublicKey != got.PublicKey || want.Payload != got.Payload {
		t.Fatalf("vector changed:\n got %s\nwant %s", got.Payload, want.Payload)
	}
	if !bytes.Equal(compact(t, want.Envelope), compact(t, env)) {
		t.Fatalf("envelope changed:\n got %s\nwant %s", env, want.Envelope)
	}

	// The vector verifies, binds the command payload, and a changed byte
	// does not verify.
	decoded, err := k.Decode()
	if err != nil {
		t.Fatal(err)
	}
	vst, err := Verify(want.Envelope, []ed25519.PublicKey{decoded})
	if err != nil {
		t.Fatal(err)
	}
	if vst.PayloadSHA256 != PayloadDigest([]byte(want.CmdPayload)) || vst.Seq != 18 || vst.Signer.KeyID != want.KeyID {
		t.Fatalf("statement %+v", vst)
	}
	var e map[string]any
	if err := json.Unmarshal(want.Envelope, &e); err != nil {
		t.Fatal(err)
	}
	e["payload"] = base64.StdEncoding.EncodeToString(append([]byte(want.Payload[:len(want.Payload)-1]), ' ', '}'))
	tampered, _ := json.Marshal(e)
	if _, err := Verify(tampered, []ed25519.PublicKey{decoded}); err == nil {
		t.Fatal("a changed payload verified")
	}
}

func compact(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestPublicKeyDecodeRefusesMismatchedID(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	k := NewPublicKey(pub)
	if _, err := k.Decode(); err != nil {
		t.Fatal(err)
	}
	k.KeyID = KeyID(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey))
	if _, err := k.Decode(); err == nil {
		t.Fatal("a key under another key's id decoded")
	}
}

func TestValidDigest(t *testing.T) {
	for d, ok := range map[string]bool{
		PayloadDigest([]byte("x")):                        true,
		"sha256:":                                         false,
		"sha512:" + PayloadDigest(nil)[7:]:                false,
		"sha256:" + string(bytes.Repeat([]byte("A"), 64)): false,
	} {
		if ValidDigest(d) != ok {
			t.Errorf("ValidDigest(%q) = %v", d, !ok)
		}
	}
}
