package scannertemplate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The sensor (sdk-go core, TestTemplateManifestEnvelopeVector) checks the
// same bytes with the same key to the same signature. A change on either
// side must change both vectors, or every sensor refuses every custom
// template.
func TestManifestEnvelopeVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	payload := []byte(`{"kind":"openctem.template-manifest/v1","tenant_id":"t","command_id":"c","issued_at":"2026-10-03T00:00:00Z","expires_at":"2026-10-03T01:00:00Z","templates":[]}`)
	pae := PreAuthEncoding(ManifestPayloadType, payload)
	if !strings.HasPrefix(string(pae), "DSSEv1 47 application/vnd.openctem.template-manifest+json 159 {") {
		t.Fatalf("PAE = %q", pae)
	}
	const wantSig = "dbNRZb9aoO+QInKMmpveKLtJjSOCbW9CV6ygkCIMxaNFxXsTMChF6eCOB3h//0BojbrjYqK/sHsc4eNa03rQBg=="
	if got := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pae)); got != wantSig {
		t.Fatalf("signature = %s, want %s", got, wantSig)
	}
	if got := KeyID(priv.Public().(ed25519.PublicKey)); got != "65b60673d6ed884b" {
		t.Fatalf("key id = %s", got)
	}
	// The manifest this package marshals has the same shape.
	m := Manifest{
		Kind: ManifestKind, TenantID: "t", CommandID: "c",
		IssuedAt:  time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC),
		Templates: []ManifestTemplate{},
	}
	if got, _ := json.Marshal(m); string(got) != string(payload) {
		t.Fatalf("manifest JSON = %s, want %s", got, payload)
	}
}

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0xA5
	}
	k, err := NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyringSealsPerTenant(t *testing.T) {
	k := testKeyring(t)
	m := Manifest{
		TenantID: "tenant-a", SensorID: "sensor-1", CommandID: "cmd-1",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(ManifestTTL),
		Templates: []ManifestTemplate{NewManifestTemplate("t1", "probe.yaml", "nuclei", []byte("id: probe\n"))},
	}
	env, err := k.Seal(m)
	if err != nil {
		t.Fatal(err)
	}
	pubA, idA, _ := k.PublicKey("tenant-a")
	pubB, idB, _ := k.PublicKey("tenant-b")
	if idA == idB || pubA.Equal(pubB) {
		t.Fatal("two tenants share a signing key")
	}
	if env.PayloadType != ManifestPayloadType || len(env.Signatures) != 1 || env.Signatures[0].KeyID != idA {
		t.Fatalf("envelope %+v", env)
	}
	pae := PreAuthEncoding(env.PayloadType, env.Payload)
	if !ed25519.Verify(pubA, pae, env.Signatures[0].Sig) {
		t.Fatal("tenant A's manifest does not verify with tenant A's key")
	}
	if ed25519.Verify(pubB, pae, env.Signatures[0].Sig) {
		t.Fatal("tenant A's manifest verifies with tenant B's key")
	}
	var back Manifest
	if err := json.Unmarshal(env.Payload, &back); err != nil || back.Kind != ManifestKind || back.CommandID != "cmd-1" {
		t.Fatalf("payload %s: %v", env.Payload, err)
	}
	// Deterministic: the same master gives the same tenant key (sensors pin it).
	k2 := testKeyring(t)
	if p, _, _ := k2.PublicKey("tenant-a"); !p.Equal(pubA) {
		t.Fatal("tenant key is not stable across restarts")
	}
	// A master derived from the encryption key differs from the key itself.
	k3, err := NewKeyringFromEncryptionKey(k.master)
	if err != nil {
		t.Fatal(err)
	}
	if p, _, _ := k3.PublicKey("tenant-a"); p.Equal(pubA) {
		t.Fatal("derived master is the encryption key itself")
	}
	if _, err := NewKeyring([]byte("short")); err == nil {
		t.Fatal("short master accepted")
	}
	if _, err := k.Seal(Manifest{CommandID: "c"}); err == nil {
		t.Fatal("sealing without a tenant accepted")
	}
	if _, err := k.Seal(Manifest{TenantID: "tenant-a"}); err == nil {
		t.Fatal("sealing without a command accepted")
	}
}
