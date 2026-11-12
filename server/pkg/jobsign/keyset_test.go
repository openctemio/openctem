package jobsign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
)

// keysetVector is the cross-implementation key set vector
// (testdata/keyset_vector.json): sdk-go's key set verifier must accept the
// key sets with the root pinned, in version order, and refuse the one
// signed by another root. Key "A" is the key of testdata/vector.json, so
// that signed job verifies under key sets 1 and 2 and not under 3.
type keysetVector struct {
	RootSeed      []byte              `json:"root_seed"`
	RootKeyID     string              `json:"root_keyid"`
	RootPublicKey string              `json:"root_public_key"`
	Now           time.Time           `json:"now"`
	Keys          []keysetVectorKey   `json:"keys"`
	KeySets       []keysetVectorEntry `json:"keysets"`
	// OtherRoot is a key set signed by a different root (refused when the
	// root above is pinned).
	OtherRoot keysetVectorEntry `json:"other_root"`
}

type keysetVectorKey struct {
	Name      string `json:"name"`
	Seed      []byte `json:"seed"`
	KeyID     string `json:"keyid"`
	PublicKey string `json:"public_key"`
}

type keysetVectorEntry struct {
	Version  uint64          `json:"version"`
	Keys     []string        `json:"keys"`
	Payload  string          `json:"payload"`
	Envelope json.RawMessage `json:"envelope"`
}

var vectorNow = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey {
	p, _ := k.Public().(ed25519.PublicKey)
	return p
}

func buildKeysetVector(t *testing.T) keysetVector {
	t.Helper()
	root, other := seedKey(9), seedKey(10)
	named := map[string]ed25519.PrivateKey{"A": seedKey(7), "B": seedKey(8)}
	v := keysetVector{RootSeed: root.Seed(), RootKeyID: KeyID(pubOf(root)),
		RootPublicKey: base64.StdEncoding.EncodeToString(pubOf(root)), Now: vectorNow}
	for _, n := range []string{"A", "B"} {
		pk := NewPublicKey(pubOf(named[n]))
		v.Keys = append(v.Keys, keysetVectorKey{Name: n, Seed: named[n].Seed(), KeyID: pk.KeyID, PublicKey: pk.PublicKey})
	}
	entry := func(r ed25519.PrivateKey, version uint64, names ...string) keysetVectorEntry {
		pubs := make([]ed25519.PublicKey, 0, len(names))
		for _, n := range names {
			pubs = append(pubs, pubOf(named[n]))
		}
		env, _, err := SignKeySet(r, version, vectorNow, MaxKeySetValidity, pubs)
		if err != nil {
			t.Fatal(err)
		}
		var e scannertemplate.Envelope
		if err := json.Unmarshal(env, &e); err != nil {
			t.Fatal(err)
		}
		return keysetVectorEntry{Version: version, Keys: names, Payload: string(e.Payload), Envelope: env}
	}
	v.KeySets = []keysetVectorEntry{entry(root, 1, "A"), entry(root, 2, "A", "B"), entry(root, 3, "B")}
	v.OtherRoot = entry(other, 4, "A")
	return v
}

func TestKeySetVector(t *testing.T) {
	got := buildKeysetVector(t)
	path := filepath.Join("testdata", "keyset_vector.json")
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
	var want keysetVector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if want.RootKeyID != got.RootKeyID || len(want.KeySets) != len(got.KeySets) {
		t.Fatalf("vector changed: root %s, want %s", got.RootKeyID, want.RootKeyID)
	}
	for i := range got.KeySets {
		if want.KeySets[i].Payload != got.KeySets[i].Payload ||
			!bytes.Equal(compact(t, want.KeySets[i].Envelope), compact(t, got.KeySets[i].Envelope)) {
			t.Fatalf("key set %d changed:\n got %s\nwant %s", i, got.KeySets[i].Payload, want.KeySets[i].Payload)
		}
	}

	// Each key set verifies with the root pinned and lists its keys; the
	// one from another root is refused.
	for _, e := range want.KeySets {
		ks, payload, err := VerifyKeySet(e.Envelope, want.RootKeyID, want.Now)
		if err != nil {
			t.Fatalf("key set %d: %v", e.Version, err)
		}
		if ks.Version != e.Version || string(payload) != e.Payload || len(ks.Keys) != len(e.Keys) {
			t.Fatalf("key set %d: %+v", e.Version, ks)
		}
	}
	if _, _, err := VerifyKeySet(want.OtherRoot.Envelope, want.RootKeyID, want.Now); keySetReason(err) != KeySetReasonRoot {
		t.Fatalf("a key set of another root: %v", err)
	}

	// Key A is the key of the signed-job vector.
	jobRaw, err := os.ReadFile(filepath.Join("testdata", "vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var job vector
	if err := json.Unmarshal(jobRaw, &job); err != nil {
		t.Fatal(err)
	}
	if want.Keys[0].Name != "A" || want.Keys[0].KeyID != job.KeyID {
		t.Fatalf("key A %s is not the job vector's key %s", want.Keys[0].KeyID, job.KeyID)
	}
}

func keySetReason(err error) string {
	var e *KeySetError
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func TestVerifyKeySet_Refusals(t *testing.T) {
	root := seedKey(9)
	rootID := KeyID(pubOf(root))
	a := pubOf(seedKey(7))
	env, _, err := SignKeySet(root, 5, vectorNow, 30*24*time.Hour, []ed25519.PublicKey{a})
	if err != nil {
		t.Fatal(err)
	}
	// resign signs an edited payload with the root (a well-signed but
	// invalid document).
	resign := func(edit func(m map[string]any)) []byte {
		var e scannertemplate.Envelope
		_ = json.Unmarshal(env, &e)
		var m map[string]any
		_ = json.Unmarshal(e.Payload, &m)
		edit(m)
		e.Payload, _ = json.Marshal(m)
		e.Signatures[0].Sig = ed25519.Sign(root, scannertemplate.PreAuthEncoding(KeySetPayloadType, e.Payload))
		b, _ := json.Marshal(e)
		return b
	}
	tampered := func() []byte {
		var e scannertemplate.Envelope
		_ = json.Unmarshal(env, &e)
		e.Payload = bytes.Replace(e.Payload, []byte(`"version":5`), []byte(`"version":6`), 1)
		b, _ := json.Marshal(e)
		return b
	}()
	other, _, _ := SignKeySet(seedKey(10), 5, vectorNow, time.Hour, []ed25519.PublicKey{a})

	cases := []struct {
		name   string
		env    []byte
		now    time.Time
		reason string
	}{
		{"another root", other, vectorNow, KeySetReasonRoot},
		{"changed byte", tampered, vectorNow, KeySetReasonSignature},
		{"expired", env, vectorNow.Add(30*24*time.Hour + MaxClockSkew), KeySetReasonExpired},
		{"not yet valid", env, vectorNow.Add(-MaxClockSkew - time.Second), KeySetReasonNotYetValid},
		{"unknown field", resign(func(m map[string]any) { m["extra"] = 1 }), vectorNow, KeySetReasonMalformed},
		{"wrong kind", resign(func(m map[string]any) { m["kind"] = "openctem.job/v1" }), vectorNow, KeySetReasonKind},
		{"version 0", resign(func(m map[string]any) { m["version"] = 0 }), vectorNow, KeySetReasonVersion},
		{"over 30 days", resign(func(m map[string]any) { m["not_after"] = vectorNow.Add(31 * 24 * time.Hour) }), vectorNow, KeySetReasonValidity},
		{"no keys", resign(func(m map[string]any) { m["keys"] = []any{} }), vectorNow, KeySetReasonKeys},
		{"root id not the key", resign(func(m map[string]any) { m["root_keyid"] = KeyID(a) }), vectorNow, KeySetReasonRoot},
		{"key id not the key", resign(func(m map[string]any) {
			m["keys"] = []any{map[string]any{"keyid": rootID, "algorithm": Algorithm, "public_key": base64.StdEncoding.EncodeToString(a)}}
		}), vectorNow, KeySetReasonKeys},
		{"payload type", bytes.Replace(env, []byte(KeySetPayloadType), []byte(PayloadType), 1), vectorNow, KeySetReasonPayloadType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := VerifyKeySet(c.env, rootID, c.now); keySetReason(err) != c.reason {
				t.Fatalf("err %v, want reason %s", err, c.reason)
			}
		})
	}
	// Within the clock skew of not_after it still verifies.
	if _, _, err := VerifyKeySet(env, rootID, vectorNow.Add(30*24*time.Hour)); err != nil {
		t.Fatalf("at not_after: %v", err)
	}
}

func TestSignKeySet_Refusals(t *testing.T) {
	root := seedKey(9)
	a := pubOf(seedKey(7))
	for name, f := range map[string]func() error{
		"root as an online key": func() error {
			_, _, err := SignKeySet(root, 1, vectorNow, time.Hour, []ed25519.PublicKey{pubOf(root)})
			return err
		},
		"duplicate key": func() error {
			_, _, err := SignKeySet(root, 1, vectorNow, time.Hour, []ed25519.PublicKey{a, a})
			return err
		},
		"over 30 days": func() error {
			_, _, err := SignKeySet(root, 1, vectorNow, MaxKeySetValidity+time.Second, []ed25519.PublicKey{a})
			return err
		},
		"version 0": func() error {
			_, _, err := SignKeySet(root, 0, vectorNow, time.Hour, []ed25519.PublicKey{a})
			return err
		},
		"no keys": func() error {
			_, _, err := SignKeySet(root, 1, vectorNow, time.Hour, nil)
			return err
		},
	} {
		if f() == nil {
			t.Errorf("%s: signed", name)
		}
	}
}
