package pairing_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/sensorproto/pairing"
)

func grantFixture(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, []byte, *pairing.SignedGrant) {
	t.Helper()
	pk := ed25519.NewKeyFromSeed(seed(2))
	sk := ed25519.NewKeyFromSeed(seed(1))
	spub := sk.Public().(ed25519.PublicKey)
	nonce := bytes.Repeat([]byte{3}, pairing.NonceSize)
	sg, err := pairing.SignGrant(pk, &pairing.Grant{PairingID: "p-1", SensorKey: pairing.Encode(spub), SensorNonce: pairing.Encode(nonce),
		Identity:   pairing.Identity{SensorID: "s-1", TenantID: "t-1", KeyID: "k"},
		SignedJobs: &pairing.JobSigning{PayloadType: "x", Keys: []pairing.JobKey{{KeyID: "a", Algorithm: "ed25519", PublicKey: "AA=="}}},
		TLSAnchors: []string{"sha256:00"}})
	if err != nil {
		t.Fatal(err)
	}
	return pk, spub, nonce, sg
}

func TestGrantVerifies(t *testing.T) {
	pk, spub, nonce, sg := grantFixture(t)
	g, err := pairing.VerifyGrant(sg, pk.Public().(ed25519.PublicKey), spub, "p-1", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if g.Identity.SensorID != "s-1" || g.SignedJobs.Keys[0].KeyID != "a" || g.TLSAnchors[0] != "sha256:00" || g.Protocol != pairing.Version {
		t.Fatalf("grant = %+v", g)
	}
}

// A man in the middle who changes any part of the statement, or signs it
// with its own key, is refused.
func TestGrantRefusesTampering(t *testing.T) {
	pk, spub, nonce, sg := grantFixture(t)
	ppub := pk.Public().(ed25519.PublicKey)
	payload, err := base64.RawURLEncoding.DecodeString(sg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var g pairing.Grant
	if err := json.Unmarshal(payload, &g); err != nil {
		t.Fatal(err)
	}
	g.SignedJobs.Keys[0].PublicKey = "Ag=="
	swapped, _ := json.Marshal(g)
	attacker := ed25519.NewKeyFromSeed(seed(9))
	resigned, _ := pairing.SignGrant(attacker, &g)
	for name, c := range map[string]*pairing.SignedGrant{
		"payload changed":       {Payload: pairing.Encode(swapped), Signature: sg.Signature},
		"signed by another key": resigned,
		"signature cut":         {Payload: sg.Payload, Signature: sg.Signature[:10]},
		"payload not base64":    {Payload: "!!", Signature: sg.Signature},
	} {
		if _, err := pairing.VerifyGrant(c, ppub, spub, "p-1", nonce); !errors.Is(err, pairing.ErrGrantSignature) {
			t.Errorf("%s: err = %v, want ErrGrantSignature", name, err)
		}
	}
	for name, c := range map[string]*pairing.SignedGrant{"nil": nil, "empty": {}} {
		if _, err := pairing.VerifyGrant(c, ppub, spub, "p-1", nonce); !errors.Is(err, pairing.ErrGrantMissing) {
			t.Errorf("%s: err = %v, want ErrGrantMissing", name, err)
		}
	}
}

// A grant the platform signed for another sensor, request or nonce is not
// valid here: a confirm answer cannot be replayed to another sensor.
func TestGrantRefusesReplay(t *testing.T) {
	pk, spub, nonce, sg := grantFixture(t)
	ppub := pk.Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(seed(5)).Public().(ed25519.PublicKey)
	cases := map[string]func() error{
		"other sensor key": func() error { _, err := pairing.VerifyGrant(sg, ppub, other, "p-1", nonce); return err },
		"other pairing":    func() error { _, err := pairing.VerifyGrant(sg, ppub, spub, "p-2", nonce); return err },
		"other nonce": func() error {
			_, err := pairing.VerifyGrant(sg, ppub, spub, "p-1", bytes.Repeat([]byte{4}, pairing.NonceSize))
			return err
		},
		"no nonce": func() error { _, err := pairing.VerifyGrant(sg, ppub, spub, "p-1", nil); return err },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, pairing.ErrGrantBinding) {
			t.Errorf("%s: err = %v, want ErrGrantBinding", name, err)
		}
	}
}
