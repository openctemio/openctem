package credential

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const fpTestKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func fpTestProtector(t *testing.T) *SecretProtector {
	t.Helper()
	c, err := crypto.NewCipherFromHex(fpTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return NewSecretProtector(c, []byte(fpTestKeyHex))
}

// The same leaked secret in two organizations must not have the same
// fingerprint: a database reader could otherwise link the organizations.
func TestFingerprint_PerTenant(t *testing.T) {
	p := fpTestProtector(t)
	a, b := shared.NewID(), shared.NewID()
	const secret = "Winter2026!"
	fa, fb := p.Fingerprint(a, secret), p.Fingerprint(b, secret)
	if fa == "" || fb == "" || fa == fb {
		t.Fatalf("cross-tenant fingerprints must differ: %q %q", fa, fb)
	}
	if p.Fingerprint(a, secret) != fa {
		t.Fatal("same tenant, same secret: same fingerprint (dedup inside one organization)")
	}
	if p.Fingerprint(a, secret+"x") == fa {
		t.Fatal("another secret must have another fingerprint")
	}
	if fa == p.FingerprintV1(secret) {
		t.Fatal("per-tenant recipe must differ from the install-wide one")
	}
	other := NewSecretProtector(nil, []byte("another-platform-key"))
	if other.Fingerprint(a, secret) == fa {
		t.Fatal("fingerprint must depend on the platform key")
	}
	if p.Fingerprint(shared.ID{}, secret) != "" {
		t.Fatal("no tenant, no fingerprint (never an install-wide one)")
	}
}

func TestSeal_StoreOffKeepsMaskTypeAndFingerprintOnly(t *testing.T) {
	p := fpTestProtector(t)
	tenant := shared.NewID()
	details := map[string]any{"credential_type": "password", DetailSecretValue: "hunter2-long-password"}
	if err := p.Seal(tenant, details, false); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{DetailSecretValue, DetailSecretCiphertext, DetailSecretScheme} {
		if _, ok := details[k]; ok {
			t.Fatalf("store off must not keep %s: %v", k, details)
		}
	}
	if details[DetailSecretMasked] != maskedSecret || details["credential_type"] != "password" {
		t.Fatalf("mask/type missing: %v", details)
	}
	if details[DetailSecretFingerprint] != p.Fingerprint(tenant, "hunter2-long-password") || !HasTenantFingerprint(details) {
		t.Fatalf("fingerprint missing: %v", details)
	}
	if HasSecret(details) {
		t.Fatal("nothing to reveal when the value is not stored")
	}
	if _, ok, _ := p.Open(details); ok {
		t.Fatal("Open must find no secret")
	}
	// Stored before, not stored now: the old ciphertext belonged to the old
	// value and is removed.
	prev := map[string]any{DetailSecretValue: "old"}
	if err := p.Seal(tenant, prev, true); err != nil {
		t.Fatal(err)
	}
	prev[DetailSecretValue] = "new"
	if err := p.Seal(tenant, prev, false); err != nil {
		t.Fatal(err)
	}
	if HasSecret(prev) {
		t.Fatalf("old ciphertext kept next to a new unstored value: %v", prev)
	}
}

func TestSeal_StoreOnEncryptsAndFingerprintsPerTenant(t *testing.T) {
	p := fpTestProtector(t)
	tenant := shared.NewID()
	details := map[string]any{DetailSecretValue: "s3cret"}
	if err := p.Seal(tenant, details, true); err != nil {
		t.Fatal(err)
	}
	if details[DetailSecretScheme] != SecretSchemeAESGCM || !HasTenantFingerprint(details) {
		t.Fatalf("details %v", details)
	}
	if got, ok, err := p.Open(details); err != nil || !ok || got != "s3cret" {
		t.Fatalf("open %q %v %v", got, ok, err)
	}
	if details[DetailSecretFingerprint] != p.Fingerprint(tenant, "s3cret") {
		t.Fatal("fingerprint is the tenant's")
	}
}

// A row written with the install-wide recipe is re-keyed once, and the
// reversal gives back exactly the old value.
func TestRekeyFingerprint_IdempotentAndReversible(t *testing.T) {
	p := fpTestProtector(t)
	tenant := shared.NewID()
	ct, err := p.enc.EncryptString("leaked")
	if err != nil {
		t.Fatal(err)
	}
	v1 := p.FingerprintV1("leaked")
	details := map[string]any{DetailSecretCiphertext: ct, DetailSecretScheme: SecretSchemeAESGCM, DetailSecretFingerprint: v1}

	if got := p.RekeyFingerprint(tenant, details); got != FingerprintRekeyed {
		t.Fatalf("first re-key = %v", got)
	}
	want := p.Fingerprint(tenant, "leaked")
	if details[DetailSecretFingerprint] != want {
		t.Fatal("re-key must write the tenant fingerprint")
	}
	// Through JSON, as stored: the version reads back as a float64.
	raw, _ := json.Marshal(details)
	back := map[string]any{}
	_ = json.Unmarshal(raw, &back)
	if got := p.RekeyFingerprint(tenant, back); got != FingerprintUnchanged || back[DetailSecretFingerprint] != want {
		t.Fatalf("second re-key must be a no-op: %v %v", got, back)
	}

	if got := p.RevertFingerprint(back); got != FingerprintRekeyed || back[DetailSecretFingerprint] != v1 || HasTenantFingerprint(back) {
		t.Fatalf("revert: %v %v", got, back)
	}
	if got := p.RevertFingerprint(back); got != FingerprintUnchanged {
		t.Fatalf("second revert must be a no-op: %v", got)
	}
}

func TestRekeyFingerprint_UnreadableRowIsLeftAlone(t *testing.T) {
	p := fpTestProtector(t)
	details := map[string]any{DetailSecretCiphertext: "bm90LWNpcGhlcnRleHQ=", DetailSecretScheme: SecretSchemeAESGCM, DetailSecretFingerprint: "abcd"}
	if got := p.RekeyFingerprint(shared.NewID(), details); got != FingerprintUnrecomputable || details[DetailSecretFingerprint] != "abcd" {
		t.Fatalf("got %v %v", got, details)
	}
	none := map[string]any{"credential_type": "password"}
	if got := p.RekeyFingerprint(shared.NewID(), none); got != FingerprintUnchanged {
		t.Fatalf("no fingerprint: %v", got)
	}
}

func TestRedactDetails_KeepsFingerprintVersion(t *testing.T) {
	out := RedactDetails(map[string]any{DetailSecretFingerprint: "ab", DetailSecretFingerprintVersion: 2})
	if out[DetailSecretFingerprintVersion] != 2 || out[DetailSecretFingerprint] != "ab" {
		t.Fatalf("redacted %v", out)
	}
}
