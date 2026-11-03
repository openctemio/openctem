package licensekey_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/licensekey"
	lkt "github.com/openctemio/openctem/api/pkg/licensekey/licensekeytest"
)

// Every embedded root is a well-formed Ed25519 key, there are at most two
// (current and next), and no test key is ever trusted by a build.
func TestEmbeddedRoots(t *testing.T) {
	if len(licensekey.EmbeddedRoots) > 2 {
		t.Fatalf("%d embedded roots; a build trusts the current and the next root only", len(licensekey.EmbeddedRoots))
	}
	test := map[string]bool{}
	for _, k := range []ed25519.PrivateKey{lkt.Root(), lkt.OtherRoot(), lkt.IssuingKey(0), lkt.IssuingKey(1), lkt.IssuingKey(2)} {
		test[base64.StdEncoding.EncodeToString(lkt.Public(k))] = true
	}
	for _, r := range licensekey.EmbeddedRoots {
		raw, err := base64.StdEncoding.DecodeString(r)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			t.Errorf("embedded root %q is not a base64 Ed25519 public key", r)
		}
		if test[r] {
			t.Errorf("embedded root %q is a public test key", r)
		}
	}
	if got := len(licensekey.Default().RootKeyIDs()); got != len(licensekey.EmbeddedRoots) {
		t.Errorf("Default trusts %d roots, %d embedded", got, len(licensekey.EmbeddedRoots))
	}
	for _, id := range licensekey.Default().RootKeyIDs() {
		if id == jobsign.KeyID(lkt.Public(lkt.Root())) {
			t.Error("Default trusts the test root")
		}
	}
}

// The build's verifier never accepts a file signed under the test root.
func TestDefaultRefusesTestLicense(t *testing.T) {
	now := time.Now()
	_, err := licensekey.Default().Verify(lkt.File(now, lkt.Claims(now)), licensekey.Options{})
	if !errors.Is(err, licensekey.ErrNoTrustedRoot) && !errors.Is(err, licensekey.ErrUntrustedRoot) {
		t.Fatalf("Default accepted or misreported a test license: %v", err)
	}
}
