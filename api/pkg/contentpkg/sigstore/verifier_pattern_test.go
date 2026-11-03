package sigstore_test

import (
	"os"

	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/openctemio/openctem/api/pkg/contentpkg/sigstore"
	"github.com/openctemio/openctem/api/pkg/releasefeed/releasefeedtest"
)

// VerifyPattern refuses a pattern that is not anchored: an unanchored one
// would accept any identity that merely contains the workflow path.
func TestVerifyPattern_RequiresAnchors(t *testing.T) {
	s := releasefeedtest.New(t)
	v := s.Verifier(t)
	art := []byte("artifact")
	sig := s.Sign(t, art, releasefeedtest.GoodIdentityMain, releasefeedtest.GitHubIssuer, time.Now().Add(time.Minute), false)
	if _, err := v.VerifyPattern(sig, art, `release-feed\.yml`, releasefeedtest.GitHubIssuer); err == nil {
		t.Fatal("an unanchored pattern was accepted")
	}
	if _, err := v.VerifyPattern(sig, art, `^https://github\.com/openctemio/openctem/.*$`, releasefeedtest.GitHubIssuer); err != nil {
		t.Fatalf("an anchored pattern: %v", err)
	}
	if _, err := v.VerifyPattern(sig, art, "", releasefeedtest.GitHubIssuer); err == nil {
		t.Fatal("an empty pattern was accepted")
	}
	// The exact-identity path still works and refuses a near miss.
	if _, err := v.Verify(sig, art, releasefeedtest.GoodIdentityMain, releasefeedtest.GitHubIssuer); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(sig, art, releasefeedtest.GoodIdentityTag, releasefeedtest.GitHubIssuer); err == nil {
		t.Fatal("another identity accepted")
	}
}

// The embedded trusted root loads and still lists a certificate authority and
// a transparency log that are valid now: when Sigstore retires them this fails
// and the root is refreshed (make sigstore-root-refresh) before the release
// feed and content signatures stop verifying.
func TestEmbeddedTrustedRoot_Current(t *testing.T) {
	if _, err := sigstore.New(""); err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromJSON(sigstoreEmbedded(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	valid := false
	for _, ca := range tr.FulcioCertificateAuthorities() {
		if f, ok := ca.(*root.FulcioCertificateAuthority); ok && !f.ValidityPeriodStart.After(now) &&
			(f.ValidityPeriodEnd.IsZero() || f.ValidityPeriodEnd.After(now.Add(30*24*time.Hour))) {
			valid = true
		}
	}
	if !valid {
		t.Fatal("no Fulcio certificate authority in the embedded trusted root is valid for the next 30 days: refresh it")
	}
	logValid := false
	for _, l := range tr.RekorLogs() {
		if !l.ValidityPeriodStart.After(now) && (l.ValidityPeriodEnd.IsZero() || l.ValidityPeriodEnd.After(now.Add(30*24*time.Hour))) {
			logValid = true
		}
	}
	if !logValid {
		t.Fatal("no transparency log in the embedded trusted root is valid for the next 30 days: refresh it")
	}
}

func sigstoreEmbedded(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
