package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Ingest stores a secret finding's fingerprint under the server-held key the
// processor was wired with, never under a key derivable from the tenant id;
// unwired, it stores none (RFC-043 §4.2).
func TestSetSecretFields_FingerprintIsKeyedByServerSecret(t *testing.T) {
	const reported = "fake-token-51HxyzABCDEFGHIJKLMNOPQRSTUV1234Qx"
	tenant := shared.NewID()
	newFinding := func() *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSecret, "betterleaks",
			vulnerability.SeverityHigh, "Stripe key")
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	ctisFinding := &ctis.Finding{Secret: &ctis.SecretDetails{SecretType: "api_key", MaskedValue: reported}}

	unwired := NewFindingProcessor(nil, nil, nil, logger.NewNop())
	f := newFinding()
	unwired.setSecretFields(f, ctisFinding)
	if f.SecretFingerprint() != "" {
		t.Fatalf("no key configured, got fingerprint %q", f.SecretFingerprint())
	}

	fpr := vulnerability.NewSecretFingerprinter([]byte("server-secret"))
	wired := NewFindingProcessor(nil, nil, nil, logger.NewNop())
	wired.SetSecretFingerprinter(fpr)
	f = newFinding()
	wired.setSecretFields(f, ctisFinding)
	if f.SecretFingerprint() == "" || f.SecretFingerprint() != fpr.Fingerprint(tenant, reported) {
		t.Fatalf("fingerprint %q, want the keyed one", f.SecretFingerprint())
	}
	mac := hmac.New(sha256.New, []byte("openctem/secret-fingerprint/v1/"+tenant.String()))
	mac.Write([]byte(reported))
	if f.SecretFingerprint() == hex.EncodeToString(mac.Sum(nil)[:16]) {
		t.Fatal("fingerprint is derivable from the tenant id alone")
	}
}
