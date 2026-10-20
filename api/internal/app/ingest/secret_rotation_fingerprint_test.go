package ingest

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func secretFindingFor(t *testing.T, tenant shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSecret, "betterleaks",
		vulnerability.SeverityHigh, "Key")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// A mask is shared by unrelated secrets, so it never becomes the fingerprint
// a rotation group is keyed on: two different AWS keys or short passwords
// reported only as a mask get no fingerprint (and so no shared rotation group).
func TestSetSecretFields_MaskNeverBecomesTheRotationFingerprint(t *testing.T) {
	tenant := shared.NewID()
	p := NewFindingProcessor(nil, nil, nil, logger.NewNop())
	p.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("server-secret-0123456789")))
	for _, mask := range []string{"REDACTED", "AKIA********", "ghp_********", "••••••••"} {
		f := secretFindingFor(t, tenant)
		p.setSecretFields(f, &ctis.Finding{Secret: &ctis.SecretDetails{SecretType: "x", MaskedValue: mask}})
		if f.SecretFingerprint() != "" {
			t.Errorf("mask %q produced fingerprint %q", mask, f.SecretFingerprint())
		}
	}
}

// With the producer's keyed hash of the raw value the fingerprint exists, is
// the same for the same secret and differs between secrets and between tenants.
func TestSetSecretFields_FingerprintFromRawHashOnly(t *testing.T) {
	p := NewFindingProcessor(nil, nil, nil, logger.NewNop())
	p.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("server-secret-0123456789")))
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	fp := func(tenant shared.ID, hash string) string {
		f := secretFindingFor(t, tenant)
		p.setSecretFields(f, &ctis.Finding{
			Secret:              &ctis.SecretDetails{SecretType: "aws", MaskedValue: "AKIA************"},
			PartialFingerprints: map[string]string{partialSecretHMAC: hash}})
		return f.SecretFingerprint()
	}
	t1, t2 := shared.NewID(), shared.NewID()
	a1, a1again, b1, a2 := fp(t1, hashA), fp(t1, hashA), fp(t1, hashB), fp(t2, hashA)
	if a1 == "" || a1 != a1again {
		t.Fatalf("same secret must share a fingerprint: %q %q", a1, a1again)
	}
	if a1 == b1 {
		t.Fatal("two different AWS keys share a fingerprint")
	}
	if a1 == a2 {
		t.Fatal("the same secret in two tenants shares a fingerprint")
	}
}

// A producer's preview is a mask: the server does not take it for the raw
// secret and key the finding (and its rotation group) on it.
func TestKeyRawSecrets_APreviewIsNotKeyedAsTheRawValue(t *testing.T) {
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("unit-test-server-secret-0123456789abcdef")))
	rep := &ctis.Report{Findings: []ctis.Finding{
		{Type: ctis.FindingTypeSecret, Secret: &ctis.SecretDetails{MaskedValue: "AKIA…MPLE"}},
		{Type: ctis.FindingTypeSecret, Secret: &ctis.SecretDetails{MaskedValue: "ghp_…6789"}},
	}}
	p.keyRawSecrets(shared.NewID(), rep)
	for i := range rep.Findings {
		if v := rep.Findings[i].PartialFingerprints[partialServerSecretHMAC]; v != "" {
			t.Errorf("finding %d: a preview was keyed as the raw secret", i)
		}
	}
}
