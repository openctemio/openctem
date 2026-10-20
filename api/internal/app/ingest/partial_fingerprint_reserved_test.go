package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A report may not set the partial-fingerprint keys only the server writes:
// the pre-composite base an asset merge re-keys by, the sensor fingerprint
// slot, or the server's keyed secret hash (B7-D11).
func TestKeyRawSecrets_RefusesServerOnlyKeys(t *testing.T) {
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("unit-test-server-secret-0123456789abcdef")))
	forged := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	rep := &ctis.Report{Findings: []ctis.Finding{{
		Type: ctis.FindingTypeSecret, RuleID: "r",
		PartialFingerprints: map[string]string{
			vulnerability.FingerprintBaseKey: forged, "Composite/Other": forged,
			partialSensorFingerprint: forged, partialServerSecretHMAC: forged,
			partialSecretHMAC: forged, "primaryLocationLineHash": "abc:1",
		},
		Secret: &ctis.SecretDetails{MaskedValue: "AKIA****"},
	}}}
	p.keyRawSecrets(shared.NewID(), rep)
	got := rep.Findings[0].PartialFingerprints
	for _, k := range []string{vulnerability.FingerprintBaseKey, "Composite/Other", partialSensorFingerprint, partialServerSecretHMAC} {
		if _, ok := got[k]; ok {
			t.Errorf("server-only key %q kept from the report", k)
		}
	}
	for _, k := range []string{partialSecretHMAC, "primaryLocationLineHash"} {
		if got[k] == "" {
			t.Errorf("producer key %q dropped", k)
		}
	}
}

// A raw secret is keyed before it is masked; two secrets that mask alike get
// two keys, and an already-masked value gets none.
func TestKeyRawSecrets_KeysTheRawValueNotTheMask(t *testing.T) {
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("unit-test-server-secret-0123456789abcdef")))
	tenant := shared.NewID()
	rep := &ctis.Report{Findings: []ctis.Finding{
		{Type: ctis.FindingTypeSecret, Secret: &ctis.SecretDetails{MaskedValue: "AKIAFAKEFAKEFAKE1111"}},
		{Type: ctis.FindingTypeSecret, Secret: &ctis.SecretDetails{MaskedValue: "AKIAFAKEFAKEFAKE2222"}},
		{Type: ctis.FindingTypeSecret, Secret: &ctis.SecretDetails{MaskedValue: "AKIA************"}},
	}}
	p.keyRawSecrets(tenant, rep)
	a := rep.Findings[0].PartialFingerprints[partialServerSecretHMAC]
	b := rep.Findings[1].PartialFingerprints[partialServerSecretHMAC]
	if a == "" || b == "" || a == b {
		t.Fatalf("raw secrets keyed %q / %q, want two distinct keys", a, b)
	}
	if v := rep.Findings[2].PartialFingerprints[partialServerSecretHMAC]; v != "" {
		t.Fatalf("a mask was keyed as a secret: %q", v)
	}
	redactReportSecrets(rep)
	if m := rep.Findings[0].Secret.MaskedValue; m == "AKIAFAKEFAKEFAKE1111" {
		t.Fatal("the raw value survived the redaction")
	}
}

// The stored finding never takes server-only keys from the report, and the
// API never returns them.
func TestPartialFingerprints_ServerKeysNeitherStoredNorReturned(t *testing.T) {
	in := map[string]string{vulnerability.FingerprintBaseKey: "x", partialSensorFingerprint: "y", partialServerSecretHMAC: "z", "snippetHash/v1": "s"}
	got := clientPartialFingerprints(in)
	if len(got) != 1 || got["snippetHash/v1"] != "s" {
		t.Fatalf("clientPartialFingerprints = %v", got)
	}
	pub := vulnerability.PublicPartialFingerprints(in)
	if len(pub) != 1 || pub["snippetHash/v1"] != "s" {
		t.Fatalf("PublicPartialFingerprints = %v", pub)
	}
	if vulnerability.PublicPartialFingerprints(map[string]string{vulnerability.FingerprintBaseKey: "x"}) != nil {
		t.Fatal("an all-server map must return nil")
	}
}

// The producer's keyed secret hash identifies the finding at ingest but is
// not stored with it: a member who can read the finding must not get a value
// to confirm a short secret against offline.
func TestClientPartialFingerprints_DropsTheProducerSecretHash(t *testing.T) {
	hash := "00000000000000000000000000000000000000000000000000000000000000ff"
	got := clientPartialFingerprints(map[string]string{
		partialSecretHMAC: hash, "SecretHMAC/v9": hash, "primaryLocationLineHash": "abc:1",
	})
	if len(got) != 1 || got["primaryLocationLineHash"] != "abc:1" {
		t.Fatalf("stored partial fingerprints = %v, want only primaryLocationLineHash", got)
	}
}
