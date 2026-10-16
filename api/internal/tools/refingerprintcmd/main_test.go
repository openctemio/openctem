package refingerprintcmd

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
)

func TestReadOnlyURL(t *testing.T) {
	cases := map[string]string{
		"postgres://u:p@h:5432/db?sslmode=disable": "postgres://u:p@h:5432/db?default_transaction_read_only=on&sslmode=disable",
		"host=h dbname=db":                         "host=h dbname=db default_transaction_read_only=on",
	}
	for in, want := range cases {
		if got := readOnlyURL(in); got != want {
			t.Errorf("readOnlyURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// A -before later than the keyed-fingerprint cutoff would clear verifiable
// fingerprints too: it needs -force.
func TestLegacyCutoff(t *testing.T) {
	cut := postgres.LegacySecretFingerprintCutoff
	if got, err := legacyCutoff("", false); err != nil || !got.Equal(cut) {
		t.Fatalf("default: %v %v", got, err)
	}
	earlier := cut.Add(-time.Hour).Format(time.RFC3339)
	if got, err := legacyCutoff(earlier, false); err != nil || !got.Before(cut) {
		t.Fatalf("earlier cutoff: %v %v", got, err)
	}
	later := cut.Add(time.Hour).Format(time.RFC3339)
	if _, err := legacyCutoff(later, false); err == nil {
		t.Fatal("a later cutoff without -force was accepted")
	}
	if got, err := legacyCutoff(later, true); err != nil || !got.After(cut) {
		t.Fatalf("later cutoff with -force: %v %v", got, err)
	}
	if _, err := legacyCutoff("yesterday", true); err == nil {
		t.Fatal("a malformed time was accepted")
	}
}
