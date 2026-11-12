package asset

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// assets.name is varchar(255): a longer name used to reach the database and
// fail the whole ingest upsert. The domain refuses it per asset now.
func TestNewAsset_NameLength(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		typ     AssetType
		wantErr bool
	}{
		{"exactly the limit", strings.Repeat("a", MaxNameLength), AssetTypeHost, false},
		{"one over the limit", strings.Repeat("a", MaxNameLength+1), AssetTypeHost, true},
		{"multi-byte characters count as characters", strings.Repeat("é", MaxNameLength), AssetTypeIdentity, false},
		{"multi-byte over the limit", strings.Repeat("é", MaxNameLength+1), AssetTypeIdentity, true},
		// The limit applies to the stored (normalized) name: the scheme and
		// trailing dot of a DNS name are stripped before the check.
		{"normalization brings it under", "https://" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".com.", AssetTypeDomain, false},
		{"long website URL", "https://example.com/" + strings.Repeat("p", 300), AssetTypeWebsite, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := NewAsset(c.in, c.typ, CriticalityMedium)
			if c.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("NewAsset err = %v, want a validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewAsset: %v", err)
			}
			if n := len([]rune(a.Name())); n > MaxNameLength {
				t.Fatalf("stored name is %d characters", n)
			}
		})
	}
}

func TestUpdateName_NameLength(t *testing.T) {
	a, err := NewAsset("web-1", AssetTypeHost, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UpdateName(strings.Repeat("x", MaxNameLength+1)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("UpdateName err = %v, want a validation error", err)
	}
	if a.Name() != "web-1" {
		t.Fatalf("name changed to %q after a refused rename", a.Name())
	}
}
