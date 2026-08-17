package asset

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TestParseImpactRating covers the CIA impact-rating enum validation for the
// CTEM Scoping critical-asset register.
func TestParseImpactRating(t *testing.T) {
	cases := []struct {
		in      string
		want    ImpactRating
		wantErr bool
	}{
		{"low", ImpactRatingLow, false},
		{"moderate", ImpactRatingModerate, false},
		{"high", ImpactRatingHigh, false},
		{"HIGH", ImpactRatingHigh, false},   // case-insensitive
		{"  low  ", ImpactRatingLow, false}, // trimmed
		{"", "", false},                     // empty allowed (optional field)
		{"medium", "", true},                // not a CIA rating
		{"critical", "", true},
	}
	for _, c := range cases {
		got, err := ParseImpactRating(c.in)
		if c.wantErr && err == nil {
			t.Errorf("ParseImpactRating(%q): expected error, got nil", c.in)
			continue
		}
		if !c.wantErr && err != nil {
			t.Errorf("ParseImpactRating(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseImpactRating(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSetImpactRatings verifies the CIA setters accept valid ratings and the
// empty (clear) value, and reject invalid ratings.
func TestSetImpactRatings(t *testing.T) {
	a, err := NewAsset("cia.example.com", AssetTypeDatabase, CriticalityHigh)
	if err != nil {
		t.Fatalf("NewAsset: %v", err)
	}

	if err := a.SetImpactConfidentiality(ImpactRatingHigh); err != nil {
		t.Fatalf("SetImpactConfidentiality(high): %v", err)
	}
	if err := a.SetImpactIntegrity(ImpactRatingModerate); err != nil {
		t.Fatalf("SetImpactIntegrity(moderate): %v", err)
	}
	if err := a.SetImpactAvailability(ImpactRatingLow); err != nil {
		t.Fatalf("SetImpactAvailability(low): %v", err)
	}

	if a.ImpactConfidentiality() != ImpactRatingHigh {
		t.Errorf("ImpactConfidentiality = %q, want high", a.ImpactConfidentiality())
	}
	if a.ImpactIntegrity() != ImpactRatingModerate {
		t.Errorf("ImpactIntegrity = %q, want moderate", a.ImpactIntegrity())
	}
	if a.ImpactAvailability() != ImpactRatingLow {
		t.Errorf("ImpactAvailability = %q, want low", a.ImpactAvailability())
	}

	// Empty clears without error.
	if err := a.SetImpactConfidentiality(""); err != nil {
		t.Errorf("SetImpactConfidentiality(\"\"): unexpected error %v", err)
	}
	if a.ImpactConfidentiality() != "" {
		t.Errorf("ImpactConfidentiality not cleared: %q", a.ImpactConfidentiality())
	}

	// Invalid rating rejected.
	if err := a.SetImpactIntegrity(ImpactRating("severe")); err == nil {
		t.Error("SetImpactIntegrity(severe): expected validation error, got nil")
	}
}

// TestReconstituteRoundTripsCIA ensures the repository reconstruction path
// carries the CIA ratings through to the entity.
func TestReconstituteRoundTripsCIA(t *testing.T) {
	now := time.Now().UTC()
	a := Reconstitute(
		shared.NewID(), shared.NewID(), nil, nil,
		"recon.example.com", AssetTypeHost, CriticalityMedium,
		StatusActive, ScopeInternal, ExposurePrivate,
		0, 0, "", nil, nil,
		ProviderManual, "", "",
		SyncStatusSynced, nil, "",
		"", "", nil,
		nil, "", false, false, nil,
		false, nil, ExposureUnknown,
		ImpactRatingHigh, ImpactRatingModerate, ImpactRatingLow,
		now, now, now, now,
	)
	if a.ImpactConfidentiality() != ImpactRatingHigh ||
		a.ImpactIntegrity() != ImpactRatingModerate ||
		a.ImpactAvailability() != ImpactRatingLow {
		t.Errorf("Reconstitute dropped CIA ratings: C=%q I=%q A=%q",
			a.ImpactConfidentiality(), a.ImpactIntegrity(), a.ImpactAvailability())
	}
}

// TestRelationshipControlPlaneFlag covers the control-plane dependency flag on
// an asset relationship edge.
func TestRelationshipControlPlaneFlag(t *testing.T) {
	tenantID := shared.NewID()
	src := shared.NewID()
	dst := shared.NewID()

	rel, err := NewRelationship(tenantID, src, dst, RelTypeDependsOn)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}

	// Defaults to false.
	if rel.IsControlPlane() {
		t.Error("new relationship should default IsControlPlane=false")
	}

	rel.SetControlPlane(true)
	if !rel.IsControlPlane() {
		t.Error("SetControlPlane(true) did not take effect")
	}

	// Round-trips through reconstruction.
	now := time.Now().UTC()
	recon := ReconstituteRelationship(
		rel.ID(), tenantID, src, dst, RelTypeDependsOn,
		"", ConfidenceMedium, DiscoveryManual, 5, nil,
		true, // isControlPlane
		nil, now, now,
	)
	if !recon.IsControlPlane() {
		t.Error("ReconstituteRelationship dropped is_control_plane=true")
	}
}
