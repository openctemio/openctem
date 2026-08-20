package assetgroup

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TestBusinessUnitID_DefaultNil verifies a freshly reconstituted group has no
// reconciled BU FK until the persistence layer sets one (migration 000211).
func TestBusinessUnitID_DefaultNil(t *testing.T) {
	g, err := NewAssetGroupWithTenant(shared.NewID(), "web", EnvironmentProduction, CriticalityHigh)
	if err != nil {
		t.Fatalf("new group: %v", err)
	}
	if g.BusinessUnitID() != nil {
		t.Fatalf("expected nil business_unit_id by default, got %v", g.BusinessUnitID())
	}
}

// TestSetBusinessUnitID roundtrips the reconciled FK setter/getter used by the
// repository after it resolves the FK from the free-text business_unit string.
func TestSetBusinessUnitID(t *testing.T) {
	g, err := NewAssetGroupWithTenant(shared.NewID(), "web", EnvironmentProduction, CriticalityHigh)
	if err != nil {
		t.Fatalf("new group: %v", err)
	}
	buID := shared.NewID()
	g.SetBusinessUnitID(&buID)
	if got := g.BusinessUnitID(); got == nil || *got != buID {
		t.Fatalf("expected business_unit_id %v, got %v", buID, got)
	}
	g.SetBusinessUnitID(nil)
	if g.BusinessUnitID() != nil {
		t.Fatalf("expected nil after clearing, got %v", g.BusinessUnitID())
	}
}

// TestWithBusinessUnitID verifies the additive FK filter builder.
func TestWithBusinessUnitID(t *testing.T) {
	id := shared.NewID().String()
	f := NewFilter().WithBusinessUnitID(id)
	if f.BusinessUnitID == nil || *f.BusinessUnitID != id {
		t.Fatalf("expected filter business_unit_id %q, got %v", id, f.BusinessUnitID)
	}
	// Must not disturb the legacy free-text filter.
	if f.BusinessUnit != nil {
		t.Fatalf("expected legacy BusinessUnit untouched, got %v", f.BusinessUnit)
	}
}
