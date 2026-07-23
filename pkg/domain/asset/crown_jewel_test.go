package asset

import "testing"

// TestAsset_IsCrownJewel reads the crown-jewel flag from properties (its source
// of truth), defaulting to false when unset or a non-bool value is stored.
func TestAsset_IsCrownJewel(t *testing.T) {
	a, err := NewAsset("db.example.com", AssetTypeHost, CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}

	if a.IsCrownJewel() {
		t.Error("a fresh asset must not be a crown jewel by default")
	}

	a.SetProperty("is_crown_jewel", true)
	if !a.IsCrownJewel() {
		t.Error("IsCrownJewel should be true after setting the property")
	}

	a.SetProperty("is_crown_jewel", false)
	if a.IsCrownJewel() {
		t.Error("IsCrownJewel should be false after unsetting the property")
	}

	// Defensive: a non-bool stored value must not panic and reads as false.
	a.SetProperty("is_crown_jewel", "yes")
	if a.IsCrownJewel() {
		t.Error("non-bool property value must read as false")
	}
}
