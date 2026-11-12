package asset

import "testing"

// UpdateExposure must stamp exposure_changed_at when the level changes (the
// program-metrics MTTD clock stop), and leave it alone when it does not.
func TestUpdateExposure_StampsChangeTime(t *testing.T) {
	a, err := NewAsset("stamp.example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAsset: %v", err)
	}
	if a.ExposureChangedAt() != nil {
		t.Fatalf("new asset: want nil exposure_changed_at, got %v", a.ExposureChangedAt())
	}

	if err := a.UpdateExposure(ExposurePublic); err != nil {
		t.Fatalf("UpdateExposure: %v", err)
	}
	first := a.ExposureChangedAt()
	if first == nil {
		t.Fatal("unknown → public: want exposure_changed_at stamped, got nil")
	}

	if err := a.UpdateExposure(ExposurePublic); err != nil {
		t.Fatalf("UpdateExposure: %v", err)
	}
	if a.ExposureChangedAt() != first {
		t.Fatal("public → public: exposure_changed_at must not move on a no-op update")
	}

	if err := a.UpdateExposure(Exposure("bogus")); err == nil {
		t.Fatal("invalid exposure: want error")
	}
	if a.ExposureChangedAt() != first || a.Exposure() != ExposurePublic {
		t.Fatal("invalid exposure must not change state")
	}
}
