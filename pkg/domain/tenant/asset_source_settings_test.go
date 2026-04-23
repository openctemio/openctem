package tenant

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/openctemio/api/pkg/domain/shared"
)

func newID(t *testing.T) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(uuid.New().String())
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	return id
}

func TestAssetSourceSettings_IsEnabled(t *testing.T) {
	// Zero value = feature off. This is the backward-compatibility
	// promise — pre-RFC-003 tenants must look identical.
	var zero AssetSourceSettings
	if zero.IsEnabled() {
		t.Fatal("zero-value AssetSourceSettings should not be enabled")
	}

	withPriority := AssetSourceSettings{Priority: []shared.ID{newID(t)}}
	if !withPriority.IsEnabled() {
		t.Error("non-empty Priority should enable the feature")
	}

	withTrust := AssetSourceSettings{
		TrustLevels: map[string]TrustLevel{newID(t).String(): TrustLevelPrimary},
	}
	if !withTrust.IsEnabled() {
		t.Error("non-empty TrustLevels should enable the feature")
	}
}

func TestAssetSourceSettings_TrustLevelFor(t *testing.T) {
	id := newID(t)
	s := AssetSourceSettings{
		TrustLevels: map[string]TrustLevel{id.String(): TrustLevelHigh},
	}

	if got := s.TrustLevelFor(id); got != TrustLevelHigh {
		t.Errorf("TrustLevelFor(known) = %v, want %v", got, TrustLevelHigh)
	}

	// Unknown ID returns empty level — caller treats as unlisted.
	if got := s.TrustLevelFor(newID(t)); got != "" {
		t.Errorf("TrustLevelFor(unknown) = %v, want empty", got)
	}

	// Empty map handled gracefully.
	var empty AssetSourceSettings
	if got := empty.TrustLevelFor(id); got != "" {
		t.Errorf("TrustLevelFor on empty settings = %v, want empty", got)
	}
}

func TestAssetSourceSettings_Validate_OK(t *testing.T) {
	s := AssetSourceSettings{
		Priority: []shared.ID{newID(t), newID(t)},
		TrustLevels: map[string]TrustLevel{
			newID(t).String(): TrustLevelPrimary,
			newID(t).String(): TrustLevelLow,
		},
		TrackFieldAttribution: true,
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
}

func TestAssetSourceSettings_Validate_Rejects(t *testing.T) {
	dupID := newID(t)

	cases := []struct {
		name string
		s    AssetSourceSettings
	}{
		{
			name: "duplicate in priority",
			s:    AssetSourceSettings{Priority: []shared.ID{dupID, dupID}},
		},
		{
			name: "empty key in trust_levels",
			s: AssetSourceSettings{
				TrustLevels: map[string]TrustLevel{"": TrustLevelMedium},
			},
		},
		{
			name: "non-UUID key in trust_levels",
			s: AssetSourceSettings{
				TrustLevels: map[string]TrustLevel{"not-a-uuid": TrustLevelMedium},
			},
		},
		{
			name: "unknown level in trust_levels",
			s: AssetSourceSettings{
				TrustLevels: map[string]TrustLevel{newID(t).String(): "bogus"},
			},
		},
		{
			name: "empty level in trust_levels",
			s: AssetSourceSettings{
				TrustLevels: map[string]TrustLevel{newID(t).String(): ""},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("expected ErrValidation, got %v", err)
			}
		})
	}
}

func TestSettings_Validate_IncludesAssetSource(t *testing.T) {
	// Ensure the parent Settings.Validate() runs AssetSource's
	// Validate. Regression guard: if someone refactors and drops
	// the hook, this test fires.
	dupID := newID(t)
	s := Settings{
		AssetSource: AssetSourceSettings{
			Priority: []shared.ID{dupID, dupID},
		},
	}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected validation to propagate AssetSource error")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSettings_RoundTrip_PreservesAssetSource(t *testing.T) {
	// ToMap → SettingsFromMap must preserve the AssetSource subtree.
	// JSON tag drift here would silently lose user config.
	id1 := newID(t)
	id2 := newID(t)
	original := Settings{
		AssetSource: AssetSourceSettings{
			SchemaVersion:         1,
			Priority:              []shared.ID{id1, id2},
			TrustLevels:           map[string]TrustLevel{id1.String(): TrustLevelPrimary},
			TrackFieldAttribution: true,
		},
	}

	roundtrip := SettingsFromMap(original.ToMap())

	if roundtrip.AssetSource.SchemaVersion != 1 {
		t.Errorf("SchemaVersion lost: got %d", roundtrip.AssetSource.SchemaVersion)
	}
	if len(roundtrip.AssetSource.Priority) != 2 {
		t.Fatalf("Priority length: got %d, want 2", len(roundtrip.AssetSource.Priority))
	}
	if roundtrip.AssetSource.Priority[0] != id1 || roundtrip.AssetSource.Priority[1] != id2 {
		t.Errorf("Priority order mismatch: %v", roundtrip.AssetSource.Priority)
	}
	if roundtrip.AssetSource.TrustLevels[id1.String()] != TrustLevelPrimary {
		t.Errorf("TrustLevels lost")
	}
	if !roundtrip.AssetSource.TrackFieldAttribution {
		t.Error("TrackFieldAttribution lost")
	}
}

func TestTenant_UpdateAssetSourceSettings(t *testing.T) {
	// Builds a minimal tenant and verifies that UpdateAssetSourceSettings
	// persists into TypedSettings().
	tn, err := NewTenant("ACME", "acme", newID(t).String())
	if err != nil {
		t.Fatalf("NewTenant: %v", err)
	}

	id := newID(t)
	target := AssetSourceSettings{
		Priority:              []shared.ID{id},
		TrustLevels:           map[string]TrustLevel{id.String(): TrustLevelHigh},
		TrackFieldAttribution: true,
	}

	if err := tn.UpdateAssetSourceSettings(target); err != nil {
		t.Fatalf("UpdateAssetSourceSettings: %v", err)
	}

	got := tn.TypedSettings().AssetSource
	if len(got.Priority) != 1 || got.Priority[0] != id {
		t.Errorf("priority not persisted: %v", got.Priority)
	}
	if got.TrustLevels[id.String()] != TrustLevelHigh {
		t.Errorf("trust level not persisted: %v", got.TrustLevels)
	}
	if !got.TrackFieldAttribution {
		t.Error("track_field_attribution not persisted")
	}

	// Invalid payload (duplicate) must be rejected and not touch
	// the stored settings.
	dup := newID(t)
	bad := AssetSourceSettings{Priority: []shared.ID{dup, dup}}
	if err := tn.UpdateAssetSourceSettings(bad); err == nil {
		t.Fatal("expected validation error for duplicate priority")
	}
	// Previous state still in place.
	if got2 := tn.TypedSettings().AssetSource; got2.Priority[0] != id {
		t.Errorf("failed update leaked state: %v", got2)
	}
}
