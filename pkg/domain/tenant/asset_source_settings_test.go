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

func TestSettingsFromMap_LegacyTenantWithoutAssetSource(t *testing.T) {
	// Regression guard for pre-RFC-003 tenants whose stored JSONB
	// payload has no "asset_source" key at all. SettingsFromMap
	// must return zero-value AssetSource without panicking, and
	// IsEnabled must stay false so these tenants see no behavior
	// change on upgrade.
	legacyJSON := map[string]any{
		"general":        map[string]any{"timezone": "UTC"},
		"security":       map[string]any{},
		"api":            map[string]any{},
		"branding":       map[string]any{},
		"branch":         map[string]any{},
		"ai":             map[string]any{},
		"risk_scoring":   map[string]any{},
		"pentest":        map[string]any{},
		"asset_identity": map[string]any{},
		// NOTE: no asset_source key — the whole point of this test
	}

	settings := SettingsFromMap(legacyJSON)

	if settings.AssetSource.IsEnabled() {
		t.Fatal("legacy tenant (no asset_source key) must not be enabled")
	}
	if len(settings.AssetSource.Priority) != 0 {
		t.Errorf("expected empty priority, got %v", settings.AssetSource.Priority)
	}
	if len(settings.AssetSource.TrustLevels) != 0 {
		t.Errorf("expected empty trust_levels, got %v", settings.AssetSource.TrustLevels)
	}
	if settings.AssetSource.TrackFieldAttribution {
		t.Error("expected track_field_attribution=false by default")
	}
}

func TestAssetSourceSettings_Validate_OversizeInputs(t *testing.T) {
	// Size bounds are a DoS guard. An attacker with admin access on
	// one tenant would otherwise be able to stuff arbitrarily large
	// arrays into tenants.settings JSONB.
	t.Run("priority exceeds limit", func(t *testing.T) {
		ids := make([]shared.ID, MaxAssetSourcePriorityLen+1)
		for i := range ids {
			ids[i] = newID(t)
		}
		s := AssetSourceSettings{Priority: ids}
		if err := s.Validate(); err == nil {
			t.Fatal("expected validation error for oversized Priority")
		} else if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("trust_levels exceeds limit", func(t *testing.T) {
		levels := make(map[string]TrustLevel, MaxAssetSourceTrustLevels+1)
		for i := 0; i <= MaxAssetSourceTrustLevels; i++ {
			levels[newID(t).String()] = TrustLevelMedium
		}
		s := AssetSourceSettings{TrustLevels: levels}
		if err := s.Validate(); err == nil {
			t.Fatal("expected validation error for oversized TrustLevels")
		}
	})

	t.Run("exactly at limit is accepted", func(t *testing.T) {
		// Boundary — MaxAssetSourcePriorityLen itself must pass.
		ids := make([]shared.ID, MaxAssetSourcePriorityLen)
		for i := range ids {
			ids[i] = newID(t)
		}
		s := AssetSourceSettings{Priority: ids}
		if err := s.Validate(); err != nil {
			t.Fatalf("priority at exact limit should pass: %v", err)
		}
	})
}

func TestAssetSourceSettings_Validate_ErrorsDoNotEchoUUIDs(t *testing.T) {
	// Security guard: error messages must not contain the offending
	// UUID — otherwise an attacker who submits probed UUIDs can
	// differentiate "format invalid" from "other tenant's UUID" via
	// response substrings. We accept that the caller already knows
	// what they submitted; but we don't want regex-style probes to
	// distinguish errors by the value echoed back.
	secretLookingUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	dup := newID(t)

	cases := []struct {
		name string
		s    AssetSourceSettings
	}{
		{"duplicate priority", AssetSourceSettings{Priority: []shared.ID{dup, dup}}},
		{"malformed key", AssetSourceSettings{
			TrustLevels: map[string]TrustLevel{"xxx-not-a-uuid": TrustLevelMedium},
		}},
		{"secret-looking UUID in trust_levels key (valid format, unknown level)", AssetSourceSettings{
			TrustLevels: map[string]TrustLevel{secretLookingUUID: "bogus-level"},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			msg := err.Error()
			// None of our error strings may contain a raw UUID
			// fragment. Check the obvious ones.
			if containsUUIDLike(msg) {
				t.Errorf("error message leaks user-supplied UUID: %q", msg)
			}
		})
	}
}

// containsUUIDLike is a best-effort check: looks for the 8-4-4-4-12
// hyphen shape that shared.ID.String() produces. Not a full UUID
// regex — we just want to catch casual echoes.
func containsUUIDLike(s string) bool {
	// Dashes in the right places indicate an echoed UUID.
	for i := 0; i < len(s)-36; i++ {
		if s[i+8] == '-' && s[i+13] == '-' && s[i+18] == '-' && s[i+23] == '-' {
			// Verify surrounding is hex-ish.
			isHex := func(b byte) bool {
				return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
			}
			allHex := true
			for j := range 36 {
				b := s[i+j]
				if j == 8 || j == 13 || j == 18 || j == 23 {
					continue
				}
				if !isHex(b) {
					allHex = false
					break
				}
			}
			if allHex {
				return true
			}
		}
	}
	return false
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
