package tenant

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Bounds for lifecycle threshold configuration. Mins are there to
// prevent operator typos from devastating the fleet (setting
// StaleThresholdDays=1 would mark every asset stale within hours of
// the next scan cycle). Maxes are a sanity ceiling — beyond 365 days
// lifecycle management is effectively off and the operator should
// just disable the feature.
const (
	MinLifecycleThresholdDays = 3
	MaxLifecycleThresholdDays = 365
	MinGracePeriodDays        = 0
	MaxGracePeriodDays        = 90
	MinExcludedSourceTypes    = 0
	MaxExcludedSourceTypes    = 20
)

// AssetLifecycleSettings controls automated asset status transitions
// based on how recently each asset has been observed by a source.
//
// Backward compatibility: a zero-value struct (Enabled=false)
// disables the feature entirely — no worker run, no transitions,
// no UI badges. Tenants upgrading see zero behavior change until
// they explicitly opt in.
type AssetLifecycleSettings struct {
	// Enabled toggles the feature. Defaults to false so tenants
	// upgrading from older versions see no change. Enabling for the
	// first time requires a successful dry-run (DryRunCompletedAt)
	// or the force flag on the admin API.
	Enabled bool `json:"enabled"`

	// StaleThresholdDays — days without a MarkSeen() update before
	// the worker flips status from active to stale. Default 14.
	StaleThresholdDays int `json:"stale_threshold_days,omitempty"`

	// GracePeriodDays — newly-discovered assets are immune from the
	// lifecycle worker for this many days after `discovered_at`.
	// Protects assets the scanner has not picked up yet. Default 3.
	GracePeriodDays int `json:"grace_period_days,omitempty"`

	// ManualReactivationGraceDays — when an operator manually
	// reactivates an asset that had been flagged stale/inactive, we
	// auto-set lifecycle_paused_until = NOW + this many days. Avoids
	// the E2.6 flap (worker re-demotes the same asset next day).
	// Default 30. Operators can override per-asset via Snooze.
	ManualReactivationGraceDays int `json:"manual_reactivation_grace_days,omitempty"`

	// ExcludedSourceTypes — source_type values that opt an asset
	// out of the lifecycle worker. Default [manual, import]:
	// user-entered data has intent behind it, the worker should
	// never quietly demote a manually-curated asset.
	ExcludedSourceTypes []string `json:"excluded_source_types,omitempty"`

	// PauseOnIntegrationFailure — when true (default), the worker
	// checks the tenant's agents and integrations before each run.
	// If any are unhealthy, the whole tenant is skipped so a
	// temporarily-offline scanner does not generate a false
	// deactivation storm.
	PauseOnIntegrationFailure bool `json:"pause_on_integration_failure,omitempty"`

	// DryRunCompletedAt records the last time the tenant admin ran
	// a dry-run that showed acceptable counts. Populated by the
	// dry-run endpoint. A non-nil value unlocks the Enabled flag;
	// unset means the API rejects Enable with "run a dry-run first".
	DryRunCompletedAt *int64 `json:"dry_run_completed_at,omitempty"`
}

// DefaultAssetLifecycleSettings returns the recommended defaults,
// used when a tenant has never configured lifecycle.
func DefaultAssetLifecycleSettings() AssetLifecycleSettings {
	return AssetLifecycleSettings{
		Enabled:                     false,
		StaleThresholdDays:          14,
		GracePeriodDays:             3,
		ManualReactivationGraceDays: 30,
		ExcludedSourceTypes:         []string{"manual", "import"},
		PauseOnIntegrationFailure:   true,
	}
}

// EffectiveStaleThresholdDays returns the configured value, falling
// back to the default when zero. Separate from Validate() because
// stored settings may have been persisted before we added a new
// field and we want to merge with defaults transparently.
func (s AssetLifecycleSettings) EffectiveStaleThresholdDays() int {
	if s.StaleThresholdDays <= 0 {
		return DefaultAssetLifecycleSettings().StaleThresholdDays
	}
	return s.StaleThresholdDays
}

// EffectiveGracePeriodDays — see EffectiveStaleThresholdDays.
func (s AssetLifecycleSettings) EffectiveGracePeriodDays() int {
	if s.GracePeriodDays < 0 {
		return DefaultAssetLifecycleSettings().GracePeriodDays
	}
	if s.GracePeriodDays == 0 {
		// Explicit zero is allowed for operators who want no grace
		// period — only the < 0 (uninitialized) case falls back.
		return 0
	}
	return s.GracePeriodDays
}

// EffectiveManualReactivationGraceDays — see above.
func (s AssetLifecycleSettings) EffectiveManualReactivationGraceDays() int {
	if s.ManualReactivationGraceDays <= 0 {
		return DefaultAssetLifecycleSettings().ManualReactivationGraceDays
	}
	return s.ManualReactivationGraceDays
}

// EffectiveExcludedSourceTypes returns the configured slice or the
// defaults when the field is nil/empty. Nil check is required so an
// upgraded tenant who never set the field gets the protective
// default instead of "exclude nothing".
func (s AssetLifecycleSettings) EffectiveExcludedSourceTypes() []string {
	if len(s.ExcludedSourceTypes) == 0 {
		return DefaultAssetLifecycleSettings().ExcludedSourceTypes
	}
	return s.ExcludedSourceTypes
}

// Validate enforces structural + range constraints. Called both from
// Settings.Validate (when the whole tenant settings blob is saved)
// and directly from the dedicated PUT /settings/asset-lifecycle
// endpoint.
func (s *AssetLifecycleSettings) Validate() error {
	if s.StaleThresholdDays != 0 {
		if s.StaleThresholdDays < MinLifecycleThresholdDays || s.StaleThresholdDays > MaxLifecycleThresholdDays {
			return fmt.Errorf(
				"%w: stale_threshold_days must be between %d and %d",
				shared.ErrValidation, MinLifecycleThresholdDays, MaxLifecycleThresholdDays,
			)
		}
	}
	if s.GracePeriodDays < MinGracePeriodDays || s.GracePeriodDays > MaxGracePeriodDays {
		return fmt.Errorf(
			"%w: grace_period_days must be between %d and %d",
			shared.ErrValidation, MinGracePeriodDays, MaxGracePeriodDays,
		)
	}
	if s.ManualReactivationGraceDays != 0 {
		if s.ManualReactivationGraceDays < MinLifecycleThresholdDays || s.ManualReactivationGraceDays > MaxLifecycleThresholdDays {
			return fmt.Errorf(
				"%w: manual_reactivation_grace_days must be between %d and %d",
				shared.ErrValidation, MinLifecycleThresholdDays, MaxLifecycleThresholdDays,
			)
		}
	}
	if len(s.ExcludedSourceTypes) > MaxExcludedSourceTypes {
		return fmt.Errorf(
			"%w: excluded_source_types exceeds the maximum of %d entries",
			shared.ErrValidation, MaxExcludedSourceTypes,
		)
	}
	// Reject obvious typos in the exclusion list by matching against
	// the canonical SourceType values from the datasource package.
	// Kept decoupled here (string compare) to avoid a circular import
	// between tenant and datasource — the valid set is small and
	// stable so the duplication is acceptable.
	validSourceTypes := map[string]struct{}{
		"integration": {},
		"collector":   {},
		"scanner":     {},
		"manual":      {},
		"import":      {},
	}
	seen := make(map[string]struct{}, len(s.ExcludedSourceTypes))
	for _, st := range s.ExcludedSourceTypes {
		if st == "" {
			return fmt.Errorf(
				"%w: excluded_source_types must not contain an empty string",
				shared.ErrValidation,
			)
		}
		if _, ok := validSourceTypes[st]; !ok {
			return fmt.Errorf(
				"%w: excluded_source_types contains an unknown source type",
				shared.ErrValidation,
			)
		}
		if _, dup := seen[st]; dup {
			return fmt.Errorf(
				"%w: excluded_source_types contains a duplicate entry",
				shared.ErrValidation,
			)
		}
		seen[st] = struct{}{}
	}

	// First-enable guard: if Enabled=true but no dry-run has ever
	// completed, reject. The admin API bypasses this when it calls
	// Validate() after a successful dry-run and stamps the timestamp.
	if s.Enabled && s.DryRunCompletedAt == nil {
		return fmt.Errorf(
			"%w: lifecycle cannot be enabled without a successful dry-run first",
			shared.ErrValidation,
		)
	}
	return nil
}
