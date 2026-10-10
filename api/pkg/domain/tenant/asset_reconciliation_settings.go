package tenant

import "github.com/openctemio/openctem/api/pkg/domain/asset"

// AssetReconciliationSettings is the organization's rule for which source
// decides an asset attribute (RFC-069). Empty: the defaults
// (asset.DefaultReconciliationPolicy).
type AssetReconciliationSettings struct {
	// Precedence lists, per attribute (criticality, owner_ref, exposure,
	// data_classification), the source kinds trusted for it, most trusted
	// first: integration, import, scan. A kind left out is not trusted for
	// the attribute. A person's edit (a lock) always wins and is not listed.
	Precedence map[string][]string `json:"precedence,omitempty"`
	// TTLDays is, per source kind, how many days a value counts after the
	// source last reported it; 0 = never stale.
	TTLDays map[string]int `json:"ttl_days,omitempty"`
}

// Policy returns the reconciliation policy these settings describe.
func (s AssetReconciliationSettings) Policy() (asset.ReconciliationPolicy, error) {
	return asset.PolicyFromSettings(s.Precedence, s.TTLDays)
}

// Validate checks the attributes, kinds and TTLs.
func (s *AssetReconciliationSettings) Validate() error {
	_, err := s.Policy()
	return err
}

// UpdateAssetReconciliationSettings replaces the section after validating it.
func (t *Tenant) UpdateAssetReconciliationSettings(ar AssetReconciliationSettings) error {
	if err := ar.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.AssetReconciliation = ar
	return t.UpdateSettings(settings)
}
