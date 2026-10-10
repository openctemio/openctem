package tenant

import "github.com/openctemio/openctem/api/pkg/domain/asset"

// AssetReconciliationSettings is the organization's rule for which source
// decides an asset attribute (RFC-069 §12). Empty: the defaults
// (asset.DefaultReconciliationPolicy).
type AssetReconciliationSettings struct {
	// Default is the ranked list of sources (kind, or kind:name) every
	// attribute class without its own list uses, most trusted first. A
	// person's lock always wins and is not listed.
	Default []asset.SourceRuleSetting `json:"default,omitempty"`
	// Classes are the attribute classes with their own list (identity,
	// network, software, ownership, cloud_tags, lifecycle).
	Classes map[string][]asset.SourceRuleSetting `json:"classes,omitempty"`
}

// Policy returns the reconciliation policy these settings describe.
func (s AssetReconciliationSettings) Policy() (asset.ReconciliationPolicy, error) {
	return asset.PolicyFromSettings(s.Default, s.Classes)
}

// Validate checks the classes, sources and TTLs.
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
