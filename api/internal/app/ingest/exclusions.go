package ingest

// Scope exclusions at ingest: a report does not add an excluded host to the
// inventory. Design: docs/rfcs/RFC-042-asset-inventory-v2.md (§3.3 F16,
// §6.13 "Discovery").
//
// Decision: ingest never deletes or changes an asset because of an
// exclusion. It only refuses to CREATE one: a new asset (or a root domain or
// resolved IP derived from one) whose name, repository URL or address matches
// an approved, active exclusion is not inserted, is counted on the ingest
// output as assets_skipped_excluded and named in its warnings. Findings that
// belonged to it are skipped and counted, never re-attached to another asset
// of the report. An asset already in the inventory is merged as before; the
// RFC's exclusion job, not ingest, archives it with a reason.

import (
	"context"
	"fmt"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ExclusionSource loads a tenant's scope exclusions in effect. Satisfied by
// *scope.Service.
type ExclusionSource interface {
	LoadExclusionMatcher(ctx context.Context, tenantID shared.ID) (*scopeapp.ExclusionMatcher, error)
}

// SetExclusionSource makes ingest skip new assets that match a scope
// exclusion. A failed exclusion lookup fails the batch (fail closed); the
// report is retried like any other storage failure.
func (s *Service) SetExclusionSource(src ExclusionSource) {
	s.assetProcessor.SetExclusionSource(src)
}

// SetExclusionSource wires the exclusion source (nil = not checked).
func (p *AssetProcessor) SetExclusionSource(src ExclusionSource) { p.exclusions = src }

// loadExclusions returns the tenant's exclusion matcher, or nil when no
// source is wired.
func (p *AssetProcessor) loadExclusions(ctx context.Context, tenantID shared.ID) (*scopeapp.ExclusionMatcher, error) {
	if p.exclusions == nil {
		return nil, nil
	}
	m, err := p.exclusions.LoadExclusionMatcher(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to load scope exclusions: %w", err)
	}
	return m, nil
}

// skipExcluded reports whether a NEW asset matches an exclusion and, when it
// does, records the skip on the output. ref is the report's id for the asset
// ("" for derived assets).
func skipExcluded(m *scopeapp.ExclusionMatcher, a *asset.Asset, ref string, output *Output) bool {
	if !m.ExcludedAsset(a) {
		return false
	}
	output.AssetsSkippedExcluded++
	if ref != "" {
		if output.ExcludedAssetRefs == nil {
			output.ExcludedAssetRefs = map[string]bool{}
		}
		output.ExcludedAssetRefs[ref] = true
	}
	addWarning(output, fmt.Sprintf("asset %s not added: it matches an active scope exclusion", shortName(a.Name())))
	return true
}

// addWarning appends a warning to the output, capped like the errors.
func addWarning(output *Output, msg string) {
	if len(output.Warnings) < MaxErrorsToReturn {
		output.Warnings = append(output.Warnings, msg)
	}
}
