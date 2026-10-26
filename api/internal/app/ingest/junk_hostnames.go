package ingest

// Junk host names at ingest (docs/architecture/asset-identity-resolution.md,
// "Discovered names").

import (
	"context"
	"fmt"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// isDNSNameType reports whether t names a DNS name (domain, subdomain).
func isDNSNameType(t asset.AssetType) bool {
	return t == asset.AssetTypeDomain || t == asset.AssetTypeSubdomain
}

// dropJunkHostnames removes from the report every domain or subdomain whose
// normalized name is not a host name, and every one that is the remnant of
// a percent-encoded delimiter of a name the report or the tenant's
// inventory already has ("2fwww.example.com" next to "www.example.com").
// Each is recorded in the output errors. The inventory lookup is tenant
// scoped; a failed lookup fails the batch (nothing is guessed).
func (p *AssetProcessor) dropJunkHostnames(ctx context.Context, tenantID shared.ID, report *ctis.Report, output *Output) error {
	type candidate struct {
		index    int
		stripped string
	}
	names := make(map[string]bool, len(report.Assets))
	junk := map[int]string{}
	var remnants []candidate
	for i := range report.Assets {
		rt := resolveCTISAssetType(&report.Assets[i])
		if !isDNSNameType(rt.normType) {
			continue
		}
		raw := getAssetName(&report.Assets[i])
		if raw == "" {
			continue
		}
		name := asset.NormalizeName(raw, rt.normType, rt.normSubType)
		if !asset.ValidHostname(name) {
			junk[i] = "is not a host name"
			continue
		}
		names[name] = true
		if stripped, ok := asset.EncodedRemnant(name); ok {
			remnants = append(remnants, candidate{index: i, stripped: stripped})
		}
	}
	if len(remnants) > 0 {
		var lookup []string
		for _, c := range remnants {
			if !names[c.stripped] {
				lookup = append(lookup, c.stripped)
			}
		}
		known := map[string]*asset.Asset{}
		if len(lookup) > 0 {
			var err error
			if known, err = p.repo.GetByNames(ctx, tenantID, lookup); err != nil {
				return fmt.Errorf("failed to look up names behind encoded remnants: %w", err)
			}
		}
		for _, c := range remnants {
			if _, ok := known[c.stripped]; ok || names[c.stripped] {
				junk[c.index] = "is the remnant of a percent-encoded delimiter before a known name"
			}
		}
	}
	if len(junk) == 0 {
		return nil
	}
	kept := report.Assets[:0:0]
	for i := range report.Assets {
		why, drop := junk[i]
		if !drop {
			kept = append(kept, report.Assets[i])
			continue
		}
		ref := report.Assets[i].ID
		if ref == "" {
			ref = fmt.Sprintf("%d", i)
		}
		// Named by its report id, never by the name (which can be long or
		// junk).
		addError(output, fmt.Sprintf("asset %s: the name %s; not added", ref, why))
	}
	p.logger.Info("junk host names left out of a report", "tenant_id", tenantID.String(), "count", len(junk))
	report.Assets = kept
	return nil
}
