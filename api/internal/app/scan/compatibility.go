package scan

// Scanner/asset type compatibility (RFC-042 §6.3.8 R5,
// docs/rfcs/RFC-042-asset-inventory-v2.md).
//
// A tool declares the target types it accepts (supported_targets: url,
// domain, ip, host ...). An asset is compatible when the registry's
// scannable_by for its stored (type, sub_type) shares one of them, or when a
// platform admin added an active target mapping for its type
// (target_asset_type_mappings extends the registry; it cannot take a
// registry pair away). Compatibility is undecidable for an `unclassified`
// asset and for a tool that declares no target type the platform knows:
// such assets are never refused.

import (
	"context"
	"fmt"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// typeCompatibility answers compatibility questions for one tool.
type typeCompatibility struct {
	targets []string
	// known is false when none of the tool's target types is a platform
	// target type: compatibility is then undecidable.
	known bool
	// extra are the stored pairs an admin mapping adds for these targets
	// (a pair with SubType "" covers every sub-type of the type).
	extra []asset.TypeRef
}

// newTypeCompatibility builds the compatibility of a tool's target types.
// repo may be nil (registry only).
func newTypeCompatibility(ctx context.Context, repo tool.TargetMappingRepository, targets []string) (*typeCompatibility, error) {
	c := &typeCompatibility{targets: targets}
	for _, t := range targets {
		if tool.IsValidTargetType(t) {
			c.known = true
		}
	}
	if repo == nil || len(targets) == 0 {
		return c, nil
	}
	// Admin mappings may still name an alias type (rows seeded before the
	// registry): ask for every registry name and read an alias row as the
	// pair it stands for.
	names := asset.AllAssetTypes()
	rows, err := repo.GetCompatibleAssetTypes(ctx, targets, names)
	if err != nil {
		return nil, fmt.Errorf("get compatible asset types: %w", err)
	}
	for _, name := range rows {
		ref := asset.TypeRef{Type: name}
		if !name.IsStored() {
			ref = asset.CanonicalPair(name, "")
		}
		if !slices.Contains(c.extra, ref) {
			c.extra = append(c.extra, ref)
		}
	}
	return c, nil
}

// decide reports whether the tool can scan a stored pair, and whether that
// could be decided at all.
func (c *typeCompatibility) decide(ref asset.TypeRef) (compatible, decidable bool) {
	// A type the registry does not know (empty, or a legacy code the data
	// normalisation has not mapped yet) cannot be decided either.
	if ref.Type == asset.AssetTypeUnclassified || !ref.Type.IsValid() || !c.known {
		return false, false
	}
	pair := asset.CanonicalPair(ref.Type, ref.SubType)
	for _, t := range asset.ScannableBy(ref.Type, ref.SubType) {
		if slices.Contains(c.targets, t) {
			return true, true
		}
	}
	for _, e := range c.extra {
		if e.Type == pair.Type && (e.SubType == "" || e.SubType == pair.SubType) {
			return true, true
		}
	}
	return false, true
}

// typeLabel names a stored pair in counts and skip reasons: "type" or
// "type/sub_type".
func typeLabel(ref asset.TypeRef) string {
	if ref.SubType == "" {
		return string(ref.Type)
	}
	return string(ref.Type) + "/" + ref.SubType
}
