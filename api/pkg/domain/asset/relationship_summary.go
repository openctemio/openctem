package asset

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Related assets of one asset, grouped for reading.
//
// An asset's relationships are shown as groups keyed by (relationship type,
// direction seen from the asset): "Resolves to" (outgoing resolves_to) and
// "Names that resolve here" (incoming resolves_to) are two groups. Each group
// carries its full count and its first rows, so one request answers "what is
// this connected to" for an asset with a handful of edges or with thousands.

// Relationship directions seen from the asset being viewed.
const (
	RelationshipDirectionOutgoing = "outgoing"
	RelationshipDirectionIncoming = "incoming"
)

// RelatedAssetsQuery selects what RelatedAssets returns.
//
// Without Type and Direction it returns every group with its first Limit rows.
// With both it returns that one group, rows Offset..Offset+Limit, optionally
// narrowed to related assets whose name contains Search.
type RelatedAssetsQuery struct {
	Type      RelationshipType
	Direction string
	Search    string
	Offset    int
	Limit     int
	// Scope, when non-nil, keeps only edges whose other asset is in the
	// caller's data scope; the rest are counted in HiddenCount only.
	Scope *shared.DataScope
}

// RelatedAsset is one edge seen from the asset being viewed: the asset at the
// other end and the facts of the edge itself.
type RelatedAsset struct {
	RelationshipID  shared.ID
	Type            RelationshipType
	Direction       string
	AssetID         shared.ID
	AssetName       string
	AssetType       AssetType
	AssetSubType    string
	AssetStatus     string
	Criticality     string
	Exposure        string
	AssetLastSeen   *time.Time
	DiscoveryMethod string
	Confidence      string
	IsControlPlane  bool
	LastVerified    *time.Time
	CreatedAt       time.Time
}

// RelatedAssetGroup is every edge of one type in one direction.
type RelatedAssetGroup struct {
	Type      RelationshipType
	Direction string
	Total     int64
	Items     []RelatedAsset
}

// RelatedAssets is the grouped answer for one asset.
type RelatedAssets struct {
	Groups []RelatedAssetGroup
	// Total counts the edges the caller may see.
	Total int64
	// HiddenCount counts edges whose other asset is outside the caller's
	// data scope. Only the number is returned: no name, type or ID.
	HiddenCount int64
}
