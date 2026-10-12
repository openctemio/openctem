package software

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProductRef is a catalog product an identity resolved to.
type ProductRef struct {
	ID shared.ID
	// Global is true for a public product (tenant_id NULL).
	Global bool
}

// Link is one asset_software row to write.
type Link struct {
	AssetID    shared.ID
	ProductID  shared.ID
	VersionID  shared.ID
	Location   string
	Port       int
	Transport  string
	Source     string
	Evidence   string
	Confidence int
}

// LinkResult says what a write changed.
type LinkResult struct {
	Inserted   int
	Superseded int
	// ChangedAssets are the assets that gained a link or whose product
	// moved to another version: they need a re-match.
	ChangedAssets []shared.ID
}

// AssetLink is one current software link of an asset, for display.
type AssetLink struct {
	ID         shared.ID
	ProductID  shared.ID
	Product    string
	Vendor     string
	CPE        string // "vendor:product", empty for a product without one
	Global     bool
	VersionID  shared.ID
	Version    string
	Qualifier  string
	Location   string
	Port       int
	Transport  string
	Source     string
	Evidence   string
	Confidence int
	FirstSeen  time.Time
	LastSeen   time.Time
}

// MaxAssetLinks bounds one asset's software list.
const MaxAssetLinks = 1000

// Repository is the catalog and the per-tenant links. Every method that
// takes a tenant reads global rows and that tenant's private rows only, and
// writes private rows only for that tenant.
type Repository interface {
	// EnsureCurated writes the curated products and their aliases to the
	// global catalog. Idempotent.
	EnsureCurated(ctx context.Context, products []Curated) error
	// Resolve maps identities to catalog products: a global alias or
	// product first, then the tenant's private ones; an identity nothing
	// resolves becomes a new private product of the tenant.
	Resolve(ctx context.Context, tenantID shared.ID, ids []Identity) (map[Identity]ProductRef, error)
	// EnsureVersion returns the catalog version of the product, creating it
	// in the product's scope.
	EnsureVersion(ctx context.Context, tenantID shared.ID, product ProductRef, v VersionKey) (shared.ID, error)
	// UpsertLinks writes the links of one ingest in one transaction. An
	// older link of the same product at the same location with another
	// version, not written by this call, is superseded.
	UpsertLinks(ctx context.Context, tenantID shared.ID, links []Link) (LinkResult, error)
	// ListAssetLinks returns the asset's current links (not superseded),
	// newest first, at most MaxAssetLinks.
	ListAssetLinks(ctx context.Context, tenantID, assetID shared.ID) ([]AssetLink, error)
}
