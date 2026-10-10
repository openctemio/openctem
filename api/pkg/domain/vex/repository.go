package vex

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Repository stores statements and reads and writes the findings they act
// on. Every method is scoped by tenant except the expiry scan, which a
// system controller runs across tenants.
type Repository interface {
	Create(ctx context.Context, s *Statement) error
	Update(ctx context.Context, s *Statement) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	Get(ctx context.Context, tenantID, id shared.ID) (*Statement, error)
	// FindBySubject returns the tenant's statement with the same subject
	// (vulnerability, package, asset, versions, range), or ErrNotFound.
	FindBySubject(ctx context.Context, s *Statement) (*Statement, error)
	List(ctx context.Context, f Filter, page pagination.Pagination) (pagination.Result[*Statement], error)

	// ActiveForProducts returns the tenant's statements about these
	// packages that have not expired at now.
	ActiveForProducts(ctx context.Context, tenantID shared.ID, productIDs []shared.ID, now time.Time) ([]*Statement, error)
	// TenantHasActive reports whether the tenant has any unexpired statement.
	TenantHasActive(ctx context.Context, tenantID shared.ID, now time.Time) (bool, error)
	// DueForExpiry returns statements of any tenant whose expiry passed and
	// that were not withdrawn yet, at most limit.
	DueForExpiry(ctx context.Context, now time.Time, limit int) ([]*Statement, error)
	MarkExpired(ctx context.Context, tenantID, id shared.ID, at time.Time) error

	// CandidateFindings returns the tenant's findings on a version of the
	// package that carry the vulnerability id (and, with assetID, on that
	// asset), ordered by id after the given id, at most limit.
	CandidateFindings(ctx context.Context, tenantID, productID shared.ID, vulnID string, assetID *shared.ID,
		after shared.ID, limit int) ([]FindingRef, error)
	// FindingsWithStatement returns the findings that carry the statement,
	// ordered by id after the given id, at most limit.
	FindingsWithStatement(ctx context.Context, tenantID, statementID shared.ID, after shared.ID, limit int) ([]FindingRef, error)
	// FindingsByFingerprints returns the tenant's findings with these
	// fingerprints that are about a package version.
	FindingsByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) ([]FindingRef, error)
	// WriteEffects applies the effects (each guarded by its OldStatus) and
	// records a status_changed activity for each status move. Returns the
	// ids whose status moved.
	WriteEffects(ctx context.Context, tenantID shared.ID, effects []Effect) ([]shared.ID, error)

	// ResolveProduct returns the package product a tenant's statement can
	// name for a package URL identity: the tenant's own product first, then
	// the global one. ErrNotFound when neither exists.
	ResolveProduct(ctx context.Context, tenantID shared.ID, purlType, namespace, name string) (shared.ID, error)
	// ProductVisible reports whether the product is a package product that
	// is global or the tenant's own.
	ProductVisible(ctx context.Context, tenantID, productID shared.ID) (bool, error)
	// ProductInScope reports whether an asset in the member's scope uses the
	// package (nil scope: any asset of the tenant).
	ProductInScope(ctx context.Context, tenantID, productID shared.ID, scope *shared.DataScope) (bool, error)
}
