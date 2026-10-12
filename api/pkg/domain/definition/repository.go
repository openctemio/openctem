package definition

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repository reads and writes the definition catalog. Every method takes the
// caller's tenant, from the authenticated context (or the sensor key), never
// from a request body.
//
// Reads see global definitions and the tenant's own; another tenant's
// definition is ErrNotFound. Writes change only the tenant's own tenant-scoped
// definitions; global content is written by platform feeds and imports, which
// are not part of this interface.
type Repository interface {
	// GetByID returns a definition visible to tenant.
	GetByID(ctx context.Context, tenant, id shared.ID) (*Definition, error)
	// Resolve returns the definition an identifier names, looking at global
	// identifiers first and then the tenant's own.
	Resolve(ctx context.Context, tenant shared.ID, namespace, externalID string) (*Definition, error)
	// ListIdentifiers returns the identifiers of a definition visible to tenant.
	ListIdentifiers(ctx context.Context, tenant, definitionID shared.ID) ([]Identifier, error)
	// ListRelations returns the edges from or to a definition visible to
	// tenant, global edges and the tenant's own.
	ListRelations(ctx context.Context, tenant, definitionID shared.ID) ([]Relation, error)
	// ListTaxonomy returns the taxonomy links of a definition visible to tenant.
	ListTaxonomy(ctx context.Context, tenant, definitionID shared.ID) ([]TaxonomyLink, error)

	// CreateTenantDefinition stores a tenant definition of tenant with its
	// primary identifier. ErrAlreadyExists when the tenant already has one
	// with that (namespace, external id).
	CreateTenantDefinition(ctx context.Context, tenant shared.ID, d *Definition) error
	// EnsureGlobalStub returns the id of the global definition with d's
	// identity, creating d (a NewGlobalStub) when there is none. An existing
	// definition is never changed.
	EnsureGlobalStub(ctx context.Context, d *Definition) (shared.ID, error)
	// AddTenantIdentifier adds an alias to one of tenant's definitions.
	AddTenantIdentifier(ctx context.Context, tenant shared.ID, ident Identifier) error
	// AddTenantRelation adds an edge from one of tenant's definitions to
	// another of its own or a global one.
	AddTenantRelation(ctx context.Context, tenant shared.ID, rel Relation) error
	// AddTenantTaxonomy maps one of tenant's definitions to a taxonomy entry.
	AddTenantTaxonomy(ctx context.Context, tenant shared.ID, link TaxonomyLink) error
}

// FindingLinkRepository reads and writes the definitions of findings.
type FindingLinkRepository interface {
	// ListByFinding returns the links of one of tenant's findings, by ord.
	ListByFinding(ctx context.Context, tenant, findingID shared.ID) ([]FindingLink, error)
	// ReplaceForFinding replaces the links of one of tenant's findings and
	// sets its primary (findings.definition_id) in one transaction. Every
	// definition must be global or tenant's own; ErrNotFound otherwise, and
	// for a finding of another tenant.
	ReplaceForFinding(ctx context.Context, tenant, findingID shared.ID, links []FindingLink) error
}
