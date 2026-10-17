package asset

// The technologies on the organization's assets, for the asset list's
// filter (docs/rfcs/RFC-112-asset-technologies.md).

import (
	"context"
	"errors"
	"fmt"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TechnologyFacetReader counts technologies over the assets an access scope
// admits.
type TechnologyFacetReader interface {
	Facets(ctx context.Context, tenantID shared.ID, access assetdom.AccessScope,
		q string, category assettech.Category, limit int) ([]assettech.Facet, error)
}

// errNoTechnologyFacets: the reader is not wired.
var errNoTechnologyFacets = errors.New("technology facets are not available")

// SetTechnologyFacets wires the technology facet reader.
func (s *AssetService) SetTechnologyFacets(r TechnologyFacetReader) { s.techFacets = r }

// TechnologyFacets returns the technologies on the assets the acting user
// may list, most used first: the same data scope as the list, so a scoped
// user never learns a name only an asset outside their scope carries.
func (s *AssetService) TechnologyFacets(ctx context.Context, tenantID, actingUserID string, isAdmin bool,
	q string, category string, limit int,
) ([]assettech.Facet, error) {
	if s.techFacets == nil {
		return nil, errNoTechnologyFacets
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	cat := assettech.Category(category)
	if category != "" && !cat.IsValid() {
		return nil, fmt.Errorf("%w: unknown technology category", shared.ErrValidation)
	}
	if len(q) > assettech.MaxNameLen {
		return nil, fmt.Errorf("%w: search too long", shared.ErrValidation)
	}
	access, err := s.listAccessScope(ctx, tenantID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	return s.techFacets.Facets(ctx, tid, access, q, cat, limit)
}
