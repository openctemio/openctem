package exposure

// The Exposure Items view of the external attack surface
// (docs/architecture/exposure-taxonomy.md, "Exposure Items view"): the
// tenant's exposures with their assets, through the list query contract.
// Every read compiles the filter for the caller (tenant predicate first,
// then the caller's data scope), so a member sees only the exposures of
// assets in their scope and nothing of another tenant.

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ItemsCaller is who reads the view.
type ItemsCaller = datascope.ListCaller

// ErrItemsUnavailable: the view is not wired (no database).
var ErrItemsUnavailable = errors.New("exposure items view is not configured")

// SetItemReader wires the Exposure Items view.
func (s *ExposureService) SetItemReader(r exposuredom.ItemReader) { s.items = r }

func (s *ExposureService) compileItems(ctx context.Context, c ItemsCaller, spec *filterspec.Spec) (*filterspec.Where, error) {
	if s.items == nil {
		return nil, ErrItemsUnavailable
	}
	a, _, err := datascope.ListActor(ctx, s.dataScope, c)
	if err != nil {
		return nil, err
	}
	return filterspec.CompileFrom(spec, exposuredom.ItemFields, a, exposuredom.ItemFilterFirstArg)
}

// ListItems lists one page of the view. scanned is the tenant's
// unclassified-scans mode (an input of the monitoring state), resolved by
// the caller.
func (s *ExposureService) ListItems(ctx context.Context, c ItemsCaller, spec *filterspec.Spec, scanned bool) (pagination.Result[*exposuredom.Item], error) {
	w, err := s.compileItems(ctx, c, spec)
	if err != nil {
		return pagination.Result[*exposuredom.Item]{}, err
	}
	return s.items.ListItems(ctx, w, scanned, pagination.New(spec.Page, spec.PerPage))
}

// ItemStats counts the view's filtered set by severity, display category
// and state.
func (s *ExposureService) ItemStats(ctx context.Context, c ItemsCaller, spec *filterspec.Spec, scanned bool) (*exposuredom.ItemStats, error) {
	w, err := s.compileItems(ctx, c, spec)
	if err != nil {
		return nil, err
	}
	return s.items.ItemStats(ctx, w, scanned)
}

// ItemsByAsset lists the view's filtered set grouped by asset.
func (s *ExposureService) ItemsByAsset(ctx context.Context, c ItemsCaller, spec *filterspec.Spec, scanned bool) (pagination.Result[*exposuredom.AssetGroup], error) {
	w, err := s.compileItems(ctx, c, spec)
	if err != nil {
		return pagination.Result[*exposuredom.AssetGroup]{}, err
	}
	return s.items.ItemsByAsset(ctx, w, scanned, pagination.New(spec.Page, spec.PerPage))
}
