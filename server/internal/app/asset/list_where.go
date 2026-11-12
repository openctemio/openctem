package asset

// The asset inventory on the list query contract
// (docs/architecture/list-query-contract.md): a decoded filter is compiled
// as the caller with the assets registry (pkg/domain/assetlist), so the
// tenant, the data scope and the hidden program assets are in every WHERE,
// whether the filter came from params, a document, a saved view, the search
// box or an AI agent's tool call.

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetlist"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// ListCaller is the request's caller.
type ListCaller = datascope.ListCaller

// ListQuery is one page of an asset filter.
type ListQuery struct {
	Spec *filterspec.Spec
	// UnclassifiedScanned is the tenant's unclassified-scans input to the
	// monitoring state.
	UnclassifiedScanned bool
	// Properties are the attribute filters of the properties param.
	Properties map[string][]string
	Keyset     bool
	After      *assetdom.Cursor
}

// ErrListUnavailable: the repository cannot list a compiled filter.
var ErrListUnavailable = errors.New("asset list query is not available")

// ListAssetsWhere lists one page of assets for a decoded filter, as the
// caller. A nil data scope enforcer refuses every member read (fail closed).
func (s *AssetService) ListAssetsWhere(ctx context.Context, c ListCaller, q ListQuery) (assetdom.WhereResult, error) {
	lister, ok := s.repo.(assetdom.WhereLister)
	if !ok {
		return assetdom.WhereResult{}, ErrListUnavailable
	}
	w, err := s.CompileList(ctx, c, q.Spec, q.UnclassifiedScanned)
	if err != nil {
		return assetdom.WhereResult{}, err
	}
	return lister.ListWhere(ctx, assetdom.WhereQuery{
		Where: w, Properties: q.Properties, Page: q.Spec.Page, PerPage: q.Spec.PerPage, Keyset: q.Keyset, After: q.After,
	})
}

// CompileList compiles an asset filter as the caller (for lists, counts
// and the other reads that must match the list).
func (s *AssetService) CompileList(ctx context.Context, c ListCaller, spec *filterspec.Spec, scanned bool) (*filterspec.Where, error) {
	actor, _, err := datascope.ListActor(ctx, s.dataScope, c)
	if err != nil {
		return nil, err
	}
	return filterspec.Compile(spec, assetlist.FieldsFor(assetlist.MonitoringScanned(scanned)), actor)
}

// ipContextReader reads the IP addresses tab's columns.
type ipContextReader interface {
	IPContexts(ctx context.Context, actor filterspec.Actor, ids []string) (map[string]assetdom.IPContext, error)
	NetworkCounts(ctx context.Context, w *filterspec.Where) ([]assetdom.NetworkCount, bool, error)
}

// IPContexts returns the names resolving to each address of ids and its
// open ports, as the caller: only names and ports in the caller's data
// scope are listed or counted.
func (s *AssetService) IPContexts(ctx context.Context, c ListCaller, ids []string) (map[string]assetdom.IPContext, error) {
	r, ok := s.repo.(ipContextReader)
	if !ok {
		return nil, ErrListUnavailable
	}
	actor, _, err := datascope.ListActor(ctx, s.dataScope, c)
	if err != nil {
		return nil, err
	}
	return r.IPContexts(ctx, actor, ids)
}

// NetworkCounts groups the addresses an asset filter matches by network,
// as the caller (the same WHERE as the list).
func (s *AssetService) NetworkCounts(ctx context.Context, c ListCaller, spec *filterspec.Spec, scanned bool) ([]assetdom.NetworkCount, bool, error) {
	r, ok := s.repo.(ipContextReader)
	if !ok {
		return nil, false, ErrListUnavailable
	}
	w, err := s.CompileList(ctx, c, spec, scanned)
	if err != nil {
		return nil, false, err
	}
	return r.NetworkCounts(ctx, w)
}
