// Package webendpoint serves the web surface sub-inventory to people
// (docs/rfcs/RFC-056-web-attack-surface.md): lists and stats compiled as the
// caller through the list query contract (tenant and data scope always in
// the WHERE), and by-id reads that answer "not found" for another tenant's
// endpoint and for one whose origin asset is outside the caller's data
// scope.
package webendpoint

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Caller is the request's caller.
type Caller struct {
	TenantID string
	UserID   string
	IsAdmin  bool
	APIKey   bool
}

// Store is the storage the service reads (*postgres.WebEndpointRepository).
type Store interface {
	webendpoint.Reader
	webendpoint.ViewReader
}

// Service reads and curates the sub-inventory.
type Service struct {
	repo      Store
	dataScope *datascope.Enforcer
}

// NewService creates a Service. dataScope must be wired in production; a
// nil enforcer refuses every member read (fail closed).
func NewService(repo Store, dataScope *datascope.Enforcer) *Service {
	return &Service{repo: repo, dataScope: dataScope}
}

func (s *Service) actor(ctx context.Context, c Caller) (filterspec.Actor, shared.ID, error) {
	tenantID, err := shared.IDFromString(c.TenantID)
	if err != nil {
		return filterspec.Actor{}, tenantID, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	var userID shared.ID
	if c.UserID != "" {
		if userID, err = shared.IDFromString(c.UserID); err != nil {
			return filterspec.Actor{}, tenantID, fmt.Errorf("%w: invalid acting user", shared.ErrValidation)
		}
	}
	var scope *shared.DataScope
	if !c.IsAdmin && c.UserID != "" {
		if s.dataScope == nil {
			return filterspec.Actor{}, tenantID, errors.New("data scope enforcer not configured")
		}
		scope, err = s.dataScope.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, APIKey: c.APIKey})
		if err != nil {
			return filterspec.Actor{}, tenantID, fmt.Errorf("resolve data scope: %w", err)
		}
	}
	a, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenantID, UserID: userID, IsAdmin: c.IsAdmin, Scope: scope})
	return a, tenantID, err
}

// List lists endpoints for a decoded filter, as the caller.
func (s *Service) List(ctx context.Context, c Caller, spec *filterspec.Spec) (pagination.Result[*webendpoint.Endpoint], error) {
	var empty pagination.Result[*webendpoint.Endpoint]
	a, _, err := s.actor(ctx, c)
	if err != nil {
		return empty, err
	}
	w, err := filterspec.Compile(spec, webendpoint.Fields, a)
	if err != nil {
		return empty, err
	}
	return s.repo.ListWhere(ctx, w, pagination.New(spec.Page, spec.PerPage))
}

// Stats counts endpoints for a decoded filter, as the caller: the same WHERE
// as List, so the counts and the table agree.
func (s *Service) Stats(ctx context.Context, c Caller, spec *filterspec.Spec) (*webendpoint.Stats, error) {
	a, _, err := s.actor(ctx, c)
	if err != nil {
		return nil, err
	}
	w, err := filterspec.Compile(spec, webendpoint.Fields, a)
	if err != nil {
		return nil, err
	}
	return s.repo.StatsWhere(ctx, w)
}

// Patterns groups the endpoints a decoded filter selects by path pattern,
// as the caller: a scoped member's counts include only their origins.
func (s *Service) Patterns(ctx context.Context, c Caller, spec *filterspec.Spec) (pagination.Result[*webendpoint.Pattern], error) {
	var empty pagination.Result[*webendpoint.Pattern]
	a, _, err := s.actor(ctx, c)
	if err != nil {
		return empty, err
	}
	spec.Sort = nil // grouped: the order is fixed (most widespread first)
	w, err := filterspec.Compile(spec, webendpoint.Fields, a)
	if err != nil {
		return empty, err
	}
	return s.repo.PatternsWhere(ctx, w, pagination.New(spec.Page, spec.PerPage))
}

// Origins groups the endpoints a decoded filter selects by origin asset,
// with the coverage gap, as the caller.
func (s *Service) Origins(ctx context.Context, c Caller, spec *filterspec.Spec) (pagination.Result[*webendpoint.Origin], error) {
	var empty pagination.Result[*webendpoint.Origin]
	a, _, err := s.actor(ctx, c)
	if err != nil {
		return empty, err
	}
	spec.Sort = nil
	w, err := filterspec.Compile(spec, webendpoint.Fields, a)
	if err != nil {
		return empty, err
	}
	return s.repo.OriginsWhere(ctx, w, pagination.New(spec.Page, spec.PerPage))
}

// Events lists the change feed for a decoded filter, as the caller.
func (s *Service) Events(ctx context.Context, c Caller, spec *filterspec.Spec) (pagination.Result[*webendpoint.Event], error) {
	var empty pagination.Result[*webendpoint.Event]
	a, _, err := s.actor(ctx, c)
	if err != nil {
		return empty, err
	}
	w, err := filterspec.Compile(spec, webendpoint.EventFields, a)
	if err != nil {
		return empty, err
	}
	return s.repo.EventsWhere(ctx, w, pagination.New(spec.Page, spec.PerPage))
}

// Get returns one endpoint the caller may see, or shared.ErrNotFound (for
// another tenant's id and for one outside the caller's data scope alike).
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*webendpoint.Endpoint, error) {
	e, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if s.dataScope == nil {
		return e, nil
	}
	if err := s.dataScope.AssertAsset(ctx, tenantID, e.OriginAssetID); err != nil {
		return nil, shared.ErrNotFound
	}
	return e, nil
}

// Params returns the parameters of one endpoint the caller may see.
func (s *Service) Params(ctx context.Context, tenantID, id shared.ID) ([]webendpoint.Param, error) {
	if _, err := s.Get(ctx, tenantID, id); err != nil {
		return nil, err
	}
	return s.repo.Params(ctx, tenantID, id)
}

// UpdateInput is a person's change.
type UpdateInput struct {
	State  *string
	Labels *[]string
}

// Update sets an endpoint's state (active or ignored) and labels, and
// returns the endpoint before and after.
func (s *Service) Update(ctx context.Context, tenantID, id shared.ID, in UpdateInput) (*webendpoint.Endpoint, error) {
	if _, err := s.Get(ctx, tenantID, id); err != nil {
		return nil, err
	}
	var u webendpoint.Update
	if in.State != nil {
		st := webendpoint.State(*in.State)
		if st != webendpoint.StateActive && st != webendpoint.StateIgnored {
			return nil, fmt.Errorf("%w: state must be active or ignored", shared.ErrValidation)
		}
		u.State = &st
	}
	if in.Labels != nil {
		labels, err := cleanLabels(*in.Labels)
		if err != nil {
			return nil, err
		}
		u.Labels = &labels
	}
	if u.State == nil && u.Labels == nil {
		return nil, fmt.Errorf("%w: nothing to change", shared.ErrValidation)
	}
	if err := s.repo.Update(ctx, tenantID, id, u); err != nil {
		return nil, err
	}
	return s.repo.Get(ctx, tenantID, id)
}

// cleanLabels trims, lower-cases and de-duplicates labels: at most
// MaxLabels of MaxLabelBytes, letters, digits, '-', '_', ':' and '.'.
func cleanLabels(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, l := range in {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" {
			continue
		}
		if len(l) > webendpoint.MaxLabelBytes || strings.IndexFunc(l, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_:.", r)
		}) >= 0 {
			return nil, fmt.Errorf("%w: invalid label", shared.ErrValidation)
		}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	if len(out) > webendpoint.MaxLabels {
		return nil, fmt.Errorf("%w: at most %d labels", shared.ErrValidation, webendpoint.MaxLabels)
	}
	return out, nil
}
