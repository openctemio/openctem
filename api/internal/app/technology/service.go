// Package technology serves the Technologies view of the external attack
// surface: lists and counts compiled as the caller through the list query
// contract, so the tenant and the caller's data scope on every asset that
// runs a technology are always in the WHERE.
package technology

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/technology"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Caller is the request's caller.
type Caller = datascope.ListCaller

// Service reads technology versions.
type Service struct {
	repo      technology.Reader
	dataScope *datascope.Enforcer
}

// NewService creates a Service. dataScope must be wired in production; a nil
// enforcer refuses every member read (fail closed).
func NewService(repo technology.Reader, dataScope *datascope.Enforcer) *Service {
	return &Service{repo: repo, dataScope: dataScope}
}

func (s *Service) compile(ctx context.Context, c Caller, spec *filterspec.Spec) (*filterspec.Where, error) {
	a, _, err := datascope.ListActor(ctx, s.dataScope, c)
	if err != nil {
		return nil, err
	}
	return filterspec.Compile(spec, technology.Fields, a)
}

// List lists technology versions for a decoded filter, as the caller.
func (s *Service) List(ctx context.Context, c Caller, spec *filterspec.Spec) (pagination.Result[*technology.Version], error) {
	var empty pagination.Result[*technology.Version]
	w, err := s.compile(ctx, c, spec)
	if err != nil {
		return empty, err
	}
	return s.repo.ListWhere(ctx, w, pagination.New(spec.Page, spec.PerPage))
}

// Stats counts technology versions for a decoded filter, as the caller: the
// same WHERE as List, so the counts and the table agree.
func (s *Service) Stats(ctx context.Context, c Caller, spec *filterspec.Spec) (*technology.Stats, error) {
	w, err := s.compile(ctx, c, spec)
	if err != nil {
		return nil, err
	}
	return s.repo.StatsWhere(ctx, w)
}
