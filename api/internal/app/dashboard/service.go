// Package dashboard is the application service for per-user customizable
// dashboards (RFC-021). It is a thin wrapper over the domain repository whose
// sole job is to parse identifiers and enforce that every operation is scoped
// to the authenticated (tenant, user) — ownership is never taken from a
// request body.
package dashboard

import (
	"context"
	"fmt"

	domain "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Service provides per-user dashboard CRUD.
type Service struct {
	repo domain.Repository
	log  *logger.Logger
}

// NewService creates a dashboard Service.
func NewService(repo domain.Repository, log *logger.Logger) *Service {
	return &Service{repo: repo, log: log}
}

// CreateInput carries the fields for creating or replacing a dashboard.
type CreateInput struct {
	Name        string
	Description string
	Columns     int
	Widgets     []domain.Widget
}

// List returns every dashboard owned by the caller.
func (s *Service) List(ctx context.Context, tenantID, userID string) ([]*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	return s.repo.ListByUser(ctx, tID, uID)
}

// Get returns one of the caller's dashboards.
func (s *Service) Get(ctx context.Context, tenantID, userID, id string) (*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	dID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid dashboard id", shared.ErrValidation)
	}
	return s.repo.GetByID(ctx, tID, uID, dID)
}

// Create persists a new dashboard for the caller.
func (s *Service) Create(ctx context.Context, tenantID, userID string, in CreateInput) (*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	d, err := domain.NewDashboard(tID, uID, in.Name, in.Description, in.Columns, in.Widgets)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// Update replaces the name and layout of one of the caller's dashboards.
func (s *Service) Update(ctx context.Context, tenantID, userID, id string, in CreateInput) (*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	dID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid dashboard id", shared.ErrValidation)
	}
	d, err := s.repo.GetByID(ctx, tID, uID, dID)
	if err != nil {
		return nil, err
	}
	if err := d.Update(in.Name, in.Description, in.Columns, in.Widgets); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// Delete removes one of the caller's dashboards.
func (s *Service) Delete(ctx context.Context, tenantID, userID, id string) error {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return err
	}
	dID, err := shared.IDFromString(id)
	if err != nil {
		return fmt.Errorf("%w: invalid dashboard id", shared.ErrValidation)
	}
	return s.repo.Delete(ctx, tID, uID, dID)
}

// SetDefault marks one of the caller's dashboards as their default.
func (s *Service) SetDefault(ctx context.Context, tenantID, userID, id string) error {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return err
	}
	dID, err := shared.IDFromString(id)
	if err != nil {
		return fmt.Errorf("%w: invalid dashboard id", shared.ErrValidation)
	}
	return s.repo.SetDefault(ctx, tID, uID, dID)
}

func parseScope(tenantID, userID string) (shared.ID, shared.ID, error) {
	tID, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uID, err := shared.IDFromString(userID)
	if err != nil {
		return shared.ID{}, shared.ID{}, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	return tID, uID, nil
}
