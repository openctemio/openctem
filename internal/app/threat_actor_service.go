package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatactor"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ThreatActorService manages threat actor intelligence.
type ThreatActorService struct {
	repo   threatactor.Repository
	logger *logger.Logger
}

// NewThreatActorService creates a new threat actor service.
func NewThreatActorService(repo threatactor.Repository, log *logger.Logger) *ThreatActorService {
	return &ThreatActorService{repo: repo, logger: log}
}

// CreateThreatActorInput holds input for creating a threat actor.
type CreateThreatActorInput struct {
	TenantID         string
	Name             string
	Aliases          []string
	Description      string
	ActorType        string
	Sophistication   string
	Motivation       string
	CountryOfOrigin  string
	MitreGroupID     string
	TTPs             []threatactor.TTP
	TargetIndustries []string
	TargetRegions    []string
	Tags             []string
}

// CreateThreatActor creates a new threat actor.
func (s *ThreatActorService) CreateThreatActor(ctx context.Context, input CreateThreatActorInput) (*threatactor.ThreatActor, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	actor, err := threatactor.NewThreatActor(tid, input.Name, threatactor.ActorType(input.ActorType))
	if err != nil {
		return nil, err
	}

	actor.Update(input.Name, input.Description, threatactor.ActorType(input.ActorType))
	actor.SetIntel(input.Sophistication, input.Motivation, input.CountryOfOrigin, input.MitreGroupID)
	actor.SetTTPs(input.TTPs)
	actor.SetTargeting(input.TargetIndustries, input.TargetRegions)

	if err := s.repo.Create(ctx, actor); err != nil {
		return nil, fmt.Errorf("failed to create threat actor: %w", err)
	}

	return actor, nil
}

// GetThreatActor retrieves a threat actor by ID.
func (s *ThreatActorService) GetThreatActor(ctx context.Context, tenantID, actorID string) (*threatactor.ThreatActor, error) {
	tid, _ := shared.IDFromString(tenantID)
	aid, _ := shared.IDFromString(actorID)
	return s.repo.GetByID(ctx, tid, aid)
}

// ListThreatActors lists threat actors with filtering.
func (s *ThreatActorService) ListThreatActors(ctx context.Context, tenantID string, filter threatactor.Filter, page pagination.Pagination) (pagination.Result[*threatactor.ThreatActor], error) {
	tid, _ := shared.IDFromString(tenantID)
	filter.TenantID = &tid
	return s.repo.List(ctx, filter, page)
}

// DeleteThreatActor deletes a threat actor.
func (s *ThreatActorService) DeleteThreatActor(ctx context.Context, tenantID, actorID string) error {
	tid, _ := shared.IDFromString(tenantID)
	aid, _ := shared.IDFromString(actorID)
	return s.repo.Delete(ctx, tid, aid)
}
