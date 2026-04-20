package threat

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatactor"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ActorService manages threat actor intelligence.
type ActorService struct {
	repo   threatactor.Repository
	logger *logger.Logger
}

// NewActorService creates a new threat actor service.
func NewActorService(repo threatactor.Repository, log *logger.Logger) *ActorService {
	return &ActorService{repo: repo, logger: log}
}

// CreateActorInput holds input for creating a threat actor.
type CreateActorInput struct {
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

// CreateActor creates a new threat actor.
func (s *ActorService) CreateActor(ctx context.Context, input CreateActorInput) (*threatactor.ThreatActor, error) {
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

// GetActor retrieves a threat actor by ID.
func (s *ActorService) GetActor(ctx context.Context, tenantID, actorID string) (*threatactor.ThreatActor, error) {
	tid, _ := shared.IDFromString(tenantID)
	aid, _ := shared.IDFromString(actorID)
	return s.repo.GetByID(ctx, tid, aid)
}

// ListActors lists threat actors with filtering.
func (s *ActorService) ListActors(ctx context.Context, tenantID string, filter threatactor.Filter, page pagination.Pagination) (pagination.Result[*threatactor.ThreatActor], error) {
	tid, _ := shared.IDFromString(tenantID)
	filter.TenantID = &tid
	return s.repo.List(ctx, filter, page)
}

// DeleteActor deletes a threat actor.
func (s *ActorService) DeleteActor(ctx context.Context, tenantID, actorID string) error {
	tid, _ := shared.IDFromString(tenantID)
	aid, _ := shared.IDFromString(actorID)
	return s.repo.Delete(ctx, tid, aid)
}
