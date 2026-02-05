package app

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/google/uuid"
)

// ExposureService handles exposure event business operations.
type ExposureService struct {
	repo                exposure.Repository
	historyRepo         exposure.StateHistoryRepository
	notificationService *NotificationService
	db                  *sql.DB
	logger              *logger.Logger
}

// NewExposureService creates a new ExposureService.
func NewExposureService(
	repo exposure.Repository,
	historyRepo exposure.StateHistoryRepository,
	log *logger.Logger,
) *ExposureService {
	return &ExposureService{
		repo:        repo,
		historyRepo: historyRepo,
		logger:      log.With("service", "exposure"),
	}
}

// SetNotificationService sets the notification service for transactional outbox pattern.
func (s *ExposureService) SetNotificationService(db *sql.DB, svc *NotificationService) {
	s.db = db
	s.notificationService = svc
}

// CreateExposureInput represents the input for creating an exposure event.
type CreateExposureInput struct {
	TenantID string `validate:"required,uuid"`

	AssetID     string         `validate:"omitempty,uuid"`
	EventType   string         `validate:"required"`
	Severity    string         `validate:"required"`
	Title       string         `validate:"required,min=1,max=500"`
	Description string         `validate:"max=2000"`
	Source      string         `validate:"required,max=100"`
	Details     map[string]any `validate:"omitempty"`
}

// CreateExposure creates a new exposure event.
func (s *ExposureService) CreateExposure(ctx context.Context, input CreateExposureInput) (*exposure.ExposureEvent, error) {
	s.logger.Info("creating exposure event", "title", input.Title, "type", input.EventType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	eventType, err := exposure.ParseEventType(input.EventType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	severity, err := exposure.ParseSeverity(input.Severity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	event, err := exposure.NewExposureEvent(tenantID, eventType, severity, input.Title, input.Source, input.Details)
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		event.UpdateDescription(input.Description)
	}

	if input.AssetID != "" {
		id, err := shared.IDFromString(input.AssetID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset ID", shared.ErrValidation)
		}
		event.SetAssetID(&id)
	}

	// Use transactional outbox pattern if NotificationService is configured
	if s.notificationService != nil && s.db != nil {
		if err := s.createExposureWithNotification(ctx, event); err != nil {
			return nil, err
		}
	} else {
		// Fallback to non-transactional create
		if err := s.repo.Create(ctx, event); err != nil {
			return nil, fmt.Errorf("failed to create exposure event: %w", err)
		}
	}

	s.logger.Info("exposure event created", "id", event.ID().String(), "fingerprint", event.Fingerprint())
	return event, nil
}

// createExposureWithNotification creates an exposure and enqueues notification in the same transaction.
func (s *ExposureService) createExposureWithNotification(ctx context.Context, event *exposure.ExposureEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Create exposure in transaction
	if err := s.repo.CreateInTx(ctx, tx, event); err != nil {
		return fmt.Errorf("failed to create exposure event: %w", err)
	}

	// Enqueue notification in the same transaction
	exposureUUID, _ := uuid.Parse(event.ID().String())
	err = s.notificationService.EnqueueNotificationInTx(ctx, tx, EnqueueNotificationParams{
		TenantID:      event.TenantID(),
		EventType:     "new_exposure",
		AggregateType: "exposure",
		AggregateID:   &exposureUUID,
		Title:         fmt.Sprintf("New %s Exposure: %s", event.Severity().String(), event.Title()),
		Body:          event.Description(),
		Severity:      event.Severity().String(),
		URL:           fmt.Sprintf("/exposures/%s", event.ID().String()),
	})
	if err != nil {
		return fmt.Errorf("enqueue notification: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// IngestExposure creates or updates an exposure event based on fingerprint (deduplication).
func (s *ExposureService) IngestExposure(ctx context.Context, input CreateExposureInput) (*exposure.ExposureEvent, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	eventType, err := exposure.ParseEventType(input.EventType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	severity, err := exposure.ParseSeverity(input.Severity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	event, err := exposure.NewExposureEvent(tenantID, eventType, severity, input.Title, input.Source, input.Details)
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		event.UpdateDescription(input.Description)
	}

	if input.AssetID != "" {
		id, err := shared.IDFromString(input.AssetID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset ID", shared.ErrValidation)
		}
		event.SetAssetID(&id)
	}

	// Use upsert for deduplication
	if err := s.repo.Upsert(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to ingest exposure event: %w", err)
	}

	return event, nil
}

// BulkIngestExposures ingests multiple exposure events.
// OPTIMIZED: Uses batch upsert instead of individual upserts to reduce N+1 queries.
func (s *ExposureService) BulkIngestExposures(ctx context.Context, inputs []CreateExposureInput) ([]*exposure.ExposureEvent, error) {
	if len(inputs) == 0 {
		return []*exposure.ExposureEvent{}, nil
	}

	events := make([]*exposure.ExposureEvent, 0, len(inputs))
	var validationErrors []error

	// First pass: validate and create event objects
	for _, input := range inputs {
		tenantID, err := shared.IDFromString(input.TenantID)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("invalid tenant ID: %w", err))
			continue
		}

		eventType, err := exposure.ParseEventType(input.EventType)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("invalid event type: %w", err))
			continue
		}

		severity, err := exposure.ParseSeverity(input.Severity)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("invalid severity: %w", err))
			continue
		}

		event, err := exposure.NewExposureEvent(tenantID, eventType, severity, input.Title, input.Source, input.Details)
		if err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}

		if input.Description != "" {
			event.UpdateDescription(input.Description)
		}

		if input.AssetID != "" {
			id, err := shared.IDFromString(input.AssetID)
			if err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("invalid asset ID: %w", err))
				continue
			}
			event.SetAssetID(&id)
		}

		events = append(events, event)
	}

	if len(validationErrors) > 0 {
		s.logger.Warn("some exposure events failed validation",
			"total", len(inputs),
			"valid", len(events),
			"invalid", len(validationErrors))
	}

	// Second pass: batch upsert all valid events
	if len(events) > 0 {
		if err := s.repo.BulkUpsert(ctx, events); err != nil {
			return nil, fmt.Errorf("failed to bulk ingest exposure events: %w", err)
		}
	}

	return events, nil
}

// GetExposure retrieves an exposure event by ID.
func (s *ExposureService) GetExposure(ctx context.Context, eventID string) (*exposure.ExposureEvent, error) {
	parsedID, err := shared.IDFromString(eventID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	return s.repo.GetByID(ctx, parsedID)
}

// ListExposuresInput represents the input for listing exposure events.
type ListExposuresInput struct {
	TenantID string

	AssetID         string
	EventTypes      []string
	Severities      []string
	States          []string
	Sources         []string
	Search          string
	FirstSeenAfter  int64
	FirstSeenBefore int64
	LastSeenAfter   int64
	LastSeenBefore  int64
	Page            int
	PerPage         int
	SortBy          string
	SortOrder       string
}

// ListExposures lists exposure events with filtering and pagination.
func (s *ExposureService) ListExposures(ctx context.Context, input ListExposuresInput) (pagination.Result[*exposure.ExposureEvent], error) {
	filter := exposure.NewFilter()

	if input.TenantID != "" {
		filter = filter.WithTenantID(input.TenantID)
	}

	if input.AssetID != "" {
		filter = filter.WithAssetID(input.AssetID)
	}
	if len(input.EventTypes) > 0 {
		types := make([]exposure.EventType, 0, len(input.EventTypes))
		for _, t := range input.EventTypes {
			et, err := exposure.ParseEventType(t)
			if err == nil {
				types = append(types, et)
			}
		}
		if len(types) > 0 {
			filter = filter.WithEventTypes(types...)
		}
	}
	if len(input.Severities) > 0 {
		sevs := make([]exposure.Severity, 0, len(input.Severities))
		for _, sev := range input.Severities {
			s, err := exposure.ParseSeverity(sev)
			if err == nil {
				sevs = append(sevs, s)
			}
		}
		if len(sevs) > 0 {
			filter = filter.WithSeverities(sevs...)
		}
	}
	if len(input.States) > 0 {
		states := make([]exposure.State, 0, len(input.States))
		for _, st := range input.States {
			state, err := exposure.ParseState(st)
			if err == nil {
				states = append(states, state)
			}
		}
		if len(states) > 0 {
			filter = filter.WithStates(states...)
		}
	}
	if len(input.Sources) > 0 {
		filter = filter.WithSources(input.Sources...)
	}
	if input.Search != "" {
		filter = filter.WithSearch(input.Search)
	}
	if input.FirstSeenAfter > 0 {
		filter = filter.WithFirstSeenAfter(input.FirstSeenAfter)
	}
	if input.FirstSeenBefore > 0 {
		filter = filter.WithFirstSeenBefore(input.FirstSeenBefore)
	}
	if input.LastSeenAfter > 0 {
		filter = filter.WithLastSeenAfter(input.LastSeenAfter)
	}
	if input.LastSeenBefore > 0 {
		filter = filter.WithLastSeenBefore(input.LastSeenBefore)
	}

	opts := exposure.NewListOptions()
	if input.SortBy != "" {
		sortStr := input.SortBy
		if input.SortOrder == "desc" {
			sortStr = "-" + sortStr
		}
		sortOpt := pagination.NewSortOption(exposure.AllowedSortFields()).Parse(sortStr)
		opts = opts.WithSort(sortOpt)
	}

	page := pagination.New(input.Page, input.PerPage)

	return s.repo.List(ctx, filter, opts, page)
}

// ChangeStateInput represents the input for changing exposure state.
type ChangeStateInput struct {
	ExposureID string `validate:"required,uuid"`
	NewState   string `validate:"required"`
	UserID     string `validate:"required,uuid"`
	Reason     string `validate:"max=500"`
}

// ResolveExposure marks an exposure event as resolved.
func (s *ExposureService) ResolveExposure(ctx context.Context, exposureID, userID, notes string) (*exposure.ExposureEvent, error) {
	return s.changeState(ctx, exposureID, userID, exposure.StateResolved, notes)
}

// AcceptExposure marks an exposure event as accepted risk.
func (s *ExposureService) AcceptExposure(ctx context.Context, exposureID, userID, notes string) (*exposure.ExposureEvent, error) {
	return s.changeState(ctx, exposureID, userID, exposure.StateAccepted, notes)
}

// MarkFalsePositive marks an exposure event as a false positive.
func (s *ExposureService) MarkFalsePositive(ctx context.Context, exposureID, userID, notes string) (*exposure.ExposureEvent, error) {
	return s.changeState(ctx, exposureID, userID, exposure.StateFalsePositive, notes)
}

// ReactivateExposure marks an exposure event as active again.
func (s *ExposureService) ReactivateExposure(ctx context.Context, exposureID, userID string) (*exposure.ExposureEvent, error) {
	parsedID, err := shared.IDFromString(exposureID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	event, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	previousState := event.State()

	if err := event.Reactivate(); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to update exposure event: %w", err)
	}

	// Record state change history with user info
	var changedBy *shared.ID
	if userID != "" {
		parsedUserID, err := shared.IDFromString(userID)
		if err == nil {
			changedBy = &parsedUserID
		}
	}
	history, err := exposure.NewStateHistory(event.ID(), previousState, exposure.StateActive, changedBy, "Reactivated")
	if err == nil {
		_ = s.historyRepo.Create(ctx, history)
	}

	s.logger.Info("exposure reactivated",
		"id", event.ID().String(),
		"from", previousState.String())

	return event, nil
}

func (s *ExposureService) changeState(ctx context.Context, exposureID, userID string, newState exposure.State, notes string) (*exposure.ExposureEvent, error) {
	parsedEventID, err := shared.IDFromString(exposureID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	parsedUserID, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user ID", shared.ErrValidation)
	}

	event, err := s.repo.GetByID(ctx, parsedEventID)
	if err != nil {
		return nil, err
	}

	previousState := event.State()

	switch newState {
	case exposure.StateResolved:
		if err := event.Resolve(parsedUserID, notes); err != nil {
			return nil, err
		}
	case exposure.StateAccepted:
		if err := event.Accept(parsedUserID, notes); err != nil {
			return nil, err
		}
	case exposure.StateFalsePositive:
		if err := event.MarkFalsePositive(parsedUserID, notes); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: invalid state transition", shared.ErrValidation)
	}

	if err := s.repo.Update(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to update exposure event: %w", err)
	}

	// Record state change history
	history, err := exposure.NewStateHistory(event.ID(), previousState, newState, &parsedUserID, notes)
	if err == nil {
		_ = s.historyRepo.Create(ctx, history)
	}

	s.logger.Info("exposure state changed",
		"id", event.ID().String(),
		"from", previousState.String(),
		"to", newState.String())

	return event, nil
}

// GetStateHistory retrieves the state change history for an exposure event.
func (s *ExposureService) GetStateHistory(ctx context.Context, exposureID string) ([]*exposure.StateHistory, error) {
	parsedID, err := shared.IDFromString(exposureID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	return s.historyRepo.ListByExposureEvent(ctx, parsedID)
}

// GetExposureStats returns statistics for a tenant.
func (s *ExposureService) GetExposureStats(ctx context.Context, tenantID string) (map[string]any, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	byState, err := s.repo.CountByState(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get state counts: %w", err)
	}

	bySeverity, err := s.repo.CountBySeverity(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get severity counts: %w", err)
	}

	stateMap := make(map[string]int64)
	for k, v := range byState {
		stateMap[k.String()] = v
	}

	severityMap := make(map[string]int64)
	for k, v := range bySeverity {
		severityMap[k.String()] = v
	}

	return map[string]any{
		"by_state":    stateMap,
		"by_severity": severityMap,
	}, nil
}

// DeleteExposure deletes an exposure event.
func (s *ExposureService) DeleteExposure(ctx context.Context, exposureID, tenantID string) error {
	parsedID, err := shared.IDFromString(exposureID)
	if err != nil {
		return shared.ErrNotFound
	}

	event, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return err
	}

	// Verify event belongs to the tenant
	if tenantID != "" {
		parsedTenantID, err := shared.IDFromString(tenantID)
		if err != nil {
			return fmt.Errorf("%w: invalid tenant ID format", shared.ErrValidation)
		}
		if event.TenantID() != parsedTenantID {
			return shared.ErrNotFound
		}
	}

	return s.repo.Delete(ctx, parsedID)
}
