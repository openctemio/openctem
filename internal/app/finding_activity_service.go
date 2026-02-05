package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// userCacheEntry stores cached user info with expiration.
type userCacheEntry struct {
	name      string
	email     string
	expiresAt time.Time
}

// userCache is a simple in-memory cache for user lookups.
// This reduces N+1 queries when broadcasting multiple activities.
type userCache struct {
	entries sync.Map
	ttl     time.Duration
}

// newUserCache creates a new user cache with the given TTL.
func newUserCache(ttl time.Duration) *userCache {
	return &userCache{ttl: ttl}
}

// get retrieves user info from cache if available and not expired.
func (c *userCache) get(id shared.ID) (name, email string, found bool) {
	if v, ok := c.entries.Load(id.String()); ok {
		entry := v.(userCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.name, entry.email, true
		}
		// Expired, delete it
		c.entries.Delete(id.String())
	}
	return "", "", false
}

// set stores user info in cache.
func (c *userCache) set(id shared.ID, name, email string) {
	c.entries.Store(id.String(), userCacheEntry{
		name:      name,
		email:     email,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// ActivityBroadcaster broadcasts activity events for real-time updates.
// This interface allows decoupling from the WebSocket implementation.
type ActivityBroadcaster interface {
	// BroadcastActivity sends an activity event to subscribers.
	// channel: the channel to broadcast to (e.g., "finding:{id}")
	// data: the activity data to broadcast
	// tenantID: tenant isolation for the broadcast
	BroadcastActivity(channel string, data any, tenantID string)
}

// FindingActivityService handles finding activity operations.
// Activities are APPEND-ONLY - once created, they should never be modified or deleted.
type FindingActivityService struct {
	activityRepo vulnerability.FindingActivityRepository
	findingRepo  vulnerability.FindingRepository
	userRepo     user.Repository     // For enriching actor info in broadcasts
	userCache    *userCache          // Cache user lookups to reduce N+1 queries
	broadcaster  ActivityBroadcaster // For real-time WebSocket updates
	logger       *logger.Logger
}

// userCacheTTL is how long to cache user info for broadcasts.
// 5 minutes is reasonable - balances freshness vs performance.
const userCacheTTL = 5 * time.Minute

// NewFindingActivityService creates a new FindingActivityService.
func NewFindingActivityService(
	activityRepo vulnerability.FindingActivityRepository,
	findingRepo vulnerability.FindingRepository,
	log *logger.Logger,
) *FindingActivityService {
	return &FindingActivityService{
		activityRepo: activityRepo,
		findingRepo:  findingRepo,
		userCache:    newUserCache(userCacheTTL),
		logger:       log.With("service", "finding_activity"),
	}
}

// SetBroadcaster sets the activity broadcaster for real-time WebSocket updates.
// This is optional - if not set, real-time updates are disabled.
func (s *FindingActivityService) SetBroadcaster(broadcaster ActivityBroadcaster) {
	s.broadcaster = broadcaster
}

// SetUserRepo sets the user repository for enriching actor info in broadcasts.
// This is optional - if not set, actor names won't be included in real-time updates.
func (s *FindingActivityService) SetUserRepo(repo user.Repository) {
	s.userRepo = repo
}

// RecordActivityInput represents the input for recording an activity.
type RecordActivityInput struct {
	TenantID       string                 `validate:"required,uuid"`
	FindingID      string                 `validate:"required,uuid"`
	ActivityType   string                 `validate:"required"`
	ActorID        *string                `validate:"omitempty,uuid"`
	ActorType      string                 `validate:"required"`
	Changes        map[string]interface{} `validate:"required"`
	Source         string
	SourceMetadata map[string]interface{}
}

// MaxChangesSize is the maximum allowed size for the changes JSONB field (15KB).
// Increased to support longer comments (up to 10000 chars) for technical discussions.
const MaxChangesSize = 15 * 1024

// RecordActivity creates a new activity record for a finding.
// This is the primary method for recording any finding lifecycle event.
// Security: Changes field is limited to MaxChangesSize to prevent DoS attacks.
func (s *FindingActivityService) RecordActivity(ctx context.Context, input RecordActivityInput) (*vulnerability.FindingActivity, error) {
	s.logger.Debug("recording activity",
		"finding_id", input.FindingID,
		"activity_type", input.ActivityType,
		"actor_type", input.ActorType,
	)

	// Security: Validate changes size to prevent DoS
	if input.Changes != nil {
		changesJSON, _ := json.Marshal(input.Changes)
		if len(changesJSON) > MaxChangesSize {
			return nil, fmt.Errorf("%w: changes exceed maximum size of %d bytes", shared.ErrValidation, MaxChangesSize)
		}
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	findingID, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id format", shared.ErrValidation)
	}

	var actorID *shared.ID
	if input.ActorID != nil && *input.ActorID != "" {
		id, err := shared.IDFromString(*input.ActorID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid actor id format", shared.ErrValidation)
		}
		actorID = &id
	}

	activityType := vulnerability.ActivityType(input.ActivityType)
	actorType := vulnerability.ActorType(input.ActorType)
	source := vulnerability.ActivitySource(input.Source)

	activity, err := vulnerability.NewFindingActivity(
		tenantID,
		findingID,
		activityType,
		actorID,
		actorType,
		input.Changes,
		source,
		input.SourceMetadata,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create activity: %w", err)
	}

	if err := s.activityRepo.Create(ctx, activity); err != nil {
		return nil, fmt.Errorf("failed to persist activity: %w", err)
	}

	s.logger.Info("activity recorded",
		"activity_id", activity.ID().String(),
		"finding_id", input.FindingID,
		"type", input.ActivityType,
	)

	// Broadcast real-time event via WebSocket
	if s.broadcaster != nil {
		var actorIDStr *string
		var actorName, actorEmail string

		// Enrich actor info from cache or user repository
		if activity.ActorID() != nil {
			actorID := *activity.ActorID()
			str := actorID.String()
			actorIDStr = &str

			// Try cache first to reduce database queries
			if s.userCache != nil {
				actorName, actorEmail, _ = s.userCache.get(actorID)
			}

			// Cache miss - look up from database
			if actorName == "" && s.userRepo != nil {
				if u, err := s.userRepo.GetByID(ctx, actorID); err == nil && u != nil {
					actorName = u.Name()
					actorEmail = u.Email()
					// Store in cache for future lookups
					if s.userCache != nil {
						s.userCache.set(actorID, actorName, actorEmail)
					}
				}
			}
		}

		// Event structure matches frontend WSActivityEvent
		event := map[string]any{
			"type": "activity_created",
			"activity": map[string]any{
				"id":            activity.ID().String(),
				"finding_id":    activity.FindingID().String(),
				"tenant_id":     activity.TenantID().String(),
				"activity_type": string(activity.ActivityType()),
				"actor_id":      actorIDStr,
				"actor_type":    string(activity.ActorType()),
				"actor_name":    actorName,
				"actor_email":   actorEmail,
				"changes":       activity.Changes(),
				"created_at":    activity.CreatedAt().Format("2006-01-02T15:04:05.000Z"),
			},
		}

		// Channel format: "finding:{finding_id}"
		channel := fmt.Sprintf("finding:%s", activity.FindingID().String())
		s.broadcaster.BroadcastActivity(channel, event, activity.TenantID().String())
	}

	return activity, nil
}

// RecordStatusChange is a convenience method for recording status changes.
func (s *FindingActivityService) RecordStatusChange(
	ctx context.Context,
	tenantID, findingID string,
	actorID *string,
	oldStatus, newStatus string,
	reason string,
	source string,
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"old_status": oldStatus,
		"new_status": newStatus,
	}
	if reason != "" {
		changes["reason"] = reason
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityStatusChanged),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       source,
	})
}

// RecordSeverityChange is a convenience method for recording severity changes.
func (s *FindingActivityService) RecordSeverityChange(
	ctx context.Context,
	tenantID, findingID string,
	actorID *string,
	oldSeverity, newSeverity string,
	source string,
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"old_severity": oldSeverity,
		"new_severity": newSeverity,
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivitySeverityChanged),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       source,
	})
}

// RecordAssignment is a convenience method for recording assignment changes.
func (s *FindingActivityService) RecordAssignment(
	ctx context.Context,
	tenantID, findingID string,
	actorID *string,
	assigneeID, assigneeName, assigneeEmail string,
	source string,
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"assignee_id":    assigneeID,
		"assignee_name":  assigneeName,
		"assignee_email": assigneeEmail,
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityAssigned),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       source,
	})
}

// RecordUnassignment is a convenience method for recording unassignment.
func (s *FindingActivityService) RecordUnassignment(
	ctx context.Context,
	tenantID, findingID string,
	actorID *string,
	previousAssigneeName string,
	source string,
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"previous_assignee_name": previousAssigneeName,
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityUnassigned),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       source,
	})
}

// RecordCommentAdded is a convenience method for recording comment additions.
// content is the full comment text, stored for display in activity feed.
func (s *FindingActivityService) RecordCommentAdded(
	ctx context.Context,
	tenantID, findingID string,
	actorID *string,
	commentID, content string,
	source string,
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"comment_id": commentID,
	}
	if content != "" {
		// Store full content for display in activity feed
		changes["content"] = content
		// Also store truncated preview for list views
		preview := content
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		changes["preview"] = preview
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityCommentAdded),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       source,
	})
}

// RecordCommentUpdated is a convenience method for recording comment updates.
func (s *FindingActivityService) RecordCommentUpdated(
	ctx context.Context,
	tenantID, findingID string,
	actorID *string,
	commentID string,
	source string,
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"comment_id": commentID,
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityCommentUpdated),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       source,
	})
}

// RecordCommentDeleted is a convenience method for recording comment deletions.
func (s *FindingActivityService) RecordCommentDeleted(
	ctx context.Context,
	tenantID, findingID string,
	actorID *string,
	commentID string,
	source string,
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"comment_id": commentID,
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:     tenantID,
		FindingID:    findingID,
		ActivityType: string(vulnerability.ActivityCommentDeleted),
		ActorID:      actorID,
		ActorType:    string(vulnerability.ActorTypeUser),
		Changes:      changes,
		Source:       source,
	})
}

// RecordScanDetected is a convenience method for recording scan detections.
func (s *FindingActivityService) RecordScanDetected(
	ctx context.Context,
	tenantID, findingID string,
	scanID, scanner, scanType string,
	sourceMetadata map[string]interface{},
) (*vulnerability.FindingActivity, error) {
	changes := map[string]interface{}{
		"scan_id":   scanID,
		"scanner":   scanner,
		"scan_type": scanType,
	}

	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:       tenantID,
		FindingID:      findingID,
		ActivityType:   string(vulnerability.ActivityScanDetected),
		ActorID:        nil,
		ActorType:      string(vulnerability.ActorTypeScanner),
		Changes:        changes,
		Source:         string(vulnerability.SourceCI),
		SourceMetadata: sourceMetadata,
	})
}

// RecordCreated records that a finding was created.
func (s *FindingActivityService) RecordCreated(
	ctx context.Context,
	tenantID, findingID string,
	source string,
	sourceMetadata map[string]interface{},
) (*vulnerability.FindingActivity, error) {
	return s.RecordActivity(ctx, RecordActivityInput{
		TenantID:       tenantID,
		FindingID:      findingID,
		ActivityType:   string(vulnerability.ActivityCreated),
		ActorID:        nil,
		ActorType:      string(vulnerability.ActorTypeSystem),
		Changes:        map[string]interface{}{},
		Source:         source,
		SourceMetadata: sourceMetadata,
	})
}

// ListActivitiesInput represents the input for listing activities.
type ListActivitiesInput struct {
	TenantID      string   `validate:"required,uuid"` // Security: Required for tenant isolation
	FindingID     string   `validate:"required,uuid"`
	ActivityTypes []string `validate:"omitempty"`
	Page          int      `validate:"gte=0"`
	PageSize      int      `validate:"gte=1,lte=100"`
}

// ListActivities retrieves activities for a finding with pagination.
// Security: TenantID is required to ensure tenant isolation.
func (s *FindingActivityService) ListActivities(ctx context.Context, input ListActivitiesInput) (pagination.Result[*vulnerability.FindingActivity], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	findingID, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("%w: invalid finding id format", shared.ErrValidation)
	}

	filter := vulnerability.NewFindingActivityFilter()
	if len(input.ActivityTypes) > 0 {
		actTypes := make([]vulnerability.ActivityType, len(input.ActivityTypes))
		for i, t := range input.ActivityTypes {
			actTypes[i] = vulnerability.ActivityType(t)
		}
		filter = filter.WithActivityTypes(actTypes...)
	}

	page := pagination.New(input.Page, input.PageSize)

	// Security: Pass tenantID to ensure tenant isolation at repository level
	return s.activityRepo.ListByFinding(ctx, findingID, tenantID, filter, page)
}

// GetActivity retrieves a single activity by ID.
func (s *FindingActivityService) GetActivity(ctx context.Context, activityID string) (*vulnerability.FindingActivity, error) {
	id, err := shared.IDFromString(activityID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid activity id format", shared.ErrValidation)
	}

	return s.activityRepo.GetByID(ctx, id)
}

// CountActivities counts activities for a finding.
// Security: tenantID is required to ensure tenant isolation.
func (s *FindingActivityService) CountActivities(ctx context.Context, tenantID, findingID string, filter vulnerability.FindingActivityFilter) (int64, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid finding id format", shared.ErrValidation)
	}

	return s.activityRepo.CountByFinding(ctx, fid, tid, filter)
}
