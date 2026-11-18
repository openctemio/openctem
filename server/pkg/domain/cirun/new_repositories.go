package cirun

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// New repositories of an all_repositories trust configuration: projects seen
// for the first time (pending) and projects or groups an administrator
// blocked. Approved ones join the configuration's Repositories or Owners.

// Kinds of a new repository row.
const (
	NewRepoProject = "project"
	NewRepoGroup   = "group"
)

// States of a new repository row. An approved project keeps its row (not
// listed) so its first admitted run must carry the ids that were seen.
const (
	NewRepoPending  = "pending"
	NewRepoBlocked  = "blocked"
	NewRepoApproved = "approved"
)

// Decision actions.
const (
	DecisionApprove = "approve"
	DecisionBlock   = "block"
	DecisionUnblock = "unblock"
)

// MaxPendingRepositories bounds the pending projects kept per configuration
// (any user of the instance can create projects).
const MaxPendingRepositories = 500

// MaxPendingPerGroup bounds the pending projects kept per top-level group, so
// one user who creates many projects or personal namespaces cannot fill the
// configuration's list and push out everyone else's.
const MaxPendingPerGroup = 25

// MaxDecisionItems bounds one decision.
const MaxDecisionItems = 100

// NewRepository is one pending or blocked row.
type NewRepository struct {
	Kind  string
	Name  string
	Group string
	State string
	// ProjectID, NamespacePath and NamespaceID are the verified token claims
	// of the first sighting (a project row; empty for a group or a block).
	// Approving the project binds it to them.
	ProjectID     string
	NamespacePath string
	NamespaceID   string
	FirstSeen     time.Time
	LastSeen      time.Time
	Count         int64
	DecidedBy     string
	DecidedAt     *time.Time
}

// NewRepositoryItem names one project (full path) or group.
type NewRepositoryItem struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Group is the item's top-level group.
func (i NewRepositoryItem) Group() string {
	g, _, _ := strings.Cut(i.Name, "/")
	return g
}

// NewRepositoryDecision is one administrator decision on several items.
type NewRepositoryDecision struct {
	Action string
	Items  []NewRepositoryItem
}

// Sighting is a project seen for the first time, from verified claims.
type Sighting struct {
	Group         string
	Project       string
	ProjectID     string
	NamespacePath string
	NamespaceID   string
}

// Outcomes of recording a sighting.
const (
	SightingRecorded  = "recorded"
	SightingGroupFull = "group_full"
	SightingListFull  = "list_full"
)

// NewRepositoryStore keeps the new repositories.
type NewRepositoryStore interface {
	NewRepositoryBlocked(ctx context.Context, tenantID, configID shared.ID, group, project string) (bool, error)
	// RecordPendingRepository records a sighting; outcome is one of the
	// Sighting* values, firstOfGroup is true when the group had no row.
	RecordPendingRepository(ctx context.Context, tenantID, configID shared.ID, s Sighting, at time.Time) (outcome string, firstOfGroup bool, err error)
	// ApprovedProjectID is the project id an approved project was seen with
	// ("" and false when the project has no approved row).
	ApprovedProjectID(ctx context.Context, tenantID, configID shared.ID, project string) (string, bool, error)
	ListNewRepositories(ctx context.Context, tenantID, configID shared.ID) ([]NewRepository, error)
	ApplyNewRepositoryDecision(ctx context.Context, tenantID, configID shared.ID, d NewRepositoryDecision, by string, at time.Time) error
}
