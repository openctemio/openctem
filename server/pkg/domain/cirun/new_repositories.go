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

// States of a new repository row.
const (
	NewRepoPending = "pending"
	NewRepoBlocked = "blocked"
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

// MaxDecisionItems bounds one decision.
const MaxDecisionItems = 100

// NewRepository is one pending or blocked row.
type NewRepository struct {
	Kind      string
	Name      string
	Group     string
	State     string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int64
	DecidedBy string
	DecidedAt *time.Time
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

// NewRepositoryStore keeps the new repositories.
type NewRepositoryStore interface {
	NewRepositoryBlocked(ctx context.Context, tenantID, configID shared.ID, group, project string) (bool, error)
	RecordPendingRepository(ctx context.Context, tenantID, configID shared.ID, group, project string, at time.Time) (recorded, firstOfGroup bool, err error)
	ListNewRepositories(ctx context.Context, tenantID, configID shared.ID) ([]NewRepository, error)
	ApplyNewRepositoryDecision(ctx context.Context, tenantID, configID shared.ID, d NewRepositoryDecision, by string, at time.Time) error
}
