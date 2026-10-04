package easm

// The attribution review queue (RFC-036 §6.4 "Review queue", §6.10
// GET /easm/candidates and POST /easm/candidates/decisions).
//
// Until the candidate table of RFC-036 P2 exists, the queue is the set of
// inventory assets whose attribution is needs_review or candidate: names the
// platform found (CT logs, recon) but could not prove are the tenant's.
//
// Security:
//   - every read and write is tenant-scoped in the store;
//   - the caller's data scope narrows the queue, and a decision on an asset
//     outside it is reported as not found, exactly like a foreign or deleted
//     asset, so the response never confirms the asset exists;
//   - a data-scope resolution error denies the whole request (fail closed).

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxDecisionBatch caps how many assets one bulk decision may name.
const MaxDecisionBatch = 200

// ReviewQuery filters the queue.
type ReviewQuery struct {
	// States to list; empty = needs_review and candidate.
	States []attribution.State
	// Types narrows by asset type (domain, subdomain, ip_address, ...).
	Types []string
	// MinConfidence keeps rows at or above this confidence (0-100).
	MinConfidence int
	// Search is a substring of the asset name.
	Search string
	Limit  int
	Offset int
}

// ReviewEvidence is one reason in a queue row.
type ReviewEvidence struct {
	Rule            string         `json:"rule"`
	Technique       string         `json:"technique"`
	Source          string         `json:"source"`
	Weight          float64        `json:"weight"`
	Observed        map[string]any `json:"observed,omitempty"`
	FirstObservedAt time.Time      `json:"first_observed_at"`
	LastObservedAt  time.Time      `json:"last_observed_at"`
}

// ReviewItem is one asset awaiting (or past) a decision.
type ReviewItem struct {
	AssetID    string           `json:"asset_id"`
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	State      string           `json:"state"`
	Confidence int              `json:"confidence"`
	Reason     string           `json:"reason,omitempty"`
	InQueueAt  time.Time        `json:"in_queue_since"`
	LastSeen   *time.Time       `json:"last_seen,omitempty"`
	Evidence   []ReviewEvidence `json:"evidence"`
}

// ReviewPage is one page of the queue.
type ReviewPage struct {
	Items []ReviewItem `json:"data"`
	Total int          `json:"total"`
}

// ReviewStore is the storage the queue needs. scopeUserID nil = unrestricted.
type ReviewStore interface {
	ListForReview(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID, q ReviewQuery) (*ReviewPage, error)
	// SaveDecisions records a person's decision on each asset that is the
	// tenant's and not deleted. It returns, for each asset written, the state
	// it had before ("" = no record, a legacy confirmed asset).
	SaveDecisions(ctx context.Context, tenantID shared.ID, assetIDs []string, state attribution.State, decidedBy string) (map[string]attribution.State, error)
}

// ReviewService serves the queue and records decisions.
type ReviewService struct {
	store     ReviewStore
	dataScope *datascope.Enforcer
}

// NewReviewService creates the service. A nil enforcer means unrestricted.
func NewReviewService(store ReviewStore, scope *datascope.Enforcer) *ReviewService {
	return &ReviewService{store: store, dataScope: scope}
}

// DecidableStates are the states a person may set.
var DecidableStates = []attribution.State{
	attribution.StateConfirmed, attribution.StateRejected, attribution.StateDependency,
	attribution.StateMonitorOnly, attribution.StateNeedsReview,
}

func decidable(s attribution.State) bool {
	for _, d := range DecidableStates {
		if s == d {
			return true
		}
	}
	return false
}

// Queue lists the queue for the caller, narrowed to its data scope.
func (s *ReviewService) Queue(ctx context.Context, tenantID shared.ID, q ReviewQuery) (*ReviewPage, error) {
	if len(q.States) == 0 {
		q.States = []attribution.State{attribution.StateNeedsReview, attribution.StateCandidate}
	}
	for _, st := range q.States {
		if !st.Valid() {
			return nil, fmt.Errorf("%w: unknown attribution state %q", shared.ErrValidation, st)
		}
	}
	if q.MinConfidence < 0 || q.MinConfidence > 100 {
		return nil, fmt.Errorf("%w: min_confidence must be 0-100", shared.ErrValidation)
	}
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	scopeUser, err := s.scopeUser(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.store.ListForReview(ctx, tenantID, scopeUser, q)
}

// Decision is the outcome for one asset of a bulk decision.
type Decision struct {
	AssetID string `json:"asset_id"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// DecisionResult lists what was decided and what was not found (not the
// tenant's, deleted, or outside the caller's data scope: indistinguishable on
// purpose).
type DecisionResult struct {
	Decided  []Decision `json:"decided"`
	NotFound []string   `json:"not_found"`
}

// Decide records one decision on many assets.
func (s *ReviewService) Decide(ctx context.Context, tenantID shared.ID, assetIDs []string, state attribution.State, actorID string) (*DecisionResult, error) {
	if !decidable(state) {
		return nil, fmt.Errorf("%w: state must be confirmed, rejected, dependency, monitor_only or needs_review", shared.ErrValidation)
	}
	if len(assetIDs) == 0 {
		return nil, fmt.Errorf("%w: asset_ids is required", shared.ErrValidation)
	}
	if len(assetIDs) > MaxDecisionBatch {
		return nil, fmt.Errorf("%w: at most %d assets per decision", shared.ErrValidation, MaxDecisionBatch)
	}
	ids := make([]shared.ID, 0, len(assetIDs))
	seen := map[string]bool{}
	for _, raw := range assetIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
		}
		if seen[id.String()] {
			continue
		}
		seen[id.String()] = true
		ids = append(ids, id)
	}

	inScope, err := s.dataScope.FilterForCaller(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("data scope: %w", err)
	}
	res := &DecisionResult{Decided: []Decision{}, NotFound: []string{}}
	allowed := make([]string, 0, len(ids))
	for _, id := range ids {
		if inScope(id) {
			allowed = append(allowed, id.String())
		} else {
			res.NotFound = append(res.NotFound, id.String())
		}
	}
	if len(allowed) == 0 {
		return res, nil
	}
	prev, err := s.store.SaveDecisions(ctx, tenantID, allowed, state, actorID)
	if err != nil {
		return nil, err
	}
	for _, id := range allowed {
		from, ok := prev[id]
		if !ok {
			res.NotFound = append(res.NotFound, id)
			continue
		}
		if from == "" {
			from = attribution.StateConfirmed // no record: a legacy, confirmed asset
		}
		res.Decided = append(res.Decided, Decision{AssetID: id, From: string(from), To: string(state)})
	}
	return res, nil
}

func (s *ReviewService) scopeUser(ctx context.Context, tenantID shared.ID) (*shared.ID, error) {
	if s.dataScope == nil {
		return nil, nil
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if scope == nil {
		return nil, nil
	}
	id := scope.UserID
	return &id, nil
}
