// Package jira implements the application service for the jira bounded context — orchestrates pkg/domain/jira entities and cross-cutting concerns (audit, notifications, RBAC).
package jira

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// B3 wire: when a Jira "Done" webhook transitions a finding to fix_applied,
// verify the fix automatically: a proof-of-fix retest re-runs the finding's own
// check against its target (RFC-039), confirming the fix (→ resolved) or sending
// the finding back to in_progress. This replaced the whole-asset "verification
// scan" (retired, RFC-039 D4). A per-finding 24h cooldown keeps a chatty Jira
// automation rule from hammering a target.

// ProofOfFixRequester starts a proof-of-fix check for a finding
// (*retest.ProofOfFix).
type ProofOfFixRequester interface {
	ValidateFinding(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error)
}

// FindingByIDReader is the narrow Finding-repo surface the hook uses to check
// the finding is still fix_applied.
type FindingByIDReader interface {
	GetByID(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, error)
}

// RescanHook wraps the proof-of-fix request with a per-finding cooldown.
// Install via SyncService.SetPostFixAppliedHook(hook.Hook).
type RescanHook struct {
	proof ProofOfFixRequester
	repo  FindingByIDReader

	mu       sync.Mutex
	lastFire map[shared.ID]time.Time
	cooldown time.Duration
	logger   *logger.Logger
}

// NewRescanHook wires the deps + cooldown.
func NewRescanHook(proof ProofOfFixRequester, repo FindingByIDReader, log *logger.Logger) *RescanHook {
	if log == nil {
		log = logger.NewNop()
	}
	return &RescanHook{
		proof:    proof,
		repo:     repo,
		lastFire: make(map[shared.ID]time.Time),
		cooldown: 24 * time.Hour,
		logger:   log.With("hook", "jira-proof-of-fix"),
	}
}

// SetCooldown overrides the default 24h cooldown. Useful for tests.
func (h *RescanHook) SetCooldown(d time.Duration) { h.cooldown = d }

// Hook is the callback installed on SyncService. Matches the FixAppliedHook
// function signature.
func (h *RescanHook) Hook(ctx context.Context, tenantID, findingID shared.ID) error {
	if h.proof == nil || h.repo == nil {
		return nil // misconfigured → silent no-op; not the hook's job to fail
	}

	h.mu.Lock()
	last, seen := h.lastFire[findingID]
	now := time.Now().UTC()
	if seen && now.Sub(last) < h.cooldown {
		h.mu.Unlock()
		h.logger.Info("jira proof-of-fix suppressed by cooldown",
			"tenant_id", tenantID.String(), "finding_id", findingID.String(), "since_last", now.Sub(last))
		return nil
	}
	h.lastFire[findingID] = now
	h.mu.Unlock()

	f, err := h.repo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("lookup finding: %w", err)
	}
	if f.Status() != vulnerability.FindingStatusFixApplied {
		return nil // something else moved it already; nothing to verify
	}

	if _, err := h.proof.ValidateFinding(ctx, tenantID, findingID); err != nil {
		return fmt.Errorf("request proof of fix: %w", err)
	}
	h.logger.Info("jira proof-of-fix requested", "tenant_id", tenantID.String(), "finding_id", findingID.String())
	return nil
}
