package jira

import (
	"github.com/openctemio/api/internal/app"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// B3 wire (Q1/WS-E): when a Jira "Done" webhook transitions a finding
// to `fix_applied`, automatically trigger a verification scan that
// either confirms the fix (→ resolved) or reverts (→ in_progress).
//
// This turns the fix-applied transition from a status label into a
// closed-loop edge of the CTEM model.
//
// The hook itself is tiny; the real work happens in
// FindingActionsService.RequestVerificationScan. We also apply a
// per-finding 24h cooldown so a chatty Jira automation rule can't
// spam the scanner.

// VerificationScanRequester is the narrow surface the hook needs
// from FindingActionsService. Kept as an interface so the hook is
// testable without standing up the full finding-actions graph.
// *FindingActionsService satisfies it directly.
type VerificationScanRequester interface {
	RequestVerificationScan(ctx context.Context, tenantID, userID string, input app.RequestVerificationScanInput) (*app.RequestVerificationScanResult, error)
}

// FindingByIDReader is the narrow Finding-repo surface the hook uses
// to look up the scanner that originally produced the finding.
type FindingByIDReader interface {
	GetByID(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, error)
}

// RescanHook wraps the verification trigger with a per-finding
// cooldown. Install via
// SyncService.SetPostFixAppliedHook(hook.Hook).
type RescanHook struct {
	actions VerificationScanRequester
	repo    FindingByIDReader

	mu       sync.Mutex
	lastFire map[shared.ID]time.Time
	cooldown time.Duration
	logger   *logger.Logger
}

// NewRescanHook wires the deps + cooldown.
func NewRescanHook(
	actions VerificationScanRequester,
	repo FindingByIDReader,
	log *logger.Logger,
) *RescanHook {
	if log == nil {
		log = logger.NewNop()
	}
	return &RescanHook{
		actions:  actions,
		repo:     repo,
		lastFire: make(map[shared.ID]time.Time),
		cooldown: 24 * time.Hour,
		logger:   log.With("hook", "jira-rescan"),
	}
}

// SetCooldown overrides the default 24h cooldown. Useful for tests.
func (h *RescanHook) SetCooldown(d time.Duration) { h.cooldown = d }

// Hook is the callback installed on SyncService. Matches the
// FixAppliedHook function signature in jira_sync_service.go.
func (h *RescanHook) Hook(ctx context.Context, tenantID, findingID shared.ID) error {
	if h.actions == nil || h.repo == nil {
		return nil // misconfigured → silent no-op; not the hook's job to fail
	}

	// Cooldown check — per finding, not per tenant, so one noisy
	// finding can't block other fixes.
	h.mu.Lock()
	last, seen := h.lastFire[findingID]
	now := time.Now().UTC()
	if seen && now.Sub(last) < h.cooldown {
		h.mu.Unlock()
		h.logger.Info("jira rescan suppressed by cooldown",
			"tenant_id", tenantID.String(),
			"finding_id", findingID.String(),
			"since_last", now.Sub(last),
		)
		return nil
	}
	h.lastFire[findingID] = now
	h.mu.Unlock()

	// Look up the finding to find the scanner that originally
	// produced it — that's the scanner most likely able to verify
	// the fix now.
	f, err := h.repo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("lookup finding: %w", err)
	}

	// If we cannot derive a scanner name, skip the rescan rather
	// than error: the tenant-admin UI's "Verify Fix" button is
	// still available as a manual fallback.
	scannerName := f.ToolName()
	if scannerName == "" {
		h.logger.Info("jira rescan skipped: no scanner name on finding",
			"finding_id", findingID.String())
		return nil
	}

	_, err = h.actions.RequestVerificationScan(ctx, tenantID.String(), "" /*userID: system*/, app.RequestVerificationScanInput{
		FindingID:   findingID.String(),
		ScannerName: scannerName,
	})
	if err != nil {
		return fmt.Errorf("request verification scan: %w", err)
	}
	h.logger.Info("jira rescan triggered",
		"tenant_id", tenantID.String(),
		"finding_id", findingID.String(),
		"scanner", scannerName,
	)
	return nil
}
