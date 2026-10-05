package scan

// Scan freeze windows at trigger time (docs/architecture/scan-zones.md,
// "Freeze windows"). The claim predicate holds active work of a frozen
// tenant or zone whatever created it; the trigger answers earlier and
// clearly: a scheduled run is deferred to the window's end, any other
// trigger is refused unless the caller holds scans:freeze:override and asked
// for it, in which case the run and its commands carry an audited override.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanfreeze"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// FreezeWindows reports the freeze windows active for a tenant's work.
// postgres.ScanFreezeWindowRepository implements it.
type FreezeWindows interface {
	ActiveAt(ctx context.Context, tenantID shared.ID, zoneIDs []shared.ID, at time.Time) ([]*scanfreeze.Window, error)
}

// WithFreezeWindows enables the trigger-time freeze check.
func WithFreezeWindows(f FreezeWindows) ServiceOption {
	return func(s *Service) { s.freezeWindows = f }
}

// CodeScanFrozen is the error code of a trigger refused by a freeze window.
const CodeScanFrozen = "SCAN_FREEZE_ACTIVE"

// FrozenError is returned when an active freeze window stops a trigger. It
// wraps shared.ErrConflict (HTTP 409).
type FrozenError struct {
	WindowID   shared.ID
	WindowName string
	Until      time.Time
}

func (e *FrozenError) Error() string {
	return fmt.Sprintf("scan freeze window %q is active until %s: active scans are not started until it ends",
		e.WindowName, e.Until.UTC().Format(time.RFC3339))
}

// Unwrap makes a FrozenError a conflict with its own code.
func (e *FrozenError) Unwrap() error {
	return shared.NewDomainError(CodeScanFrozen, e.Error(), shared.ErrConflict)
}

// AsFrozen returns the FrozenError in err's chain, or nil.
func AsFrozen(err error) *FrozenError {
	var fe *FrozenError
	if errors.As(err, &fe) {
		return fe
	}
	return nil
}

// freezeRequest is what the trigger knows about who asked.
type freezeRequest struct {
	triggerType pipeline.TriggerType
	triggeredBy string
	// override: the caller asked to override and holds the permission
	// (decided by the HTTP layer).
	override bool
}

// checkFreeze decides a trigger against the active freeze windows of the
// tenant and of zoneIDs. active is false for a scan that sends no traffic to
// its targets (every tool passive, T0): such a scan is never frozen. It
// returns whether the run must carry the override. A failed lookup refuses
// the trigger (fail closed).
func (s *Service) checkFreeze(ctx context.Context, sc *scan.Scan, fr freezeRequest, zoneIDs []shared.ID, active bool) (bool, error) {
	if s.freezeWindows == nil || !active {
		return false, nil
	}
	ws, err := s.freezeWindows.ActiveAt(ctx, sc.TenantID, zoneIDs, time.Now())
	if err != nil {
		return false, fmt.Errorf("freeze window check failed, scan not started: %w", err)
	}
	w := scanfreeze.Latest(ws)
	if w == nil {
		return false, nil
	}
	frozen := &FrozenError{WindowID: w.ID, WindowName: w.Name, Until: *w.ActiveUntil}
	actx := AuditContext{TenantID: sc.TenantID.String(), ActorID: fr.triggeredBy}
	if fr.override && fr.triggerType != pipeline.TriggerTypeSchedule {
		s.logAudit(ctx, actx,
			NewSuccessEvent(audit.ActionScanFreezeOverridden, audit.ResourceTypeScanConfig, sc.ID.String()).
				WithResourceName(sc.Name).
				WithMessage(fmt.Sprintf("Scan '%s' started during freeze window '%s' (override)", sc.Name, w.Name)).
				WithMetadata("freeze_window_id", w.ID.String()).
				WithMetadata("freeze_window", w.Name).
				WithMetadata("active_until", w.ActiveUntil.UTC().Format(time.RFC3339)))
		return true, nil
	}
	if fr.triggerType != pipeline.TriggerTypeSchedule {
		s.logAudit(ctx, actx,
			NewFailureEvent(audit.ActionScanFreezeRefused, audit.ResourceTypeScanConfig, sc.ID.String(), frozen).
				WithResourceName(sc.Name).
				WithMessage(fmt.Sprintf("Scan '%s' not started: freeze window '%s' is active", sc.Name, w.Name)).
				WithMetadata("freeze_window_id", w.ID.String()).
				WithMetadata("trigger_type", string(fr.triggerType)))
	}
	return false, frozen
}

// singleScanActive reports whether a single scan sends traffic to its
// targets: its tool is not a passive tool of the stage catalog.
func singleScanActive(sc *scan.Scan) bool {
	return !stage.PassiveTool(sc.ScannerName)
}

// workflowActive reports whether any step of a workflow is active work. A
// step whose stage cannot be told is active.
func workflowActive(steps []*pipeline.Step) bool {
	for _, st := range steps {
		if st.Tool != "" {
			if !stage.PassiveTool(st.Tool) {
				return true
			}
			continue
		}
		sg, err := stage.ForCapabilities(st.Capabilities)
		if err != nil || !sg.Tier.Passive() {
			return true
		}
	}
	return false
}

// planZoneIDs returns the zones a zone plan sends work to.
func planZoneIDs(plan *zonePlan) []shared.ID {
	if plan == nil {
		return nil
	}
	var out []shared.ID
	seen := map[shared.ID]bool{}
	for _, b := range plan.Batches {
		if b.Zone != nil && !seen[b.Zone.ID] {
			seen[b.Zone.ID] = true
			out = append(out, b.Zone.ID)
		}
	}
	return out
}
