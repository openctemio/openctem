package scan

// Scan windows at trigger time (RFC-067, docs/architecture/scan-windows.md).
// The claim decides per job whatever created it; the trigger answers earlier
// and clearly:
//
//   - a target whose windows never open (an empty intersection) refuses the
//     run (SCAN_WINDOW_NEVER_OPENS), naming the targets and the sources;
//   - a scheduled run none of whose targets may run now is deferred to the
//     earliest next opening (WindowDeferError; the scheduler moves
//     next_run_at), never skipped;
//   - otherwise the run starts; the targets that wait, and until when, go
//     into the run context (window_waits) so the console can say so.
//
// A failed lookup refuses the trigger (fail closed).

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	swapp "github.com/openctemio/openctem/api/internal/app/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// WindowLoader loads what governs targets (*scanwindow.Resolver).
type WindowLoader interface {
	Load(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*swapp.Snapshot, error)
}

// WithScanWindows enables the trigger-time window checks.
func WithScanWindows(l WindowLoader) ServiceOption {
	return func(s *Service) { s.windows = l }
}

// CodeWindowNeverOpens is the error code of a trigger refused because a
// target's windows never open.
const CodeWindowNeverOpens = "SCAN_WINDOW_NEVER_OPENS"

// RunContextKeyWindowWaits is the run context key of the targets that wait
// for a window (platform bookkeeping, never sent to a sensor).
const RunContextKeyWindowWaits = "window_waits"

// maxListedWaits bounds the waiting targets a run context or message names.
const maxListedWaits = 50

// TargetWait is a target that cannot be scanned now.
type TargetWait struct {
	Target     string        `json:"target"`
	NextOpenAt *time.Time    `json:"next_open_at,omitempty"`
	Never      bool          `json:"never,omitempty"`
	Blocking   []swdom.Block `json:"blocking"`
}

// NeverOpensError: targets whose windows never open. It wraps
// shared.ErrConflict (HTTP 409).
type NeverOpensError struct {
	Targets []string
	Sources []string
}

func (e *NeverOpensError) Error() string {
	return fmt.Sprintf("these targets can never be scanned under the organization's scan windows (the windows that apply to them never open together): %s; windows: %s",
		listed(e.Targets), listed(e.Sources))
}

// Unwrap makes a NeverOpensError a conflict with its own code.
func (e *NeverOpensError) Unwrap() error {
	return shared.NewDomainError(CodeWindowNeverOpens, e.Error(), shared.ErrConflict)
}

// WindowDeferError: a scheduled run none of whose targets may run now; the
// scheduler moves the occurrence to Until.
type WindowDeferError struct {
	Until    time.Time
	Blocking []swdom.Block
}

func (e *WindowDeferError) Error() string {
	return fmt.Sprintf("no target of this scan may be scanned now (scan windows); the run is deferred to %s",
		e.Until.UTC().Format(time.RFC3339))
}

// AsWindowDefer returns the WindowDeferError in err's chain, or nil.
func AsWindowDefer(err error) *WindowDeferError {
	var we *WindowDeferError
	if errors.As(err, &we) {
		return we
	}
	return nil
}

// WindowPreview is what the windows mean for a scan's targets.
type WindowPreview struct {
	// Governed: at least one window applies to the targets.
	Governed bool `json:"governed"`
	// Total: the distinct targets evaluated.
	Total int `json:"total"`
	// Waiting: targets that cannot be scanned now (at most 50 listed).
	WaitingCount int          `json:"waiting_count"`
	Waiting      []TargetWait `json:"waiting"`
	// Never: targets whose windows never open (the trigger refuses them).
	NeverCount int          `json:"never_count"`
	Never      []TargetWait `json:"never"`
	// NextOpenAt: when every waiting target may run (nil when some never).
	NextOpenAt *time.Time `json:"next_open_at,omitempty"`
}

// evaluateWindows decides every target at tier (zoneOf gives a target's
// zone; nil means none). A nil preview means no window applies.
func (s *Service) evaluateWindows(ctx context.Context, tenantID shared.ID, targets []string, zoneOf func(string) *shared.ID, tier int) (*WindowPreview, error) {
	targets = uniqueStrings(targets)
	if s.windows == nil || len(targets) == 0 {
		return nil, nil
	}
	now := time.Now()
	snap, err := s.windows.Load(ctx, tenantID, targets, now)
	if err != nil {
		return nil, fmt.Errorf("scan window check failed: %w", err)
	}
	if snap.Empty() {
		return nil, nil
	}
	out := &WindowPreview{Total: len(targets), Waiting: []TargetWait{}, Never: []TargetWait{}}
	var latest *time.Time
	for _, t := range targets {
		var zone *shared.ID
		if zoneOf != nil {
			zone = zoneOf(t)
		}
		d := swdom.Decide(snap.SourcesFor(t, zone), tier, now)
		out.Governed = out.Governed || d.Governed
		if d.Open {
			continue
		}
		w := TargetWait{Target: t, NextOpenAt: d.NextOpen, Never: d.Never, Blocking: d.Blocking}
		if d.Never {
			out.NeverCount++
			if len(out.Never) < maxListedWaits {
				out.Never = append(out.Never, w)
			}
			continue
		}
		out.WaitingCount++
		if len(out.Waiting) < maxListedWaits {
			out.Waiting = append(out.Waiting, w)
		}
		if d.NextOpen != nil && (latest == nil || d.NextOpen.After(*latest)) {
			latest = d.NextOpen
		}
	}
	if out.NeverCount == 0 {
		out.NextOpenAt = latest
	}
	if !out.Governed {
		return nil, nil
	}
	return out, nil
}

// earliestOpening is the earliest next opening of the waiting targets.
func (p *WindowPreview) earliestOpening() *time.Time {
	var out *time.Time
	for _, w := range p.Waiting {
		if w.NextOpenAt != nil && (out == nil || w.NextOpenAt.Before(*out)) {
			out = w.NextOpenAt
		}
	}
	return out
}

// checkWindows applies the windows to a trigger: it refuses never-opening
// targets, defers a scheduled run with nothing open, and records the waits
// in runContext.
func (s *Service) checkWindows(ctx context.Context, sc *scan.Scan, triggerType scanworkflow.TriggerType, triggeredBy string,
	targets []string, zoneOf func(string) *shared.ID, tier int, runContext map[string]any,
) error {
	p, err := s.evaluateWindows(ctx, sc.TenantID, targets, zoneOf, tier)
	if err != nil {
		return fmt.Errorf("%w; scan not started", err)
	}
	if p == nil {
		return nil
	}
	if p.NeverCount > 0 {
		ne := &NeverOpensError{}
		for _, w := range p.Never {
			ne.Targets = append(ne.Targets, w.Target)
			for _, b := range w.Blocking {
				if !slices.Contains(ne.Sources, b.Name) {
					ne.Sources = append(ne.Sources, b.Name)
				}
			}
		}
		if extra := p.NeverCount - len(p.Never); extra > 0 {
			ne.Targets = append(ne.Targets, fmt.Sprintf("(%d more)", extra))
		}
		s.logAudit(ctx, AuditContext{TenantID: sc.TenantID.String(), ActorID: triggeredBy},
			NewFailureEvent(audit.ActionScanWindowRefused, audit.ResourceTypeScanConfig, sc.ID.String(), ne).
				WithResourceName(sc.Name).
				WithMessage(fmt.Sprintf("Scan '%s' not started: %d target(s) can never be scanned under the scan windows", sc.Name, p.NeverCount)).
				WithMetadata("trigger_type", string(triggerType)).
				WithMetadata("windows", ne.Sources))
		return ne
	}
	if p.WaitingCount == 0 {
		return nil
	}
	if triggerType == scanworkflow.TriggerTypeSchedule && p.WaitingCount == p.Total {
		if until := p.earliestOpening(); until != nil {
			var blocking []swdom.Block
			if len(p.Waiting) > 0 {
				blocking = p.Waiting[0].Blocking
			}
			return &WindowDeferError{Until: *until, Blocking: blocking}
		}
	}
	if runContext != nil {
		runContext[RunContextKeyWindowWaits] = map[string]any{
			"waiting_count": p.WaitingCount,
			"waiting":       p.Waiting,
			"next_open_at":  p.NextOpenAt,
		}
	}
	return nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// singleScanTier is the tier a single scan probes at.
func singleScanTier(sc *scan.Scan) int { return int(ProbeTier(sc.ScannerName)) }

// workflowTier is the highest tier of a workflow's steps; a step whose
// stage cannot be told is active.
func workflowTier(steps []*scanworkflow.Step) int {
	tier := 0
	for _, st := range steps {
		t := int(stage.TierActive)
		if st.Tool != "" {
			t = int(stage.ProbeTier(st.Tool))
		} else if sg, err := stage.ForCapabilities(st.Capabilities); err == nil {
			t = int(sg.Tier)
		}
		tier = max(tier, t)
	}
	return tier
}

// planZoneOf returns each target's zone in a zone plan (nil: no plan).
func planZoneOf(plan *zonePlan) func(string) *shared.ID {
	if plan == nil {
		return nil
	}
	zones := map[string]*shared.ID{}
	for _, b := range plan.Batches {
		if b.Zone == nil {
			continue
		}
		id := b.Zone.ID
		for _, t := range b.Targets {
			zones[t] = &id
		}
	}
	return func(t string) *shared.ID { return zones[t] }
}

// oneZone returns a zoneOf that answers zone for every target.
func oneZone(zone *shared.ID) func(string) *shared.ID {
	return func(string) *shared.ID { return zone }
}

// previewWindows adds the scan windows of the resolved targets to a routing
// preview; a never-opening target is what the trigger would refuse.
func (s *Service) previewWindows(ctx context.Context, sc *scan.Scan, in ZoneRoutingPreviewInput, targets []string, plan *zonePlan, out *ZoneRoutingPreview) error {
	tier := int(stage.TierActive)
	switch {
	case in.Tier != nil:
		tier = *in.Tier
	case sc.ScanType == scan.ScanTypeSingle:
		tier = singleScanTier(sc)
	}
	zoneOf := planZoneOf(plan)
	if zoneOf == nil && sc.ScanZoneID != nil {
		zoneOf = oneZone(sc.ScanZoneID)
	}
	p, err := s.evaluateWindows(ctx, sc.TenantID, targets, zoneOf, tier)
	if err != nil {
		return err
	}
	out.Windows = p
	if p != nil && p.NeverCount > 0 && out.Error == nil {
		ne := &NeverOpensError{}
		for _, w := range p.Never {
			ne.Targets = append(ne.Targets, w.Target)
			for _, b := range w.Blocking {
				if !slices.Contains(ne.Sources, b.Name) {
					ne.Sources = append(ne.Sources, b.Name)
				}
			}
		}
		out.Error = &PreviewError{Code: CodeWindowNeverOpens, Message: ne.Error()}
	}
	return nil
}
