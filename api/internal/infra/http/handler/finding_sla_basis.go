package handler

// The "why this date" block of a single-finding response: the SLA policy,
// the window and what set it, the known exploited cap and the clock start,
// computed with the same rule as the stored deadline. It rides on
// GET /findings/{id}, so it has that route's permission and data-scope check
// and adds no route of its own.

import (
	"context"
	"time"

	slaapp "github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingSLAExplainer explains a deadline from the governing policy.
type FindingSLAExplainer interface {
	ExplainDeadline(ctx context.Context, tenantID, assetID, priorityClass string, severity vulnerability.Severity) (*slaapp.Explanation, error)
}

// FindingSLAClockReader reads when a finding's SLA clock started.
type FindingSLAClockReader interface {
	SLAClock(ctx context.Context, tenantID, findingID shared.ID) (sladom.Clock, error)
}

// SetSLABasis wires the "why this date" block; without it the block is left out.
func (h *VulnerabilityHandler) SetSLABasis(e FindingSLAExplainer, c FindingSLAClockReader) {
	h.slaExplainer, h.slaClock = e, c
}

// FindingSLABasisResponse says why the SLA deadline is the date it is.
type FindingSLABasisResponse struct {
	PolicyID    string `json:"policy_id,omitempty"`
	PolicyName  string `json:"policy_name"`
	PolicyScope string `json:"policy_scope" enums:"asset,organization,platform"`
	// Basis: priority (the class window), severity (no class window
	// applies) or none (no SLA for this finding).
	Basis      string `json:"basis" enums:"priority,severity,none"`
	Days       int    `json:"days"`
	KEVCapDays int    `json:"kev_cap_days"`
	KEVCapped  bool   `json:"kev_capped"`
	// ClockStartedAt is when the current clock started; ClockReason says
	// why: first_detected, reopened (a regression restarted it) or
	// recalculated (a later priority change counted a new window from then).
	ClockStartedAt     time.Time `json:"clock_started_at"`
	ClockReason        string    `json:"clock_reason" enums:"first_detected,reopened,recalculated"`
	Restarts           int       `json:"restarts"`
	LastRestartTrigger string    `json:"last_restart_trigger,omitempty"`
	// ExpectedDeadline is clock start + window (capped for KEV); Earlier is
	// true when the stored deadline is earlier (deadlines only ever move
	// earlier, except on a restart).
	ExpectedDeadline *time.Time `json:"expected_deadline,omitempty"`
	Earlier          bool       `json:"earlier,omitempty"`
}

func (h *VulnerabilityHandler) enrichFindingWithSLABasis(ctx context.Context, tenantID string, f *vulnerability.Finding, resp *FindingResponse) {
	if h.slaExplainer == nil || f == nil {
		return
	}
	pc := ""
	if p := f.PriorityClass(); p != nil {
		pc = string(*p)
	}
	assetID := ""
	if !f.AssetID().IsZero() {
		assetID = f.AssetID().String()
	}
	e, err := h.slaExplainer.ExplainDeadline(ctx, tenantID, assetID, pc, f.Severity())
	if err != nil {
		h.logger.Debug("sla basis: explain failed", "error", err)
		return
	}
	resp.SLABasis = slaBasisResponse(e, f, h.readSLAClock(ctx, f))
}

func (h *VulnerabilityHandler) readSLAClock(ctx context.Context, f *vulnerability.Finding) sladom.Clock {
	if h.slaClock == nil {
		return sladom.Clock{}
	}
	c, err := h.slaClock.SLAClock(ctx, f.TenantID(), f.ID())
	if err != nil {
		h.logger.Debug("sla basis: clock read failed", "error", err)
		return sladom.Clock{}
	}
	return c
}

// slaBasisResponse composes the block from the explanation, the finding and
// its clock (pure, unit-tested).
func slaBasisResponse(e *slaapp.Explanation, f *vulnerability.Finding, c sladom.Clock) *FindingSLABasisResponse {
	out := &FindingSLABasisResponse{
		PolicyID: e.PolicyID, PolicyName: e.PolicyName, PolicyScope: e.PolicyScope,
		Basis: e.Basis, Days: e.Days, KEVCapDays: e.KEVCapDays, KEVCapped: f.SLAKEVCapped(),
		ClockStartedAt: f.FirstDetectedAt(), ClockReason: "first_detected",
		Restarts: c.Restarts, LastRestartTrigger: c.LastRestartTrigger,
	}
	if c.StartedAt != nil && c.StartedAt.After(f.FirstDetectedAt().Add(time.Minute)) {
		out.ClockStartedAt = *c.StartedAt
		out.ClockReason = "recalculated"
		if c.LastReopenedAt != nil && !c.StartedAt.Before(c.LastReopenedAt.Add(-time.Minute)) {
			out.ClockReason = "reopened"
		}
	}
	if exp, _ := e.ExpectedDeadline(out.ClockStartedAt, f.IsInKEV()); !exp.IsZero() {
		out.ExpectedDeadline = &exp
		if d := f.SLADeadline(); d != nil && d.Before(exp.Add(-time.Minute)) {
			out.Earlier = true
		}
	}
	return out
}
