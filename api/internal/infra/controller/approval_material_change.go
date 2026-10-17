package controller

// Material change of standing decisions
// (api/docs/rfcs/RFC-111-approval-policy.md §6). Every few minutes the
// controller takes the approved accepted risks and one-person false
// positives whose finding facts moved up since their baseline (severity or
// priority up, KEV added, EPSS reaching the threshold, an exploit newly
// validated, the asset newly internet exposed or a crown jewel) and, under
// the organization's approval policy:
//
//   - ends an accepted risk when the tier it needs now is above the decided
//     one or its cap now ends sooner (the floor), or on any change under
//     end_on_any_change; otherwise flags it for review;
//   - flags a one-person false positive (the floor) or withdraws it under
//     revoke.
//
// Each write is one transaction with its timeline entry and audit row; the
// requester and the approvers of the decision are told. A change below the
// threshold moves the baseline and does nothing. Nothing is approved here:
// the controller only makes risks visible again.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MaterialChangeStore reads and writes standing decisions
// (*postgres.FindingMaterialChangeRepository).
type MaterialChangeStore interface {
	ListStandingDecisions(ctx context.Context, limit int) ([]vulnerability.StandingDecision, error)
	SetBaseline(ctx context.Context, d vulnerability.StandingDecision, facts approvalpolicy.Facts) error
	// MarkChecked records that the decision was looked at now, whatever came
	// of it. The list is ordered by it, least recently checked first, so a
	// decision that keeps failing cannot hold the batch.
	MarkChecked(ctx context.Context, d vulnerability.StandingDecision) error
	EndAcceptance(ctx context.Context, d vulnerability.StandingDecision, signals []approvalpolicy.Signal, newDeadline *time.Time, now time.Time) (bool, error)
	FlagDecision(ctx context.Context, d vulnerability.StandingDecision, reason string, signals []approvalpolicy.Signal) (bool, error)
	RevokeFalsePositive(ctx context.Context, d vulnerability.StandingDecision, signals []approvalpolicy.Signal, newDeadline *time.Time, now time.Time) (bool, error)
}

// ApprovalPolicySource answers an organization's approval policy in force
// (*finding.VulnerabilityService).
type ApprovalPolicySource interface {
	EffectiveApprovalPolicy(ctx context.Context, tenantID shared.ID) (approvalpolicy.Policy, error)
}

// MaterialChangeNotifier tells the requester and the approvers of a decision
// that it was ended, flagged or withdrawn (*finding.VulnerabilityService).
type MaterialChangeNotifier interface {
	NotifyMaterialChange(ctx context.Context, d vulnerability.StandingDecision, action approvalpolicy.Action, signals []approvalpolicy.Signal)
}

// ApprovalMaterialChangeController applies material changes to standing
// decisions.
type ApprovalMaterialChangeController struct {
	store    MaterialChangeStore
	policies ApprovalPolicySource
	sla      SLADeadlineCalculator
	notifier MaterialChangeNotifier
	interval time.Duration
	batch    int
	now      func() time.Time
	logger   *logger.Logger
}

// NewApprovalMaterialChangeController returns the controller (interval 10
// minutes, 200 decisions per run unless set).
func NewApprovalMaterialChangeController(store MaterialChangeStore, policies ApprovalPolicySource, sla SLADeadlineCalculator,
	notifier MaterialChangeNotifier, interval time.Duration, batch int, log *logger.Logger,
) *ApprovalMaterialChangeController {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	if batch <= 0 {
		batch = 200
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &ApprovalMaterialChangeController{store: store, policies: policies, sla: sla, notifier: notifier,
		interval: interval, batch: batch, now: time.Now, logger: log}
}

// Name implements Controller.
func (c *ApprovalMaterialChangeController) Name() string { return "approval-material-change" }

// Interval implements Controller.
func (c *ApprovalMaterialChangeController) Interval() time.Duration { return c.interval }

// Reconcile checks one batch of standing decisions; it answers how many it
// ended, flagged or withdrew.
func (c *ApprovalMaterialChangeController) Reconcile(ctx context.Context) (int, error) {
	decisions, err := c.store.ListStandingDecisions(ctx, c.batch)
	if err != nil {
		c.logger.Error("material change: list standing decisions", "error", err)
		return 0, err
	}
	policies := map[shared.ID]approvalpolicy.Policy{}
	acted := 0
	for _, d := range decisions {
		if c.check(ctx, policies, d) {
			acted++
		}
		// On every attempt, a failed one included: the next run starts with
		// the decisions checked least recently.
		if err := c.store.MarkChecked(ctx, d); err != nil {
			c.logger.Warn("material change: mark checked", "finding_id", d.FindingID, "error", err)
		}
	}
	return acted, nil
}

// check looks at one standing decision; it reports whether it changed it.
func (c *ApprovalMaterialChangeController) check(ctx context.Context, policies map[shared.ID]approvalpolicy.Policy, d vulnerability.StandingDecision) bool {
	if d.Baseline == nil {
		// A decision made before the check existed: today's facts are its
		// baseline; no action.
		if err := c.store.SetBaseline(ctx, d, d.Current); err != nil {
			c.logger.Warn("material change: set baseline", "finding_id", d.FindingID, "error", err)
		}
		return false
	}
	p, ok := policies[d.TenantID]
	if !ok {
		var err error
		if p, err = c.policies.EffectiveApprovalPolicy(ctx, d.TenantID); err != nil {
			c.logger.Warn("material change: policy", "tenant_id", d.TenantID, "error", err)
			return false
		}
		policies[d.TenantID] = p
	}
	return c.apply(ctx, p, d)
}

// apply decides and writes one decision; it reports whether it changed it.
func (c *ApprovalMaterialChangeController) apply(ctx context.Context, p approvalpolicy.Policy, d vulnerability.StandingDecision) bool {
	kind := approvalpolicy.KindFalsePositive
	if d.Status == vulnerability.FindingStatusAccepted {
		kind = approvalpolicy.KindAccepted
	}
	now := c.now().UTC()
	ch := approvalpolicy.MaterialChange(p, approvalpolicy.Decision{
		Kind: kind, DecidedTier: approvalpolicy.Tier(d.Tier), Baseline: *d.Baseline, End: d.ExpiresAt,
	}, d.Current, now)

	var (
		done bool
		err  error
	)
	switch ch.Action {
	case approvalpolicy.ActionEnd:
		done, err = c.store.EndAcceptance(ctx, d, ch.Signals, c.newDeadline(ctx, d, now), now)
	case approvalpolicy.ActionRevoke:
		done, err = c.store.RevokeFalsePositive(ctx, d, ch.Signals, c.newDeadline(ctx, d, now), now)
	case approvalpolicy.ActionFlag:
		reason := vulnerability.DecisionReviewMaterialChangeSinglePerson
		if kind == approvalpolicy.KindAccepted {
			reason = vulnerability.DecisionReviewMaterialChangeAccepted
		}
		done, err = c.store.FlagDecision(ctx, d, reason, ch.Signals)
	default:
		// Nothing material (an EPSS rise below the threshold): move the
		// baseline so the same change is not looked at again.
		err = c.store.SetBaseline(ctx, d, d.Current)
	}
	if err != nil {
		c.logger.Error("material change: apply", "finding_id", d.FindingID, "tenant_id", d.TenantID,
			"action", string(ch.Action), "error", err)
		return false
	}
	if !done {
		return false
	}
	c.logger.Info("standing decision changed by a material change", "finding_id", d.FindingID,
		"tenant_id", d.TenantID, "action", string(ch.Action), "signals", ch.Signals)
	if c.notifier != nil {
		c.notifier.NotifyMaterialChange(ctx, d, ch.Action, ch.Signals)
	}
	return true
}

// newDeadline is the SLA deadline of a finding reopened now (nil: none).
func (c *ApprovalMaterialChangeController) newDeadline(ctx context.Context, d vulnerability.StandingDecision, now time.Time) *time.Time {
	if c.sla == nil {
		return nil
	}
	sev, err := vulnerability.ParseSeverity(d.Severity)
	if err != nil {
		sev = vulnerability.SeverityMedium
	}
	assetID := ""
	if !d.AssetID.IsZero() {
		assetID = d.AssetID.String()
	}
	deadline, err := c.sla.CalculateSLADeadlineForPriority(ctx, d.TenantID.String(), assetID, d.PriorityClass, sev, now)
	if err != nil || deadline.IsZero() {
		return nil
	}
	return &deadline
}
