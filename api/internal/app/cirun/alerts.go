package cirun

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Notifier is the slice of the notification outbox the alert job needs.
type Notifier interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// AlertJob walks every tenant with CI pipelines, sends the CI alerts whose
// condition started to hold (once each, until it clears) and marks the
// findings only a stale pipeline reported as not observed (RFC-051 §10.6).
// Signals only, never one notification per run.
type AlertJob struct {
	repo     cirun.Repository
	notifier Notifier
	audit    Auditor
	versions cirun.StatusPolicy
	log      *logger.Logger
	now      func() time.Time
}

// NewAlertJob creates the job. notifier and audit may be nil.
func NewAlertJob(repo cirun.Repository, notifier Notifier, audit Auditor, versions cirun.StatusPolicy, log *logger.Logger) *AlertJob {
	if log == nil {
		log = logger.NewNop()
	}
	return &AlertJob{repo: repo, notifier: notifier, audit: audit, versions: versions,
		log: log.With("job", "ci-alerts"), now: time.Now}
}

// SetClock replaces the clock (tests).
func (j *AlertJob) SetClock(now func() time.Time) { j.now = now }

// AlertRunResult counts one run.
type AlertRunResult struct {
	Tenants        int
	Fired          int
	Cleared        int
	StaleFindings  int
	TenantFailures int
}

// Run reconciles every tenant. A tenant that fails is logged and skipped.
func (j *AlertJob) Run(ctx context.Context) (AlertRunResult, error) {
	var res AlertRunResult
	tenants, err := j.repo.PipelineTenantsForPlatform(ctx)
	if err != nil {
		return res, fmt.Errorf("list tenants with pipelines: %w", err)
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		r, err := j.ReconcileTenant(ctx, t)
		res.Tenants++
		res.Fired += r.Fired
		res.Cleared += r.Cleared
		res.StaleFindings += r.StaleFindings
		if err != nil {
			res.TenantFailures++
			j.log.Warn("ci alerts: tenant not reconciled", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return res, nil
}

// ReconcileTenant evaluates one tenant.
func (j *AlertJob) ReconcileTenant(ctx context.Context, tenantID shared.ID) (AlertRunResult, error) {
	var res AlertRunResult
	now := j.now().UTC()
	pipes, err := j.repo.ListPipelines(ctx, tenantID, cirun.PipelineFilter{})
	if err != nil {
		return res, err
	}
	current := cirun.EvaluateAlerts(pipes, now, j.versions)
	refused, err := j.repo.TokenRefusalsSince(ctx, tenantID, now.Add(-cirun.TokenRefusalWindow))
	if err != nil {
		return res, fmt.Errorf("count token refusals: %w", err)
	}
	if refused >= cirun.TokenRefusalBurst {
		current = append(current, cirun.Alert{Kind: cirun.AlertTokenRefusals, SubjectID: tenantID,
			Detail: map[string]any{"refusals": refused, "window": cirun.TokenRefusalWindow.String()}})
	}
	state, err := j.repo.ListAlertState(ctx, tenantID)
	if err != nil {
		return res, err
	}
	holding := make(map[string]bool, len(current))
	for _, a := range current {
		holding[a.Key()] = true
		fired, err := j.repo.FireAlert(ctx, tenantID, a, now)
		if err != nil {
			return res, fmt.Errorf("record alert: %w", err)
		}
		if fired {
			res.Fired++
			j.notify(ctx, tenantID, a)
		}
	}
	for _, s := range state {
		if holding[string(s.Kind)+":"+s.SubjectID.String()] {
			continue
		}
		if err := j.repo.ClearAlert(ctx, tenantID, s.SubjectID, s.Kind); err != nil {
			return res, fmt.Errorf("clear alert: %w", err)
		}
		res.Cleared++
	}

	// Findings whose only source is a stale or archived pipeline are not
	// observed any more: not fixed, not current.
	// The freshness decides, not the badge: a stale pipeline whose last
	// default-branch run failed shows "failing" but still stopped looking.
	for i := range pipes {
		p := &pipes[i]
		a := p.Assess(now, j.versions)
		if p.RetiredAt != nil || (a.Freshness != cirun.FreshnessStale && a.Freshness != cirun.FreshnessArchived) {
			continue
		}
		ids, err := j.repo.MarkStaleSourceFindings(ctx, tenantID, p)
		if err != nil {
			return res, err
		}
		if len(ids) == 0 {
			continue
		}
		res.StaleFindings += len(ids)
		j.auditStale(ctx, tenantID, p, ids)
	}
	return res, nil
}

// alertEvent maps an alert kind to its notification event type and severity.
func alertEvent(k cirun.AlertKind) (integration.EventType, string) {
	switch k {
	case cirun.AlertScheduleMissed:
		return integration.EventTypeCIScheduleMissed, "high"
	case cirun.AlertCoverageRegression:
		return integration.EventTypeCICoverageRegression, "high"
	case cirun.AlertGateFailing:
		return integration.EventTypeCIGateFailing, "medium"
	case cirun.AlertTokenRefusals:
		return integration.EventTypeCITokenRefusals, notificationdom.SeverityHigh
	default:
		return integration.EventTypeCIRunnerOutdated, "medium"
	}
}

func (j *AlertJob) notify(ctx context.Context, tenantID shared.ID, a cirun.Alert) {
	if j.notifier == nil {
		return
	}
	eventType, severity := alertEvent(a.Kind)
	var title, body, url, aggregate string
	subject := a.SubjectID.String()
	switch a.Kind {
	case cirun.AlertScheduleMissed:
		title = "Scheduled CI scan missed: " + a.Repository
		body = fmt.Sprintf("The scheduled CI pipeline %s on %s missed two expected runs. Someone may have disabled or broken the scan.",
			a.Workflow, a.Repository)
	case cirun.AlertCoverageRegression:
		title = "CI coverage lost: " + a.Repository
		body = fmt.Sprintf("%s had a CI pipeline scanning it; none of its pipelines has run within its expected cadence.", a.Repository)
	case cirun.AlertTokenRefusals:
		title = "CI token exchanges refused repeatedly"
		body = fmt.Sprintf("%v CI token exchanges were refused in the last %s: a pipeline outside the trust rules, "+
			"a replayed token or a misconfiguration. The audit log (ci_run.token_refused) names each repository and reason.",
			a.Detail["refusals"], cirun.TokenRefusalWindow)
	case cirun.AlertGateFailing:
		title = "Default branch failing the CI gate: " + a.Repository
		body = fmt.Sprintf("The last run of %s on the default branch of %s failed the CI gate.", a.Workflow, a.Repository)
	default:
		title = "Outdated CI runner: " + a.Repository
		body = fmt.Sprintf("The CI pipeline %s on %s runs a sensor older than the minimum supported version.", a.Workflow, a.Repository)
	}
	switch {
	case a.Kind == cirun.AlertTokenRefusals:
		aggregate = "tenant"
		url = "/settings/scanning/ci"
	case a.PipelineID != nil:
		aggregate = "ci_pipeline"
		url = "/sensors?mode=runner&pipeline=" + a.PipelineID.String()
	default:
		aggregate = "repository"
		url = "/sensors?mode=runner&view=coverage"
	}
	meta := map[string]any{"kind": string(a.Kind)}
	if a.Repository != "" {
		meta["repository"], meta["repository_asset_id"] = a.Repository, a.RepositoryAssetID.String()
	}
	if a.Workflow != "" {
		meta["workflow"] = a.Workflow
	}
	for k, v := range a.Detail {
		meta[k] = v
	}
	var aggID *uuid.UUID
	if id, err := uuid.Parse(subject); err == nil {
		aggID = &id
	}
	if err := j.notifier.Enqueue(ctx, outbox.EnqueueParams{TenantID: tenantID, EventType: string(eventType),
		AggregateType: aggregate, AggregateID: aggID, Title: title, Body: body, Severity: severity, URL: url,
		Metadata: meta}); err != nil {
		j.log.Warn("ci alert not enqueued", "kind", string(a.Kind), "subject", subject, "error", logger.SanitizeError(err))
	}
}

func (j *AlertJob) auditStale(ctx context.Context, tenantID shared.ID, p *cirun.Pipeline, ids []shared.ID) {
	if j.audit == nil {
		return
	}
	list := make([]string, 0, min(len(ids), maxAuditedFindingIDs))
	for i, id := range ids {
		if i == maxAuditedFindingIDs {
			break
		}
		list = append(list, id.String())
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionCIStaleSourceFindings, auditdom.ResourceTypeCIPipeline, p.ID.String()).
		WithResourceName(p.RepositoryName+" "+p.WorkflowPath).
		WithMessage(fmt.Sprintf("%d finding(s) only the stale CI pipeline %s on %s reported are now not observed (source stale)",
			len(ids), p.WorkflowPath, p.RepositoryName)).
		WithMetadata("findings", len(ids)).
		WithMetadata("finding_ids", list)
	if err := j.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "system"}, ev); err != nil {
		j.log.Warn("ci stale-source audit not written", "error", logger.SanitizeError(err))
	}
}
