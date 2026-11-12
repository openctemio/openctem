package exploration

// Rules open leads (docs/architecture/exploration.md, "Rules"). A rule is
// deterministic code: it reads a trigger state the platform derives itself,
// and for each subject asks the question of its lead type with the
// catalog's action for the subject's type. Rules re-read state on every
// pass instead of consuming events, so nothing is lost when a pass fails and
// a repeated pass opens nothing twice (the live dedup key, and the triggers
// leave out subjects asked about recently).

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Caps on opening leads.
const (
	// MaxLiveLeadsPerSubject: at most this many live leads on one asset.
	MaxLiveLeadsPerSubject = 5
	// DefaultMaxOpenLeads: live leads of one exploration (budget default).
	DefaultMaxOpenLeads = 500
	// PlatformMaxOpenLeads: no budget may raise the cap above this.
	PlatformMaxOpenLeads = 5000
	// DefaultRuleBatch: candidates one rule reads per pass.
	DefaultRuleBatch = 100
)

// ActiveSwitch says whether the tenant's automatic coverage is on, which
// lets active (T1) leads open without a person's approval.
type ActiveSwitch interface {
	CoverageEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
}

// Auditor records audit events (auditapp.AuditService).
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// rule is one trigger and the lead type it opens.
type rule struct {
	leadType string
	reason   string
	read     func(ctx context.Context, tenantID shared.ID, leadType string, limit int) ([]exploration.Candidate, error)
}

// Rules opens leads from the trigger states.
type Rules struct {
	repo     exploration.Repository
	triggers exploration.TriggerStore
	sw       ActiveSwitch
	audit    Auditor
	logger   *logger.Logger
	batch    int
	rules    []rule
}

// NewRules wires the rules of the catalog's first lead types.
func NewRules(repo exploration.Repository, triggers exploration.TriggerStore, sw ActiveSwitch, audit Auditor, log *logger.Logger) *Rules {
	r := &Rules{repo: repo, triggers: triggers, sw: sw, audit: audit, logger: log.With("component", "exploration-rules"), batch: DefaultRuleBatch}
	r.rules = []rule{
		{leadType: "dns.takeover_check", reason: "cname_dangling", read: triggers.DanglingAliases},
		{leadType: "version.confirm", reason: "kev_on_unconfirmed_version", read: triggers.UnconfirmedCriticalMatches},
		{leadType: "asset.gone_with_findings", reason: "gone_with_open_findings", read: triggers.GoneWithOpenFindings},
	}
	return r
}

// autoActive reads the tenant's switch; an unreadable switch is off (fail
// closed: active leads then wait for a person).
func (r *Rules) autoActive(ctx context.Context, tenantID shared.ID) bool {
	if r.sw == nil {
		return false
	}
	on, err := r.sw.CoverageEnabled(ctx, tenantID)
	if err != nil {
		r.logger.Warn("exploration: automatic coverage setting not read; active leads wait for approval",
			"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return false
	}
	return on
}

// RunTenant runs every rule for one tenant and returns how many leads it
// opened. A rule that fails is logged and the others still run.
func (r *Rules) RunTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	explorationID, err := r.repo.EnsureContinuous(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	live, err := r.repo.CountLive(ctx, tenantID, explorationID, nil)
	if err != nil {
		return 0, err
	}
	room := DefaultMaxOpenLeads - live
	auto := r.autoActive(ctx, tenantID)
	opened := 0
	var errs []error
	for _, ru := range r.rules {
		if room <= 0 {
			break
		}
		n, err := r.runRule(ctx, tenantID, explorationID, ru, auto, min(r.batch, room))
		opened += n
		room -= n
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ru.leadType, err))
		}
	}
	return opened, errors.Join(errs...)
}

func (r *Rules) runRule(ctx context.Context, tenantID, explorationID shared.ID, ru rule, auto bool, limit int) (int, error) {
	lt, ok := exploration.LookupLeadType(ru.leadType)
	if !ok {
		return 0, exploration.ErrNotInCatalog
	}
	cands, err := ru.read(ctx, tenantID, ru.leadType, limit)
	if err != nil {
		return 0, err
	}
	opened := 0
	for _, c := range cands {
		action, ok := lt.ActionFor(c.Type, c.SubType)
		if !ok {
			continue // no step of this type applies to the subject's type
		}
		subject := c.AssetID
		l, err := exploration.NewLead(exploration.NewLeadInput{
			TenantID: tenantID, ExplorationID: explorationID, Type: lt.ID,
			Action:         exploration.Action{Capability: action.Capability},
			SubjectAssetID: &subject, ReasonCode: ru.reason,
			Origin: exploration.OriginRule, OriginRef: lt.RuleRef(), Likelihood: lt.Likelihood,
			AutoActive: auto,
		})
		if err != nil {
			return opened, err
		}
		if _, err := exploration.CheckCatalog(l); err != nil {
			return opened, err
		}
		n, err := r.repo.CountLive(ctx, tenantID, explorationID, &subject)
		if err != nil {
			return opened, err
		}
		if n >= MaxLiveLeadsPerSubject {
			continue
		}
		created, err := r.repo.OpenLead(ctx, l, c.Evidence)
		if err != nil {
			return opened, err
		}
		if !created {
			continue
		}
		opened++
		r.record(ctx, l, audit.ActionExplorationLeadOpened, auditapp.AuditContext{
			TenantID: tenantID.String(), ActorEmail: "rule:" + lt.RuleRef(),
		}, map[string]any{"evidence": len(c.Evidence)})
	}
	return opened, nil
}

// record writes one audit event about a lead: who acted, its type, its
// state and its action hash, so "why did this run" has one answer.
func (r *Rules) record(ctx context.Context, l *exploration.Lead, action audit.Action, actx auditapp.AuditContext, meta map[string]any) {
	recordLead(ctx, r.audit, r.logger, l, action, actx, meta)
}

func recordLead(ctx context.Context, a Auditor, log *logger.Logger, l *exploration.Lead, action audit.Action, actx auditapp.AuditContext, meta map[string]any) {
	if a == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeExplorationLead, l.ID.String())
	ev.ResourceName = l.Type
	ev.Message = string(action) + ": " + l.Type
	ev.Metadata["lead_type"] = l.Type
	ev.Metadata["state"] = string(l.State)
	ev.Metadata["capability"] = l.Action.Capability
	ev.Metadata["tier"] = l.Tier.String()
	ev.Metadata["action_hash"] = l.ActionHash
	ev.Metadata["origin"] = string(l.Origin)
	ev.Metadata["origin_ref"] = l.OriginRef
	if l.SubjectAssetID != nil {
		ev.Metadata["subject_asset_id"] = l.SubjectAssetID.String()
	}
	for k, v := range meta {
		ev.Metadata[k] = v
	}
	if err := a.LogEvent(ctx, actx, ev); err != nil {
		log.Warn("exploration: audit event not written", "action", string(action), "error", logger.SanitizeError(err))
	}
}
