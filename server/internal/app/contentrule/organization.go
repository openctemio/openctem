package contentrule

// Organization detection rules: create, edit, switch on or off, delete and
// test, each change audited. The tenant always comes from the caller's
// authenticated context, never from a request field; every repository call
// is scoped to it, so another organization's rule is not found (404). A
// rule is validated (RE2, keyword prefilter, size and complexity limits)
// before it is stored or tested. Audit events carry the kind, rule id and
// version, never a sample or a matched value. A change drops the
// organization's cached engine so the next report uses it.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MaxSampleBytes bounds the sample a rule is tested against.
const MaxSampleBytes = 256 << 10

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// RulesService manages an organization's detection rules.
type RulesService struct {
	repo    contentrule.Repository
	engines *Service
	audit   AuditLogger
	logger  *logger.Logger
	now     func() time.Time
}

// NewRulesService creates a RulesService. engines and audit may be nil.
func NewRulesService(repo contentrule.Repository, engines *Service, audit AuditLogger, log *logger.Logger) *RulesService {
	return &RulesService{repo: repo, engines: engines, audit: audit, logger: log.With("service", "content_rule"), now: time.Now}
}

// CreateInput creates a rule.
type CreateInput struct {
	Kind    string
	Rule    contentrule.Rule
	Enabled *bool
}

// UpdateInput changes a rule; nil fields are unchanged.
type UpdateInput struct {
	Rule    *contentrule.Rule
	Enabled *bool
}

// TestInput tests a draft rule against a sample document.
type TestInput struct {
	Kind     string
	Rule     contentrule.Rule
	Document contentrule.Document
}

func tenantOf(actx auditapp.AuditContext) (shared.ID, error) {
	tid, err := shared.IDFromString(actx.TenantID)
	if err != nil || tid.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return tid, nil
}

func actorOf(actx auditapp.AuditContext) *shared.ID {
	if id, err := shared.IDFromString(actx.ActorID); err == nil {
		return &id
	}
	return nil
}

func parseKind(k string) (contentrule.Kind, error) {
	kind := contentrule.Kind(k)
	if !kind.IsValid() {
		return "", shared.NewDomainError("DETECTION_RULE_KIND", "kind must be web-fingerprints or secret-rules", shared.ErrValidation)
	}
	return kind, nil
}

// List returns the caller's organization's rules.
func (s *RulesService) List(ctx context.Context, actx auditapp.AuditContext) ([]*contentrule.StoredRule, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	return s.repo.List(ctx, tid)
}

// Get returns one rule of the caller's organization; a malformed id or a
// rule of another organization is ErrRuleNotFound.
func (s *RulesService) Get(ctx context.Context, actx auditapp.AuditContext, id string) (*contentrule.StoredRule, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	rid, err := shared.IDFromString(id)
	if err != nil {
		return nil, contentrule.ErrRuleNotFound
	}
	return s.repo.Get(ctx, tid, rid)
}

// Create validates and stores a rule.
func (s *RulesService) Create(ctx context.Context, actx auditapp.AuditContext, in CreateInput) (*contentrule.StoredRule, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	kind, err := parseKind(in.Kind)
	if err != nil {
		return nil, err
	}
	if err := in.Rule.Validate(kind); err != nil {
		return nil, err
	}
	_, sum, err := contentrule.Canonical(in.Rule)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	r := &contentrule.StoredRule{ID: shared.NewID(), TenantID: tid, Kind: kind, Rule: in.Rule, Enabled: in.Enabled == nil || *in.Enabled,
		Version: 1, SHA256: sum, CreatedBy: actorOf(actx), UpdatedBy: actorOf(actx), CreatedAt: now, UpdatedAt: now}
	if err := s.repo.Create(ctx, r); err != nil {
		return nil, err
	}
	s.changed(tid)
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentRuleCreated, r, "created"))
	return r, nil
}

// Update changes a rule. The version rises only when the rule's content
// changes.
func (s *RulesService) Update(ctx context.Context, actx auditapp.AuditContext, id string, in UpdateInput) (*contentrule.StoredRule, error) {
	r, err := s.Get(ctx, actx, id)
	if err != nil {
		return nil, err
	}
	changes := auditdom.NewChanges()
	if in.Rule != nil {
		if err := in.Rule.Validate(r.Kind); err != nil {
			return nil, err
		}
		_, sum, err := contentrule.Canonical(*in.Rule)
		if err != nil {
			return nil, err
		}
		if sum != r.SHA256 {
			if in.Rule.ID != r.Rule.ID {
				changes.Set("rule_id", r.Rule.ID, in.Rule.ID)
			}
			changes.Set("version", r.Version, r.Version+1)
			r.Rule, r.SHA256 = *in.Rule, sum
			r.Version++
		}
	}
	if in.Enabled != nil && *in.Enabled != r.Enabled {
		changes.Set("enabled", r.Enabled, *in.Enabled)
		r.Enabled = *in.Enabled
	}
	r.UpdatedBy, r.UpdatedAt = actorOf(actx), s.now().UTC()
	if err := s.repo.Update(ctx, r); err != nil {
		return nil, err
	}
	s.changed(r.TenantID)
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentRuleUpdated, r, "updated").WithChanges(changes))
	return r, nil
}

// Delete removes a rule.
func (s *RulesService) Delete(ctx context.Context, actx auditapp.AuditContext, id string) error {
	r, err := s.Get(ctx, actx, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, r.TenantID, r.ID); err != nil {
		return err
	}
	s.changed(r.TenantID)
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentRuleDeleted, r, "deleted"))
	return nil
}

// Test validates a draft rule and runs it alone on a sample document. The
// result holds masked secrets only, without fingerprints: a test never
// stores, logs or returns a matched value.
func (s *RulesService) Test(ctx context.Context, actx auditapp.AuditContext, in TestInput) (contentrule.Result, error) {
	if _, err := tenantOf(actx); err != nil {
		return contentrule.Result{}, err
	}
	kind, err := parseKind(in.Kind)
	if err != nil {
		return contentrule.Result{}, err
	}
	if err := in.Rule.Validate(kind); err != nil {
		return contentrule.Result{}, err
	}
	if len(in.Document.Body) > MaxSampleBytes {
		return contentrule.Result{}, shared.NewDomainError("DETECTION_RULE_SAMPLE_TOO_LARGE",
			fmt.Sprintf("the sample is larger than %d bytes", MaxSampleBytes), shared.ErrValidation)
	}
	e, errs := contentrule.Compile([]contentrule.RuleSet{{Kind: kind, Origin: contentrule.Origin{Scope: contentrule.ScopeOrganization}, Rules: []contentrule.Rule{in.Rule}}})
	if len(errs) > 0 {
		return contentrule.Result{}, errs[0]
	}
	return e.Scan(ctx, in.Document, contentrule.DefaultBudget, nil), nil
}

func (s *RulesService) changed(tenantID shared.ID) {
	if s.engines != nil {
		s.engines.Invalidate(tenantID)
	}
}

func (s *RulesService) event(action auditdom.Action, r *contentrule.StoredRule, verb string) auditapp.AuditEvent {
	return auditapp.NewSuccessEvent(action, auditdom.ResourceTypeContentRule, r.ID.String()).
		WithResourceName(r.Rule.ID).
		WithMessage(fmt.Sprintf("Detection rule '%s' %s", r.Rule.Name, verb)).
		WithMetadata("kind", string(r.Kind)).
		WithMetadata("version", r.Version).
		WithMetadata("enabled", r.Enabled).
		WithSeverity(auditdom.SeverityMedium)
}

func (s *RulesService) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to write detection rule audit event", "action", string(ev.Action), "error", err)
	}
}
