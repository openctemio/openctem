// Package lifecycle runs the idle lifecycle of Free organizations
// (docs/architecture/idle-workspaces.md): the daily sweep that reminds,
// makes read-only, warns and marks for deletion the Free organizations
// nobody signs in to, the read-only check the API applies, and the platform
// administrator's exemption.
//
// Nothing is deleted automatically: an organization that reaches
// deletion_due is reported to the platform administrators, who delete it
// (after its owners had the chance to export) from the console.
package lifecycle

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	lifecycledom "github.com/openctemio/openctem/api/pkg/domain/lifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Alert is the WARN log key the operator alerts on for an organization that
// reached deletion_due.
const Alert = "idle_workspace_deletion_due"

// systemActor is the audit actor of the sweep.
const systemActor = "system:idle-workspaces"

const (
	readOnlyCacheTTL = 60 * time.Second
	maxReasonRunes   = 500
	actionExemption  = "organization.idle_exemption_changed"
)

// Notice is one email the sweep sends.
type Notice struct {
	Stage        lifecycledom.Stage
	Organization string
	// ReadOnlyOn and DeletionDueOn are when the next steps happen.
	ReadOnlyOn    time.Time
	DeletionDueOn time.Time
	Recipients    []string
}

// Notifier emails the owners and admins (and, for deletion_due, the
// platform administrators).
type Notifier interface {
	NotifyIdle(ctx context.Context, n Notice) error
}

// AuditLogger writes the organization's audit log.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// AdminAudit writes the platform admin audit log.
type AdminAudit interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// AdminLister lists the active platform administrators.
type AdminLister interface {
	ListActive(ctx context.Context) ([]*admin.AdminUser, error)
}

// Service runs the lifecycle.
type Service struct {
	repo       lifecycledom.Repository
	thresholds lifecycledom.Thresholds
	audit      AuditLogger
	adminAudit AdminAudit
	admins     AdminLister
	notifier   Notifier
	log        *logger.Logger
	now        func() time.Time

	mu    sync.Mutex
	cache map[shared.ID]cachedReadOnly
}

type cachedReadOnly struct {
	readOnly bool
	at       time.Time
}

// NewService creates the service; audit, adminAudit, admins and notifier may
// be nil.
func NewService(repo lifecycledom.Repository, audit AuditLogger, adminAudit AdminAudit, admins AdminLister, notifier Notifier, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{
		repo: repo, thresholds: lifecycledom.DefaultThresholds(), audit: audit, adminAudit: adminAudit,
		admins: admins, notifier: notifier, log: log.With("service", "idle-workspaces"), now: time.Now,
		cache: map[shared.ID]cachedReadOnly{},
	}
}

// SetNotifier wires the email notifier.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

var stageAction = map[lifecycledom.Stage]auditdom.Action{
	lifecycledom.StageActive:       auditdom.ActionTenantIdleReactivated,
	lifecycledom.StageReminded:     auditdom.ActionTenantIdleReminded,
	lifecycledom.StageReadOnly:     auditdom.ActionTenantIdleReadOnly,
	lifecycledom.StageFinalWarning: auditdom.ActionTenantIdleFinalWarning,
	lifecycledom.StageDeletionDue:  auditdom.ActionTenantIdleDeletionDue,
}

// Sweep moves each Free organization to the stage its idle time calls for:
// one step per sweep, each audited and announced. It returns how many
// organizations changed stage.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	now := s.now().UTC()
	list, err := s.repo.FreeWorkspaces(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, w := range list {
		current := w.Stage
		if !current.IsValid() {
			current = lifecycledom.StageActive
		}
		next := s.thresholds.Decide(w, now)
		if next == current {
			continue
		}
		if err := s.repo.SetStage(ctx, w.TenantID, next, now); err != nil {
			s.log.Error("set idle stage", "tenant_id", w.TenantID.String(), "error", err)
			continue
		}
		changed++
		s.forget(w.TenantID)
		s.auditStage(ctx, w, current, next, now)
		s.announce(ctx, w, next, now)
	}
	return changed, nil
}

func (s *Service) auditStage(ctx context.Context, w lifecycledom.Workspace, from, to lifecycledom.Stage, now time.Time) {
	if s.audit == nil {
		return
	}
	severity := auditdom.SeverityMedium
	if to == lifecycledom.StageDeletionDue {
		severity = auditdom.SeverityHigh
	}
	event := auditapp.NewSuccessEvent(stageAction[to], auditdom.ResourceTypeTenant, w.TenantID.String()).
		WithResourceName(w.Name).
		WithMessage("Idle workspace: "+string(from)+" -> "+string(to)).
		WithMetadata("from", string(from)).
		WithMetadata("to", string(to)).
		WithMetadata("idle_days", int(w.Idle(now).Hours()/24)).
		WithSeverity(severity)
	actx := auditapp.AuditContext{TenantID: w.TenantID.String(), ActorEmail: systemActor}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.log.Error("audit idle stage", "tenant_id", w.TenantID.String(), "error", err)
	}
}

func (s *Service) announce(ctx context.Context, w lifecycledom.Workspace, stage lifecycledom.Stage, now time.Time) {
	if stage == lifecycledom.StageActive {
		return
	}
	since := w.LastSignIn
	if since.IsZero() || since.Before(w.CreatedAt) {
		since = w.CreatedAt
	}
	n := Notice{
		Stage: stage, Organization: w.Name,
		ReadOnlyOn:    laterOf(since.Add(s.thresholds.ReadOnly), now),
		DeletionDueOn: laterOf(since.Add(s.thresholds.DeletionDue), now),
	}
	if stage == lifecycledom.StageDeletionDue {
		s.log.Warn("idle Free organization is due for deletion", "alert", Alert,
			"tenant_id", w.TenantID.String(), "idle_days", int(w.Idle(now).Hours()/24))
		if s.admins != nil {
			if list, err := s.admins.ListActive(ctx); err == nil {
				for _, a := range list {
					n.Recipients = append(n.Recipients, a.Email())
				}
			}
		}
	} else {
		r, err := s.repo.Recipients(ctx, w.TenantID)
		if err != nil {
			s.log.Error("idle notice recipients", "tenant_id", w.TenantID.String(), "error", err)
			return
		}
		n.Recipients = r
	}
	if s.notifier == nil || len(n.Recipients) == 0 {
		return
	}
	if err := s.notifier.NotifyIdle(ctx, n); err != nil {
		s.log.Warn("idle notice email", "tenant_id", w.TenantID.String(), "error", err)
	}
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// ReadOnly reports whether the organization refuses changes now (cached for
// a minute). Fail-open on a read error: the read-only state is a commercial
// nudge, not a security boundary, and must not take an organization down.
func (s *Service) ReadOnly(ctx context.Context, tenantID shared.ID) bool {
	now := s.now()
	s.mu.Lock()
	if c, ok := s.cache[tenantID]; ok && now.Sub(c.at) < readOnlyCacheTTL {
		s.mu.Unlock()
		return c.readOnly
	}
	s.mu.Unlock()
	ro, err := s.repo.ReadOnly(ctx, tenantID)
	if err != nil {
		s.log.Warn("idle read-only check failed; allowing the request", "tenant_id", tenantID.String(), "error", err)
		return false
	}
	s.mu.Lock()
	if len(s.cache) > 10000 {
		s.cache = map[shared.ID]cachedReadOnly{}
	}
	s.cache[tenantID] = cachedReadOnly{readOnly: ro, at: now}
	s.mu.Unlock()
	return ro
}

func (s *Service) forget(tenantID shared.ID) {
	s.mu.Lock()
	delete(s.cache, tenantID)
	s.mu.Unlock()
}

// Status returns the organization's lifecycle (console).
func (s *Service) Status(ctx context.Context, tenantID shared.ID) (*lifecycledom.Status, error) {
	return s.repo.Status(ctx, tenantID)
}

// ErrInvalidExemption is returned for an exemption without a reason (or one
// over 500 characters).
var ErrInvalidExemption = errors.New("an exemption needs a reason of up to 500 characters")

// ChangeExemption exempts an organization from the idle lifecycle (returning it
// to active), or lifts the exemption. Audited in the admin log and the
// organization's own log.
func (s *Service) ChangeExemption(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, exempt bool, reason, ip, ua string) error {
	if actor == nil {
		return errors.New("an exemption needs an administrator")
	}
	reason = strings.TrimSpace(reason)
	if exempt && (reason == "" || len([]rune(reason)) > maxReasonRunes) {
		return ErrInvalidExemption
	}
	id := actor.ID()
	now := s.now().UTC()
	if err := s.repo.SetExemption(ctx, tenantID, lifecycledom.Exemption{Exempt: exempt, Reason: reason, By: &id, At: now}); err != nil {
		return err
	}
	s.forget(tenantID)
	if s.adminAudit != nil {
		entry := admin.NewAuditLogBuilder(actor, actionExemption).
			Resource("tenant", &tenantID, "").
			Context(ip, ua).
			Request("PUT", "", map[string]any{"exempt": exempt, "reason": reason}).
			High().
			Build()
		if err := s.adminAudit.Create(ctx, entry); err != nil {
			s.log.Error("admin audit idle exemption", "error", err)
		}
	}
	if s.audit != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionTenantIdleExemptionChanged, auditdom.ResourceTypeTenant, tenantID.String()).
			WithMetadata("exempt", exempt).
			WithMetadata("reason", reason).
			WithSeverity(auditdom.SeverityMedium)
		actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: actor.Email()}
		if err := s.audit.LogEvent(ctx, actx, event); err != nil {
			s.log.Error("audit idle exemption", "error", err)
		}
	}
	return nil
}
