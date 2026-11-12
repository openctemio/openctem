package threatalert

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatalert"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service is the alert API: list, detail and triage, always for one
// organization and narrowed to the viewer's data scope.
type Service struct {
	store  threatalert.ReadStore
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
}

// NewService creates the alert API service. audit may be nil.
func NewService(store threatalert.ReadStore, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{store: store, audit: audit, logger: log.With("service", "threat_alerts_api"), now: time.Now}
}

// List returns a page of the alerts the viewer sees.
func (s *Service) List(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, f threatalert.ListFilter) ([]threatalert.Alert, int, threatalert.Summary, error) {
	return s.store.List(ctx, tenantID, scope, f)
}

// Get returns an alert the viewer sees (ErrNotFound otherwise).
func (s *Service) Get(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, id shared.ID) (*threatalert.Detail, error) {
	return s.store.Get(ctx, tenantID, scope, id)
}

// StateChange is a triage decision.
type StateChange struct {
	State  threatalert.State
	Reason string
	Note   string
	Actor  shared.ID
}

// ChangeState records a triage decision. The viewer must see the alert;
// "not affected" needs every asset of the alert in the viewer's scope (a
// member cannot suppress what they cannot see). Audited.
func (s *Service) ChangeState(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, id shared.ID, c StateChange, actx auditapp.AuditContext) (*threatalert.Detail, error) {
	if c.State != threatalert.StateNotAffected {
		c.Reason = ""
	}
	if err := threatalert.ValidateTransition(c.State, c.Reason, c.Note); err != nil {
		return nil, err
	}
	d, err := s.store.Get(ctx, tenantID, scope, id)
	if err != nil {
		return nil, err
	}
	if c.State == threatalert.StateNotAffected && !d.AllInScope {
		return nil, threatalert.ErrOutOfScope
	}
	now := s.now().UTC()
	var until *time.Time
	if c.State == threatalert.StateNotAffected {
		u := now.Add(threatalert.SuppressFor)
		until = &u
	}
	before := d.Alert.State
	if err := s.store.SetState(ctx, tenantID, id, c.State, c.Reason, c.Note, c.Actor, now, until); err != nil {
		return nil, err
	}
	if s.audit != nil {
		actx.TenantID = tenantID.String()
		ev := auditapp.NewSuccessEvent(audit.ActionEmergingThreatStateChanged, audit.ResourceTypeEmergingThreat, id.String()).
			WithResourceName(d.Alert.VulnID).
			WithMessage(fmt.Sprintf("Emerging threat %s: %s -> %s", d.Alert.VulnID, before, c.State)).
			WithMetadata("from", string(before)).
			WithMetadata("to", string(c.State)).
			WithMetadata("reason", c.Reason)
		if c.State == threatalert.StateNotAffected && d.Alert.InKEV {
			// Suppressing a known-exploited vulnerability is the decision
			// most worth a second look.
			ev = ev.WithSeverity(audit.SeverityHigh)
		}
		if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
			s.logger.Warn("emerging threat audit not written", "error", logger.SanitizeError(err))
		}
	}
	return s.store.Get(ctx, tenantID, scope, id)
}
