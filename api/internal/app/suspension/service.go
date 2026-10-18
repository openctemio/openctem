package suspension

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions (critical: they cut or restore access for a whole
// organization).
const (
	ActionOrganizationSuspended   = "organization.suspended"
	ActionOrganizationUnsuspended = "organization.unsuspended"
)

// Reason length bounds (the console asks for the same).
const (
	MinReasonRunes = 10
	MaxReasonRunes = 500
)

var (
	// ErrReasonRequired: a suspension or its lifting needs a reason.
	ErrReasonRequired = fmt.Errorf("%w: a reason of %d to %d characters is required", shared.ErrValidation, MinReasonRunes, MaxReasonRunes)
	// ErrAlreadySuspended: the organization is already suspended.
	ErrAlreadySuspended = fmt.Errorf("%w: the organization is already suspended", shared.ErrConflict)
	// ErrNotSuspended: the organization is not suspended.
	ErrNotSuspended = fmt.Errorf("%w: the organization is not suspended", shared.ErrConflict)
	// ErrSystemOrganization: the platform's own system organization cannot be
	// suspended.
	ErrSystemOrganization = fmt.Errorf("%w: the system organization cannot be suspended", shared.ErrConflict)
)

// Store persists the suspension (tenants.status and the suspended_* columns).
type Store interface {
	StatusReader
	// Suspension returns the organization's status, who set it and why, and
	// its name; shared.ErrNotFound when it does not exist.
	Suspension(ctx context.Context, tenantID shared.ID) (*tenantdom.Suspension, string, error)
	// Suspend sets the status to suspended; false when it already was.
	Suspend(ctx context.Context, tenantID shared.ID, by *shared.ID, reason string, at time.Time) (bool, error)
	// Unsuspend sets the status back to active and clears the suspended_*
	// columns; false when it was not suspended.
	Unsuspend(ctx context.Context, tenantID shared.ID) (bool, error)
}

// AdminAudit writes the platform admin audit log.
type AdminAudit interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// TenantAudit writes the organization's own audit log, so its owners see the
// suspension in their history.
type TenantAudit interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// SocketCloser closes every live connection of an organization, on every
// API instance (websocket.Hub.RevokeOrganization).
type SocketCloser interface {
	RevokeOrganization(ctx context.Context, tenantID string)
}

// Client is where a console request came from (admin audit).
type Client struct {
	IP        string
	UserAgent string
}

// Service suspends and restores organizations.
type Service struct {
	store       Store
	gate        *Gate
	adminAudit  AdminAudit
	tenantAudit TenantAudit
	sockets     SocketCloser
	log         *logger.Logger
	now         func() time.Time
}

// NewService creates the service. adminAudit and tenantAudit may be nil.
func NewService(store Store, gate *Gate, adminAudit AdminAudit, tenantAudit TenantAudit, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: store, gate: gate, adminAudit: adminAudit, tenantAudit: tenantAudit,
		log: log.With("service", "organization-suspension"), now: time.Now}
}

// SetSocketCloser wires the closing of live connections on suspension.
func (s *Service) SetSocketCloser(c SocketCloser) { s.sockets = c }

func cleanReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < MinReasonRunes || n > MaxReasonRunes {
		return "", ErrReasonRequired
	}
	return reason, nil
}

// Suspend suspends an organization: from the next request on, no credential
// reaches it and its scheduled work stops. Nothing is deleted. The caller
// checked the administrator's role and a fresh step-up.
func (s *Service) Suspend(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, reason string, c Client) error {
	return s.change(ctx, actor, tenantID, reason, c, true)
}

// Unsuspend lifts a suspension; every credential works again as it did.
func (s *Service) Unsuspend(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, reason string, c Client) error {
	return s.change(ctx, actor, tenantID, reason, c, false)
}

func (s *Service) change(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, reason string, c Client, suspend bool) error {
	if actor == nil {
		return errors.New("an administrator is required")
	}
	reason, err := cleanReason(reason)
	if err != nil {
		return err
	}
	if tenantID.String() == tenantdom.SystemTenantID {
		return ErrSystemOrganization
	}
	_, name, err := s.store.Suspension(ctx, tenantID)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	var changed bool
	if suspend {
		by := actor.ID()
		changed, err = s.store.Suspend(ctx, tenantID, &by, reason, now)
	} else {
		changed, err = s.store.Unsuspend(ctx, tenantID)
	}
	if err != nil {
		return err
	}
	if !changed {
		if suspend {
			return ErrAlreadySuspended
		}
		return ErrNotSuspended
	}
	status := tenantdom.OrganizationActive
	if suspend {
		status = tenantdom.OrganizationSuspended
	}
	// Every replica sees the change on its next request, and open
	// real-time connections end now (a reconnect meets the gate).
	s.gate.Remember(ctx, tenantID, status)
	if suspend && s.sockets != nil {
		s.sockets.RevokeOrganization(ctx, tenantID.String())
	}

	s.audit(ctx, actor, tenantID, name, reason, c, suspend)
	return nil
}

func (s *Service) audit(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, name, reason string, c Client, suspend bool) {
	action, tenantAction, verb := ActionOrganizationUnsuspended, auditdom.ActionTenantUnsuspended, "lifted the suspension of"
	if suspend {
		action, tenantAction, verb = ActionOrganizationSuspended, auditdom.ActionTenantSuspended, "suspended"
	}
	if s.adminAudit != nil {
		entry := admin.NewAuditLogBuilder(actor, action).
			Resource("tenant", &tenantID, name).
			Context(c.IP, c.UserAgent).
			Request("POST", "", map[string]any{"reason": reason}).
			Response(200).
			Critical().
			Build()
		if err := s.adminAudit.Create(ctx, entry); err != nil {
			s.log.Error("admin audit organization suspension", "tenant_id", tenantID.String(), "error", err)
		}
	}
	if s.tenantAudit != nil {
		// The organization's log names the platform, not the person, and
		// carries no reason: the reason is for platform administrators.
		event := auditapp.NewSuccessEvent(tenantAction, auditdom.ResourceTypeTenant, tenantID.String()).
			WithResourceName(name).
			WithMessage("A platform administrator " + verb + " this organization").
			WithSeverity(auditdom.SeverityCritical)
		actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "platform-admin"}
		if err := s.tenantAudit.LogEvent(ctx, actx, event); err != nil {
			s.log.Error("audit organization suspension", "tenant_id", tenantID.String(), "error", err)
		}
	}
}
