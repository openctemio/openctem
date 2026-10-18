// Package orgdeletion deletes organizations after a grace period
// (docs/architecture/organization-deletion.md).
//
// An owner's request schedules the deletion: the organization is refused to
// every credential at once (status pending_deletion, the same access gate as
// a suspension) and the purge worker deletes it when the grace period ends.
// Until then an owner can cancel and everything works again as before. A
// platform administrator can delete an organization at once from the
// console (step-up, reason, critical admin audit).
package orgdeletion

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

// ActionOrganizationPurged is the critical admin audit action of an
// immediate deletion from the console.
const ActionOrganizationPurged = "organization.purged"

// Reason length bounds for the console's immediate deletion.
const (
	MinReasonRunes = 10
	MaxReasonRunes = 500
)

var (
	// ErrNotOwner: only an active owner schedules or cancels a deletion.
	ErrNotOwner = fmt.Errorf("%w: only an owner of the organization can do this", shared.ErrForbidden)
	// ErrNotActive: a deletion is scheduled only for an active organization.
	ErrNotActive = fmt.Errorf("%w: the organization is not active (already scheduled for deletion or suspended)", shared.ErrConflict)
	// ErrNotPending: there is no scheduled deletion to cancel.
	ErrNotPending = fmt.Errorf("%w: the organization is not scheduled for deletion", shared.ErrConflict)
	// ErrSystemOrganization: the platform's system organization is never deleted.
	ErrSystemOrganization = fmt.Errorf("%w: the system organization cannot be deleted", shared.ErrConflict)
	// ErrReasonRequired: an immediate deletion needs a reason.
	ErrReasonRequired = fmt.Errorf("%w: a reason of %d to %d characters is required", shared.ErrValidation, MinReasonRunes, MaxReasonRunes)
)

// Store persists the scheduled deletion (tenants.status and deletion_*).
type Store interface {
	// IsActiveOwner reports whether userID is an active owner of tenantID.
	IsActiveOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// OrganizationName returns the name; shared.ErrNotFound when it does not exist.
	OrganizationName(ctx context.Context, tenantID shared.ID) (string, error)
	// Schedule moves an active organization to pending_deletion; false when
	// it was not active.
	Schedule(ctx context.Context, tenantID, by shared.ID, at, due time.Time) (bool, error)
	// Cancel moves a pending organization back to active; false when it was
	// not pending.
	Cancel(ctx context.Context, tenantID shared.ID) (bool, error)
	// ListDue returns up to limit organizations whose grace ended.
	ListDue(ctx context.Context, now time.Time, limit int) ([]shared.ID, error)
}

// Purger deletes an organization and everything in it
// (tenant.TenantService.DeleteTenant: stored files, rows, platform audit).
type Purger interface {
	DeleteTenant(ctx context.Context, actx auditapp.AuditContext, tenantID string) error
}

// StatusCache is the access gate's shared cache (suspension.Gate).
type StatusCache interface {
	Remember(ctx context.Context, tenantID shared.ID, status tenantdom.OrganizationStatus)
	Forget(ctx context.Context, tenantID shared.ID)
}

// SocketCloser closes an organization's live connections.
type SocketCloser interface {
	RevokeOrganization(ctx context.Context, tenantID string)
}

// AdminAudit writes the platform admin audit log.
type AdminAudit interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// TenantAudit writes the organization's own audit log.
type TenantAudit interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Client is where a console request came from (admin audit).
type Client struct {
	IP        string
	UserAgent string
}

// Service schedules, cancels and carries out organization deletions.
type Service struct {
	store      Store
	purger     Purger
	cache      StatusCache
	sockets    SocketCloser
	adminAudit AdminAudit
	audit      TenantAudit
	log        *logger.Logger
	now        func() time.Time
}

// NewService creates the service. cache, adminAudit and audit may be nil.
func NewService(store Store, purger Purger, cache StatusCache, adminAudit AdminAudit, audit TenantAudit, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: store, purger: purger, cache: cache, adminAudit: adminAudit, audit: audit,
		log: log.With("service", "organization-deletion"), now: time.Now}
}

// SetSocketCloser wires the closing of live connections when a deletion is
// scheduled.
func (s *Service) SetSocketCloser(c SocketCloser) { s.sockets = c }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

func isSystem(id shared.ID) bool { return id.String() == tenantdom.SystemTenantID }

// Schedule is an owner's deletion request: from the next request on the
// organization is refused to every credential, and it is deleted when the
// grace period ends unless an owner cancels. Returns when it will be deleted.
// The caller checked the route's owner gate and a recent sign-in; the owner
// is checked again here against the database.
func (s *Service) Schedule(ctx context.Context, actx auditapp.AuditContext, tenantID, userID shared.ID) (time.Time, error) {
	if isSystem(tenantID) {
		return time.Time{}, ErrSystemOrganization
	}
	if err := s.owner(ctx, tenantID, userID); err != nil {
		return time.Time{}, err
	}
	name, err := s.store.OrganizationName(ctx, tenantID)
	if err != nil {
		return time.Time{}, err
	}
	now := s.now().UTC()
	due := now.Add(tenantdom.DeletionGrace)
	ok, err := s.store.Schedule(ctx, tenantID, userID, now, due)
	if err != nil {
		return time.Time{}, err
	}
	if !ok {
		return time.Time{}, ErrNotActive
	}
	s.remember(ctx, tenantID, tenantdom.OrganizationPendingDeletion)
	if s.sockets != nil {
		s.sockets.RevokeOrganization(ctx, tenantID.String())
	}
	s.logEvent(ctx, actx, tenantID, auditapp.NewSuccessEvent(auditdom.ActionTenantDeletionScheduled, auditdom.ResourceTypeTenant, tenantID.String()).
		WithResourceName(name).
		WithSeverity(auditdom.SeverityCritical).
		WithMessage(fmt.Sprintf("Deletion of the organization scheduled for %s; an owner can cancel until then", due.Format(time.RFC3339))).
		WithMetadata("deletion_due_at", due.Format(time.RFC3339)))
	return due, nil
}

// Cancel lifts a scheduled deletion; everything works again as before. Any
// active owner may cancel (not only the one who asked).
func (s *Service) Cancel(ctx context.Context, actx auditapp.AuditContext, tenantID, userID shared.ID) error {
	if err := s.owner(ctx, tenantID, userID); err != nil {
		return err
	}
	name, err := s.store.OrganizationName(ctx, tenantID)
	if err != nil {
		return err
	}
	ok, err := s.store.Cancel(ctx, tenantID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotPending
	}
	s.remember(ctx, tenantID, tenantdom.OrganizationActive)
	s.logEvent(ctx, actx, tenantID, auditapp.NewSuccessEvent(auditdom.ActionTenantDeletionCancelled, auditdom.ResourceTypeTenant, tenantID.String()).
		WithResourceName(name).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage("The scheduled deletion of the organization was canceled"))
	return nil
}

// PurgeDue deletes the organizations whose grace period ended (the purge
// worker). One failure does not stop the others; it is retried next run.
func (s *Service) PurgeDue(ctx context.Context) (int64, error) {
	ids, err := s.store.ListDue(ctx, s.now().UTC(), 50)
	if err != nil {
		return 0, err
	}
	var n int64
	var errs []error
	for _, id := range ids {
		if isSystem(id) {
			continue
		}
		actx := auditapp.AuditContext{ActorEmail: "system:organization-deletion"}
		if err := s.purger.DeleteTenant(ctx, actx, id.String()); err != nil {
			s.log.Error("scheduled organization deletion failed; retried next run", "tenant_id", id.String(), "error", err)
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// PurgeNow deletes an organization at once (console: abuse, legal request),
// whatever its status. The caller checked the administrator's role and a
// fresh step-up.
func (s *Service) PurgeNow(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, reason string, c Client) error {
	if actor == nil {
		return errors.New("an administrator is required")
	}
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < MinReasonRunes || n > MaxReasonRunes {
		return ErrReasonRequired
	}
	if isSystem(tenantID) {
		return ErrSystemOrganization
	}
	name, err := s.store.OrganizationName(ctx, tenantID)
	if err != nil {
		return err
	}
	// Refuse new requests first, so nothing writes while the rows go.
	s.remember(ctx, tenantID, tenantdom.OrganizationPendingDeletion)
	if s.sockets != nil {
		s.sockets.RevokeOrganization(ctx, tenantID.String())
	}
	actx := auditapp.AuditContext{ActorEmail: "platform-admin:" + actor.Email(), ActorIP: c.IP, UserAgent: c.UserAgent}
	err = s.purger.DeleteTenant(ctx, actx, tenantID.String())
	if s.adminAudit != nil {
		b := admin.NewAuditLogBuilder(actor, ActionOrganizationPurged).
			Resource("tenant", &tenantID, name).
			Context(c.IP, c.UserAgent).
			Request("POST", "", map[string]any{"reason": reason}).
			Critical()
		if err != nil {
			b = b.Response(500).Error("the deletion failed")
		} else {
			b = b.Response(200)
		}
		if aerr := s.adminAudit.Create(ctx, b.Build()); aerr != nil {
			s.log.Error("admin audit organization purge", "tenant_id", tenantID.String(), "error", aerr)
		}
	}
	if err != nil {
		// The status cache said pending: put the real status back on the
		// next read (the rows still exist).
		s.forget(ctx, tenantID)
		return err
	}
	return nil
}

func (s *Service) owner(ctx context.Context, tenantID, userID shared.ID) error {
	ok, err := s.store.IsActiveOwner(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotOwner
	}
	return nil
}

func (s *Service) remember(ctx context.Context, tenantID shared.ID, status tenantdom.OrganizationStatus) {
	if s.cache != nil {
		s.cache.Remember(ctx, tenantID, status)
	}
}

// forget drops a cached status that may be wrong; the gate reads the store.
func (s *Service) forget(ctx context.Context, tenantID shared.ID) {
	if s.cache != nil {
		s.cache.Forget(ctx, tenantID)
	}
}

func (s *Service) logEvent(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, e auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	actx.TenantID = tenantID.String()
	if err := s.audit.LogEvent(ctx, actx, e); err != nil {
		s.log.Error("audit organization deletion", "tenant_id", tenantID.String(), "error", err)
	}
}
