// Package platformrole manages who holds which platform role (RFC-134): the
// console's own role assignments, never the tenant roles. A base role
// (owner, admin, viewer) follows the administrator's tier and is changed
// through the administrator's role (with its four-eyes rules); this service
// gives and takes the additional roles.
package platformrole

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RosterKind is the roster notice kind of a platform role change.
const RosterKind = "admin_platform_role"

// Audit actions.
const (
	ActionAssigned = "platform_role.assigned"
	ActionRevoked  = "platform_role.revoked"
)

// Errors.
var (
	ErrUnknownRole      = fmt.Errorf("%w: unknown platform role", shared.ErrValidation)
	ErrBaseRole         = fmt.Errorf("%w: the owner, admin and read-only roles follow the administrator's role; change it there", shared.ErrValidation)
	ErrSelf             = fmt.Errorf("%w: you cannot change your own platform roles", shared.ErrForbidden)
	ErrAboveOwn         = fmt.Errorf("%w: you can give or take only a role whose permissions you hold", shared.ErrForbidden)
	ErrReason           = fmt.Errorf("%w: give a reason of 10 to 500 characters", shared.ErrValidation)
	ErrInactive         = fmt.Errorf("%w: the administrator is not active", shared.ErrConflict)
	ErrAuditUnavailable = errors.New("the administrators' audit log cannot be written")
)

// Assignment is one administrator and the platform roles they hold.
type Assignment struct {
	AdminID    shared.ID
	Email      string
	Name       string
	Active     bool
	BreakGlass bool
	Roles      []platformauthz.RoleKey
}

// Store persists the assignments.
type Store interface {
	ListAssignments(ctx context.Context) ([]Assignment, error)
	// Assign gives an additional (non-base) role; giving a held role is a no-op.
	Assign(ctx context.Context, adminID shared.ID, role platformauthz.RoleKey, by shared.ID) error
	// Revoke takes an additional role; reports whether it was held.
	Revoke(ctx context.Context, adminID shared.ID, role platformauthz.RoleKey) (bool, error)
}

// Admins reads administrators.
type Admins interface {
	GetByID(ctx context.Context, id shared.ID) (*admin.AdminUser, error)
}

// RosterNotifier announces a roster change to the other administrators.
type RosterNotifier interface {
	NotifyRosterChange(ctx context.Context, actor *admin.AdminUser, kind, summary string, ip, userAgent string)
}

// Service manages platform role assignments.
type Service struct {
	store  Store
	admins Admins
	audit  admin.AuditLogRepository
	roster RosterNotifier
	log    *logger.Logger
}

// NewService creates the service.
func NewService(store Store, admins Admins, audit admin.AuditLogRepository, roster RosterNotifier, log *logger.Logger) *Service {
	return &Service{store: store, admins: admins, audit: audit, roster: roster, log: log.With("service", "platform_role")}
}

// Client is where a change came from.
type Client struct{ IP, UserAgent string }

// Owners counts the named platform owners: active, not break-glass. Below two
// the console warns (a single owner can be locked out, and four-eyes has no
// second approver).
func Owners(as []Assignment) int {
	n := 0
	for _, a := range as {
		if !a.Active || a.BreakGlass {
			continue
		}
		for _, r := range a.Roles {
			if r == platformauthz.RoleOwner {
				n++
				break
			}
		}
	}
	return n
}

// List returns every administrator's roles.
func (s *Service) List(ctx context.Context) ([]Assignment, error) {
	return s.store.ListAssignments(ctx)
}

// Assign gives target an additional role.
func (s *Service) Assign(ctx context.Context, actor *admin.AdminUser, targetID shared.ID, role platformauthz.RoleKey, reason string, c Client) error {
	target, reason, err := s.check(ctx, actor, targetID, role, reason)
	if err != nil {
		return err
	}
	if err := s.record(ctx, actor, target, ActionAssigned, role, reason, c); err != nil {
		return err
	}
	if err := s.store.Assign(ctx, target.ID(), role, actor.ID()); err != nil {
		return err
	}
	s.announce(ctx, actor, fmt.Sprintf("%s was given the platform role %s. Reason: %s", target.Email(), roleName(role), reason), c)
	return nil
}

// Revoke takes an additional role from target.
func (s *Service) Revoke(ctx context.Context, actor *admin.AdminUser, targetID shared.ID, role platformauthz.RoleKey, reason string, c Client) error {
	target, reason, err := s.check(ctx, actor, targetID, role, reason)
	if err != nil && !errors.Is(err, ErrInactive) {
		return err
	}
	if err := s.record(ctx, actor, target, ActionRevoked, role, reason, c); err != nil {
		return err
	}
	held, err := s.store.Revoke(ctx, target.ID(), role)
	if err != nil {
		return err
	}
	if held {
		s.announce(ctx, actor, fmt.Sprintf("The platform role %s was taken from %s. Reason: %s", roleName(role), target.Email(), reason), c)
	}
	return nil
}

func (s *Service) check(ctx context.Context, actor *admin.AdminUser, targetID shared.ID, role platformauthz.RoleKey, reason string) (*admin.AdminUser, string, error) {
	def, ok := platformauthz.Builtin(role)
	if !ok {
		return nil, "", ErrUnknownRole
	}
	if def.Base {
		return nil, "", ErrBaseRole
	}
	if actor == nil || actor.ID() == targetID {
		return nil, "", ErrSelf
	}
	if !platformauthz.RolePermissions(role).SubsetOf(actor.HeldPermissions()) {
		return nil, "", ErrAboveOwn
	}
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < 10 || n > 500 {
		return nil, "", ErrReason
	}
	target, err := s.admins.GetByID(ctx, targetID)
	if err != nil {
		return nil, "", err
	}
	if !target.IsActive() {
		return target, reason, ErrInactive
	}
	return target, reason, nil
}

// record writes the audit row before the change; no row, no change.
func (s *Service) record(ctx context.Context, actor, target *admin.AdminUser, action string, role platformauthz.RoleKey, reason string, c Client) error {
	if s.audit == nil {
		return nil
	}
	id := target.ID()
	entry := admin.NewAuditLogBuilder(actor, action).
		Resource("admin_user", &id, target.Email()).
		Context(c.IP, c.UserAgent).
		Request("", "", map[string]any{"role": string(role), "reason": reason, "at": time.Now().UTC().Format(time.RFC3339)}).
		High().
		Build()
	if err := s.audit.Create(ctx, entry); err != nil {
		s.log.Error("audit platform role change; change refused", "error", err)
		return ErrAuditUnavailable
	}
	return nil
}

func (s *Service) announce(ctx context.Context, actor *admin.AdminUser, summary string, c Client) {
	if s.roster != nil {
		s.roster.NotifyRosterChange(ctx, actor, RosterKind, summary, c.IP, c.UserAgent)
	}
}

func roleName(k platformauthz.RoleKey) string {
	if d, ok := platformauthz.Builtin(k); ok {
		return d.Name
	}
	return string(k)
}
