package platformuser

// Blocking an account platform-wide: docs/architecture/organization-suspension.md.
//
// A blocked account (users.status 'suspended') cannot sign in, and every
// credential it holds stops working at once: its sessions are revoked, and
// the per-request checks refuse an inactive account for session tokens, API
// keys and MCP tokens. Nothing it made is removed; unblocking restores
// sign-in (sessions stay ended).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions (critical: they cut or restore an account's access
// everywhere).
const (
	ActionUserBlocked   = "platform_user.blocked"
	ActionUserUnblocked = "platform_user.unblocked"
)

// Reason length bounds (as for the other support actions).
const (
	MinBlockReasonRunes = 10
	MaxBlockReasonRunes = 500
)

var (
	// ErrBlockReasonRequired: a block or unblock needs a reason.
	ErrBlockReasonRequired = fmt.Errorf("%w: a reason of %d to %d characters is required", shared.ErrValidation, MinBlockReasonRunes, MaxBlockReasonRunes)
	// ErrAlreadyBlocked: the account is already blocked (or not active).
	ErrAlreadyBlocked = fmt.Errorf("%w: the account is already blocked or not active", shared.ErrConflict)
	// ErrNotBlocked: the account is not blocked.
	ErrNotBlocked = fmt.Errorf("%w: the account is not blocked", shared.ErrConflict)
)

// Blocker stores the block (PlatformUserDirectory.SetBlocked).
type Blocker interface {
	SetBlocked(ctx context.Context, id shared.ID, blocked bool, by *shared.ID, reason string) (bool, error)
}

// AdminAudit writes the platform admin audit log.
type AdminAudit interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// Client is where a console request came from (admin audit).
type Client struct {
	IP        string
	UserAgent string
}

// SetBlocking wires block / unblock. Without a blocker both are refused.
func (s *Service) SetBlocking(b Blocker, audit AdminAudit, log *logger.Logger) {
	s.blocker, s.adminAudit = b, audit
	if log == nil {
		log = logger.NewNop()
	}
	s.log = log.With("service", "platform-user")
}

// Block blocks the account everywhere and ends every session it has. The
// caller checked the administrator's role and a fresh step-up.
func (s *Service) Block(ctx context.Context, actor *admin.AdminUser, id shared.ID, reason string, c Client) error {
	return s.setBlocked(ctx, actor, id, reason, c, true)
}

// Unblock lifts a block; the account may sign in again.
func (s *Service) Unblock(ctx context.Context, actor *admin.AdminUser, id shared.ID, reason string, c Client) error {
	return s.setBlocked(ctx, actor, id, reason, c, false)
}

func (s *Service) setBlocked(ctx context.Context, actor *admin.AdminUser, id shared.ID, reason string, c Client, block bool) error {
	if actor == nil {
		return errors.New("an administrator is required")
	}
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < MinBlockReasonRunes || n > MaxBlockReasonRunes {
		return ErrBlockReasonRequired
	}
	if s.blocker == nil {
		return errors.New("account blocking is not configured")
	}
	u, err := s.target(ctx, id)
	if err != nil {
		return err
	}
	by := actor.ID()
	changed, err := s.blocker.SetBlocked(ctx, id, block, &by, reason)
	if err != nil {
		return err
	}
	if !changed {
		if block {
			return ErrAlreadyBlocked
		}
		return ErrNotBlocked
	}
	if block && s.sessions != nil {
		// The per-request account check already refuses every token; ending
		// the sessions also drops refresh tokens and permission caches.
		if err := s.sessions.RevokeAllSessions(ctx, id.String(), ""); err != nil {
			s.log.Error("revoke sessions of a blocked account", "user_id", id.String(), "error", err)
		}
	}
	s.auditBlock(ctx, actor, id, u.Email(), reason, c, block)
	return nil
}

func (s *Service) auditBlock(ctx context.Context, actor *admin.AdminUser, id shared.ID, email, reason string, c Client, block bool) {
	if s.adminAudit == nil {
		return
	}
	action := ActionUserUnblocked
	if block {
		action = ActionUserBlocked
	}
	entry := admin.NewAuditLogBuilder(actor, action).
		Resource("user", &id, email).
		Context(c.IP, c.UserAgent).
		Request("POST", "", map[string]any{"reason": reason}).
		Response(200).
		Critical().
		Build()
	if err := s.adminAudit.Create(ctx, entry); err != nil {
		s.log.Error("admin audit account block", "user_id", id.String(), "error", err)
	}
}
