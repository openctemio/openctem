package supportaccess

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/supportaccess"
)

// Grant-bypass paths (RFC-063 section 11.5): older console routes that reach an
// organization's data (its users, its sign-in providers, its owner) without a
// support grant. They are not blocked. Each use is written to the
// organization's audit log before the route runs, and the organization's
// owners are emailed.

// ConsoleAccessInput describes one grant-bypass use.
type ConsoleAccessInput struct {
	TenantID shared.ID
	// Route names the path, e.g. "user list", "owner create or recovery".
	Route  string
	Method string
	// Repeatable marks a read that is refreshed and paged: the organization's
	// audit log gets every use, the owners' email at most once per
	// administrator, organization and route within ConsoleAccessEmailEvery.
	Repeatable bool
}

// ConsoleAccessEmailEvery bounds the owner emails of a repeatable read.
const ConsoleAccessEmailEvery = time.Hour

type consoleMailKey struct {
	adminID, tenantID shared.ID
	route             string
}

func (s *Service) consoleMailDue(k consoleMailKey, now time.Time) bool {
	s.consoleMu.Lock()
	defer s.consoleMu.Unlock()
	if s.consoleMail == nil {
		s.consoleMail = map[consoleMailKey]time.Time{}
	}
	if at, ok := s.consoleMail[k]; ok && now.Sub(at) < ConsoleAccessEmailEvery {
		return false
	}
	if len(s.consoleMail) > 4096 {
		for key, at := range s.consoleMail {
			if now.Sub(at) >= ConsoleAccessEmailEvery {
				delete(s.consoleMail, key)
			}
		}
	}
	s.consoleMail[k] = now
	return true
}

// NoticeConsoleAccess records a grant-bypass use in the organization's audit
// log (actor `console:<email>`) and emails the owners. A failed audit write
// returns ErrAuditUnavailable: no audit, no access, as for a support read.
func (s *Service) NoticeConsoleAccess(ctx context.Context, a *admin.AdminUser, in ConsoleAccessInput, client Client) error {
	if s.tenantAudit == nil || a == nil {
		return dom.ErrAuditUnavailable
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionAdminConsoleTenantAccess, auditdom.ResourceTypeTenant, in.TenantID.String()).
		WithMessage("Platform administrator used the console: "+in.Route+" (no support grant)").
		WithMetadata("platform_admin", a.Email()).
		WithMetadata("route", in.Route).
		WithMetadata("method", in.Method)
	if err := s.tenantAudit.LogEvent(ctx, auditapp.AuditContext{
		TenantID: in.TenantID.String(), ActorEmail: "console:" + a.Email(),
		ActorIP: client.IP, UserAgent: client.UserAgent, RequestID: client.RequestID,
	}, ev); err != nil {
		s.log.Error("console tenant access: tenant audit failed", "route", in.Route, "error", err)
		return dom.ErrAuditUnavailable
	}
	now := s.now()
	if in.Repeatable && !s.consoleMailDue(consoleMailKey{a.ID(), in.TenantID, in.Route}, now) {
		return nil
	}
	name := s.tenantName(ctx, in.TenantID)
	s.emailOwners(ctx, in.TenantID,
		fmt.Sprintf("A platform administrator used the admin console on %s", name),
		fmt.Sprintf("Platform administrator %s used the admin console for %s: %s, at %s. This path does not need a support grant; it is recorded in your organization's audit log. If you did not expect it, contact your platform operator.",
			a.Email(), name, in.Route, fmtTime(now)))
	return nil
}
