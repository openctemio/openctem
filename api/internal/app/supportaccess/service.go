// Package supportaccess runs support access: an organization owner grants a
// named platform administrator time-boxed, read-only access for a reason;
// the administrator opens support sessions inside the grant from the console;
// every access is written to both the organization's audit log and the admin
// audit log, and owners are emailed.
//
// Design: docs/rfcs/RFC-063-support-access.md.
package supportaccess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	dom "github.com/openctemio/openctem/api/pkg/domain/supportaccess"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions.
const (
	AdminActionSessionStarted = "support.session_started"
	AdminActionSessionEnded   = "support.session_ended"
	AdminActionAccessed       = "support.accessed"
	AdminActionRefused        = "support.refused"
)

// TenantAuditor writes the organization's audit log.
type TenantAuditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Owners lists an organization's active owners (for the emails).
type Owners interface {
	ListActiveOwners(ctx context.Context, tenantID shared.ID) ([]ssochange.OwnerContact, error)
}

// TenantNames resolves an organization's display name.
type TenantNames interface {
	TenantName(ctx context.Context, tenantID shared.ID) (string, error)
}

// Mailer sends the owners' notices (asynchronously; failures are logged).
type Mailer interface {
	NotifySupportAccess(ctx context.Context, email, name, subject, message string)
}

// Admins finds the administrator a grant names.
type Admins interface {
	GetByEmail(ctx context.Context, email string) (*admin.AdminUser, error)
}

// Client is who asked, for the audit rows.
type Client struct {
	IP        string
	UserAgent string
	RequestID string
}

// Service implements support access.
type Service struct {
	repo        dom.Repository
	reads       dom.ReadRepository
	admins      Admins
	tenantAudit TenantAuditor
	adminAudit  admin.AuditLogRepository
	owners      Owners
	tenants     TenantNames
	mailer      Mailer
	now         func() time.Time
	log         *logger.Logger

	// Owner-email throttle of repeatable grant-bypass reads (console_access.go).
	consoleMu   sync.Mutex
	consoleMail map[consoleMailKey]time.Time
}

// NewService wires the service. mailer may be nil (no emails).
func NewService(repo dom.Repository, reads dom.ReadRepository, admins Admins, tenantAudit TenantAuditor,
	adminAudit admin.AuditLogRepository, owners Owners, tenants TenantNames, mailer Mailer, log *logger.Logger) *Service {
	return &Service{
		repo: repo, reads: reads, admins: admins, tenantAudit: tenantAudit, adminAudit: adminAudit,
		owners: owners, tenants: tenants, mailer: mailer, now: time.Now, log: log.With("service", "support_access"),
	}
}

// supportActor is how the organization's audit log names a support
// administrator: never a users row, so actor_id stays empty.
func supportActor(email string) string { return "support:" + email }

// canSupport reports whether an administrator may be named in, and use, a grant.
func canSupport(a *admin.AdminUser) bool {
	return a != nil && a.IsActive() && !a.IsLocked() &&
		(a.Role() == admin.AdminRoleSuperAdmin || a.Role() == admin.AdminRoleOpsAdmin)
}

// ---------------------------------------------------------------------------
// Organization side
// ---------------------------------------------------------------------------

// CreateGrantInput is an owner's grant.
type CreateGrantInput struct {
	TenantID       shared.ID
	GrantedBy      shared.ID
	GrantedByEmail string
	AdminEmail     string
	Scopes         []string
	DurationHours  int
	Reason         string
	CaseRef        string
}

// CreateGrant stores an owner's grant (the route checked owner and step-up).
func (s *Service) CreateGrant(ctx context.Context, in CreateGrantInput, client Client) (*dom.Grant, error) {
	scopes, err := dom.NormalizeScopes(in.Scopes)
	if err != nil {
		return nil, err
	}
	reason, err := dom.NormalizeReason(in.Reason)
	if err != nil {
		return nil, err
	}
	caseRef, err := dom.NormalizeCaseRef(in.CaseRef)
	if err != nil {
		return nil, err
	}
	duration := dom.DefaultDuration
	if in.DurationHours != 0 {
		duration = time.Duration(in.DurationHours) * time.Hour
	}
	if duration < dom.MinDuration || duration > dom.MaxDuration {
		return nil, dom.ErrInvalidDuration
	}
	// The route checked the owner role in the token; the grant re-checks it
	// in the database, so an owner demoted a minute ago cannot grant.
	if !s.isActiveOwner(ctx, in.TenantID, in.GrantedBy) {
		return nil, dom.ErrNotOwner
	}
	email := strings.ToLower(strings.TrimSpace(in.AdminEmail))
	if email == "" || len(email) > 254 {
		return nil, dom.ErrNotSupportAdmin
	}
	a, err := s.admins.GetByEmail(ctx, email)
	if err != nil {
		if admin.IsAdminNotFound(err) {
			return nil, dom.ErrNotSupportAdmin
		}
		return nil, fmt.Errorf("find support administrator: %w", err)
	}
	if !canSupport(a) {
		return nil, dom.ErrNotSupportAdmin
	}
	now := s.now()
	active, err := s.repo.ListActiveGrants(ctx, in.TenantID, now)
	if err != nil {
		return nil, err
	}
	for _, g := range active {
		if g.AdminID == a.ID() {
			return nil, dom.ErrTooManyActiveGrant
		}
	}
	g := &dom.Grant{
		ID: shared.NewID(), TenantID: in.TenantID, AdminID: a.ID(), AdminEmail: a.Email(), AdminName: a.Name(),
		Level: dom.LevelRead, Scopes: scopes, Reason: reason, CaseRef: caseRef, GrantedBy: in.GrantedBy,
		StartsAt: now, ExpiresAt: now.Add(duration), CreatedAt: now,
	}
	if err := s.repo.CreateGrant(ctx, g); err != nil {
		return nil, err
	}
	_ = s.tenantEvent(ctx, g.TenantID, in.GrantedBy.String(), in.GrantedByEmail, client,
		auditdom.ActionSupportGrantCreated, g, "Support access granted to "+g.AdminEmail, nil)
	s.emailOwners(ctx, g.TenantID, "Support access was granted for your organization",
		fmt.Sprintf("%s granted platform support (%s) read-only access to %s until %s. Reason: %s%s. "+
			"Every access is recorded in the audit log. Revoke it at any time under Settings > Access > Support access.",
			in.GrantedByEmail, g.AdminEmail, strings.Join(g.Scopes, " and "), fmtTime(g.ExpiresAt), g.Reason, caseSuffix(g.CaseRef)))
	return g, nil
}

// ListGrants returns the organization's grants (newest first, history included).
func (s *Service) ListGrants(ctx context.Context, tenantID shared.ID) ([]*dom.Grant, error) {
	return s.repo.ListGrants(ctx, tenantID, 50)
}

// ActiveGrants returns the organization's grants usable now (the banner).
func (s *Service) ActiveGrants(ctx context.Context, tenantID shared.ID) ([]*dom.Grant, error) {
	return s.repo.ListActiveGrants(ctx, tenantID, s.now())
}

// RevokeGrant ends a grant and its open sessions at once.
func (s *Service) RevokeGrant(ctx context.Context, tenantID, id, by shared.ID, byEmail string, client Client) (*dom.Grant, error) {
	g, err := s.repo.RevokeGrant(ctx, tenantID, id, by, s.now())
	if err != nil {
		return nil, err
	}
	_ = s.tenantEvent(ctx, tenantID, by.String(), byEmail, client, auditdom.ActionSupportGrantRevoked, g,
		"Support access of "+g.AdminEmail+" revoked", nil)
	s.emailOwners(ctx, tenantID, "Support access was revoked",
		fmt.Sprintf("%s revoked the read-only support access of %s. Any open support session ended at once.", byEmail, g.AdminEmail))
	return g, nil
}

// ---------------------------------------------------------------------------
// Console side
// ---------------------------------------------------------------------------

// GrantsForAdmin returns the grants naming the administrator that are usable now.
func (s *Service) GrantsForAdmin(ctx context.Context, a *admin.AdminUser) ([]*dom.Grant, error) {
	if !canSupport(a) {
		return []*dom.Grant{}, nil
	}
	return s.repo.ListGrantsForAdmin(ctx, a.ID(), s.now())
}

// StartSession opens a support session inside a grant that names the
// administrator (the route took the console step-up). The session is bound
// to the console session that opened it.
func (s *Service) StartSession(ctx context.Context, a *admin.AdminUser, consoleSessionID, grantID shared.ID, reason string, client Client) (*dom.Session, *dom.Grant, error) {
	if !canSupport(a) || consoleSessionID.IsZero() {
		_ = s.adminEvent(ctx, a, AdminActionRefused, nil, "", client, http.MethodPost, "start support session", "not a support administrator")
		return nil, nil, dom.ErrGrantRequired
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > dom.MaxReasonLength {
		return nil, nil, fmt.Errorf("%w: the reason is at most %d characters", shared.ErrValidation, dom.MaxReasonLength)
	}
	now := s.now()
	g, err := s.repo.GetGrantForAdmin(ctx, a.ID(), grantID, now)
	if err != nil {
		if errors.Is(err, dom.ErrGrantNotFound) {
			_ = s.adminEvent(ctx, a, AdminActionRefused, nil, "", client, http.MethodPost, "start support session", "no active grant")
			return nil, nil, dom.ErrGrantRequired
		}
		return nil, nil, err
	}
	sess := &dom.Session{
		ID: shared.NewID(), TenantID: g.TenantID, GrantID: g.ID, AdminID: a.ID(),
		ConsoleSessionID: consoleSessionID, Reason: reason, StartedAt: now,
	}
	if err := s.repo.CreateSession(ctx, sess); err != nil {
		return nil, nil, err
	}
	name := s.tenantName(ctx, g.TenantID)
	tenantErr := s.tenantEvent(ctx, g.TenantID, "", supportActor(a.Email()), client, auditdom.ActionSupportSessionStarted, g,
		"Support session started by "+a.Email(), map[string]any{"support_session_id": sess.ID.String(), "session_reason": reason})
	adminErr := s.adminEvent(ctx, a, AdminActionSessionStarted, &g.TenantID, name, client, http.MethodPost, "start support session", "")
	if tenantErr != nil || adminErr != nil {
		// No audit, no access.
		_, _ = s.repo.EndSessionForPlatform(ctx, sess.ID, a.ID(), "audit_unavailable", now)
		return nil, nil, dom.ErrAuditUnavailable
	}
	s.emailOwners(ctx, g.TenantID, "Platform support opened a session in your organization",
		fmt.Sprintf("%s opened a read-only support session in %s under the access granted until %s%s. "+
			"Every page they open is recorded in the audit log. Revoke the access under Settings > Access > Support access to end it at once.",
			a.Email(), name, fmtTime(g.ExpiresAt), caseSuffix(g.CaseRef)))
	return sess, g, nil
}

// EndSession ends one of the administrator's open support sessions.
func (s *Service) EndSession(ctx context.Context, a *admin.AdminUser, sessionID shared.ID, client Client) error {
	if a == nil {
		return dom.ErrNoLiveSession
	}
	sess, err := s.repo.EndSessionForPlatform(ctx, sessionID, a.ID(), "ended_by_admin", s.now())
	if err != nil {
		return err
	}
	g, gerr := s.repo.GetGrant(ctx, sess.TenantID, sess.GrantID)
	if gerr != nil {
		g = &dom.Grant{ID: sess.GrantID, TenantID: sess.TenantID, AdminEmail: a.Email()}
	}
	name := s.tenantName(ctx, sess.TenantID)
	_ = s.tenantEvent(ctx, sess.TenantID, "", supportActor(a.Email()), client, auditdom.ActionSupportSessionEnded, g,
		"Support session ended by "+a.Email(), map[string]any{"support_session_id": sess.ID.String()})
	_ = s.adminEvent(ctx, a, AdminActionSessionEnded, &sess.TenantID, name, client, http.MethodDelete, "end support session", "")
	s.emailOwners(ctx, sess.TenantID, "Platform support ended its session",
		fmt.Sprintf("%s ended the read-only support session in %s.", a.Email(), name))
	return nil
}

// AccessInput is one support read.
type AccessInput struct {
	SessionID        shared.ID
	ConsoleSessionID shared.ID
	// Scope is the data area read; "" for the overview (any grant).
	Scope      string
	Method     string
	Route      string
	ResourceID string
}

// Access authorizes one read and records it in both audit logs before any
// data is returned. The session is resolved live (no cache), so a revoked or
// expired grant, an ended session, or another console session fails at once.
func (s *Service) Access(ctx context.Context, a *admin.AdminUser, in AccessInput, client Client) (*dom.LiveSession, error) {
	if !canSupport(a) || in.ConsoleSessionID.IsZero() {
		_ = s.adminEvent(ctx, a, AdminActionRefused, nil, "", client, in.Method, in.Route, "not a support administrator")
		return nil, dom.ErrNoLiveSession
	}
	ls, err := s.repo.LiveSession(ctx, in.SessionID, a.ID(), in.ConsoleSessionID, s.now())
	if err != nil {
		if errors.Is(err, dom.ErrNoLiveSession) {
			_ = s.adminEvent(ctx, a, AdminActionRefused, nil, "", client, in.Method, in.Route, "no live support session")
		}
		return nil, err
	}
	if in.Scope != "" && !ls.Grant.HasScope(in.Scope) {
		_ = s.adminEvent(ctx, a, AdminActionRefused, &ls.Grant.TenantID, ls.TenantName, client, in.Method, in.Route, "scope not granted: "+in.Scope)
		return nil, dom.ErrScopeNotGranted
	}
	meta := map[string]any{
		"support_session_id": ls.Session.ID.String(), "method": in.Method, "route": in.Route,
	}
	if in.ResourceID != "" {
		meta["resource_id"] = in.ResourceID
	}
	tenantErr := s.tenantEvent(ctx, ls.Grant.TenantID, "", supportActor(a.Email()), client, auditdom.ActionSupportAccessed, &ls.Grant,
		"Support read "+in.Route, meta)
	adminErr := s.adminEvent(ctx, a, AdminActionAccessed, &ls.Grant.TenantID, ls.TenantName, client, in.Method, in.Route, "")
	if tenantErr != nil || adminErr != nil {
		return nil, dom.ErrAuditUnavailable
	}
	return ls, nil
}

// Overview returns the organization at a glance.
func (s *Service) Overview(ctx context.Context, ls *dom.LiveSession) (*dom.Overview, error) {
	return s.reads.Overview(ctx, ls.Grant.TenantID, dom.ReadScopeOf(&ls.Grant))
}

// ListFindings pages the organization's findings (grant scope "findings").
func (s *Service) ListFindings(ctx context.Context, ls *dom.LiveSession, q dom.ListQuery) ([]dom.FindingView, int64, error) {
	q.WithAssets = ls.Grant.HasScope(dom.ScopeAssets)
	return s.reads.ListFindings(ctx, ls.Grant.TenantID, q)
}

// GetFinding returns one finding of the organization.
func (s *Service) GetFinding(ctx context.Context, ls *dom.LiveSession, id shared.ID) (*dom.FindingView, error) {
	return s.reads.GetFinding(ctx, ls.Grant.TenantID, id, ls.Grant.HasScope(dom.ScopeAssets))
}

// ListAssets pages the organization's assets (grant scope "assets").
func (s *Service) ListAssets(ctx context.Context, ls *dom.LiveSession, q dom.ListQuery) ([]dom.AssetView, int64, error) {
	return s.reads.ListAssets(ctx, ls.Grant.TenantID, q)
}

// GetAsset returns one asset of the organization.
func (s *Service) GetAsset(ctx context.Context, ls *dom.LiveSession, id shared.ID) (*dom.AssetView, error) {
	return s.reads.GetAsset(ctx, ls.Grant.TenantID, id)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (s *Service) tenantEvent(ctx context.Context, tenantID shared.ID, actorID, actorEmail string, client Client,
	action auditdom.Action, g *dom.Grant, message string, extra map[string]any) error {
	if s.tenantAudit == nil {
		return dom.ErrAuditUnavailable
	}
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeSupportGrant, g.ID.String()).
		WithResourceName(g.AdminEmail).WithMessage(message).
		WithMetadata("support_admin", g.AdminEmail).
		WithMetadata("scopes", strings.Join(g.Scopes, ",")).
		WithMetadata("expires_at", g.ExpiresAt.UTC().Format(time.RFC3339))
	if g.CaseRef != "" {
		ev = ev.WithMetadata("case_ref", g.CaseRef)
	}
	for k, v := range extra {
		ev = ev.WithMetadata(k, v)
	}
	err := s.tenantAudit.LogEvent(ctx, auditapp.AuditContext{
		TenantID: tenantID.String(), ActorID: actorID, ActorEmail: actorEmail,
		ActorIP: client.IP, UserAgent: client.UserAgent, RequestID: client.RequestID,
	}, ev)
	if err != nil {
		s.log.Error("support access: tenant audit failed", "action", string(action), "error", err)
	}
	return err
}

func (s *Service) adminEvent(ctx context.Context, a *admin.AdminUser, action string, tenantID *shared.ID, tenantName string,
	client Client, method, route, refusal string) error {
	if s.adminAudit == nil || a == nil {
		return dom.ErrAuditUnavailable
	}
	b := admin.NewAuditLogBuilder(a, action).Context(client.IP, client.UserAgent).Request(method, route, nil)
	if tenantID != nil {
		b = b.Resource("tenant", tenantID, tenantName)
	}
	if refusal != "" {
		b = b.Error(refusal)
	} else if action != AdminActionAccessed {
		b = b.High()
	}
	if err := s.adminAudit.Create(ctx, b.Build()); err != nil {
		s.log.Error("support access: admin audit failed", "action", action, "error", err)
		return err
	}
	return nil
}

func (s *Service) isActiveOwner(ctx context.Context, tenantID, userID shared.ID) bool {
	if s.owners == nil {
		return false
	}
	owners, err := s.owners.ListActiveOwners(ctx, tenantID)
	if err != nil {
		s.log.Error("support access: list owners", "tenant_id", tenantID.String(), "error", err)
		return false
	}
	for _, o := range owners {
		if o.UserID == userID {
			return true
		}
	}
	return false
}

func (s *Service) tenantName(ctx context.Context, tenantID shared.ID) string {
	if s.tenants != nil {
		if n, err := s.tenants.TenantName(ctx, tenantID); err == nil && n != "" {
			return n
		}
	}
	return "your organization"
}

func (s *Service) emailOwners(ctx context.Context, tenantID shared.ID, subject, message string) {
	if s.mailer == nil || s.owners == nil {
		return
	}
	owners, err := s.owners.ListActiveOwners(ctx, tenantID)
	if err != nil {
		s.log.Error("support access: list owners", "tenant_id", tenantID.String(), "error", err)
		return
	}
	for _, o := range owners {
		if o.Email != "" {
			s.mailer.NotifySupportAccess(ctx, o.Email, o.Name, subject, message)
		}
	}
}

func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 MST") }

func caseSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return " (case " + ref + ")"
}
