// Package scopenames serves the platform's "Blocked target names" policy: the
// government and military rule of the scope guardrails as a console switch,
// the operator's own blocked names, and per-organization exceptions
// (docs/rfcs/RFC-154-blocked-target-names.md).
//
// Threat model: an exception lets one organization add a government or
// military name to its scope; turning the rule off lets every organization.
// Only a platform owner (platform.settings.scope_guardrails) changes either,
// with a fresh console authenticator code (route) and a reason; on a hosted
// service (MANAGED_SERVICE) the handler also asks for a second owner's
// approval. Every change writes a critical admin audit row with the values
// before and after, and every administrator is e-mailed. No tenant route
// reads or writes any of it. The guardrails read the policy through one
// shared scopedom.NamePolicy that this service refreshes after each change
// and, on other replicas, when it is older than RefreshTTL; an unreadable
// policy keeps the last one read (at start: the rule on, no exceptions).
package scopenames

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SettingKey is the platform_settings key of the policy.
const SettingKey = "scope_blocked_names"

// Admin audit actions (all critical).
const (
	ActionPolicyChanged     = "platform.scope_blocked_names_changed"
	ActionExceptionGranted  = "platform.scope_name_exception_granted"
	ActionExceptionExtended = "platform.scope_name_exception_extended"
	ActionExceptionRevoked  = "platform.scope_name_exception_revoked"
)

// titleException names an exception change in the administrators' notice.
const titleException = "Scope name exception"

// Bounds.
const (
	DefaultMaxExceptionDays = 365
	MaxMaxExceptionDays     = 1095
	MaxNames                = 200
	MaxRefRunes             = 500
	// RefreshTTL bounds how long another replica serves a policy it read.
	RefreshTTL = 15 * time.Second
)

// Exception states.
const (
	StateActive  = "active"
	StateExpired = "expired"
	StateRevoked = "revoked"
)

// Errors (each with a code the console shows).
var (
	ErrNotFound      = shared.NewDomainError("EXCEPTION_NOT_FOUND", "exception not found", shared.ErrNotFound)
	ErrDuplicate     = shared.NewDomainError("EXCEPTION_EXISTS", "this organization already has a live exception for this name; extend it instead", shared.ErrConflict)
	ErrRevoked       = shared.NewDomainError("EXCEPTION_REVOKED", "the exception is revoked; grant a new one", shared.ErrConflict)
	ErrExpiry        = shared.NewDomainError("EXCEPTION_EXPIRY", "the expiry must be in the future and within the platform's longest exception", shared.ErrValidation)
	ErrReference     = shared.NewDomainError("AUTHORIZATION_REF_REQUIRED", "a reference to the written authorisation is required (1-500 characters, one line)", shared.ErrValidation)
	ErrUnknownTenant = shared.NewDomainError("ORGANIZATION_NOT_FOUND", "organization not found", shared.ErrValidation)
	ErrNames         = shared.NewDomainError("BLOCKED_NAMES_INVALID", "blocked names are domain names such as internal.example.com (at most 200)", shared.ErrValidation)
	ErrMaxDays       = shared.NewDomainError("MAX_EXCEPTION_DAYS", "the longest exception is 1 to 1095 days", shared.ErrValidation)
)

// Settings is the stored policy.
type Settings struct {
	// GovernmentRule: nil (never stored) is on.
	GovernmentRule   *bool    `json:"government_rule,omitempty"`
	Names            []string `json:"names,omitempty"`
	MaxExceptionDays int      `json:"max_exception_days,omitempty"`
}

// RuleOn reports whether the built-in rule is on.
func (s Settings) RuleOn() bool { return s.GovernmentRule == nil || *s.GovernmentRule }

// MaxDays is the longest exception in days.
func (s Settings) MaxDays() int {
	if s.MaxExceptionDays <= 0 {
		return DefaultMaxExceptionDays
	}
	return s.MaxExceptionDays
}

// Exception is one stored exception.
type Exception struct {
	ID               shared.ID
	TenantID         shared.ID
	TenantName       string
	Name             string
	Subdomains       bool
	Reason           string
	AuthorizationRef string
	GrantedBy        *shared.ID
	GrantedByEmail   string
	GrantedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevokedByEmail   string
	RevokeReason     string
	UpdatedAt        time.Time
}

// State is active, expired or revoked at now.
func (e Exception) State(now time.Time) string {
	switch {
	case e.RevokedAt != nil:
		return StateRevoked
	case !now.Before(e.ExpiresAt):
		return StateExpired
	}
	return StateActive
}

// Repository stores the exceptions (scope_name_exceptions).
type Repository interface {
	// List returns every exception, newest first, with the organization's
	// name (at most 1000).
	List(ctx context.Context) ([]Exception, error)
	// ListLive returns the exceptions not revoked and not expired at now.
	ListLive(ctx context.Context, now time.Time) ([]scopedom.NameException, error)
	Get(ctx context.Context, id shared.ID) (Exception, error)
	// Create stores e; a live exception for the same organization and name
	// is ErrDuplicate.
	Create(ctx context.Context, e Exception) error
	// Extend sets the expiry of the organization's exception that is not
	// revoked (the tenant predicate guards against a mismatched id).
	Extend(ctx context.Context, tenantID, id shared.ID, expiresAt, at time.Time) error
	// Revoke revokes the organization's exception that is not revoked.
	Revoke(ctx context.Context, tenantID, id shared.ID, byEmail, reason string, at time.Time) error
}

// TenantNamer names an organization (ErrNotFound-like error when none).
type TenantNamer interface {
	TenantName(ctx context.Context, id shared.ID) (string, error)
}

// Request is the request that made a change (audit).
type Request struct {
	IP, UserAgent, Method, Path string
}

// Service reads and changes the policy.
type Service struct {
	store    *consolesetting.Store[Settings]
	repo     Repository
	tenants  TenantNamer
	recorder *consolesetting.Recorder
	policy   *scopedom.NamePolicy
	envNames []string
	managed  bool
	now      func() time.Time
	log      *logger.Logger
}

// NewService creates the service. envNames are SCOPE_DENY_EXTRA's names
// (shown read-only); managed is MANAGED_SERVICE.
func NewService(settings platformsetting.Repository, repo Repository, tenants TenantNamer, recorder *consolesetting.Recorder,
	policy *scopedom.NamePolicy, envNames []string, managed bool, log *logger.Logger,
) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: consolesetting.NewStore[Settings](settings, SettingKey), repo: repo, tenants: tenants,
		recorder: recorder, policy: policy, envNames: envNames, managed: managed, now: time.Now,
		log: log.With("service", "scope_blocked_names")}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) {
	s.now = now
	s.store.SetClock(now)
}

// Managed reports MANAGED_SERVICE (a second owner approves exceptions).
func (s *Service) Managed() bool { return s.managed }

// Start loads the policy and keeps it fresh: a snapshot older than
// RefreshTTL is reloaded on its next read.
func (s *Service) Start(ctx context.Context) {
	if err := s.Refresh(ctx); err != nil {
		s.log.Warn("blocked names policy unreadable at start; the government rule stays on with no exceptions",
			"error", logger.SanitizeError(err))
	}
	s.policy.OnStale(RefreshTTL, func() {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Refresh(rctx); err != nil {
			s.log.Warn("blocked names policy refresh failed; keeping the last one read", "error", logger.SanitizeError(err))
		}
	})
}

// Refresh reloads the stored policy into the guardrails.
func (s *Service) Refresh(ctx context.Context) error {
	st, _, err := s.store.Fresh(ctx)
	if err != nil {
		return err
	}
	live, err := s.repo.ListLive(ctx, s.now())
	if err != nil {
		return err
	}
	s.policy.Set(scopedom.NameSnapshot{GovernmentRuleOff: !st.RuleOn(), Names: st.Names, Exceptions: live})
	return nil
}

// View is the policy as the console shows it.
type View struct {
	Settings Settings
	Meta     consolesetting.Meta
	EnvNames []string
	Managed  bool
}

// Get returns the policy.
func (s *Service) Get(ctx context.Context) (View, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return View{}, err
	}
	return View{Settings: st, Meta: m, EnvNames: slices.Clone(s.envNames), Managed: s.managed}, nil
}

// PolicyInput is a policy change.
type PolicyInput struct {
	GovernmentRule   bool
	Names            []string
	MaxExceptionDays int
	Reason           string
	Version          int
}

// RuleOffNeedsApproval reports whether in turns the rule off on a hosted
// service (a second owner approves).
func (s *Service) RuleOffNeedsApproval(ctx context.Context, in PolicyInput) (bool, error) {
	if !s.managed || in.GovernmentRule {
		return false, nil
	}
	v, err := s.Get(ctx)
	if err != nil {
		return false, err
	}
	return v.Settings.RuleOn(), nil
}

// normalizeNames checks the operator's names: domain names, deduplicated,
// sorted.
func normalizeNames(in []string) ([]string, error) {
	if len(in) > MaxNames {
		return nil, ErrNames
	}
	out := make([]string, 0, len(in))
	for _, n := range in {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(n), "*."), "."))
		if n == "" {
			continue
		}
		if !strings.Contains(n, ".") || strings.ContainsAny(n, "*/:@ ") || scopedom.ValidatePattern(scopedom.TargetTypeDomain, n) != nil {
			return nil, ErrNames
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// UpdatePolicy changes the policy. The caller checked the permission, a
// fresh authenticator code and, when RuleOffNeedsApproval, the approval.
func (s *Service) UpdatePolicy(ctx context.Context, actor *admin.AdminUser, in PolicyInput, req Request) (View, error) {
	reason, err := consolesetting.CheckReason(in.Reason)
	if err != nil {
		return View{}, err
	}
	names, err := normalizeNames(in.Names)
	if err != nil {
		return View{}, err
	}
	if in.MaxExceptionDays == 0 {
		in.MaxExceptionDays = DefaultMaxExceptionDays
	}
	if in.MaxExceptionDays < 1 || in.MaxExceptionDays > MaxMaxExceptionDays {
		return View{}, ErrMaxDays
	}
	prev, _, err := s.store.Fresh(ctx)
	if err != nil {
		return View{}, err
	}
	rule := in.GovernmentRule
	next := Settings{GovernmentRule: &rule, Names: names, MaxExceptionDays: in.MaxExceptionDays}
	m, err := s.store.Put(ctx, next, in.Version, actor.ID())
	if err != nil {
		return View{}, err
	}
	s.refreshAfterChange(ctx)
	s.record(ctx, actor, req, consolesetting.Change{
		Action: ActionPolicyChanged, Title: "Blocked target names", Reason: reason,
		Details: map[string]any{
			"government_rule_before": onOff(prev.RuleOn()), "government_rule_after": onOff(rule),
			"names_before": prev.Names, "names_after": names,
			"max_exception_days_before": prev.MaxDays(), "max_exception_days_after": in.MaxExceptionDays,
		},
	})
	return View{Settings: next, Meta: m, EnvNames: slices.Clone(s.envNames), Managed: s.managed}, nil
}

// GrantInput is a new exception.
type GrantInput struct {
	TenantID         shared.ID
	Name             string
	Subdomains       bool
	Reason           string
	AuthorizationRef string
	ExpiresAt        time.Time
}

// PrepareGrant checks and normalises a grant (also the handler's approval
// target).
func (s *Service) PrepareGrant(ctx context.Context, in GrantInput) (GrantInput, error) {
	var err error
	if in.Reason, err = consolesetting.CheckReason(in.Reason); err != nil {
		return in, err
	}
	if in.AuthorizationRef, err = checkRef(in.AuthorizationRef); err != nil {
		return in, err
	}
	if in.Name, err = scopedom.NormalizeExceptionName(in.Name); err != nil {
		return in, err
	}
	if in.TenantID.IsZero() || s.tenants == nil {
		return in, ErrUnknownTenant
	}
	if _, err := s.tenants.TenantName(ctx, in.TenantID); err != nil {
		return in, ErrUnknownTenant
	}
	if err := s.checkExpiry(ctx, in.ExpiresAt); err != nil {
		return in, err
	}
	in.ExpiresAt = in.ExpiresAt.UTC()
	return in, nil
}

// ApprovalTarget is the four-eyes target of a grant or an extension.
func ApprovalTarget(tenantID shared.ID, name string, subdomains bool, expires time.Time) string {
	return admin.ScopeNameExceptionTarget(tenantID, name, subdomains, expires)
}

// Grant stores a new exception. in comes from PrepareGrant; the caller checked
// the permission, a fresh authenticator code and, on a hosted service, the
// approval.
func (s *Service) Grant(ctx context.Context, actor *admin.AdminUser, in GrantInput, req Request) (Exception, error) {
	in, err := s.PrepareGrant(ctx, in)
	if err != nil {
		return Exception{}, err
	}
	now := s.now().UTC()
	by := actor.ID()
	e := Exception{ID: shared.NewID(), TenantID: in.TenantID, Name: in.Name, Subdomains: in.Subdomains,
		Reason: in.Reason, AuthorizationRef: in.AuthorizationRef, GrantedBy: &by, GrantedByEmail: actor.Email(),
		GrantedAt: now, ExpiresAt: in.ExpiresAt, UpdatedAt: now}
	if err := s.repo.Create(ctx, e); err != nil {
		return Exception{}, err
	}
	e.TenantName, _ = s.tenants.TenantName(ctx, in.TenantID)
	s.refreshAfterChange(ctx)
	s.record(ctx, actor, req, consolesetting.Change{
		Action: ActionExceptionGranted, Title: titleException, Reason: in.Reason,
		Details: exceptionDetails(e, map[string]any{"expires_at_after": e.ExpiresAt.Format(time.RFC3339)}),
	})
	return e, nil
}

// Exception returns one exception.
func (s *Service) Exception(ctx context.Context, id shared.ID) (Exception, error) {
	return s.repo.Get(ctx, id)
}

// List returns every exception.
func (s *Service) List(ctx context.Context) ([]Exception, error) { return s.repo.List(ctx) }

// Now is the service clock.
func (s *Service) Now() time.Time { return s.now() }

// Extend moves the expiry of an exception that is not revoked (an expired one
// comes back). The caller checked what Grant's caller checks.
func (s *Service) Extend(ctx context.Context, actor *admin.AdminUser, id shared.ID, expiresAt time.Time, reason string, req Request) (Exception, error) {
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Exception{}, err
	}
	e, err := s.repo.Get(ctx, id)
	if err != nil {
		return Exception{}, err
	}
	if e.RevokedAt != nil {
		return Exception{}, ErrRevoked
	}
	if err := s.checkExpiry(ctx, expiresAt); err != nil {
		return Exception{}, err
	}
	before := e.ExpiresAt
	now := s.now().UTC()
	if err := s.repo.Extend(ctx, e.TenantID, id, expiresAt.UTC(), now); err != nil {
		return Exception{}, err
	}
	e.ExpiresAt, e.UpdatedAt = expiresAt.UTC(), now
	s.refreshAfterChange(ctx)
	s.record(ctx, actor, req, consolesetting.Change{
		Action: ActionExceptionExtended, Title: titleException, Reason: reason,
		Details: exceptionDetails(e, map[string]any{
			"expires_at_before": before.Format(time.RFC3339), "expires_at_after": e.ExpiresAt.Format(time.RFC3339),
		}),
	})
	return e, nil
}

// Revoke ends an exception at once. Narrowing: no approval.
func (s *Service) Revoke(ctx context.Context, actor *admin.AdminUser, id shared.ID, reason string, req Request) (Exception, error) {
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Exception{}, err
	}
	e, err := s.repo.Get(ctx, id)
	if err != nil {
		return Exception{}, err
	}
	if e.RevokedAt != nil {
		return Exception{}, ErrRevoked
	}
	now := s.now().UTC()
	if err := s.repo.Revoke(ctx, e.TenantID, id, actor.Email(), reason, now); err != nil {
		return Exception{}, err
	}
	e.RevokedAt, e.RevokedByEmail, e.RevokeReason, e.UpdatedAt = &now, actor.Email(), reason, now
	s.refreshAfterChange(ctx)
	s.record(ctx, actor, req, consolesetting.Change{
		Action: ActionExceptionRevoked, Title: titleException, Reason: reason,
		Details: exceptionDetails(e, map[string]any{"state_before": StateActive, "state_after": StateRevoked}),
	})
	return e, nil
}

func (s *Service) checkExpiry(ctx context.Context, at time.Time) error {
	v, err := s.Get(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	// The day picker sends the end of a day: the last allowed day counts.
	limit := now.AddDate(0, 0, v.Settings.MaxDays()).Add(24 * time.Hour)
	if at.IsZero() || !at.After(now) || at.After(limit) {
		return ErrExpiry
	}
	return nil
}

func (s *Service) refreshAfterChange(ctx context.Context) {
	if err := s.Refresh(context.WithoutCancel(ctx)); err != nil {
		// The change is stored; other reads pick it up within RefreshTTL.
		s.log.Error("refresh blocked names policy after a change", "error", logger.SanitizeError(err))
	}
}

func (s *Service) record(ctx context.Context, actor *admin.AdminUser, req Request, ch consolesetting.Change) {
	ch.Key, ch.Method, ch.Path, ch.Critical, ch.Notify = SettingKey, req.Method, req.Path, true, true
	s.recorder.Record(ctx, actor, ch, req.IP, req.UserAgent)
}

func exceptionDetails(e Exception, extra map[string]any) map[string]any {
	d := map[string]any{
		"exception_id": e.ID.String(), "organization_id": e.TenantID.String(), "organization": e.TenantName,
		"name": e.Name, "include_subdomains": e.Subdomains, "authorization_ref": e.AuthorizationRef,
		"expires_at": e.ExpiresAt.Format(time.RFC3339),
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func checkRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || utf8.RuneCountInString(ref) > MaxRefRunes {
		return "", ErrReference
	}
	for _, r := range ref {
		if unicode.IsControl(r) {
			return "", ErrReference
		}
	}
	return ref, nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
