// Package signup serves the platform sign-up policy (who may create an
// organization) to every sign-up path, and lets a platform administrator
// change it in the console (docs/architecture/user-onboarding.md, "Sign-up
// policy").
//
// The policy in force is the stored policy clamped to the deployment's
// ceiling (SIGNUP_MODE): the console can lower what the server configuration
// allows, never raise it.
//
// Reads are fail-closed: when the policy cannot be read, the answer is
// admin_only, the mode that creates nothing.
package signup

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ActionPolicyChanged is the admin audit action of a policy change.
const ActionPolicyChanged = "platform.signup_policy_changed"

// AlertPolicyChanged is the stable "alert" field of the WARN log line written
// for every change, for log-based alerting without SMTP.
const AlertPolicyChanged = "signup_policy_changed"

// cacheTTL bounds how long a replica serves a policy it read. A change made
// on another replica takes effect here within this time.
const cacheTTL = 15 * time.Second

// ChangeAlert describes one policy change, for the other administrators.
type ChangeAlert struct {
	AdminEmail string
	Previous   signupdom.Policy
	Current    signupdom.Policy
	IP         string
	At         time.Time
	Recipients []string
}

// ChangeNotifier tells the other administrators about a change. It must not
// block the change (send asynchronously).
type ChangeNotifier interface {
	NotifySignupPolicyChanged(ctx context.Context, alert ChangeAlert) error
}

// AdminLister lists the active administrators (the alert recipients).
type AdminLister interface {
	ListActive(ctx context.Context) ([]*admin.AdminUser, error)
}

// Service reads and changes the sign-up policy.
type Service struct {
	repo     signupdom.Repository
	audit    admin.AuditLogRepository
	admins   AdminLister
	notifier ChangeNotifier
	log      *logger.Logger
	now      func() time.Time
	// ceiling is SIGNUP_MODE; the zero value is disabled.
	ceiling signupdom.Ceiling
	// mailReady reports whether the platform can send e-mail. Under a
	// domain or open ceiling every self-registered address is verified by
	// e-mail, so without it public sign-up is closed (fail-closed). Nil:
	// not checked (tests).
	mailReady func() bool

	mu       sync.Mutex
	cached   *signupdom.State
	cachedAt time.Time

	// startLimits reports whether the starting limits of self-service
	// organizations are configured; self-service sign-up needs them.
	startLimits func(ctx context.Context) (bool, error)
}

// SetStartLimitsCheck wires the check that self-service sign-up has starting
// limits configured (the entitlement service).
func (s *Service) SetStartLimitsCheck(f func(ctx context.Context) (bool, error)) { s.startLimits = f }

// ErrStartLimitsRequired refuses turning self-service sign-up on while no
// starting limits are configured.
var ErrStartLimitsRequired = errors.New("self-service sign-up needs starting limits first: save them in System > Limits " +
	"(empty is allowed only by setting SELF_SERVICE_START_LIMITS=unlimited), or turn on the internal entitlements API")

// NewService creates the service. audit, admins and notifier may be nil
// (tests); production wires all three.
func NewService(repo signupdom.Repository, audit admin.AuditLogRepository, admins AdminLister, notifier ChangeNotifier, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, audit: audit, admins: admins, notifier: notifier,
		log: log.With("service", "signup"), now: time.Now}
}

// SetCeiling sets the deployment ceiling (SIGNUP_MODE).
func (s *Service) SetCeiling(c signupdom.Ceiling) { s.ceiling = c }

// Ceiling returns the deployment ceiling.
func (s *Service) Ceiling() signupdom.Ceiling { return signupdom.Ceiling(s.ceiling.String()) }

// SetMailReady wires the check that the platform can send e-mail.
func (s *Service) SetMailReady(f func() bool) { s.mailReady = f }

// SetNotifier wires the notification to the other administrators (email in
// production).
func (s *Service) SetNotifier(n ChangeNotifier) { s.notifier = n }

// Seed stores the policy from the ceiling when none is stored yet (first
// start): open seeds self_service, anything else admin_only. A stored policy
// always wins: the environment only seeds, and the ceiling clamps it on read.
func (s *Service) Seed(ctx context.Context) error {
	p := s.ceiling.SeedPolicy()
	created, err := s.repo.CreateIfAbsent(ctx, signupdom.State{
		Policy: p, Version: 1, Source: signupdom.SourceEnvironment, UpdatedAt: s.now().UTC(),
	})
	if err != nil {
		return err
	}
	if created {
		s.log.Info("sign-up policy seeded from the environment", "mode", string(p.Mode), "accounts", string(p.Accounts))
	}
	return nil
}

// Current returns the policy in force: the stored policy clamped to the
// ceiling. Fail-closed: when it cannot be read, it is admin_only.
func (s *Service) Current(ctx context.Context) signupdom.Policy {
	st, err := s.Get(ctx)
	if err != nil {
		s.log.Warn("sign-up policy unreadable; admin_only in force (fail-closed)", "error", err)
		return signupdom.Default()
	}
	return s.Effective(st.Policy)
}

// Effective clamps a stored policy to what this deployment allows now: the
// ceiling, and, when public sign-up would need it, working e-mail.
func (s *Service) Effective(p signupdom.Policy) signupdom.Policy {
	p = s.ceiling.Clamp(p)
	if p.AllowsPublicSignup() && s.mailReady != nil && !s.mailReady() {
		s.log.Warn("platform e-mail is not configured; public sign-up is closed until it is (System > E-mail)")
		p.Mode, p.Accounts = signupdom.ModeAdminOnly, signupdom.AccountsClosed
	}
	return p
}

// Get returns the stored policy (cached for cacheTTL). With nothing stored it
// returns the default with SourceDefault.
func (s *Service) Get(ctx context.Context) (signupdom.State, error) {
	s.mu.Lock()
	if s.cached != nil && s.now().Sub(s.cachedAt) < cacheTTL {
		st := *s.cached
		s.mu.Unlock()
		return st, nil
	}
	s.mu.Unlock()

	st, err := s.repo.Get(ctx)
	if err != nil {
		if !signupdom.IsNotFound(err) {
			return signupdom.State{}, err
		}
		st = signupdom.State{Policy: signupdom.Default(), Version: 0, Source: signupdom.SourceDefault}
	}
	s.mu.Lock()
	s.cached, s.cachedAt = &st, s.now()
	s.mu.Unlock()
	return st, nil
}

// ErrNoActor is returned when an update has no administrator.
var ErrNoActor = errors.New("sign-up policy change needs an administrator")

// Update changes the policy. The caller has already checked the actor's role
// and a fresh authenticator code (step-up). expectedVersion is the version the
// administrator read (0 when nothing was stored). The change never touches
// existing organizations, users or sessions. It is audited (critical) and the
// other active administrators are told.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, p signupdom.Policy, expectedVersion int, ip, userAgent string) (signupdom.State, error) {
	if actor == nil {
		return signupdom.State{}, ErrNoActor
	}
	if err := p.Validate(); err != nil {
		return signupdom.State{}, err
	}
	p = p.Normalized()
	if !s.ceiling.Permits(p) {
		return signupdom.State{}, signupdom.ErrLockedByDeployment
	}
	if p.Mode == signupdom.ModeSelfService && s.startLimits != nil {
		ok, cerr := s.startLimits(ctx)
		if cerr != nil {
			return signupdom.State{}, cerr
		}
		if !ok {
			return signupdom.State{}, ErrStartLimitsRequired
		}
	}
	previous, err := s.repo.Get(ctx)
	if err != nil && !signupdom.IsNotFound(err) {
		return signupdom.State{}, err
	}
	now := s.now().UTC()
	if signupdom.IsNotFound(err) {
		// Nothing stored (no seed ran): store version 1 first so the
		// optimistic check below has a row to compare against.
		previous = signupdom.State{Policy: s.ceiling.SeedPolicy()}
		if expectedVersion != 0 {
			return signupdom.State{}, signupdom.ErrVersionConflict
		}
		if _, cerr := s.repo.CreateIfAbsent(ctx, signupdom.State{
			Policy: s.ceiling.SeedPolicy(), Version: 1, Source: signupdom.SourceEnvironment, UpdatedAt: now,
		}); cerr != nil {
			return signupdom.State{}, cerr
		}
		expectedVersion = 1
	}

	next, err := s.repo.Update(ctx, p, expectedVersion, actor.ID(), now)
	if err != nil {
		return signupdom.State{}, err
	}
	s.mu.Lock()
	s.cached, s.cachedAt = &next, s.now()
	s.mu.Unlock()

	s.record(ctx, actor, previous.Policy, next, ip, userAgent)
	return next, nil
}

// record writes the critical admin audit row, the WARN alert line and the
// notification to the other administrators.
func (s *Service) record(ctx context.Context, actor *admin.AdminUser, prev signupdom.Policy, next signupdom.State, ip, userAgent string) {
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(actor, ActionPolicyChanged).
			Resource("platform_setting", nil, signupdom.SettingKey).
			Context(ip, userAgent).
			Request("PUT", "/api/v1/admin/settings/signup", map[string]any{
				"previous_mode":           string(prev.Mode),
				"previous_accounts":       string(prev.AccountSignup()),
				"previous_request_access": prev.RequestAccess,
				"mode":                    string(next.Policy.Mode),
				"accounts":                string(next.Policy.AccountSignup()),
				"request_access":          next.Policy.RequestAccess,
				"version":                 next.Version,
			}).
			Critical().
			Build()
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if err := s.audit.Create(actx, entry); err != nil {
			s.log.Error("write admin audit for sign-up policy change", "error", err)
		}
		cancel()
	}

	recipients := []string{}
	if s.admins != nil {
		if others, err := s.admins.ListActive(ctx); err != nil {
			s.log.Warn("list administrators for sign-up policy alert", "error", err)
		} else {
			for _, o := range others {
				if o.ID() != actor.ID() {
					recipients = append(recipients, o.Email())
				}
			}
		}
	}
	s.log.Warn("sign-up policy changed",
		"alert", AlertPolicyChanged,
		"admin_id", actor.ID().String(),
		"from_mode", logger.SanitizeValue(string(prev.Mode)), "to_mode", logger.SanitizeValue(string(next.Policy.Mode)),
		"from_accounts", string(prev.AccountSignup()), "to_accounts", string(next.Policy.AccountSignup()),
		"request_access", strconv.FormatBool(next.Policy.RequestAccess),
		"notified", len(recipients),
	)
	if s.notifier == nil || len(recipients) == 0 {
		return
	}
	if err := s.notifier.NotifySignupPolicyChanged(ctx, ChangeAlert{
		AdminEmail: actor.Email(),
		Previous:   prev,
		Current:    next.Policy,
		IP:         ip,
		At:         next.UpdatedAt,
		Recipients: recipients,
	}); err != nil {
		s.log.Warn("notify administrators of sign-up policy change", "alert", AlertPolicyChanged, "error", err)
	}
}
