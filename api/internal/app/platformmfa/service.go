// Package platformmfa is the platform setting auth.mfa: the lowest two-factor
// requirement every organization carries (the floor). Organizations may
// require more, never less.
//
//	none      the platform requires nothing; organizations decide
//	admins    owners, administrators and members holding a privileged role
//	everyone  every member
//
// Defaults while nothing is stored: the environment value AUTH_MFA_FLOOR when
// set, else "admins" (a managed service, and a fresh self-managed install).
// An instance that already had users when this shipped keeps "none" through
// a seeded row (source migration) until its operator raises it, so an
// upgrade never locks anyone out; on a managed service that row is ignored
// (the default applies) and only its effective_from is used, so the grace
// period starts at the upgrade.
//
// Grace: a person whose only reason for 2FA is the floor is not gated at
// token mint until their due date: the later of effective_from plus the
// grace for existing members (14 days) and the account's creation plus the
// grace for new accounts (7 days). Creating credentials (API keys, sensor
// enrolment, integration secrets) needs an enrolled factor even in grace; see
// auth.CredentialFactorGate. A requirement the organization chose itself has
// no grace.
//
// A change is made by a super admin with a fresh step-up and a reason, is
// audited as critical and told to every administrator. A stored value that
// cannot be read is an error, never a silent "none": the token-mint gate
// fails closed on it.
//
// Design: research 308, decision D16; docs/architecture/two-factor-floor.md.
package platformmfa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// SettingKey is the platform_settings key.
const SettingKey = "auth.mfa"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.auth_mfa_changed"

// EnvVar is the environment default.
const EnvVar = "AUTH_MFA_FLOOR"

// Grace defaults, in days.
const (
	DefaultGraceExistingDays = 14
	DefaultGraceNewDays      = 7
	MaxGraceDays             = 90
)

// Sources of the policy in force.
const (
	SourceConsole   = "console"
	SourceMigration = "migration"
	SourceDefault   = "default"
)

// Errors of the service.
var (
	ErrInvalidFloor = fmt.Errorf("%w: the floor must be none, admins or everyone", shared.ErrValidation)
	ErrInvalidGrace = fmt.Errorf("%w: grace days must be between 0 and %d", shared.ErrValidation, MaxGraceDays)
	ErrNoActor      = errors.New("a two-factor floor change needs an administrator")
)

type stored struct {
	Floor             string    `json:"floor"`
	GraceExistingDays *int      `json:"grace_days_existing,omitempty"`
	GraceNewDays      *int      `json:"grace_days_new,omitempty"`
	EffectiveFrom     time.Time `json:"effective_from"`
}

// Policy is the floor in force with its grace rules.
type Policy struct {
	Floor             tenant.MFAFloor
	GraceExistingDays int
	GraceNewDays      int
	// EffectiveFrom is when the floor came into force (zero: from the
	// start, only the new-account grace applies).
	EffectiveFrom time.Time
}

// DueAt is when a person covered only by the floor must have 2FA: the later
// of the existing-member grace from EffectiveFrom and the new-account grace
// from the account's creation.
func (p Policy) DueAt(accountCreated time.Time) time.Time {
	byFloor := time.Time{}
	if !p.EffectiveFrom.IsZero() {
		byFloor = p.EffectiveFrom.AddDate(0, 0, p.GraceExistingDays)
	}
	byAccount := accountCreated.AddDate(0, 0, p.GraceNewDays)
	if byFloor.After(byAccount) {
		return byFloor
	}
	return byAccount
}

// Settings is what an administrator sees.
type Settings struct {
	Policy
	Source  string
	Default tenant.MFAFloor
	Version int
	// RecommendRaise is true on an upgraded install still on the seeded
	// "none": the console shows a card recommending "admins".
	RecommendRaise bool
	UpdatedAt      time.Time
	UpdatedBy      *shared.ID
}

// Service answers the policy and changes it.
type Service struct {
	store    *consolesetting.Store[stored]
	recorder *consolesetting.Recorder
	managed  bool
	def      tenant.MFAFloor
	now      func() time.Time
}

// NewService creates the service. envFloor is AUTH_MFA_FLOOR (empty or
// invalid: admins).
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder, managed bool, envFloor string) *Service {
	def := tenant.MFAFloorAdmins
	if f, ok := tenant.ParseMFAFloor(envFloor); ok {
		def = f
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), recorder: recorder, managed: managed, def: def, now: time.Now}
}

func graceOrDefault(v *int, def int) int {
	if v == nil || *v < 0 || *v > MaxGraceDays {
		return def
	}
	return *v
}

// Get returns the policy in force and where it comes from.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{
		Policy:  Policy{Floor: s.def, GraceExistingDays: DefaultGraceExistingDays, GraceNewDays: DefaultGraceNewDays},
		Source:  SourceDefault,
		Default: s.def,
	}
	if !m.Stored {
		return out, nil
	}
	floor, ok := tenant.ParseMFAFloor(st.Floor)
	if !ok {
		return Settings{}, fmt.Errorf("stored %s has an unknown floor", SettingKey)
	}
	out.Version, out.UpdatedAt, out.UpdatedBy = m.Version, m.UpdatedAt, m.UpdatedBy
	out.EffectiveFrom = st.EffectiveFrom
	out.GraceExistingDays = graceOrDefault(st.GraceExistingDays, DefaultGraceExistingDays)
	out.GraceNewDays = graceOrDefault(st.GraceNewDays, DefaultGraceNewDays)
	if m.Source == platformsetting.SourceMigration {
		out.RecommendRaise = floor == tenant.MFAFloorNone
		if s.managed {
			// The seeded "none" is an upgrade default for self-managed
			// installs; a managed service keeps its own default and only
			// takes the upgrade time as the start of the grace period.
			out.Version = m.Version
			out.RecommendRaise = false
			return out, nil
		}
		out.Floor, out.Source = floor, SourceMigration
		return out, nil
	}
	out.Floor, out.Source = floor, SourceConsole
	return out, nil
}

// Policy is the policy in force (an unreadable setting is an error).
func (s *Service) Policy(ctx context.Context) (Policy, error) {
	v, err := s.Get(ctx)
	if err != nil {
		return Policy{}, err
	}
	return v.Policy, nil
}

// Update stores the floor and the grace rules. The caller checked super_admin
// and the fresh step-up. expectedVersion is the version read (0: nothing
// stored). Raising the floor starts a new grace period (effective_from is
// now); any other change keeps the earlier start.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, floor string, graceExisting, graceNew *int, reason string, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	f, ok := tenant.ParseMFAFloor(floor)
	if !ok {
		return Settings{}, ErrInvalidFloor
	}
	for _, g := range []*int{graceExisting, graceNew} {
		if g != nil && (*g < 0 || *g > MaxGraceDays) {
			return Settings{}, ErrInvalidGrace
		}
	}
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Settings{}, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	prev, err := s.Get(ctx)
	if err != nil {
		prev = Settings{Policy: Policy{Floor: tenant.MFAFloorNone}, Source: "unreadable"}
	}
	from := prev.EffectiveFrom
	if f.Rank() > prev.Floor.Rank() || from.IsZero() {
		from = s.now().UTC()
	}
	next := stored{Floor: string(f), GraceExistingDays: graceExisting, GraceNewDays: graceNew, EffectiveFrom: from}
	if graceExisting == nil {
		d := prev.GraceExistingDays
		next.GraceExistingDays = &d
	}
	if graceNew == nil {
		d := prev.GraceNewDays
		next.GraceNewDays = &d
	}
	if _, err := s.store.Put(ctx, next, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Two-factor floor",
		Method: "PUT", Path: "/api/v1/admin/settings/auth-mfa", Reason: reason, Critical: true, Notify: true,
		Details: map[string]any{
			"previous_floor": string(prev.Floor), "previous_source": prev.Source, "floor": string(f),
			"grace_days_existing": *next.GraceExistingDays, "grace_days_new": *next.GraceNewDays,
		},
	}, ip, userAgent)
	return s.Get(ctx)
}
