// Package orgrelay is the platform setting email.tenant_relay: whether an
// organization's own mail relay carries its organization mail (invitations,
// account setup, member notices, scheduled reports).
//
//	off              organization mail always goes through the platform relay
//	verified_sender  the organization relay is used when the sender address is
//	                 on a verified domain of the organization and the relay
//	                 meets the managed transport rules
//	on               the organization relay is used as configured
//
// Defaults while nothing is stored: the environment value ORG_EMAIL_RELAY_MODE
// when set, else "verified_sender" on a managed service (MANAGED_SERVICE) and
// "on" on a self-managed install. Plans are not modeled on the platform yet,
// so a hosted service has one default for every organization (verified
// sender); a per-plan "off" for free organizations arrives with the plan
// model.
//
// Account security mail (verification, password reset, MFA and sign-in
// notices) never uses an organization relay, whatever the mode: that rule is
// in auth.EmailService, not here.
//
// A change is made by a super admin with a fresh step-up and a reason, and is
// audited as critical and told to every administrator. An unreadable stored
// value counts as "off" (fail closed).
//
// Design: research 308, decision D12; docs/architecture/notification-system.md.
package orgrelay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	emailpkg "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "email.tenant_relay"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.email_tenant_relay_changed"

// EnvVar is the environment default.
const EnvVar = "ORG_EMAIL_RELAY_MODE"

// Sources of the mode in force.
const (
	SourceConsole = "console"
	SourceDefault = "default"
)

// ErrInvalid refuses an unknown mode.
var ErrInvalid = fmt.Errorf("%w: the mode must be off, verified_sender or on", shared.ErrValidation)

// ErrNoActor refuses a change without an administrator.
var ErrNoActor = errors.New("a relay mode change needs an administrator")

type stored struct {
	Mode string `json:"mode"`
}

// Settings is what an administrator sees.
type Settings struct {
	Mode      emailpkg.RelayMode
	Source    string
	Default   emailpkg.RelayMode
	Version   int
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Service answers the mode and changes it.
type Service struct {
	store    *consolesetting.Store[stored]
	recorder *consolesetting.Recorder
	def      emailpkg.RelayMode
	log      *logger.Logger
}

// NewService creates the service. envMode is ORG_EMAIL_RELAY_MODE (empty or
// invalid: the managed or self-managed default).
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder, managed bool, envMode string, log *logger.Logger) *Service {
	def := emailpkg.DefaultRelayMode(managed)
	if m, ok := emailpkg.ParseRelayMode(envMode); ok {
		def = m
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), recorder: recorder, def: def, log: log}
}

// Get returns the mode in force and where it comes from.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{Mode: s.def, Source: SourceDefault, Default: s.def}
	if m.Stored {
		mode, ok := emailpkg.ParseRelayMode(st.Mode)
		if !ok {
			return Settings{}, fmt.Errorf("stored %s is not a mode", SettingKey)
		}
		out.Mode, out.Source = mode, SourceConsole
		out.Version, out.UpdatedAt, out.UpdatedBy = m.Version, m.UpdatedAt, m.UpdatedBy
	}
	return out, nil
}

// RelayMode is the mode in force. An unreadable setting answers off.
func (s *Service) RelayMode(ctx context.Context) emailpkg.RelayMode {
	v, err := s.Get(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Warn("email.tenant_relay unreadable; organization relays are off", "error", err)
		}
		return emailpkg.RelayModeOff
	}
	return v.Mode
}

// Update stores the mode. The caller checked super_admin and the fresh
// step-up. expectedVersion is the version read (0: nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, mode, reason string, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	m, ok := emailpkg.ParseRelayMode(mode)
	if !ok {
		return Settings{}, ErrInvalid
	}
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Settings{}, err
	}
	prev, err := s.Get(ctx)
	if err != nil {
		// A broken stored value must still be replaceable.
		prev = Settings{Mode: emailpkg.RelayModeOff, Source: "unreadable"}
	}
	if _, err := s.store.Put(ctx, stored{Mode: string(m)}, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Organization mail relay mode",
		Method: "PUT", Path: "/api/v1/admin/settings/email-relay", Reason: reason, Critical: true, Notify: true,
		Details: map[string]any{"previous_mode": string(prev.Mode), "previous_source": prev.Source, "mode": string(m)},
	}, ip, userAgent)
	return s.Get(ctx)
}
