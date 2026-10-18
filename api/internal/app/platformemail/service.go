// Package platformemail is the platform's own e-mail (SMTP) settings, set by a
// platform administrator in the admin console (Settings > E-mail) instead of
// SMTP_* environment variables. Organizations may still send through their
// own e-mail integration; this is the default.
//
// The SMTP password is encrypted at rest with APP_ENCRYPTION_KEY and is
// write-only: reads say whether one is set, never what it is.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package platformemail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	emaildom "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "email.smtp"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.email_settings_changed"

// cacheTTL bounds how long a replica serves settings it read; a change made
// on another replica applies here within this time.
const cacheTTL = 15 * time.Second

// Errors of the service.
var (
	ErrNoActor   = errors.New("e-mail settings change needs an administrator")
	ErrInvalid   = errors.New("invalid e-mail settings")
	ErrNoAddress = errors.New("the administrator has no e-mail address")
)

// stored is the JSON kept in platform_settings. PasswordEncrypted never leaves
// the service.
type stored struct {
	Enabled           bool   `json:"enabled"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Username          string `json:"username,omitempty"`
	PasswordEncrypted string `json:"password_encrypted,omitempty"`
	From              string `json:"from"`
	FromName          string `json:"from_name,omitempty"`
	StartTLS          bool   `json:"starttls"`
}

// Settings is what an administrator sees: everything but the password.
type Settings struct {
	Enabled     bool
	Host        string
	Port        int
	Username    string
	PasswordSet bool
	From        string
	FromName    string
	StartTLS    bool
	Version     int
	UpdatedAt   time.Time
}

// Input is a change. Password: nil keeps the stored one; "" clears it; any
// other value replaces it.
type Input struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password *string
	From     string
	FromName string
	StartTLS bool
}

// hostRE: a DNS name or an IP literal, no scheme, port, path or spaces.
var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:.]+\]?$`)

func (in Input) validate() error {
	if !in.Enabled {
		return nil
	}
	if !hostRE.MatchString(strings.TrimSpace(in.Host)) || len(in.Host) > 253 {
		return fmt.Errorf("%w: host must be a host name or IP address", ErrInvalid)
	}
	if in.Port < 1 || in.Port > 65535 {
		return fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalid)
	}
	addr, err := mail.ParseAddress(strings.TrimSpace(in.From))
	if err != nil || addr.Name != "" || len(in.From) > 254 {
		return fmt.Errorf("%w: from must be an e-mail address", ErrInvalid)
	}
	if len(in.Username) > 254 || len(in.FromName) > 128 || strings.ContainsAny(in.FromName, "\r\n") {
		return fmt.Errorf("%w: username or sender name too long or not one line", ErrInvalid)
	}
	if in.Password != nil && len(*in.Password) > 1024 {
		return fmt.Errorf("%w: password too long", ErrInvalid)
	}
	return nil
}

// Service reads and changes the platform e-mail settings and sends through
// them.
type Service struct {
	repo      platformsetting.Repository
	encryptor crypto.Encryptor
	audit     admin.AuditLogRepository
	log       *logger.Logger
	now       func() time.Time

	mu        sync.Mutex
	cached    *stored
	version   int
	updatedAt time.Time
	cachedAt  time.Time
}

// NewService creates the service. audit may be nil (tools, tests).
func NewService(repo platformsetting.Repository, encryptor crypto.Encryptor, audit admin.AuditLogRepository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, encryptor: encryptor, audit: audit, log: log.With("service", "platform_email"), now: time.Now}
}

// load returns the stored settings (cached for cacheTTL); nothing stored is
// the zero value (e-mail off).
func (s *Service) load(ctx context.Context) (stored, int, time.Time, error) {
	s.mu.Lock()
	if s.cached != nil && s.now().Sub(s.cachedAt) < cacheTTL {
		st, v, at := *s.cached, s.version, s.updatedAt
		s.mu.Unlock()
		return st, v, at, nil
	}
	s.mu.Unlock()

	row, err := s.repo.Get(ctx, SettingKey)
	if err != nil {
		if errors.Is(err, platformsetting.ErrNotFound) {
			s.remember(stored{}, 0, time.Time{})
			return stored{}, 0, time.Time{}, nil
		}
		return stored{}, 0, time.Time{}, err
	}
	var st stored
	if err := json.Unmarshal(row.Value, &st); err != nil {
		return stored{}, 0, time.Time{}, fmt.Errorf("decode e-mail settings: %w", err)
	}
	s.remember(st, row.Version, row.UpdatedAt)
	return st, row.Version, row.UpdatedAt, nil
}

func (s *Service) remember(st stored, version int, updatedAt time.Time) {
	s.mu.Lock()
	s.cached, s.version, s.updatedAt, s.cachedAt = &st, version, updatedAt, s.now()
	s.mu.Unlock()
}

// Get returns the settings without the password.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, v, at, err := s.load(ctx)
	if err != nil {
		return Settings{}, err
	}
	return Settings{
		Enabled: st.Enabled, Host: st.Host, Port: st.Port, Username: st.Username,
		PasswordSet: st.PasswordEncrypted != "", From: st.From, FromName: st.FromName,
		StartTLS: st.StartTLS, Version: v, UpdatedAt: at,
	}, nil
}

// Update replaces the settings. The caller has checked the actor's role and a
// fresh authenticator code. expectedVersion is the version read (0 when
// nothing was stored). Audited (critical) without the password.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, in Input, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	in.Host, in.From, in.Username, in.FromName = strings.TrimSpace(in.Host), strings.TrimSpace(in.From), strings.TrimSpace(in.Username), strings.TrimSpace(in.FromName)
	if err := in.validate(); err != nil {
		return Settings{}, err
	}
	prev, _, _, err := s.loadFresh(ctx)
	if err != nil {
		return Settings{}, err
	}
	next := stored{Enabled: in.Enabled, Host: in.Host, Port: in.Port, Username: in.Username,
		From: in.From, FromName: in.FromName, StartTLS: in.StartTLS, PasswordEncrypted: prev.PasswordEncrypted}
	credentialChanged := false
	if in.Password != nil {
		credentialChanged = true
		next.PasswordEncrypted = ""
		if *in.Password != "" {
			enc, err := s.encryptor.EncryptString(*in.Password)
			if err != nil {
				return Settings{}, fmt.Errorf("encrypt SMTP password: %w", err)
			}
			next.PasswordEncrypted = enc
		}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return Settings{}, err
	}
	now := s.now().UTC()
	if expectedVersion == 0 {
		by := actor.ID()
		created, err := s.repo.CreateIfAbsent(ctx, SettingKey, platformsetting.State{Value: raw, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: now})
		if err != nil {
			return Settings{}, err
		}
		if !created {
			return Settings{}, platformsetting.ErrVersionConflict
		}
		s.remember(next, 1, now)
	} else {
		st, err := s.repo.Update(ctx, SettingKey, raw, expectedVersion, actor.ID(), now)
		if err != nil {
			return Settings{}, err
		}
		s.remember(next, st.Version, now)
	}
	s.record(ctx, actor, prev, next, credentialChanged, ip, userAgent)
	return s.Get(ctx)
}

func (s *Service) loadFresh(ctx context.Context) (stored, int, time.Time, error) {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
	return s.load(ctx)
}

func (s *Service) record(ctx context.Context, actor *admin.AdminUser, prev, next stored, credentialChanged bool, ip, userAgent string) {
	s.log.Warn("platform e-mail settings changed", "admin_id", actor.ID().String(),
		"enabled", next.Enabled, "host", logger.SanitizeValue(next.Host), "credential_changed", credentialChanged)
	if s.audit == nil {
		return
	}
	entry := admin.NewAuditLogBuilder(actor, ActionChanged).
		Resource("platform_setting", nil, SettingKey).
		Context(ip, userAgent).
		Request("PUT", "/api/v1/admin/settings/email", map[string]any{
			"previous_enabled": prev.Enabled, "previous_host": prev.Host, "previous_from": prev.From,
			"enabled": next.Enabled, "host": next.Host, "port": next.Port, "username": next.Username,
			"from": next.From, "from_name": next.FromName, "starttls": next.StartTLS,
			// Never the value: only that it changed.
			"password_changed": credentialChanged,
		}).
		Critical().
		Build()
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.audit.Create(actx, entry); err != nil {
		s.log.Error("write admin audit for e-mail settings change", "error", err)
	}
}

// senderConfig returns the SMTP configuration in force, or ok=false when
// e-mail is off, incomplete or the password cannot be decrypted.
func (s *Service) senderConfig(ctx context.Context) (emaildom.Config, bool) {
	st, _, _, err := s.load(ctx)
	if err != nil {
		s.log.Warn("platform e-mail settings unreadable; e-mail off", "error", err)
		return emaildom.Config{}, false
	}
	if !st.Enabled || st.Host == "" || st.Port == 0 || st.From == "" {
		return emaildom.Config{}, false
	}
	password := ""
	if st.PasswordEncrypted != "" {
		p, err := s.encryptor.DecryptString(st.PasswordEncrypted)
		if err != nil {
			// Fail closed: never send with a wrong credential or ciphertext.
			s.log.Error("platform SMTP password does not decrypt (was APP_ENCRYPTION_KEY rotated without rekey?); e-mail off")
			return emaildom.Config{}, false
		}
		password = p
	}
	return emaildom.Config{Host: st.Host, Port: st.Port, User: st.Username, Password: password,
		From: st.From, FromName: st.FromName, TLS: st.StartTLS}, true
}

// Sender returns an e-mail sender that always uses the settings in force, so a
// change in the console applies without a restart.
func (s *Service) Sender() emaildom.Sender { return &dynamicSender{svc: s} }

type dynamicSender struct{ svc *Service }

func (d *dynamicSender) current(ctx context.Context) (*emaildom.SMTPSender, bool) {
	cfg, ok := d.svc.senderConfig(ctx)
	if !ok {
		return nil, false
	}
	return emaildom.NewSMTPSender(cfg), true
}

func (d *dynamicSender) Send(ctx context.Context, msg *emaildom.Message) error {
	snd, ok := d.current(ctx)
	if !ok {
		return emaildom.ErrNotConfigured
	}
	return snd.Send(ctx, msg)
}

func (d *dynamicSender) SendTemplate(ctx context.Context, to string, t emaildom.Template, data any) error {
	snd, ok := d.current(ctx)
	if !ok {
		return emaildom.ErrNotConfigured
	}
	return snd.SendTemplate(ctx, to, t, data)
}

func (d *dynamicSender) IsConfigured() bool {
	_, ok := d.svc.senderConfig(context.Background())
	return ok
}

// SendTest sends a test message to the acting administrator's own address
// (never to an address the caller chooses, so the endpoint cannot relay mail).
func (s *Service) SendTest(ctx context.Context, actor *admin.AdminUser, appName string) error {
	if actor == nil {
		return ErrNoActor
	}
	to := strings.TrimSpace(actor.Email())
	if to == "" {
		return ErrNoAddress
	}
	return s.Sender().Send(ctx, &emaildom.Message{
		To:      []string{to},
		Subject: appName + ": test e-mail",
		Body:    "This is a test message from the " + appName + " admin console. Platform e-mail is working.",
	})
}

// Seed stores settings when none are stored (the first-start path of
// bootstrap-admin for headless installs). It reports whether it stored them.
func (s *Service) Seed(ctx context.Context, in Input) (bool, error) {
	in.Enabled = true
	if err := in.validate(); err != nil {
		return false, err
	}
	next := stored{Enabled: true, Host: in.Host, Port: in.Port, Username: in.Username, From: in.From, FromName: in.FromName, StartTLS: in.StartTLS}
	if in.Password != nil && *in.Password != "" {
		enc, err := s.encryptor.EncryptString(*in.Password)
		if err != nil {
			return false, fmt.Errorf("encrypt SMTP password: %w", err)
		}
		next.PasswordEncrypted = enc
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return false, err
	}
	created, err := s.repo.CreateIfAbsent(ctx, SettingKey, platformsetting.State{Value: raw, Source: platformsetting.SourceEnvironment, UpdatedAt: s.now().UTC()})
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
	return created, nil
}
