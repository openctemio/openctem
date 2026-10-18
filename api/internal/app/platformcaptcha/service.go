// Package platformcaptcha is the platform's CAPTCHA (Cloudflare Turnstile):
// the site key and secret key a platform administrator sets in the console
// (Settings > CAPTCHA) instead of CAPTCHA_TURNSTILE_SITE_KEY and
// CAPTCHA_TURNSTILE_SECRET and a restart.
//
// The CAPTCHA protects registration, the request-access form and every
// sign-in after repeated failures (tenant and console). The secret is
// encrypted with APP_ENCRYPTION_KEY and write-only: reads say whether it is
// set and who changed it last, never what it is. A change applies on every
// replica within the console setting cache time.
//
// The environment pins the keys: when CAPTCHA_TURNSTILE_SECRET is set (the
// installer kit's secret file), the environment keys are used and the
// console cannot change them (it shows "locked by the server
// configuration"). Changing or removing the keys weakens the abuse controls,
// so it needs a super admin, a fresh confirmation, a reason, a critical
// audit row and a notice to every administrator.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package platformcaptcha

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "captcha.turnstile"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.captcha_changed"

// Environment variables that pin the keys.
const (
	EnvSiteKey = "CAPTCHA_TURNSTILE_SITE_KEY"
	EnvSecret  = "CAPTCHA_TURNSTILE_SECRET"
)

// Sources of the keys in force.
const (
	SourceNone        = "none"
	SourceConsole     = "console"
	SourceEnvironment = "environment"
)

// Errors of the service.
var (
	ErrLockedByEnvironment = errors.New("the CAPTCHA keys are set by the server configuration (CAPTCHA_TURNSTILE_SECRET)")
	ErrInvalid             = fmt.Errorf("%w: invalid CAPTCHA keys", shared.ErrValidation)
	ErrNoActor             = errors.New("a CAPTCHA change needs an administrator")
	ErrNoSecret            = errors.New("no CAPTCHA secret key to check")
)

// keyRE is the shape of a Turnstile site key or secret key.
var keyRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]{8,256}$`)

// stored is the JSON kept in platform_settings. SecretEncrypted never leaves
// the service.
type stored struct {
	SiteKey         string `json:"site_key,omitempty"`
	SecretEncrypted string `json:"secret_encrypted,omitempty"`
}

// Settings is what an administrator sees.
type Settings struct {
	SiteKey             string
	SecretSet           bool
	Source              string
	LockedByEnvironment bool
	Version             int
	UpdatedAt           time.Time
	UpdatedBy           *shared.ID
}

// Input is a change. Secret: nil keeps the stored one, "" removes it, any
// other value replaces it. Both keys are set together or removed together.
type Input struct {
	SiteKey string
	Secret  *string
	Reason  string
}

// Service reads and changes the CAPTCHA keys and verifies tokens with the
// keys in force.
type Service struct {
	store     *consolesetting.Store[stored]
	encryptor crypto.Encryptor
	recorder  *consolesetting.Recorder
	envSite   string
	envSecret string
	check     *siteverify
	log       *logger.Logger
}

// NewService creates the service. envSiteKey and envSecret are the
// environment keys (both or neither, checked at start).
func NewService(repo platformsetting.Repository, encryptor crypto.Encryptor, recorder *consolesetting.Recorder,
	envSiteKey, envSecret string, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{
		store: consolesetting.NewStore[stored](repo, SettingKey), encryptor: encryptor, recorder: recorder,
		envSite: strings.TrimSpace(envSiteKey), envSecret: strings.TrimSpace(envSecret),
		check: newSiteverify(), log: log.With("service", "platform_captcha"),
	}
}

// LockedByEnvironment reports whether the environment pins the keys.
func (s *Service) LockedByEnvironment() bool { return s.envSecret != "" }

// keys returns the keys in force. undecryptable reports a stored secret
// that does not decrypt: the CAPTCHA then stays on and refuses every token
// (fail closed) until an administrator replaces the secret.
func (s *Service) keys(ctx context.Context) (site, secret string, undecryptable bool, err error) {
	if s.LockedByEnvironment() {
		return s.envSite, s.envSecret, false, nil
	}
	st, _, err := s.store.Get(ctx)
	if err != nil {
		return "", "", false, err
	}
	if st.SecretEncrypted == "" {
		return st.SiteKey, "", false, nil
	}
	plain, derr := s.encryptor.DecryptString(st.SecretEncrypted)
	if derr != nil {
		s.log.Error("CAPTCHA secret does not decrypt (was APP_ENCRYPTION_KEY rotated without rekey?); every CAPTCHA is refused until the secret is replaced",
			"error", derr)
		return st.SiteKey, "", true, nil //nolint:nilerr // fail closed: reported as undecryptable, not as a read error
	}
	return st.SiteKey, plain, false, nil
}

// Active reports whether a CAPTCHA is configured. An unreadable setting
// counts as active (the CAPTCHA is asked, and refused): a database hiccup
// must not open the forms it protects.
func (s *Service) Active(ctx context.Context) bool {
	site, secret, undecryptable, err := s.keys(ctx)
	if err != nil {
		s.log.Warn("CAPTCHA setting unreadable; CAPTCHA asked (fail closed)", "error", err)
		return true
	}
	return undecryptable || (site != "" && secret != "")
}

// SiteKey is the public site key the sign-up and sign-in pages render; ""
// when no CAPTCHA is configured.
func (s *Service) SiteKey(ctx context.Context) string {
	site, secret, undecryptable, err := s.keys(ctx)
	if err != nil || (secret == "" && !undecryptable) {
		return ""
	}
	return site
}

// Verify checks one browser token with the keys in force. It fails closed:
// no usable secret, a network error or a refusal is "not verified".
func (s *Service) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	_, secret, _, err := s.keys(ctx)
	if err != nil {
		return false, err
	}
	if secret == "" {
		return false, ErrNoSecret
	}
	return s.check.verify(ctx, secret, token, remoteIP)
}

// Get returns the settings without the secret.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	if s.LockedByEnvironment() {
		return Settings{SiteKey: s.envSite, SecretSet: true, Source: SourceEnvironment, LockedByEnvironment: true}, nil
	}
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{SiteKey: st.SiteKey, SecretSet: st.SecretEncrypted != "", Source: SourceNone,
		Version: m.Version, UpdatedAt: m.UpdatedAt, UpdatedBy: m.UpdatedBy}
	if out.SecretSet {
		out.Source = SourceConsole
	}
	return out, nil
}

// Update replaces the keys. The caller checked the actor's role and a fresh
// confirmation. expectedVersion is the version read (0: nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, in Input, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if s.LockedByEnvironment() {
		return Settings{}, ErrLockedByEnvironment
	}
	reason, err := consolesetting.CheckReason(in.Reason)
	if err != nil {
		return Settings{}, err
	}
	in.SiteKey = strings.TrimSpace(in.SiteKey)
	if in.SiteKey != "" && !keyRE.MatchString(in.SiteKey) {
		return Settings{}, fmt.Errorf("%w: the site key has an unexpected shape", ErrInvalid)
	}
	if in.Secret != nil {
		v := strings.TrimSpace(*in.Secret)
		if v != "" && !keyRE.MatchString(v) {
			return Settings{}, fmt.Errorf("%w: the secret key has an unexpected shape", ErrInvalid)
		}
		in.Secret = &v
	}
	prev, _, err := s.store.Fresh(ctx)
	if err != nil {
		return Settings{}, err
	}
	next := stored{SiteKey: in.SiteKey, SecretEncrypted: prev.SecretEncrypted}
	secretChanged := false
	if in.Secret != nil {
		secretChanged = true
		next.SecretEncrypted = ""
		if *in.Secret != "" {
			enc, err := s.encryptor.EncryptString(*in.Secret)
			if err != nil {
				return Settings{}, fmt.Errorf("encrypt CAPTCHA secret: %w", err)
			}
			next.SecretEncrypted = enc
		}
	}
	if (next.SiteKey == "") != (next.SecretEncrypted == "") {
		return Settings{}, fmt.Errorf("%w: set both keys, or remove both", ErrInvalid)
	}
	if _, err := s.store.Put(ctx, next, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "CAPTCHA keys",
		Method: "PUT", Path: "/api/v1/admin/settings/captcha", Reason: reason,
		Details: map[string]any{
			"previous_site_key": prev.SiteKey, "site_key": next.SiteKey,
			"previous_enabled": prev.SecretEncrypted != "", "enabled": next.SecretEncrypted != "",
			// Never the value: only that it changed.
			"secret_changed": secretChanged,
		},
		Critical: true, Notify: true,
	}, ip, userAgent)
	return s.Get(ctx)
}

// CheckSecret asks Turnstile whether it knows a secret key: candidate when
// given (before saving it), otherwise the secret in force. The address it
// asks is fixed; the candidate is never stored or logged.
func (s *Service) CheckSecret(ctx context.Context, candidate string) (SecretCheck, error) {
	secret := strings.TrimSpace(candidate)
	if secret == "" {
		_, inForce, _, err := s.keys(ctx)
		if err != nil {
			return "", err
		}
		secret = inForce
	} else if !keyRE.MatchString(secret) {
		return SecretInvalid, nil
	}
	if secret == "" {
		return "", ErrNoSecret
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.check.checkSecret(cctx, secret), nil
}
