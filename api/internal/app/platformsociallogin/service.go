// Package platformsociallogin is the platform's social login (Google,
// GitHub, Microsoft): the client ID, client secret, scopes and on/off switch
// a platform administrator sets per provider in the console (Settings >
// Social login) instead of OAUTH_<PROVIDER>_* and a restart.
//
// The client secret is encrypted with APP_ENCRYPTION_KEY and write-only:
// reads say whether it is set and who changed it last, never what it is. A
// change applies on every replica within the console setting cache time,
// because the OAuth service asks this service for the provider in force on
// every authorize and callback.
//
// The environment pins a provider: while OAUTH_<PROVIDER>_CLIENT_SECRET is
// set (the installer kit's secret file), that provider's environment values
// are used and the console cannot change them. OAUTH_ENABLED=false stays a
// server-side master switch. OAUTH_STATE_SECRET is not a console setting: it
// is a bootstrap secret the server derives from its JWT secret when absent,
// so a console change can never weaken the CSRF binding of a login.
//
// Turning a provider on or changing its client changes who can start a
// sign-in, so it needs a super admin, a fresh confirmation, a reason, a
// critical audit row (never the secret) and a notice to every administrator.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package platformsociallogin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "auth.social_login"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.social_login_changed"

// Provider names, as used in the routes and in /auth/oauth/{provider}.
const (
	Google    = "google"
	GitHub    = "github"
	Microsoft = "microsoft"
)

// Providers in page order.
var Providers = []string{Google, GitHub, Microsoft}

// Sources of the values in force.
const (
	SourceNone        = "none"
	SourceConsole     = "console"
	SourceEnvironment = "environment"
)

// Errors of the service.
var (
	ErrUnknownProvider     = fmt.Errorf("%w: unknown provider", shared.ErrValidation)
	ErrInvalid             = fmt.Errorf("%w: invalid social login settings", shared.ErrValidation)
	ErrLockedByEnvironment = errors.New("this provider is set by the server configuration")
	ErrNoActor             = errors.New("a social login change needs an administrator")
	ErrNoSecret            = errors.New("no client secret to check")
)

var (
	clientIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:@\-]{4,256}$`)
	secretRE   = regexp.MustCompile(`^[\x21-\x7e]{8,512}$`)
	scopeRE    = regexp.MustCompile(`^[A-Za-z0-9_.:/\-]{1,128}$`)
)

// maxScopes bounds the scope list of a provider.
const maxScopes = 20

// requiredScopes are the scopes the sign-in cannot work without: the id_token
// (openid) or the verified e-mail it is mapped from.
var requiredScopes = map[string][]string{
	Google:    {"openid", "email"},
	GitHub:    {"user:email"},
	Microsoft: {"openid", "email"},
}

// defaultScopes are used when none are stored.
var defaultScopes = map[string][]string{
	Google:    {"openid", "email", "profile"},
	GitHub:    {"read:user", "user:email"},
	Microsoft: {"openid", "email", "profile", "User.Read"},
}

// envVarOf names the variable that pins a provider.
func envVarOf(provider string) string {
	return "OAUTH_" + strings.ToUpper(provider) + "_CLIENT_SECRET"
}

// storedProvider is one provider's JSON. SecretEncrypted never leaves the
// service.
type storedProvider struct {
	Enabled         bool     `json:"enabled"`
	ClientID        string   `json:"client_id,omitempty"`
	SecretEncrypted string   `json:"secret_encrypted,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
}

// stored is the JSON kept in platform_settings.
type stored struct {
	Google    storedProvider `json:"google"`
	GitHub    storedProvider `json:"github"`
	Microsoft storedProvider `json:"microsoft"`
}

func (s *stored) of(provider string) *storedProvider {
	switch provider {
	case Google:
		return &s.Google
	case GitHub:
		return &s.GitHub
	case Microsoft:
		return &s.Microsoft
	}
	return nil
}

// ProviderSettings is what an administrator sees of one provider.
type ProviderSettings struct {
	Provider string
	Enabled  bool
	ClientID string
	// SecretSet says a client secret is stored; the secret itself is never
	// returned.
	SecretSet bool
	Scopes    []string
	// DefaultScopes are used when Scopes is empty.
	DefaultScopes []string
	// RedirectURI is what to register at this provider.
	RedirectURI string
	// Source: none, console or environment.
	Source              string
	LockedByEnvironment bool
	EnvVar              string
	// Active: sign-in with this provider is offered right now.
	Active bool
	// Undecryptable: a stored secret does not decrypt (the provider is off
	// until the secret is replaced).
	Undecryptable bool
}

// Settings is the whole page.
type Settings struct {
	Providers []ProviderSettings
	// MasterEnabled is OAUTH_ENABLED; false switches every provider off.
	MasterEnabled bool
	// JavaScriptOrigin is what to register as the authorized origin.
	JavaScriptOrigin string
	Version          int
	UpdatedAt        time.Time
	UpdatedBy        *shared.ID
}

// Input is a change to one provider. Secret: nil keeps the stored one, ""
// removes it, any other value replaces it. Scopes empty uses the defaults.
type Input struct {
	Enabled  bool
	ClientID string
	Secret   *string
	Scopes   []string
	Reason   string
}

// Service reads and changes the social login settings and answers the OAuth
// service which provider configuration is in force.
type Service struct {
	store     *consolesetting.Store[stored]
	encryptor crypto.Encryptor
	recorder  *consolesetting.Recorder
	env       config.OAuthConfig
	check     *tester
	log       *logger.Logger
}

// NewService creates the service. env is the environment configuration
// (OAUTH_*); a provider with an environment client secret is pinned.
func NewService(repo platformsetting.Repository, encryptor crypto.Encryptor, recorder *consolesetting.Recorder,
	env config.OAuthConfig, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{
		store: consolesetting.NewStore[stored](repo, SettingKey), encryptor: encryptor, recorder: recorder,
		env: env, check: newTester(), log: log.With("service", "platform_social_login"),
	}
}

func (s *Service) envOf(provider string) *config.OAuthProviderConfig {
	switch provider {
	case Google:
		return &s.env.Google
	case GitHub:
		return &s.env.GitHub
	case Microsoft:
		return &s.env.Microsoft
	}
	return nil
}

// LockedByEnvironment reports whether the environment pins a provider.
func (s *Service) LockedByEnvironment(provider string) bool {
	e := s.envOf(provider)
	return e != nil && strings.TrimSpace(e.ClientSecret) != ""
}

// resolved is a provider in force with its secret in clear (never leaves
// this package except to the OAuth service).
type resolved struct {
	cfg           config.OAuthProviderConfig
	source        string
	undecryptable bool
}

func (s *Service) resolve(st stored, provider string) resolved {
	if s.LockedByEnvironment(provider) {
		e := *s.envOf(provider)
		if len(e.Scopes) == 0 {
			e.Scopes = defaultScopes[provider]
		}
		return resolved{cfg: e, source: SourceEnvironment}
	}
	p := st.of(provider)
	if p == nil {
		return resolved{source: SourceNone}
	}
	out := resolved{cfg: config.OAuthProviderConfig{Enabled: p.Enabled, ClientID: p.ClientID, Scopes: p.Scopes}, source: SourceNone}
	if len(out.cfg.Scopes) == 0 {
		out.cfg.Scopes = defaultScopes[provider]
	}
	if p.ClientID != "" || p.SecretEncrypted != "" {
		out.source = SourceConsole
	}
	if p.SecretEncrypted != "" {
		plain, err := s.encryptor.DecryptString(p.SecretEncrypted)
		if err != nil {
			s.log.Error("social login secret does not decrypt (was APP_ENCRYPTION_KEY rotated without rekey?); the provider is off until the secret is replaced",
				"provider", provider, "error", err)
			out.cfg.Enabled = false
			out.undecryptable = true
			return out
		}
		out.cfg.ClientSecret = plain
	}
	return out
}

// OAuthProvider is the configuration in force for a provider: what the OAuth
// service uses on every authorize and callback. An unreadable setting turns
// the provider off (fail closed: no sign-in starts on a guess).
func (s *Service) OAuthProvider(ctx context.Context, provider string) config.OAuthProviderConfig {
	if !s.env.Enabled || s.envOf(provider) == nil {
		return config.OAuthProviderConfig{}
	}
	if s.LockedByEnvironment(provider) {
		return s.resolve(stored{}, provider).cfg
	}
	st, _, err := s.store.Get(ctx)
	if err != nil {
		s.log.Warn("social login setting unreadable; the provider is off (fail closed)", "provider", provider, "error", err)
		return config.OAuthProviderConfig{}
	}
	return s.resolve(st, provider).cfg
}

// Offered reports whether sign-in with the provider is offered right now.
func (s *Service) Offered(ctx context.Context, provider string) bool {
	cfg := s.OAuthProvider(ctx, provider)
	return cfg.IsConfigured()
}

// RedirectURI is the address to register at one provider: the web app's
// callback page of that provider (<callback base>/<provider>), the exact
// redirect_uri the sign-in sends and the configuration check uses.
func (s *Service) RedirectURI(provider string) string {
	base := strings.TrimRight(s.env.FrontendCallbackURL, "/")
	if base == "" {
		return ""
	}
	return base + "/" + provider
}

// Credentials is the client of a provider as stored or pinned, whether or not
// sign-in with it is offered (OAuthProvider answers empty for a provider that
// is not offered). It is the internal read path for features that reuse the
// platform's client, such as organization connections locked to it; the
// secret leaves this package only through this method, never through an API.
// ok is false when there is no usable client.
func (s *Service) Credentials(ctx context.Context, provider string) (cfg config.OAuthProviderConfig, ok bool) {
	if s.envOf(provider) == nil {
		return config.OAuthProviderConfig{}, false
	}
	var r resolved
	if s.LockedByEnvironment(provider) {
		r = s.resolve(stored{}, provider)
	} else {
		st, _, err := s.store.Get(ctx)
		if err != nil {
			s.log.Warn("social login setting unreadable", "provider", provider, "error", err)
			return config.OAuthProviderConfig{}, false
		}
		r = s.resolve(st, provider)
	}
	if r.undecryptable || r.cfg.ClientID == "" || r.cfg.ClientSecret == "" {
		return config.OAuthProviderConfig{}, false
	}
	return r.cfg, true
}

// JavaScriptOrigin is the origin of RedirectURI.
func (s *Service) JavaScriptOrigin() string {
	u, err := url.Parse(s.env.FrontendCallbackURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Get returns the settings without any secret.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{MasterEnabled: s.env.Enabled, JavaScriptOrigin: s.JavaScriptOrigin(),
		Version: m.Version, UpdatedAt: m.UpdatedAt, UpdatedBy: m.UpdatedBy}
	for _, name := range Providers {
		r := s.resolve(st, name)
		ps := ProviderSettings{
			Provider: name, Enabled: r.cfg.Enabled, ClientID: r.cfg.ClientID, SecretSet: r.cfg.ClientSecret != "" || r.undecryptable,
			Scopes: customScopes(name, r.cfg.Scopes), DefaultScopes: defaultScopes[name], Source: r.source,
			LockedByEnvironment: s.LockedByEnvironment(name), EnvVar: envVarOf(name), RedirectURI: s.RedirectURI(name),
			Active: s.env.Enabled && r.cfg.IsConfigured(), Undecryptable: r.undecryptable,
		}
		if sp := st.of(name); sp != nil && !ps.LockedByEnvironment {
			ps.Enabled = sp.Enabled
		}
		out.Providers = append(out.Providers, ps)
	}
	return out, nil
}

// customScopes is the scope list when it differs from the defaults.
func customScopes(provider string, scopes []string) []string {
	def := defaultScopes[provider]
	if len(scopes) != len(def) {
		return scopes
	}
	for i := range def {
		if def[i] != scopes[i] {
			return scopes
		}
	}
	return nil
}

func validate(provider string, in *Input, next *storedProvider) error {
	in.ClientID = strings.TrimSpace(in.ClientID)
	if in.ClientID != "" && !clientIDRE.MatchString(in.ClientID) {
		return fmt.Errorf("%w: the client ID has an unexpected shape", ErrInvalid)
	}
	if in.Secret != nil {
		v := strings.TrimSpace(*in.Secret)
		if v != "" && !secretRE.MatchString(v) {
			return fmt.Errorf("%w: the client secret has an unexpected shape", ErrInvalid)
		}
		in.Secret = &v
	}
	if len(in.Scopes) > maxScopes {
		return fmt.Errorf("%w: at most %d scopes", ErrInvalid, maxScopes)
	}
	seen := map[string]bool{}
	scopes := make([]string, 0, len(in.Scopes))
	for _, sc := range in.Scopes {
		sc = strings.TrimSpace(sc)
		if sc == "" || seen[sc] {
			continue
		}
		if !scopeRE.MatchString(sc) {
			return fmt.Errorf("%w: a scope has an unexpected shape", ErrInvalid)
		}
		seen[sc] = true
		scopes = append(scopes, sc)
	}
	if len(scopes) > 0 {
		for _, need := range requiredScopes[provider] {
			if !seen[need] {
				return fmt.Errorf("%w: the scope %q is required for sign-in", ErrInvalid, need)
			}
		}
	}
	in.Scopes = scopes
	next.Scopes = scopes
	return nil
}

// Update replaces one provider's settings. The caller checked the actor's
// role and a fresh confirmation. expectedVersion is the version read (0:
// nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, provider string, in Input, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if s.envOf(provider) == nil {
		return Settings{}, ErrUnknownProvider
	}
	if s.LockedByEnvironment(provider) {
		return Settings{}, ErrLockedByEnvironment
	}
	reason, err := consolesetting.CheckReason(in.Reason)
	if err != nil {
		return Settings{}, err
	}
	prev, _, err := s.store.Fresh(ctx)
	if err != nil {
		return Settings{}, err
	}
	next := prev
	np := next.of(provider)
	old := *prev.of(provider)
	np.ClientID, np.Enabled = "", in.Enabled
	if err := validate(provider, &in, np); err != nil {
		return Settings{}, err
	}
	np.ClientID = in.ClientID
	secretChanged := false
	if in.Secret != nil {
		secretChanged = true
		np.SecretEncrypted = ""
		if *in.Secret != "" {
			enc, err := s.encryptor.EncryptString(*in.Secret)
			if err != nil {
				return Settings{}, fmt.Errorf("encrypt social login secret: %w", err)
			}
			np.SecretEncrypted = enc
		}
	}
	if (np.ClientID == "") != (np.SecretEncrypted == "") {
		return Settings{}, fmt.Errorf("%w: set the client ID and the client secret together, or remove both", ErrInvalid)
	}
	if np.Enabled && np.ClientID == "" {
		return Settings{}, fmt.Errorf("%w: a provider needs a client ID and a client secret before it can be turned on", ErrInvalid)
	}
	if _, err := s.store.Put(ctx, next, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Social login (" + provider + ")",
		Method: "PUT", Path: "/api/v1/admin/settings/social-login/" + provider, Reason: reason,
		Details: map[string]any{
			"provider":           provider,
			"previous_enabled":   old.Enabled,
			"enabled":            np.Enabled,
			"previous_client_id": old.ClientID,
			"client_id":          np.ClientID,
			"scopes":             np.Scopes,
			// Never the value: only that it changed.
			"secret_changed": secretChanged,
		},
		Critical: true, Notify: true,
	}, ip, userAgent)
	return s.Get(ctx)
}

// Check asks the provider's token endpoint whether it accepts the client:
// candidate secret when given (before saving it), otherwise the secret in
// force. The address it asks is fixed; the secret is never stored, logged or
// returned.
func (s *Service) Check(ctx context.Context, provider, clientID, candidateSecret string) (Result, error) {
	if s.envOf(provider) == nil {
		return "", ErrUnknownProvider
	}
	clientID, secret := strings.TrimSpace(clientID), strings.TrimSpace(candidateSecret)
	if clientID != "" && !clientIDRE.MatchString(clientID) {
		return ResultInvalid, nil
	}
	if secret != "" && !secretRE.MatchString(secret) {
		return ResultInvalid, nil
	}
	if clientID == "" || secret == "" {
		var inForce resolved
		if s.LockedByEnvironment(provider) {
			inForce = s.resolve(stored{}, provider)
		} else {
			st, _, err := s.store.Fresh(ctx)
			if err != nil {
				return "", err
			}
			inForce = s.resolve(st, provider)
		}
		if clientID == "" {
			clientID = inForce.cfg.ClientID
		}
		if secret == "" {
			secret = inForce.cfg.ClientSecret
		}
	}
	if clientID == "" || secret == "" {
		return "", ErrNoSecret
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.check.check(cctx, provider, clientID, secret, s.RedirectURI(provider)), nil
}
