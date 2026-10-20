// Package platformai is the platform's own AI provider: the provider, model
// and API key that organizations in "platform" AI mode use, set by a
// platform administrator in the console (Settings > AI provider) instead of
// AI_PLATFORM_PROVIDER, AI_PLATFORM_MODEL and ANTHROPIC/OPENAI/GEMINI_API_KEY
// and a restart. Organizations can always bring their own key instead.
//
// It is off by default: nothing is sent to an AI provider until an
// administrator turns it on with a key. A platform key is a cost and a
// subprocessor of every organization's findings, so a change needs a super
// admin, a fresh confirmation, a reason, a critical audit row and a notice
// to every administrator. The key is encrypted with APP_ENCRYPTION_KEY and
// write-only.
//
// The environment pins the provider: when any of ANTHROPIC_API_KEY,
// OPENAI_API_KEY or GEMINI_API_KEY is set, the environment configuration is
// used and the console shows it as locked.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package platformai

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "ai.platform"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.ai_provider_changed"

// Providers the platform can use.
var Providers = []string{"claude", "openai", "gemini", llm.ProviderOpenAICompatible}

// maxAllowedModels bounds the model allow-list.
const maxAllowedModels = 50

// EnvKeys are the environment variables that pin the provider.
var EnvKeys = []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"}

// Errors of the service.
var (
	ErrLockedByEnvironment = errors.New("the platform AI provider is set by the server configuration (ANTHROPIC_API_KEY, OPENAI_API_KEY or GEMINI_API_KEY)")
	ErrInvalid             = fmt.Errorf("%w: invalid AI provider settings", shared.ErrValidation)
	ErrNoActor             = errors.New("an AI provider change needs an administrator")
	ErrNotConfigured       = errors.New("the platform AI provider is not configured")
)

var (
	modelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,127}$`)
	keyRE   = regexp.MustCompile(`^[\x21-\x7e]{8,512}$`)
)

type stored struct {
	Enabled      bool   `json:"enabled"`
	Provider     string `json:"provider,omitempty"`
	Model        string `json:"model,omitempty"`
	KeyEncrypted string `json:"key_encrypted,omitempty"`
	// BaseURL is the OpenAI-compatible server (openai_compatible only).
	BaseURL string `json:"base_url,omitempty"`
	// AllowPrivate lets the base URL be on a private network (RFC1918 / ULA)
	// and plain http: a self-hosted model server. Never applies to an
	// organization's own provider.
	AllowPrivate bool `json:"allow_private,omitempty"`
	// AllowedModels, when not empty, limits the models the platform
	// provider (and an organization that picks a model on it) may use.
	AllowedModels []string `json:"allowed_models,omitempty"`
}

// usable reports whether the stored configuration can make a call: an
// OpenAI-compatible server may run without a key, any other provider needs one.
func (st stored) usable() bool {
	if st.Provider == "" || st.Model == "" {
		return false
	}
	if st.Provider == llm.ProviderOpenAICompatible {
		return st.BaseURL != ""
	}
	return st.KeyEncrypted != ""
}

// Platform is the configuration the AI client uses.
type Platform struct {
	Provider     string
	Model        string
	APIKey       string
	BaseURL      string
	AllowPrivate bool
}

// Settings is what an administrator sees: never the key.
type Settings struct {
	Enabled             bool
	Provider            string
	Model               string
	BaseURL             string
	AllowPrivate        bool
	AllowedModels       []string
	KeySet              bool
	LockedByEnvironment bool
	Version             int
	UpdatedAt           time.Time
	UpdatedBy           *shared.ID
}

// Input is a change. APIKey: nil keeps the stored key, "" removes it, any
// other value replaces it.
type Input struct {
	Enabled  bool
	Provider string
	Model    string
	APIKey   *string
	Reason   string
	// BaseURL, AllowPrivate and AllowedModels: see stored.
	BaseURL       string
	AllowPrivate  bool
	AllowedModels []string
}

// Tester sends one minimal request with a configuration (the AI client
// factory); nil error means the provider accepted the key.
type Tester func(ctx context.Context, p Platform) error

// Service reads and changes the platform AI provider.
type Service struct {
	store       *consolesetting.Store[stored]
	encryptor   crypto.Encryptor
	recorder    *consolesetting.Recorder
	envLocked   bool
	envProvider string
	envModel    string
	tester      Tester
	log         *logger.Logger
}

// NewService creates the service. envLocked reports that an environment key
// is set; envProvider and envModel are then shown as the configuration.
func NewService(repo platformsetting.Repository, encryptor crypto.Encryptor, recorder *consolesetting.Recorder,
	envLocked bool, envProvider, envModel string, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), encryptor: encryptor, recorder: recorder,
		envLocked: envLocked, envProvider: envProvider, envModel: envModel, log: log.With("service", "platform_ai")}
}

// SetTester wires the key test.
func (s *Service) SetTester(t Tester) { s.tester = t }

// LockedByEnvironment reports whether an environment key pins the provider.
func (s *Service) LockedByEnvironment() bool { return s.envLocked }

// Platform returns the console configuration when it is on and usable. It
// never reports the environment configuration (the client reads that
// itself). A key that does not decrypt is "not usable" and logged.
func (s *Service) Platform(ctx context.Context) (Platform, bool) {
	if s.envLocked {
		return Platform{}, false
	}
	st, _, err := s.store.Get(ctx)
	if err != nil {
		s.log.Warn("platform AI setting unreadable; platform AI off", "error", err)
		return Platform{}, false
	}
	if !st.Enabled || !st.usable() {
		return Platform{}, false
	}
	var key string
	if st.KeyEncrypted != "" {
		key, err = s.encryptor.DecryptString(st.KeyEncrypted)
		if err != nil {
			s.log.Error("platform AI key does not decrypt (was APP_ENCRYPTION_KEY rotated without rekey?); platform AI off")
			return Platform{}, false
		}
	}
	return Platform{Provider: st.Provider, Model: st.Model, APIKey: key, BaseURL: st.BaseURL, AllowPrivate: st.AllowPrivate}, true
}

// PlatformAIEndpoint is the OpenAI-compatible base URL of the platform
// provider and whether it may be on a private network.
func (s *Service) PlatformAIEndpoint(ctx context.Context) (baseURL string, allowPrivate bool) {
	p, _ := s.Platform(ctx)
	return p.BaseURL, p.AllowPrivate
}

// ModelAllowed reports whether model may be used on the platform provider:
// always when no allow-list is set.
func (s *Service) ModelAllowed(ctx context.Context, model string) bool {
	st, _, err := s.store.Get(ctx)
	if err != nil || len(st.AllowedModels) == 0 {
		return err == nil
	}
	return slices.Contains(st.AllowedModels, model)
}

// PlatformAI is Platform in the shape the AI client factory asks for.
func (s *Service) PlatformAI(ctx context.Context) (provider, model, apiKey string, ok bool) {
	p, ok := s.Platform(ctx)
	return p.Provider, p.Model, p.APIKey, ok
}

// Enabled reports whether the console turned platform AI on with a key.
func (s *Service) Enabled(ctx context.Context) bool {
	_, ok := s.Platform(ctx)
	return ok
}

// Get returns the settings without the key.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	if s.envLocked {
		return Settings{Enabled: true, Provider: s.envProvider, Model: s.envModel, KeySet: true, LockedByEnvironment: true}, nil
	}
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	return Settings{Enabled: st.Enabled, Provider: st.Provider, Model: st.Model, BaseURL: st.BaseURL,
		AllowPrivate: st.AllowPrivate, AllowedModels: st.AllowedModels, KeySet: st.KeyEncrypted != "",
		Version: m.Version, UpdatedAt: m.UpdatedAt, UpdatedBy: m.UpdatedBy}, nil
}

// Update replaces the settings. The caller checked the actor's role and a
// fresh confirmation. expectedVersion is the version read (0: nothing
// stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, in Input, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if s.envLocked {
		return Settings{}, ErrLockedByEnvironment
	}
	reason, err := consolesetting.CheckReason(in.Reason)
	if err != nil {
		return Settings{}, err
	}
	in.Provider, in.Model = strings.TrimSpace(in.Provider), strings.TrimSpace(in.Model)
	if in.Provider != "" && !slices.Contains(Providers, in.Provider) {
		return Settings{}, fmt.Errorf("%w: the provider must be one of %s", ErrInvalid, strings.Join(Providers, ", "))
	}
	if in.Model != "" && !modelRE.MatchString(in.Model) {
		return Settings{}, fmt.Errorf("%w: the model name has an unexpected shape", ErrInvalid)
	}
	models, err := cleanModels(in.AllowedModels)
	if err != nil {
		return Settings{}, err
	}
	if len(models) > 0 && in.Model != "" && !slices.Contains(models, in.Model) {
		return Settings{}, fmt.Errorf("%w: the model must be one of the allowed models", ErrInvalid)
	}
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	if in.Provider == llm.ProviderOpenAICompatible {
		// SECURITY: a private address is reachable only with the explicit
		// toggle, never loopback, link-local or cloud metadata.
		in.BaseURL, err = llm.ValidateBaseURL(ctx, in.BaseURL, in.AllowPrivate)
		if err != nil {
			return Settings{}, fmt.Errorf("%w: %s", ErrInvalid, strings.TrimPrefix(err.Error(), llm.ErrInvalidProvider.Error()+": "))
		}
	} else {
		in.BaseURL, in.AllowPrivate = "", false
	}
	prev, _, err := s.store.Fresh(ctx)
	if err != nil {
		return Settings{}, err
	}
	next := stored{Enabled: in.Enabled, Provider: in.Provider, Model: in.Model, KeyEncrypted: prev.KeyEncrypted,
		BaseURL: in.BaseURL, AllowPrivate: in.AllowPrivate, AllowedModels: models}
	keyChanged := false
	if in.APIKey != nil {
		keyChanged = true
		next.KeyEncrypted = ""
		if v := strings.TrimSpace(*in.APIKey); v != "" {
			if !keyRE.MatchString(v) {
				return Settings{}, fmt.Errorf("%w: the API key must be 8-512 printable characters without spaces", ErrInvalid)
			}
			enc, err := s.encryptor.EncryptString(v)
			if err != nil {
				return Settings{}, fmt.Errorf("encrypt AI key: %w", err)
			}
			next.KeyEncrypted = enc
		}
	}
	// A key belongs to one provider: switching providers needs a new key.
	if prev.Provider != "" && next.Provider != prev.Provider && !keyChanged {
		next.KeyEncrypted = ""
	}
	if next.Enabled && !next.usable() {
		return Settings{}, fmt.Errorf("%w: choose a provider and a model and set its key (an OpenAI-compatible server: its base URL) to turn platform AI on", ErrInvalid)
	}
	if _, err := s.store.Put(ctx, next, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Platform AI provider",
		Method: "PUT", Path: "/api/v1/admin/settings/ai", Reason: reason,
		Details: map[string]any{
			"previous_enabled": prev.Enabled, "enabled": next.Enabled,
			"previous_provider": prev.Provider, "provider": next.Provider,
			"previous_model": prev.Model, "model": next.Model,
			"previous_base_url": prev.BaseURL, "base_url": next.BaseURL,
			"previous_allow_private": prev.AllowPrivate, "allow_private": next.AllowPrivate,
			"allowed_models": next.AllowedModels,
			// Never the value: only that it changed.
			"key_changed": keyChanged || (prev.KeyEncrypted != "" && next.KeyEncrypted == ""),
		},
		Critical: true, Notify: true,
	}, ip, userAgent)
	return s.Get(ctx)
}

// Test sends one minimal request with the stored configuration (whether or
// not it is turned on). The provider's answer is not returned.
func (s *Service) Test(ctx context.Context) error {
	if s.tester == nil {
		return ErrNotConfigured
	}
	var p Platform
	if s.envLocked {
		return ErrLockedByEnvironment
	}
	st, _, err := s.store.Fresh(ctx)
	if err != nil {
		return err
	}
	if !st.usable() {
		return ErrNotConfigured
	}
	var key string
	if st.KeyEncrypted != "" {
		key, err = s.encryptor.DecryptString(st.KeyEncrypted)
		if err != nil {
			return ErrNotConfigured
		}
	}
	p = Platform{Provider: st.Provider, Model: st.Model, APIKey: key, BaseURL: st.BaseURL, AllowPrivate: st.AllowPrivate}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.tester(cctx, p)
}

// cleanModels trims, validates and de-duplicates the model allow-list.
func cleanModels(in []string) ([]string, error) {
	if len(in) > maxAllowedModels {
		return nil, fmt.Errorf("%w: at most %d allowed models", ErrInvalid, maxAllowedModels)
	}
	out := make([]string, 0, len(in))
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" || slices.Contains(out, m) {
			continue
		}
		if !modelRE.MatchString(m) {
			return nil, fmt.Errorf("%w: an allowed model name has an unexpected shape", ErrInvalid)
		}
		out = append(out, m)
	}
	return out, nil
}
