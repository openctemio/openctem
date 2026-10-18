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
var Providers = []string{"claude", "openai", "gemini"}

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
}

// Platform is the configuration the AI client uses.
type Platform struct {
	Provider string
	Model    string
	APIKey   string
}

// Settings is what an administrator sees: never the key.
type Settings struct {
	Enabled             bool
	Provider            string
	Model               string
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
	if !st.Enabled || st.KeyEncrypted == "" {
		return Platform{}, false
	}
	key, err := s.encryptor.DecryptString(st.KeyEncrypted)
	if err != nil {
		s.log.Error("platform AI key does not decrypt (was APP_ENCRYPTION_KEY rotated without rekey?); platform AI off")
		return Platform{}, false
	}
	return Platform{Provider: st.Provider, Model: st.Model, APIKey: key}, true
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
	return Settings{Enabled: st.Enabled, Provider: st.Provider, Model: st.Model, KeySet: st.KeyEncrypted != "",
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
	prev, _, err := s.store.Fresh(ctx)
	if err != nil {
		return Settings{}, err
	}
	next := stored{Enabled: in.Enabled, Provider: in.Provider, Model: in.Model, KeyEncrypted: prev.KeyEncrypted}
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
	if next.Enabled && (next.Provider == "" || next.Model == "" || next.KeyEncrypted == "") {
		return Settings{}, fmt.Errorf("%w: choose a provider and a model and set its key to turn platform AI on", ErrInvalid)
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
	if st.Provider == "" || st.Model == "" || st.KeyEncrypted == "" {
		return ErrNotConfigured
	}
	key, err := s.encryptor.DecryptString(st.KeyEncrypted)
	if err != nil {
		return ErrNotConfigured
	}
	p = Platform{Provider: st.Provider, Model: st.Model, APIKey: key}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.tester(cctx, p)
}
