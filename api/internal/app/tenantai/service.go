// Package tenantai is an organization's AI settings: whether AI triage is
// turned on (consent), where the AI comes from (the platform's provider, the
// organization's own provider, or off), the own provider's kind, base URL,
// model and write-only key, and a "test connection" call.
//
// Security model (docs/architecture/ai-triage.md):
//
//   - Reads and writes are scoped to one organization; the API checks the
//     role and a recent sign-in before the service runs.
//   - The key is encrypted with APP_ENCRYPTION_KEY, never returned (only
//     "set", its last four characters and when and by whom it was set) and
//     never audited. A stored key is only ever sent to the endpoint it was
//     entered for: changing the provider or the base URL drops it.
//   - An own provider's base URL is public-only and https-only (the platform
//     toggle for private addresses never applies), vetted at save time and at
//     every connection by the SSRF-safe client.
//   - The platform may forbid own providers; the service refuses to select
//     one and the AI worker refuses to use one, without falling back to the
//     platform key.
//   - Every change is audited as critical, a test as low; neither records
//     the key.
package tenantai

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/internal/app/aitriage"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Sources an organization can choose.
const (
	SourcePlatform = "platform"
	SourceOwn      = "own"
	SourceOff      = "off"
)

// Providers an organization can bring.
var Providers = []string{"claude", "openai", "gemini", llm.ProviderOpenAICompatible}

// Errors of the service.
var (
	ErrInvalid               = fmt.Errorf("%w: invalid AI settings", shared.ErrValidation)
	ErrOwnProviderNotAllowed = aitriage.ErrOwnProviderNotAllowed
	ErrTooManyTests          = errors.New("too many connection tests; wait a moment")
	ErrNoActor               = fmt.Errorf("%w: turning AI triage on needs a signed-in administrator", shared.ErrValidation)
)

var (
	modelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,127}$`)
	keyRE   = regexp.MustCompile(`^[\x21-\x7e]{8,512}$`)
)

// OrgPolicy is the platform policy on organizations' own providers.
type OrgPolicy interface {
	OrgProviderAllowed(ctx context.Context) bool
}

// ProviderBuilder builds a provider from a configuration (*llm.Factory).
type ProviderBuilder interface {
	BuildPlatformProvider(spec llm.Spec) (llm.Provider, error)
}

// Service reads and changes an organization's AI settings.
type Service struct {
	repo      tenant.AISettingsRepository
	encryptor crypto.Encryptor
	audit     *auditapp.AuditService
	builder   ProviderBuilder
	policy    OrgPolicy
	log       *logger.Logger

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	now      func() time.Time
}

// NewService creates the service. policy may be nil (own providers allowed).
func NewService(repo tenant.AISettingsRepository, encryptor crypto.Encryptor, auditSvc *auditapp.AuditService,
	builder ProviderBuilder, policy OrgPolicy, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, encryptor: encryptor, audit: auditSvc, builder: builder, policy: policy,
		log: log.With("service", "tenant_ai"), limiters: map[string]*rate.Limiter{}, now: time.Now}
}

// View is what an administrator sees: never the key.
type View struct {
	Enabled   bool
	EnabledAt *time.Time
	EnabledBy string
	Source    string
	Provider  string
	BaseURL   string
	Model     string
	KeySet    bool
	KeyLast4  string
	// KeyUpdatedAt / KeyUpdatedBy: when and by whom the key was set.
	KeyUpdatedAt *time.Time
	KeyUpdatedBy string
	UpdatedAt    *time.Time
	UpdatedBy    string
	// OwnProviderAllowed is the platform policy.
	OwnProviderAllowed bool
}

// Update is a partial change: nil fields keep their value. APIKey: nil keeps
// the stored key, "" removes it, any other value replaces it.
type Update struct {
	Enabled  *bool
	Source   *string
	Provider *string
	BaseURL  *string
	Model    *string
	APIKey   *string
}

// stamp is the current time at the precision the database keeps.
func (s *Service) stamp() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

func (s *Service) ownAllowed(ctx context.Context) bool {
	return s.policy == nil || s.policy.OrgProviderAllowed(ctx)
}

func source(m tenant.AIMode) string {
	switch m {
	case tenant.AIModeBYOK:
		return SourceOwn
	case tenant.AIModeDisabled:
		return SourceOff
	default:
		return SourcePlatform
	}
}

func (s *Service) view(ctx context.Context, a tenant.AISettings) View {
	return View{
		Enabled: a.OptedIn(), EnabledAt: a.EnabledAt, EnabledBy: a.EnabledBy,
		Source: source(a.Mode), Provider: string(a.Provider), BaseURL: a.BaseURL, Model: a.ModelOverride,
		KeySet: a.APIKey != "", KeyLast4: a.KeyLast4, KeyUpdatedAt: a.KeyUpdatedAt, KeyUpdatedBy: a.KeyUpdatedBy,
		UpdatedAt: a.UpdatedAt, UpdatedBy: a.UpdatedBy, OwnProviderAllowed: s.ownAllowed(ctx),
	}
}

// Get returns the organization's AI settings without the key.
func (s *Service) Get(ctx context.Context, tenantID string) (View, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return View{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	a, err := s.repo.Get(ctx, tid, tenant.AISettings{})
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, a), nil
}

// Save applies a change and audits it as critical (never the key).
//
//nolint:cyclop,gocognit // one linear validation of a partial update
func (s *Service) Save(ctx context.Context, tenantID string, in Update, actx auditapp.AuditContext) (View, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return View{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	cur, err := s.repo.Get(ctx, tid, tenant.AISettings{})
	if err != nil {
		return View{}, err
	}
	next := cur
	if next.Mode == "" {
		next.Mode = tenant.AIModePlatform
	}

	if in.Enabled != nil && *in.Enabled != cur.OptedIn() {
		if *in.Enabled && actx.ActorID == "" {
			return View{}, ErrNoActor
		}
		next.SetOptIn(*in.Enabled, actx.ActorID, s.stamp())
	}
	if in.Source != nil {
		switch *in.Source {
		case SourcePlatform:
			next.Mode = tenant.AIModePlatform
		case SourceOwn:
			next.Mode = tenant.AIModeBYOK
		case SourceOff:
			next.Mode = tenant.AIModeDisabled
		default:
			return View{}, fmt.Errorf("%w: the source must be platform, own or off", ErrInvalid)
		}
	}
	if next.Mode == tenant.AIModeBYOK && !s.ownAllowed(ctx) {
		return View{}, ErrOwnProviderNotAllowed
	}
	if in.Provider != nil {
		p := strings.TrimSpace(*in.Provider)
		if p != "" && !tenant.LLMProvider(p).IsValid() {
			return View{}, fmt.Errorf("%w: the provider must be one of %s", ErrInvalid, strings.Join(Providers, ", "))
		}
		next.Provider = tenant.LLMProvider(p)
	}
	if in.BaseURL != nil {
		next.BaseURL = strings.TrimSpace(*in.BaseURL)
	}
	if in.Model != nil {
		m := strings.TrimSpace(*in.Model)
		if m != "" && !modelRE.MatchString(m) {
			return View{}, fmt.Errorf("%w: the model name has an unexpected shape", ErrInvalid)
		}
		next.ModelOverride = m
	}
	if next.Provider != tenant.LLMProviderOpenAICompatible {
		next.BaseURL = ""
	}

	// SECURITY: a stored key is sent only to the endpoint it was entered for.
	keyChanged := false
	if next.Provider != cur.Provider || next.BaseURL != cur.BaseURL {
		if cur.APIKey != "" && in.APIKey == nil {
			keyChanged = true
		}
		next.APIKey, next.KeyLast4, next.KeyUpdatedAt, next.KeyUpdatedBy = "", "", nil, ""
	}
	if in.APIKey != nil {
		keyChanged = true
		next.APIKey, next.KeyLast4, next.KeyUpdatedAt, next.KeyUpdatedBy = "", "", nil, ""
		if v := strings.TrimSpace(*in.APIKey); v != "" {
			if !keyRE.MatchString(v) {
				return View{}, fmt.Errorf("%w: the API key must be 8-512 printable characters without spaces", ErrInvalid)
			}
			enc, err := s.encryptor.EncryptString(v)
			if err != nil {
				return View{}, fmt.Errorf("encrypt AI key: %w", err)
			}
			now := s.stamp()
			next.APIKey, next.KeyLast4, next.KeyUpdatedAt, next.KeyUpdatedBy = enc, v[len(v)-4:], &now, actx.ActorID
		}
	}

	// An own provider that is selected must be complete and its URL safe.
	if next.Mode == tenant.AIModeBYOK {
		if err := s.checkComplete(ctx, next); err != nil {
			return View{}, err
		}
	}
	if next.BaseURL != "" && (next.BaseURL != cur.BaseURL || (next.Mode == tenant.AIModeBYOK && cur.Mode != tenant.AIModeBYOK)) {
		// A new URL is vetted even while the source is not "own", so a stored
		// URL is never an unsafe one.
		norm, err := llm.ValidateBaseURL(ctx, next.BaseURL, false)
		if err != nil {
			return View{}, fmt.Errorf("%w: %s", ErrInvalid, urlReason(err))
		}
		next.BaseURL = norm
	}

	now := s.stamp()
	next.UpdatedAt, next.UpdatedBy = &now, actx.ActorID
	if err := s.repo.Save(ctx, tid, next, cur.UpdatedAt); err != nil {
		return View{}, err
	}

	if changed := cur.OptedIn() != next.OptedIn() || cur.Mode != next.Mode || cur.Provider != next.Provider ||
		cur.BaseURL != next.BaseURL || cur.ModelOverride != next.ModelOverride || keyChanged; changed {
		actx.TenantID = tenantID
		event := auditapp.NewSuccessEvent(audit.ActionAISettingsUpdated, audit.ResourceTypeTenant, tenantID).
			WithChanges(auditapp.DiffChanges(
				map[string]any{"enabled": cur.OptedIn(), "source": source(cur.Mode), "provider": string(cur.Provider),
					"base_url": cur.BaseURL, "model": cur.ModelOverride, "key_set": cur.APIKey != ""},
				map[string]any{"enabled": next.OptedIn(), "source": source(next.Mode), "provider": string(next.Provider),
										"base_url": next.BaseURL, "model": next.ModelOverride, "key_set": next.APIKey != ""})).
			WithMetadata("key_changed", keyChanged). // never the key
			WithMessage(auditMessage(cur, next, keyChanged)).
			WithSeverity(audit.SeverityCritical)
		s.logAudit(ctx, actx, event)
	}
	return s.view(ctx, next), nil
}

func auditMessage(cur, next tenant.AISettings, keyChanged bool) string {
	switch {
	case cur.OptedIn() != next.OptedIn() && next.OptedIn():
		return "AI triage turned on: finding content may be sent to the AI provider"
	case cur.OptedIn() != next.OptedIn():
		return "AI triage turned off: finding content is no longer sent to the AI provider"
	case keyChanged:
		return "The organization's own AI provider key changed"
	default:
		return "The organization's AI source or provider changed"
	}
}

func urlReason(err error) string {
	return strings.TrimPrefix(err.Error(), llm.ErrInvalidProvider.Error()+": ")
}

// checkComplete refuses an own provider that cannot work yet.
func (s *Service) checkComplete(ctx context.Context, a tenant.AISettings) error {
	_ = ctx
	if a.Provider == "" {
		return fmt.Errorf("%w: choose a provider to use your own", ErrInvalid)
	}
	if a.Provider == tenant.LLMProviderOpenAICompatible {
		if a.BaseURL == "" || a.ModelOverride == "" {
			return fmt.Errorf("%w: an OpenAI-compatible provider needs a base URL and a model", ErrInvalid)
		}
		return nil // the key is optional for it
	}
	if a.APIKey == "" {
		return fmt.Errorf("%w: set the provider's API key to use your own", ErrInvalid)
	}
	return nil
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.log.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// TestResult is the answer of a connection test. Code is a fixed value, never
// the provider's text.
type TestResult struct {
	OK   bool
	Code string
}

// Test codes.
const (
	TestOK             = "ok"
	TestBlockedAddress = "blocked_address"
	TestInvalidURL     = "invalid_url"
	TestKeyRequired    = "key_required"
	TestNotConfigured  = "not_configured"
	TestAuthFailed     = "auth_failed"
	TestRateLimited    = "rate_limited"
	TestTimeout        = "timeout"
	TestUnreachable    = "unreachable"
	TestProviderError  = "provider_error"
)

// testPrompt is the whole of what a test sends: no finding data.
const testPrompt = "Reply with OK."

// Test calls the provider with one tiny prompt. The values to test are the
// ones in "in" (what is on the form) over the stored ones; the stored key is
// used only when the provider and base URL are the stored ones. The call is
// server-side, SSRF-guarded and rate limited per organization.
func (s *Service) Test(ctx context.Context, tenantID string, in Update, actx auditapp.AuditContext) (TestResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return TestResult{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	if !s.ownAllowed(ctx) {
		return TestResult{}, ErrOwnProviderNotAllowed
	}
	if !s.allow(tenantID) {
		return TestResult{}, ErrTooManyTests
	}
	cur, err := s.repo.Get(ctx, tid, tenant.AISettings{})
	if err != nil {
		return TestResult{}, err
	}
	provider, baseURL, model := string(cur.Provider), cur.BaseURL, cur.ModelOverride
	if in.Provider != nil {
		provider = strings.TrimSpace(*in.Provider)
	}
	if in.BaseURL != nil {
		baseURL = strings.TrimSpace(*in.BaseURL)
	}
	if in.Model != nil {
		model = strings.TrimSpace(*in.Model)
	}
	res := s.runTest(ctx, cur, in, provider, baseURL, model)

	actx.TenantID = tenantID
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionAISettingsTested, audit.ResourceTypeTenant, tenantID).
		WithMetadata("provider", provider).WithMetadata("ok", res.OK).WithMetadata("code", res.Code).
		WithMessage("The organization's own AI provider was tested"))
	return res, nil
}

func (s *Service) runTest(ctx context.Context, cur tenant.AISettings, in Update, provider, baseURL, model string) TestResult {
	if !tenant.LLMProvider(provider).IsValid() || (model != "" && !modelRE.MatchString(model)) {
		return TestResult{Code: TestNotConfigured}
	}
	if tenant.LLMProvider(provider) != tenant.LLMProviderOpenAICompatible {
		baseURL = ""
	}
	var key string
	switch {
	case in.APIKey != nil && strings.TrimSpace(*in.APIKey) != "":
		key = strings.TrimSpace(*in.APIKey)
		if !keyRE.MatchString(key) {
			return TestResult{Code: TestKeyRequired}
		}
	case in.APIKey != nil: // explicit empty: no key
	case cur.APIKey != "":
		// SECURITY: never send the stored key to another endpoint.
		if string(cur.Provider) != provider || cur.BaseURL != baseURL {
			return TestResult{Code: TestKeyRequired}
		}
		plain, err := s.encryptor.DecryptString(cur.APIKey)
		if err != nil {
			s.log.Error("organization AI key does not decrypt (was APP_ENCRYPTION_KEY rotated without rekey?)")
			return TestResult{Code: TestNotConfigured}
		}
		key = plain
	}
	if tenant.LLMProvider(provider) == tenant.LLMProviderOpenAICompatible {
		if baseURL == "" || model == "" {
			return TestResult{Code: TestNotConfigured}
		}
		norm, err := llm.ValidateBaseURL(ctx, baseURL, false)
		if err != nil {
			return TestResult{Code: urlCode(err)}
		}
		baseURL = norm
	} else if key == "" {
		return TestResult{Code: TestKeyRequired}
	}
	// SECURITY: AllowPrivate is never set for an organization.
	p, err := s.builder.BuildPlatformProvider(llm.Spec{Provider: provider, Model: model, APIKey: key, BaseURL: baseURL})
	if err != nil {
		return TestResult{Code: TestNotConfigured}
	}
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if _, err := p.Complete(cctx, llm.CompletionRequest{UserPrompt: testPrompt, MaxTokens: 1}); err != nil {
		return TestResult{Code: testCode(err)}
	}
	return TestResult{OK: true, Code: TestOK}
}

func urlCode(err error) string {
	if strings.Contains(err.Error(), "not allowed") || strings.Contains(err.Error(), "blocked") {
		return TestBlockedAddress
	}
	return TestInvalidURL
}

// testCode maps a provider error to a fixed code.
func testCode(err error) string {
	if strings.Contains(strings.ToLower(err.Error()), "ssrf guard") {
		return TestBlockedAddress
	}
	switch aitriage.FailureCode(err) {
	case aitriage.FailAuth:
		return TestAuthFailed
	case aitriage.FailRateLimited:
		return TestRateLimited
	case aitriage.FailTimeout:
		return TestTimeout
	case aitriage.FailUnavailable:
		return TestUnreachable
	default:
		return TestProviderError
	}
}

// allow spends one connection test of the organization: a burst of 3, then
// one every 5 seconds.
func (s *Service) allow(tenantID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.limiters[tenantID]
	if !ok {
		if len(s.limiters) > 10000 {
			s.limiters = map[string]*rate.Limiter{}
		}
		l = rate.NewLimiter(rate.Every(5*time.Second), 3)
		s.limiters[tenantID] = l
	}
	return l.Allow()
}
