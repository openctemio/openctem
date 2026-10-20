package tenantai

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// --- fakes ---------------------------------------------------------------

type fakeRepo struct {
	mu   sync.Mutex
	rows map[shared.ID]tenant.AISettings
	// conflictNext simulates a concurrent writer winning between read and write.
	conflictNext bool
}

func newFakeRepo() *fakeRepo { return &fakeRepo{rows: map[shared.ID]tenant.AISettings{}} }

func (f *fakeRepo) Get(_ context.Context, id shared.ID, d tenant.AISettings) (tenant.AISettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.rows[id]; ok {
		return s, nil
	}
	return d, nil
}

func (f *fakeRepo) Save(_ context.Context, id shared.ID, s tenant.AISettings, expected *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.rows[id]
	if f.conflictNext || (ok && (expected == nil || cur.UpdatedAt == nil || !cur.UpdatedAt.Equal(*expected))) || (!ok && expected != nil) {
		f.conflictNext = false
		return shared.ErrConflict
	}
	f.rows[id] = s
	return nil
}

type fakeProvider struct {
	err  error
	reqs []llm.CompletionRequest
}

func (p *fakeProvider) Complete(_ context.Context, r llm.CompletionRequest) (*llm.CompletionResponse, error) {
	p.reqs = append(p.reqs, r)
	return &llm.CompletionResponse{Content: "OK"}, p.err
}
func (p *fakeProvider) Name() string    { return "fake" }
func (p *fakeProvider) Model() string   { return "m" }
func (p *fakeProvider) Validate() error { return nil }

type fakeBuilder struct {
	specs []llm.Spec
	p     *fakeProvider
}

func (b *fakeBuilder) BuildPlatformProvider(s llm.Spec) (llm.Provider, error) {
	b.specs = append(b.specs, s)
	return b.p, nil
}

type policy struct{ allow bool }

func (p policy) OrgProviderAllowed(context.Context) bool { return p.allow }

const secret = "sk-fake-secret-0123456789"

type harness struct {
	svc *Service
	rep *fakeRepo
	b   *fakeBuilder
	enc crypto.Encryptor
	tid string
	id  shared.ID
}

func newHarness(t *testing.T, allow bool) *harness {
	t.Helper()
	c, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	h := &harness{rep: newFakeRepo(), b: &fakeBuilder{p: &fakeProvider{}}, enc: c, id: shared.NewID()}
	h.tid = h.id.String()
	h.svc = NewService(h.rep, c, nil, h.b, policy{allow: allow}, nil)
	return h
}

var actx = auditapp.AuditContext{ActorID: "11111111-1111-7111-8111-111111111111"}

func sp(s string) *string { return &s }
func bp(b bool) *bool     { return &b }

// --- tests ---------------------------------------------------------------

// The key is encrypted, shown only as set + last four, and the view never
// carries it.
func TestSaveKeyIsEncryptedAndWriteOnly(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	v, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai"), Model: sp("gpt-4o"), APIKey: sp(secret), Enabled: bp(true)}, actx)
	require.NoError(t, err)
	assert.True(t, v.KeySet)
	assert.Equal(t, "6789", v.KeyLast4)
	assert.Equal(t, actx.ActorID, v.KeyUpdatedBy)
	assert.NotNil(t, v.KeyUpdatedAt)
	assert.Equal(t, "own", v.Source)
	assert.NotContains(t, strings.ToLower(spew(v)), strings.ToLower(secret))

	stored := h.rep.rows[h.id]
	assert.NotEqual(t, secret, stored.APIKey)
	assert.NotContains(t, stored.APIKey, secret)
	plain, err := h.enc.DecryptString(stored.APIKey)
	require.NoError(t, err)
	assert.Equal(t, secret, plain)

	// Omitting the key keeps it; "" removes it.
	v, err = h.svc.Save(ctx, h.tid, Update{Model: sp("gpt-4o-mini")}, actx)
	require.NoError(t, err)
	assert.True(t, v.KeySet)
	v, err = h.svc.Save(ctx, h.tid, Update{APIKey: sp(""), Source: sp("platform")}, actx)
	require.NoError(t, err)
	assert.False(t, v.KeySet)
	assert.Empty(t, h.rep.rows[h.id].APIKey)
}

func spew(v View) string {
	return v.Provider + v.BaseURL + v.Model + v.KeyLast4 + v.KeyUpdatedBy + v.Source
}

// A stored key is only sent to the endpoint it was entered for: changing the
// provider or base URL drops it.
func TestSaveChangingTargetDropsKey(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai"), APIKey: sp(secret)}, actx)
	require.NoError(t, err)
	// Staying on "own" with a new provider and no new key is refused (the
	// old key is not carried over)...
	_, err = h.svc.Save(ctx, h.tid, Update{Provider: sp("gemini")}, actx)
	require.ErrorIs(t, err, ErrInvalid)
	assert.True(t, h.rep.rows[h.id].APIKey != "", "a refused change stores nothing")
	// ... and leaving "own" drops it.
	v, err := h.svc.Save(ctx, h.tid, Update{Provider: sp("gemini"), Source: sp("platform")}, actx)
	require.NoError(t, err)
	assert.False(t, v.KeySet, "a new provider must not inherit the old provider's key")

	// Same for the base URL of an OpenAI-compatible server.
	_, err = h.svc.Save(ctx, h.tid, Update{Provider: sp("openai_compatible"), BaseURL: sp("https://93.184.216.34/v1"), Model: sp("m"), APIKey: sp(secret)}, actx)
	require.NoError(t, err)
	v, err = h.svc.Save(ctx, h.tid, Update{BaseURL: sp("https://93.184.216.35/v1")}, actx)
	require.NoError(t, err)
	assert.False(t, v.KeySet, "a new base URL must not receive the stored key")
}

// An own provider's base URL is public-only: private, loopback, link-local,
// metadata and plain-http targets are refused at save time.
func TestSaveRefusesUnsafeBaseURL(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	for _, u := range []string{
		"https://10.0.0.5/v1", "https://192.168.1.1/v1", "https://172.16.0.1/v1", "https://127.0.0.1/v1", "https://localhost/v1",
		"https://169.254.169.254/latest", "https://metadata.google.internal/", "https://[::1]/v1", "https://[fd12:3456::1]/v1",
		"http://llm.example.com/v1", "https://u:p@llm.example.com/v1", "ftp://x.example.com",
	} {
		_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai_compatible"), BaseURL: sp(u), Model: sp("m")}, actx)
		require.Error(t, err, u)
		assert.ErrorIs(t, err, shared.ErrValidation, u)
	}
	assert.Empty(t, h.rep.rows, "nothing is stored for a refused URL")

	_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai_compatible"), BaseURL: sp("https://93.184.216.34/v1/"), Model: sp("llama3")}, actx)
	require.NoError(t, err)
	assert.Equal(t, "https://93.184.216.34/v1", h.rep.rows[h.id].BaseURL)
	// The key is optional for an OpenAI-compatible server; a hosted provider needs one.
	_, err = h.svc.Save(ctx, h.tid, Update{Provider: sp("openai")}, actx)
	require.Error(t, err)
}

func TestSaveValidation(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("everyone")}, actx)
	assert.ErrorIs(t, err, ErrInvalid)
	_, err = h.svc.Save(ctx, h.tid, Update{Provider: sp("skynet")}, actx)
	assert.ErrorIs(t, err, ErrInvalid)
	_, err = h.svc.Save(ctx, h.tid, Update{Model: sp("bad model!")}, actx)
	assert.ErrorIs(t, err, ErrInvalid)
	_, err = h.svc.Save(ctx, h.tid, Update{APIKey: sp("short")}, actx)
	assert.ErrorIs(t, err, ErrInvalid)
	_, err = h.svc.Save(ctx, h.tid, Update{Source: sp("own")}, actx)
	assert.ErrorIs(t, err, ErrInvalid, "an own provider needs a provider")
	_, err = h.svc.Save(ctx, h.tid, Update{Enabled: bp(true)}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation, "consent needs a signed-in actor")
	_, err = h.svc.Save(ctx, "not-an-id", Update{}, actx)
	assert.ErrorIs(t, err, shared.ErrValidation)
}

// The platform may forbid own providers: saving, selecting and testing one is
// refused.
func TestPlatformPolicyForbidsOwnProvider(t *testing.T) {
	h := newHarness(t, false)
	ctx := context.Background()
	_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai"), APIKey: sp(secret)}, actx)
	assert.ErrorIs(t, err, ErrOwnProviderNotAllowed)
	_, err = h.svc.Test(ctx, h.tid, Update{Provider: sp("openai"), APIKey: sp(secret)}, actx)
	assert.ErrorIs(t, err, ErrOwnProviderNotAllowed)
	assert.Empty(t, h.b.specs, "no outbound call when the policy forbids it")
	// Platform and off stay possible.
	v, err := h.svc.Save(ctx, h.tid, Update{Source: sp("off")}, actx)
	require.NoError(t, err)
	assert.Equal(t, "off", v.Source)
	assert.False(t, v.OwnProviderAllowed)
}

// Test connection: one tiny prompt, no finding data, never AllowPrivate, the
// stored key only to its own endpoint, fixed codes.
func TestTestConnection(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	res, err := h.svc.Test(ctx, h.tid, Update{Provider: sp("openai"), Model: sp("gpt-4o"), APIKey: sp(secret)}, actx)
	require.NoError(t, err)
	assert.True(t, res.OK)
	assert.Equal(t, TestOK, res.Code)
	require.Len(t, h.b.specs, 1)
	assert.False(t, h.b.specs[0].AllowPrivate, "an organization never gets the private-address toggle")
	assert.Equal(t, secret, h.b.specs[0].APIKey)
	require.Len(t, h.b.p.reqs, 1)
	assert.Equal(t, testPrompt, h.b.p.reqs[0].UserPrompt)
	assert.Equal(t, 1, h.b.p.reqs[0].MaxTokens)
	assert.Empty(t, h.b.p.reqs[0].SystemPrompt)

	// Without a key, nothing is sent.
	res, err = h.svc.Test(ctx, h.tid, Update{Provider: sp("openai")}, actx)
	require.NoError(t, err)
	assert.Equal(t, TestKeyRequired, res.Code)
	assert.Len(t, h.b.specs, 1)

	// An unsafe URL never reaches the provider.
	res, err = h.svc.Test(ctx, h.tid, Update{Provider: sp("openai_compatible"), BaseURL: sp("https://169.254.169.254/v1"), Model: sp("m")}, actx)
	require.NoError(t, err)
	assert.False(t, res.OK)
	assert.Equal(t, TestBlockedAddress, res.Code)
	assert.Len(t, h.b.specs, 1)
}

func TestTestConnectionNeverSendsStoredKeyToAnotherEndpoint(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai_compatible"), BaseURL: sp("https://93.184.216.34/v1"), Model: sp("m"), APIKey: sp(secret)}, actx)
	require.NoError(t, err)

	// The stored endpoint: the stored key is used.
	res, err := h.svc.Test(ctx, h.tid, Update{}, actx)
	require.NoError(t, err)
	assert.True(t, res.OK)
	require.Len(t, h.b.specs, 1)
	assert.Equal(t, secret, h.b.specs[0].APIKey)

	// Another URL with no new key: refused, the key goes nowhere.
	res, err = h.svc.Test(ctx, h.tid, Update{BaseURL: sp("https://93.184.216.99/v1")}, actx)
	require.NoError(t, err)
	assert.Equal(t, TestKeyRequired, res.Code)
	// Another provider: same.
	res, err = h.svc.Test(ctx, h.tid, Update{Provider: sp("openai")}, actx)
	require.NoError(t, err)
	assert.Equal(t, TestKeyRequired, res.Code)
	assert.Len(t, h.b.specs, 1, "the stored key was never offered to another endpoint")
}

func TestTestConnectionErrorCodes(t *testing.T) {
	for want, err := range map[string]error{
		TestAuthFailed:     errors.New("openai API error: status 401"),
		TestRateLimited:    llm.ErrRateLimited,
		TestTimeout:        context.DeadlineExceeded,
		TestUnreachable:    errors.New("server error: status 503"),
		TestBlockedAddress: errors.New(`dial: ssrf guard: host "x" resolves to blocked address 10.0.0.1`),
		TestProviderError:  llm.ErrInvalidResponse,
	} {
		h := newHarness(t, true)
		h.b.p.err = err
		res, e := h.svc.Test(context.Background(), h.tid, Update{Provider: sp("openai"), APIKey: sp(secret)}, actx)
		require.NoError(t, e)
		assert.False(t, res.OK)
		assert.Equal(t, want, res.Code, err.Error())
		assert.NotContains(t, res.Code, "401", "raw provider text is never returned")
	}
}

func TestTestConnectionRateLimited(t *testing.T) {
	h := newHarness(t, true)
	h.svc.now = func() time.Time { return time.Unix(0, 0) }
	var limited bool
	for i := 0; i < 10; i++ {
		_, err := h.svc.Test(context.Background(), h.tid, Update{Provider: sp("openai"), APIKey: sp(secret)}, actx)
		if errors.Is(err, ErrTooManyTests) {
			limited = true
			break
		}
	}
	assert.True(t, limited, "tests are limited per organization")
	// Another organization has its own allowance.
	_, err := h.svc.Test(context.Background(), shared.NewID().String(), Update{Provider: sp("openai"), APIKey: sp(secret)}, actx)
	assert.NoError(t, err)
}

// Settings are per organization.
func TestIsolationBetweenOrganizations(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai"), APIKey: sp(secret), Enabled: bp(true)}, actx)
	require.NoError(t, err)
	other, err := h.svc.Get(ctx, shared.NewID().String())
	require.NoError(t, err)
	assert.False(t, other.Enabled)
	assert.False(t, other.KeySet)
	assert.Equal(t, "platform", other.Source)
	assert.Empty(t, other.Provider)
}

// A concurrent writer winning between the read and the write makes Save fail
// with a conflict (HTTP 409) and leaves the stored row as it was.
func TestSaveConflictWhenSettingsChangedConcurrently(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, err := h.svc.Save(ctx, h.tid, Update{Source: sp("own"), Provider: sp("openai"), Model: sp("gpt-4o"), APIKey: sp(secret), Enabled: bp(true)}, actx)
	require.NoError(t, err)
	before := h.rep.rows[h.id]

	h.rep.conflictNext = true
	_, err = h.svc.Save(ctx, h.tid, Update{Model: sp("gpt-4o-mini")}, actx)
	require.ErrorIs(t, err, shared.ErrConflict)
	assert.Equal(t, before, h.rep.rows[h.id])
}
