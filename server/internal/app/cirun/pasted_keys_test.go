package cirun

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/oidc"
)

const keysIssuer = "https://gitlab.example.com"

// keysRepo serves the tenant's trust configurations and records writes.
type keysRepo struct {
	cirun.Repository
	mu      sync.Mutex
	configs map[shared.ID][]cirun.TrustConfig // by tenant
	stored  *cirun.TrustConfig
}

func (r *keysRepo) EnabledTrustConfigs(_ context.Context, tenantID shared.ID, issuer string) ([]cirun.TrustConfig, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []cirun.TrustConfig
	for _, c := range r.configs[tenantID] {
		if c.Issuer == issuer && c.Enabled {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *keysRepo) PurgeExpiredJTIs(context.Context, time.Time) (int64, error) { return 0, nil }

func (r *keysRepo) CreateTrustConfig(_ context.Context, c *cirun.TrustConfig) error {
	cp := *c
	r.stored = &cp
	return nil
}

func (r *keysRepo) UpdateTrustConfig(_ context.Context, c *cirun.TrustConfig) error {
	cp := *c
	r.stored = &cp
	return nil
}

func (r *keysRepo) GetTrustConfig(_ context.Context, tenantID, _ shared.ID) (*cirun.TrustConfig, error) {
	if r.stored == nil || r.stored.TenantID != tenantID {
		return nil, cirun.ErrTrustConfigNotFound
	}
	cp := *r.stored
	return &cp, nil
}

type recordingAuditor struct {
	mu     sync.Mutex
	events []auditapp.AuditEvent
	ctxs   []auditapp.AuditContext
}

func (a *recordingAuditor) LogEvent(_ context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	a.ctxs = append(a.ctxs, actx)
	return nil
}

type recordingAlerter struct {
	mu      sync.Mutex
	alerts  []AdminAlert
	tenants []shared.ID
}

func (a *recordingAlerter) AlertAdmins(_ context.Context, tenantID shared.ID, al AdminAlert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alerts = append(a.alerts, al)
	a.tenants = append(a.tenants, tenantID)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// offlineVerifier is the real verifier with every outbound call counted and
// refused.
func offlineVerifier(calls *atomic.Int32) *oidc.Client {
	return oidc.NewClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("no network")
	})}, func(string) error {
		calls.Add(1)
		return errors.New("blocked")
	})
}

func pastedDoc(t *testing.T, kid string, k *rsa.PrivateKey) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	b, err := json.Marshal(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gitlabToken(t *testing.T, k *rsa.PrivateKey, kid string, tenant shared.ID) string {
	t.Helper()
	now := time.Now()
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{"iss": keysIssuer, "aud": cirun.DefaultAudience(tenant),
		"sub": "project_path:acme/api:ref_type:branch:ref:main", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"nbf": now.Unix(), "jti": "j-" + kid, "project_path": "acme/api", "project_id": "42", "namespace_path": "acme",
		"ref": "main", "ref_type": "branch", "sha": "abc123", "pipeline_source": "push"})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type keysFixture struct {
	svc     *Service
	repo    *keysRepo
	audit   *recordingAuditor
	alerts  *recordingAlerter
	calls   *atomic.Int32
	tenant  shared.ID
	key     *rsa.PrivateKey
	rotated *rsa.PrivateKey
	cfg     cirun.TrustConfig
	now     time.Time
}

func newKeysFixture(t *testing.T) *keysFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tenant := shared.NewID()
	cfg := cirun.TrustConfig{ID: shared.NewID(), TenantID: tenant, Name: "self-managed", Provider: cirun.ProviderGitLab,
		Issuer: keysIssuer, Rules: cirun.Rules{Owners: []string{"acme"}}, Enabled: true,
		KeySource: cirun.KeySourcePasted, SigningKeys: pastedDoc(t, "old-key", key)}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	f := &keysFixture{repo: &keysRepo{configs: map[shared.ID][]cirun.TrustConfig{tenant: {cfg}}},
		audit: &recordingAuditor{}, alerts: &recordingAlerter{}, calls: &atomic.Int32{}, tenant: tenant,
		key: key, rotated: rotated, cfg: cfg, now: time.Now()}
	f.svc = NewService(Deps{Repo: f.repo, Verifier: offlineVerifier(f.calls), Audit: f.audit, Alerts: f.alerts}, Config{}, nil)
	f.svc.SetClock(func() time.Time { return f.now })
	return f
}

// A token signed with a pasted key verifies without any network call, and
// the verifying kid is known.
func TestPastedKeysVerifyOffline(t *testing.T) {
	f := newKeysFixture(t)
	tok, claims, err := f.svc.verify(context.Background(), gitlabToken(t, f.key, "old-key", f.tenant), []cirun.TrustConfig{f.cfg}, cirun.Hints{})
	if err != nil {
		t.Fatalf("token refused: %v", err)
	}
	if tok.KeyID != "old-key" || claims.Repository != "acme/api" {
		t.Fatalf("token %+v claims %+v", tok, claims)
	}
	if n := f.calls.Load(); n != 0 {
		t.Fatalf("%d network calls with pasted keys", n)
	}
}

// After a rotation the job gets CI_TOKEN_UNKNOWN_KEY (never the retryable
// issuer-unavailable error), nothing is fetched, and the administrators are
// told once an hour per configuration.
func TestPastedKeysUnknownKidRefusedAndNoticed(t *testing.T) {
	f := newKeysFixture(t)
	exchange := func() error {
		_, err := f.svc.Exchange(context.Background(), ExchangeInput{TenantID: f.tenant.String(),
			IDToken: gitlabToken(t, f.rotated, "new-key", f.tenant)})
		return err
	}
	err := exchange()
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Code != RefuseUnknownKey || errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v, want the unknown_key refusal", err)
	}
	if !strings.Contains(refused.Message, "/oauth/discovery/keys") {
		t.Fatalf("message does not say where the keys are: %q", refused.Message)
	}
	if len(f.audit.events) != 1 || len(f.alerts.alerts) != 1 {
		t.Fatalf("audit %d, alerts %d, want 1 and 1", len(f.audit.events), len(f.alerts.alerts))
	}
	ev := f.audit.events[0]
	if ev.ResourceID != f.cfg.ID.String() || ev.Metadata["token_kid"] != "new-key" || f.audit.ctxs[0].TenantID != f.tenant.String() {
		t.Fatalf("audit = %+v %+v", ev, f.audit.ctxs[0])
	}
	// The recent refusals list reads reasons and provider.
	if r, _ := ev.Metadata["reasons"].([]string); len(r) != 1 || r[0] != RefuseUnknownKey || ev.Metadata["provider"] != "gitlab" {
		t.Fatalf("refusal list metadata = %v %v", ev.Metadata["reasons"], ev.Metadata["provider"])
	}
	if kids, _ := ev.Metadata["pasted_kids"].([]string); len(kids) != 1 || kids[0] != "old-key" {
		t.Fatalf("pasted kids = %v", ev.Metadata["pasted_kids"])
	}
	if f.alerts.tenants[0] != f.tenant || f.alerts.alerts[0].AggregateID == nil || *f.alerts.alerts[0].AggregateID != f.cfg.ID {
		t.Fatalf("alert = %+v", f.alerts.alerts[0])
	}

	// A burst of the same refusal writes nothing more within the hour.
	for range 5 {
		_ = exchange()
	}
	if len(f.audit.events) != 1 || len(f.alerts.alerts) != 1 {
		t.Fatalf("burst wrote audit %d, alerts %d", len(f.audit.events), len(f.alerts.alerts))
	}
	f.now = f.now.Add(unknownKeyNoticeEvery + time.Minute)
	_ = exchange()
	if len(f.audit.events) != 2 || len(f.alerts.alerts) != 2 {
		t.Fatalf("after an hour: audit %d, alerts %d", len(f.audit.events), len(f.alerts.alerts))
	}
	if n := f.calls.Load(); n != 0 {
		t.Fatalf("%d network calls with pasted keys", n)
	}
}

// Another tenant's pasted keys never verify this tenant's token, and an
// unknown-key refusal is recorded only for the tenant that was asked.
func TestPastedKeysTenantIsolation(t *testing.T) {
	f := newKeysFixture(t)
	other := shared.NewID()
	// The other tenant pasted the key the rotated token is signed with.
	oc := f.cfg
	oc.ID, oc.TenantID, oc.SigningKeys = shared.NewID(), other, pastedDoc(t, "new-key", f.rotated)
	f.repo.configs[other] = []cirun.TrustConfig{oc}
	_, err := f.svc.Exchange(context.Background(), ExchangeInput{TenantID: f.tenant.String(),
		IDToken: gitlabToken(t, f.rotated, "new-key", f.tenant)})
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Code != RefuseUnknownKey {
		t.Fatalf("err = %v, want the unknown_key refusal", err)
	}
	for _, id := range f.alerts.tenants {
		if id != f.tenant {
			t.Fatalf("alert sent to tenant %v", id)
		}
	}
}

// Two configurations of one issuer with different pasted keys are verified
// separately: the token verifies with the one that has its key.
func TestPastedKeysPerConfiguration(t *testing.T) {
	f := newKeysFixture(t)
	second := f.cfg
	second.ID, second.Name, second.SigningKeys = shared.NewID(), "second", pastedDoc(t, "new-key", f.rotated)
	tok, _, err := f.svc.verify(context.Background(), gitlabToken(t, f.rotated, "new-key", f.tenant),
		[]cirun.TrustConfig{f.cfg, second}, cirun.Hints{})
	if err != nil || tok.KeyID != "new-key" {
		t.Fatalf("token = %+v, err = %v", tok, err)
	}
}

// Fetch mode is unchanged: an unreachable issuer is still the retryable
// issuer-unavailable error, and it fetches (through the URL guard).
func TestFetchModeUnchanged(t *testing.T) {
	f := newKeysFixture(t)
	c := f.cfg
	c.KeySource, c.SigningKeys = cirun.KeySourceFetch, ""
	f.repo.configs[f.tenant] = []cirun.TrustConfig{c}
	_, err := f.svc.Exchange(context.Background(), ExchangeInput{TenantID: f.tenant.String(),
		IDToken: gitlabToken(t, f.key, "old-key", f.tenant)})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v, want ErrIssuerUnavailable", err)
	}
	if f.calls.Load() == 0 {
		t.Fatal("fetch mode did not try to fetch the keys")
	}
	if len(f.audit.events) != 0 || len(f.alerts.alerts) != 0 {
		t.Fatal("fetch mode wrote a pasted-key notice")
	}
}

// Stored keys that no longer parse refuse the token (fail closed), without
// fetching.
func TestPastedKeysBrokenStoredKeysFailClosed(t *testing.T) {
	f := newKeysFixture(t)
	c := f.cfg
	c.SigningKeys = `{"keys":[]}`
	if _, _, err := f.svc.verify(context.Background(), gitlabToken(t, f.key, "old-key", f.tenant), []cirun.TrustConfig{c}, cirun.Hints{}); err == nil {
		t.Fatal("token accepted with unusable stored keys")
	}
	if n := f.calls.Load(); n != 0 {
		t.Fatalf("%d network calls", n)
	}
}

// Saving pasted keys is audited by their kids (before and after), never the
// document, and the paste date is set only when the keys change.
func TestTrustConfigSigningKeysAudited(t *testing.T) {
	f := newKeysFixture(t)
	pasted, fetch := string(cirun.KeySourcePasted), string(cirun.KeySourceFetch)
	doc := f.cfg.SigningKeys
	in := TrustConfigInput{Name: "self-managed", Provider: "gitlab", Issuer: keysIssuer,
		Rules: cirun.Rules{Owners: []string{"acme"}}, KeySource: &pasted, SigningKeys: &doc}
	c, err := f.svc.CreateTrustConfig(context.Background(), f.tenant, in, Actor{UserID: shared.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if c.KeySource != cirun.KeySourcePasted || c.SigningKeysUpdatedAt == nil || !c.SigningKeysUpdatedAt.Equal(f.now.UTC()) {
		t.Fatalf("created = %q %v", c.KeySource, c.SigningKeysUpdatedAt)
	}
	created := f.audit.events[len(f.audit.events)-1]
	after := created.Changes.After["config"].(map[string]any)
	if ids, _ := after["signing_key_ids"].([]string); len(ids) != 1 || ids[0] != "old-key" || after["key_source"] != pasted {
		t.Fatalf("create audit = %+v", after)
	}

	// Same keys again: the paste date stays.
	f.now = f.now.Add(time.Hour)
	if c, err = f.svc.UpdateTrustConfig(context.Background(), f.tenant, c.ID, in, Actor{}); err != nil {
		t.Fatal(err)
	}
	if !c.SigningKeysUpdatedAt.Equal(f.now.Add(-time.Hour).UTC()) {
		t.Fatalf("unchanged keys restamped: %v", c.SigningKeysUpdatedAt)
	}

	// Rotated keys: new kids in the audit, the old ones before.
	newDoc := pastedDoc(t, "new-key", f.rotated)
	in.SigningKeys = &newDoc
	if c, err = f.svc.UpdateTrustConfig(context.Background(), f.tenant, c.ID, in, Actor{}); err != nil {
		t.Fatal(err)
	}
	if !c.SigningKeysUpdatedAt.Equal(f.now.UTC()) {
		t.Fatalf("new keys not stamped: %v", c.SigningKeysUpdatedAt)
	}
	ev := f.audit.events[len(f.audit.events)-1]
	before := ev.Changes.Before["config"].(map[string]any)["signing_key_ids"].([]string)
	afterIDs := ev.Changes.After["config"].(map[string]any)["signing_key_ids"].([]string)
	if strings.Join(before, ",") != "old-key" || strings.Join(afterIDs, ",") != "new-key" {
		t.Fatalf("audit kids %v -> %v", before, afterIDs)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), f.rotated.N.String()) || strings.Contains(string(raw), `"n"`) {
		t.Fatal("the key document reached the audit log")
	}

	// Back to fetch and clear the keys.
	empty := ""
	in.KeySource, in.SigningKeys = &fetch, &empty
	if c, err = f.svc.UpdateTrustConfig(context.Background(), f.tenant, c.ID, in, Actor{}); err != nil {
		t.Fatal(err)
	}
	if c.KeySource != cirun.KeySourceFetch || c.SigningKeys != "" || c.SigningKeysUpdatedAt != nil {
		t.Fatalf("cleared = %q %q %v", c.KeySource, c.SigningKeys, c.SigningKeysUpdatedAt)
	}

	// An invalid document is a validation error and nothing is stored.
	bad := strings.Replace(newDoc, `"kty":"RSA"`, `"kty":"RSA","d":"AQAB"`, 1)
	in.KeySource, in.SigningKeys = &pasted, &bad
	stored := *f.repo.stored
	if _, err := f.svc.UpdateTrustConfig(context.Background(), f.tenant, c.ID, in, Actor{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("private key accepted: %v", err)
	}
	if f.repo.stored.SigningKeys != stored.SigningKeys {
		t.Fatal("refused keys were stored")
	}
	// Another tenant cannot change this configuration.
	if _, err := f.svc.UpdateTrustConfig(context.Background(), shared.NewID(), c.ID, in, Actor{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
}
