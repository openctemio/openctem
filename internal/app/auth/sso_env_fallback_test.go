package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/config"
	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// --- fakes (embed the interface; override only what these tests touch) ---

type fakeIPRepo struct {
	identityproviderdom.Repository
	byProvider map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider
	active     []*identityproviderdom.IdentityProvider
}

func (f *fakeIPRepo) GetByTenantAndProvider(_ context.Context, _ string, p identityproviderdom.Provider) (*identityproviderdom.IdentityProvider, error) {
	if ip, ok := f.byProvider[p]; ok {
		return ip, nil
	}
	return nil, identityproviderdom.ErrNotFound
}

func (f *fakeIPRepo) ListActiveByTenant(_ context.Context, _ string) ([]*identityproviderdom.IdentityProvider, error) {
	return f.active, nil
}

type fakeTenantRepo struct {
	tenantdom.Repository
	t *tenantdom.Tenant
}

func (f *fakeTenantRepo) GetBySlug(_ context.Context, _ string) (*tenantdom.Tenant, error) {
	return f.t, nil
}

// identityEncryptor treats stored "ciphertext" as plaintext, so DB-path tests
// can assert the secret flows through without real crypto.
type identityEncryptor struct{}

func (identityEncryptor) EncryptString(s string) (string, error) { return s, nil }
func (identityEncryptor) DecryptString(s string) (string, error) { return s, nil }

func newSSOForTest(ipRepo *fakeIPRepo, entra config.EntraSSOConfig) *SSOService {
	t, _ := tenantdom.NewTenant("Acme", "acme", "00000000-0000-0000-0000-000000000001")
	return &SSOService{
		ipRepo:     ipRepo,
		tenantRepo: &fakeTenantRepo{t: t},
		encryptor:  identityEncryptor{},
		authConfig: config.AuthConfig{EntraSSO: entra},
		logger:     logger.NewNop(),
	}
}

func enabledEntra() config.EntraSSOConfig {
	return config.EntraSSOConfig{
		Enabled:      true,
		ClientID:     "env-client-id",
		ClientSecret: "env-secret",
		TenantID:     "dir-1234",
		DefaultRole:  "member",
		DisplayName:  "Microsoft Entra ID",
	}
}

func TestResolveProvider_EnvFallbackWhenTenantHasNone(t *testing.T) {
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}}, enabledEntra())

	rp, err := svc.resolveProvider(context.Background(), "tid", identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("resolveProvider: %v", err)
	}
	if rp.source != "env" {
		t.Fatalf("expected env source, got %q", rp.source)
	}
	if rp.clientID != "env-client-id" || rp.clientSecret != "env-secret" {
		t.Fatalf("env creds not used: %+v", rp)
	}
	if rp.tenantIdentifier != "dir-1234" {
		t.Fatalf("expected env directory id, got %q", rp.tenantIdentifier)
	}
}

func TestResolveProvider_NoTenantNoEnv_NotFound(t *testing.T) {
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}}, config.EntraSSOConfig{})

	_, err := svc.resolveProvider(context.Background(), "tid", identityproviderdom.ProviderEntraID)
	if err != ErrSSOProviderNotFound {
		t.Fatalf("expected ErrSSOProviderNotFound, got %v", err)
	}
}

func TestResolveProvider_TenantConfigWinsOverEnv(t *testing.T) {
	ip := identityproviderdom.New("ip-1", "tid", identityproviderdom.ProviderEntraID, "Tenant Entra", "tenant-client-id", "tenant-secret")
	ip.SetTenantIdentifier("tenant-dir")
	repo := &fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{
		identityproviderdom.ProviderEntraID: ip,
	}}
	svc := newSSOForTest(repo, enabledEntra())

	rp, err := svc.resolveProvider(context.Background(), "tid", identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("resolveProvider: %v", err)
	}
	if rp.source != "tenant" {
		t.Fatalf("tenant config must win, got source %q", rp.source)
	}
	if rp.clientID != "tenant-client-id" || rp.clientSecret != "tenant-secret" {
		t.Fatalf("expected tenant creds, got %+v", rp)
	}
}

func TestGenerateAuthorizeURL_UsesEnvFallback(t *testing.T) {
	svc := newSSOForTest(&fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}}, enabledEntra())

	res, err := svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{
		OrgSlug:     "acme",
		Provider:    "entra_id",
		RedirectURI: "https://app.example.com/sso/callback",
	})
	if err != nil {
		t.Fatalf("GenerateAuthorizeURL: %v", err)
	}
	if !strings.Contains(res.AuthorizationURL, "login.microsoftonline.com/dir-1234/oauth2/v2.0/authorize") {
		t.Fatalf("authorize URL should target the env directory: %s", res.AuthorizationURL)
	}
	if !strings.Contains(res.AuthorizationURL, "client_id=env-client-id") {
		t.Fatalf("authorize URL should use env client id: %s", res.AuthorizationURL)
	}
}

func TestGetProvidersForTenant_AppendsEnvFallback(t *testing.T) {
	svc := newSSOForTest(&fakeIPRepo{active: nil}, enabledEntra())

	got, err := svc.GetProvidersForTenant(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetProvidersForTenant: %v", err)
	}
	if len(got) != 1 || got[0].Provider != "entra_id" || got[0].ID != "env:entra_id" {
		t.Fatalf("expected env entra fallback entry, got %+v", got)
	}
}

func TestGetProvidersForTenant_TenantEntraSuppressesFallback(t *testing.T) {
	ip := identityproviderdom.New("ip-1", "tid", identityproviderdom.ProviderEntraID, "Tenant Entra", "c", "s")
	svc := newSSOForTest(&fakeIPRepo{active: []*identityproviderdom.IdentityProvider{ip}}, enabledEntra())

	got, err := svc.GetProvidersForTenant(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetProvidersForTenant: %v", err)
	}
	if len(got) != 1 || got[0].ID == "env:entra_id" {
		t.Fatalf("tenant's own entra should suppress the env fallback, got %+v", got)
	}
}
