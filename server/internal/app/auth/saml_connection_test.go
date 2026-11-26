package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	samldom "github.com/openctemio/openctem/server/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SAML addresses are keyed by connection (research 516): the organization's
// current slug never addresses a connection, a frozen legacy key addresses
// only the configuration that held it, and a response is only ever checked
// against the addressed connection's certificate and audience.

type multiTenantRepo struct {
	tenantdom.Repository
	byID map[shared.ID]*tenantdom.Tenant
}

func (r multiTenantRepo) GetByID(_ context.Context, id shared.ID) (*tenantdom.Tenant, error) {
	if t, ok := r.byID[id]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}

func newTenantForSAML(t *testing.T, slug string) *tenantdom.Tenant {
	t.Helper()
	tn, err := tenantdom.NewTenant(slug, slug, shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func enabledSAMLConfig(t *testing.T, tn *tenantdom.Tenant, legacyKey string) *samldom.SAMLProvider {
	t.Helper()
	return samldom.Reconstruct(shared.NewID(), tn.ID(), "https://idp.example.com/"+tn.Slug(), "https://idp.example.com/sso",
		genTestCertPEM(t), nil, "viewer", false, true, time.Now(), time.Now()).WithLegacyPathKey(legacyKey)
}

func TestSAMLConnection_AddressedByIDNeverBySlug(t *testing.T) {
	ctx := context.Background()
	tn := newTenantForSAML(t, "acme")
	repo := newFakeSAMLRepo()
	cfg := enabledSAMLConfig(t, tn, "")
	repo.byTenant[tn.ID()] = cfg
	svc := NewSAMLService(repo, multiTenantRepo{byID: map[shared.ID]*tenantdom.Tenant{tn.ID(): tn}}, nil, logger.NewNop())

	redirect, _, err := svc.Login(ctx, cfg.ID().String(), samlACSBase, false)
	if err != nil {
		t.Fatalf("login by connection id: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("RelayState") != "" {
		t.Errorf("RelayState = %q, want none", u.Query().Get("RelayState"))
	}
	// The organization's slug is not an address of its connection.
	if _, _, err := svc.Login(ctx, "acme", samlACSBase, false); !errors.Is(err, ErrSAMLNotConfigured) {
		t.Errorf("login by slug: %v, want not configured", err)
	}
	// Unknown, malformed and empty keys are one answer.
	for _, k := range []string{shared.NewID().String(), "", "../acs", "Not A Key"} {
		if _, _, err := svc.Login(ctx, k, samlACSBase, false); !errors.Is(err, ErrSAMLNotConfigured) {
			t.Errorf("login by %q: %v, want not configured", k, err)
		}
	}
	// The SP entity ID and ACS are built on the connection id.
	md, err := svc.Metadata(ctx, cfg.ID().String(), samlACSBase)
	if err != nil {
		t.Fatal(err)
	}
	want := samlACSBase + "/api/v1/auth/saml/" + cfg.ID().String()
	if !strings.Contains(md, `entityID="`+want+`/metadata"`) || !strings.Contains(md, want+`/acs`) || strings.Contains(md, "acme") {
		t.Errorf("metadata not keyed by connection id:\n%s", md)
	}
}

// A slug given up by a rename and taken by another organization addresses
// nothing of the new owner: the frozen legacy key still reaches the
// connection that held it, and only that one.
func TestSAMLConnection_LegacyKeyIsFrozenAgainstSlugTakeover(t *testing.T) {
	ctx := context.Background()
	original := newTenantForSAML(t, "acme-renamed") // was "acme" when migrated
	taker := newTenantForSAML(t, "acme")            // took the free slug later
	repo := newFakeSAMLRepo()
	legacy := enabledSAMLConfig(t, original, "acme")
	fresh := enabledSAMLConfig(t, taker, "")
	repo.byTenant[original.ID()] = legacy
	repo.byTenant[taker.ID()] = fresh
	svc := NewSAMLService(repo, multiTenantRepo{byID: map[shared.ID]*tenantdom.Tenant{original.ID(): original, taker.ID(): taker}},
		nil, logger.NewNop())

	sp, rc, err := svc.resolveServiceProvider(ctx, "acme", samlACSBase)
	if err != nil {
		t.Fatalf("legacy address: %v", err)
	}
	if rc.tenant.ID() != original.ID() || rc.cfg.ID() != legacy.ID() {
		t.Fatalf("legacy address resolved to tenant %s, want the original %s", rc.tenant.ID(), original.ID())
	}
	if sp.EntityID != samlACSBase+"/api/v1/auth/saml/acme/metadata" {
		t.Errorf("legacy entity ID changed: %s", sp.EntityID)
	}
	// The legacy connection reached by its id keeps its registered address.
	sp, _, err = svc.resolveServiceProvider(ctx, legacy.ID().String(), samlACSBase)
	if err != nil || sp.AcsURL.String() != samlACSBase+"/api/v1/auth/saml/acme/acs" {
		t.Errorf("legacy connection by id: %v %v", sp, err)
	}
	// The new owner of the slug is reachable only by its own id.
	_, rc, err = svc.resolveServiceProvider(ctx, fresh.ID().String(), samlACSBase)
	if err != nil || rc.tenant.ID() != taker.ID() {
		t.Errorf("taker by id: %v", err)
	}
}

func TestSAMLConnection_DisabledIsRefused(t *testing.T) {
	tn := newTenantForSAML(t, "acme")
	repo := newFakeSAMLRepo()
	cfg := enabledSAMLConfig(t, tn, "")
	cfg.SetEnabled(false)
	repo.byTenant[tn.ID()] = cfg
	svc := NewSAMLService(repo, multiTenantRepo{byID: map[shared.ID]*tenantdom.Tenant{tn.ID(): tn}}, nil, logger.NewNop())
	if _, _, err := svc.Login(context.Background(), cfg.ID().String(), samlACSBase, false); !errors.Is(err, ErrSAMLDisabled) {
		t.Errorf("disabled connection: %v", err)
	}
}

// A response issued for connection A and posted to connection B's ACS is
// refused: B's certificate, audience and destination decide, never the
// message.
func TestSAMLConnection_ResponseForAnotherConnectionIsRefused(t *testing.T) {
	f := newSAMLACSFixture(t)
	_, resp := f.respond(t, false, time.Now(), nil)

	other := newTenantForSAML(t, "other")
	otherCfg := enabledSAMLConfig(t, other, "")
	f.repo.byTenant[other.ID()] = otherCfg
	svcB := NewSAMLService(f.repo, multiTenantRepo{byID: map[shared.ID]*tenantdom.Tenant{other.ID(): other, f.tenant.ID(): f.tenant}},
		f.svc.sso, logger.NewNop())

	body := url.Values{"SAMLResponse": {resp}}.Encode()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/auth/saml/"+otherCfg.ID().String()+"/acs", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := svcB.ACS(context.Background(), otherCfg.ID().String(), samlACSBase, r, []string{f.requestID}, false); !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("A's response at B's ACS: %v, want refused", err)
	}
}

// The SP addresses exist before the configuration only once the
// administrator creates them (an audited write); reading the SP metadata and
// building a configuration never write. The reserved id is the one the first
// saved configuration takes, and deleting the configuration retires it.
func TestSAMLConnection_ReservedIDIsAdoptedAndRetired(t *testing.T) {
	ctx := context.Background()
	tn := newTenantForSAML(t, "acme")
	repo := newFakeSAMLRepo()
	sso := &SSOService{logger: logger.NewNop()}
	svc := NewSAMLService(repo, multiTenantRepo{byID: map[shared.ID]*tenantdom.Tenant{tn.ID(): tn}}, sso, logger.NewNop())

	// Reading creates nothing.
	if _, _, err := svc.SPMetadataForTenant(ctx, tn.ID(), samlACSBase); !errors.Is(err, ErrSAMLNoAddress) {
		t.Fatalf("SP metadata before any address: %v, want ErrSAMLNoAddress", err)
	}
	if _, err := svc.BuildConfig(ctx, tn.ID(), SAMLConfigInput{IDPEntityID: "https://idp", IDPSSOURL: "https://idp/sso",
		IDPCertificate: genTestCertPEM(t)}); err != nil {
		t.Fatal(err)
	}
	if len(repo.reserved) != 0 {
		t.Fatal("a read or a build reserved a connection id")
	}

	_, before, err := svc.ReserveAddress(ctx, tn.ID(), samlACSBase)
	if err != nil {
		t.Fatal(err)
	}
	if before.Legacy || !strings.Contains(before.ACSURL, before.Key) || strings.Contains(before.ACSURL, "acme") {
		t.Fatalf("addresses before configuration: %+v", before)
	}
	if _, again, err := svc.SPMetadataForTenant(ctx, tn.ID(), samlACSBase); err != nil || again.Key != before.Key {
		t.Fatalf("read after reserving: %+v %v", again, err)
	}
	p, err := svc.UpsertConfig(ctx, tn.ID(), SAMLConfigInput{IDPEntityID: "https://idp", IDPSSOURL: "https://idp/sso",
		IDPCertificate: genTestCertPEM(t), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID().String() != before.Key {
		t.Fatalf("configuration took id %s, the addresses given to the IdP use %s", p.ID(), before.Key)
	}
	if err := svc.DeleteConfig(ctx, tn.ID()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.SPMetadataForTenant(ctx, tn.ID(), samlACSBase); !errors.Is(err, ErrSAMLNoAddress) {
		t.Fatalf("after delete: %v, want no address", err)
	}
	_, after, err := svc.ReserveAddress(ctx, tn.ID(), samlACSBase)
	if err != nil {
		t.Fatal(err)
	}
	if after.Key == before.Key {
		t.Error("a deleted connection's address was handed out again")
	}
}
