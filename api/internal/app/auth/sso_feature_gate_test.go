package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// featureGate answers Allowed per tenant and feature and records the calls.
type featureGate struct {
	allowed map[shared.ID]bool
	err     error
	calls   []string
}

func (g *featureGate) Allowed(_ context.Context, tenantID shared.ID, feature string) (bool, error) {
	g.calls = append(g.calls, feature)
	return g.allowed[tenantID], g.err
}

func isFeatureDenied(err error, feature string) bool {
	var fd *limits.ErrFeatureDenied
	return errors.As(err, &fd) && fd.Feature == feature
}

// research/232 D16: without sso.connections in the plan, no SAML or OIDC
// connection can be created or changed, through any path (direct, pending
// change submission, approval of a change submitted before the downgrade).
func TestSSOFeatureDeniedRefusesCreate(t *testing.T) {
	ctx := context.Background()
	free, paid := shared.NewID(), shared.NewID()
	gate := &featureGate{allowed: map[shared.ID]bool{paid: true}}
	sso := &SSOService{features: gate, logger: logger.NewNop()}
	repo := newFakeSAMLRepo()
	saml := NewSAMLService(repo, nil, sso, logger.NewNop())
	changes := &SSOChangeService{sso: sso, saml: saml, logger: logger.NewNop()}

	cfg := SAMLConfigInput{IDPEntityID: "https://idp.example.com", IDPSSOURL: "https://idp.example.com/sso",
		IDPCertificate: genTestCertPEM(t)}

	if _, err := saml.UpsertConfig(ctx, free, cfg); !isFeatureDenied(err, limits.FeatureSSOConnections) {
		t.Fatalf("SAML config on a plan without connections: %v", err)
	}
	if _, ok := repo.byTenant[free]; ok {
		t.Fatal("a refused SAML config must not be stored")
	}
	if _, err := sso.CreateProvider(ctx, CreateProviderInput{TenantID: free.String(), Provider: "okta"}); !isFeatureDenied(err, limits.FeatureSSOConnections) {
		t.Fatalf("OIDC provider create: %v", err)
	}
	if _, err := sso.BuildProviderUpdate(ctx, UpdateProviderInput{TenantID: free.String(), ID: shared.NewID().String()}); !isFeatureDenied(err, limits.FeatureSSOConnections) {
		t.Fatalf("OIDC provider update: %v", err)
	}
	if _, err := changes.SubmitCreateProvider(ctx, CreateProviderInput{TenantID: free.String(), Provider: "okta"}, SSOChangeRequester{}); !isFeatureDenied(err, limits.FeatureSSOConnections) {
		t.Fatalf("pending change submission: %v", err)
	}
	if _, err := changes.liveWrite(ctx, &ssochange.Change{TenantID: free, Kind: ssochange.KindSAMLConfig}); !isFeatureDenied(err, limits.FeatureSSOConnections) {
		t.Fatalf("approval after the downgrade: %v", err)
	}

	// The paid organization is not affected by the free one's plan.
	if _, err := saml.UpsertConfig(ctx, paid, cfg); err != nil {
		t.Fatalf("a plan with connections must save: %v", err)
	}
}

// A plan that cannot be read refuses the change (fail-closed).
func TestSSOFeatureGateReadErrorRefuses(t *testing.T) {
	sso := &SSOService{features: &featureGate{err: errors.New("db down")}, logger: logger.NewNop()}
	_, err := sso.CreateProvider(context.Background(), CreateProviderInput{TenantID: shared.NewID().String(), Provider: "okta"})
	var fd *limits.ErrFeatureDenied
	if !errors.As(err, &fd) || !fd.Unavailable {
		t.Fatalf("read error must refuse as unavailable: %v", err)
	}
}
