package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/ssochange"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// connLimiter refuses sso_connections additions for the organizations in
// full, the way the entitlement service does at the limit.
type connLimiter struct {
	full  map[shared.ID]bool
	err   error
	calls int
}

func (c *connLimiter) Check(_ context.Context, id shared.ID, key limits.Key, _ int) error {
	c.calls++
	if key != limits.SSOConnections {
		return errors.New("unexpected limit key " + string(key))
	}
	if c.err != nil {
		return &limits.ErrLimitReached{Key: key, Unavailable: true}
	}
	if c.full[id] {
		return &limits.ErrLimitReached{Key: key, Limit: 1, Used: 1}
	}
	return nil
}
func (c *connLimiter) Headroom(context.Context, shared.ID, limits.Key) (int, error) { return 0, nil }
func (c *connLimiter) RecordRefusals(limits.Key, int)                               {}

func isLimitReached(err error) bool {
	var lr *limits.ErrLimitReached
	return errors.As(err, &lr) && lr.Key == limits.SSOConnections
}

func samlInput(t *testing.T) SAMLConfigInput {
	return SAMLConfigInput{IDPEntityID: "https://idp.example.com", IDPSSOURL: "https://idp.example.com/sso",
		IDPCertificate: genTestCertPEM(t)}
}

// Tenant A at its sso_connections limit cannot add a connection, through any
// path; tenant B is not affected by A's limit.
func TestSSOConnectionsLimitRefusesCreateOnly(t *testing.T) {
	ctx := context.Background()
	a, b := shared.NewID(), shared.NewID()
	sso := &SSOService{limits: &connLimiter{full: map[shared.ID]bool{a: true}}, logger: logger.NewNop()}
	repo := newFakeSAMLRepo()
	saml := NewSAMLService(repo, nil, sso, logger.NewNop())
	changes := &SSOChangeService{sso: sso, saml: saml, logger: logger.NewNop()}

	if _, err := saml.UpsertConfig(ctx, a, samlInput(t)); !isLimitReached(err) {
		t.Fatalf("first SAML configuration over the limit: %v", err)
	}
	if _, ok := repo.byTenant[a]; ok {
		t.Fatal("a refused SAML configuration must not be stored")
	}
	if _, err := sso.CreateProvider(ctx, CreateProviderInput{TenantID: a.String(), Provider: "okta"}); !isLimitReached(err) {
		t.Fatalf("OIDC provider create over the limit: %v", err)
	}
	if _, err := changes.SubmitCreateProvider(ctx, CreateProviderInput{TenantID: a.String(), Provider: "okta"}, SSOChangeRequester{}); !isLimitReached(err) {
		t.Fatalf("pending change submission over the limit: %v", err)
	}
	if _, err := changes.liveWrite(ctx, &ssochange.Change{TenantID: a, Kind: ssochange.KindIdPCreate, Payload: []byte(`{}`)}); !isLimitReached(err) {
		t.Fatalf("approval of a create over the limit: %v", err)
	}

	if _, err := saml.UpsertConfig(ctx, b, samlInput(t)); err != nil {
		t.Fatalf("tenant under its limit must save: %v", err)
	}
}

// After a downgrade below the count, existing connections keep working:
// changing one and deleting one are never limited, and sign-in is not touched.
func TestSSOConnectionsLimitNeverBlocksExisting(t *testing.T) {
	ctx := context.Background()
	a := shared.NewID()
	lim := &connLimiter{}
	sso := &SSOService{limits: lim, logger: logger.NewNop()}
	repo := newFakeSAMLRepo()
	saml := NewSAMLService(repo, nil, sso, logger.NewNop())
	if _, err := saml.UpsertConfig(ctx, a, samlInput(t)); err != nil {
		t.Fatal(err)
	}

	lim.full = map[shared.ID]bool{a: true} // downgrade: now over the limit
	if _, err := saml.UpsertConfig(ctx, a, samlInput(t)); err != nil {
		t.Fatalf("changing the existing connection over the limit must work: %v", err)
	}
	if err := saml.DeleteConfig(ctx, a); err != nil {
		t.Fatalf("delete must work over the limit: %v", err)
	}
	if _, ok := repo.byTenant[a]; ok {
		t.Fatal("the connection must be deleted")
	}
}

// A limit that cannot be read refuses a new connection (fail-closed).
func TestSSOConnectionsLimitReadErrorRefuses(t *testing.T) {
	sso := &SSOService{limits: &connLimiter{err: errors.New("db down")}, logger: logger.NewNop()}
	_, err := sso.CreateProvider(context.Background(), CreateProviderInput{TenantID: shared.NewID().String(), Provider: "okta"})
	var lr *limits.ErrLimitReached
	if !errors.As(err, &lr) || !lr.Unavailable {
		t.Fatalf("read error must refuse as unavailable: %v", err)
	}
}

// Without a limit source (self-managed Community) connections are unlimited.
func TestSSOConnectionsNoLimitSourceIsUnlimited(t *testing.T) {
	ctx := context.Background()
	sso := &SSOService{logger: logger.NewNop()}
	repo := newFakeSAMLRepo()
	saml := NewSAMLService(repo, nil, sso, logger.NewNop())
	if _, err := saml.UpsertConfig(ctx, shared.NewID(), samlInput(t)); err != nil {
		t.Fatalf("no limit source must allow: %v", err)
	}
}
