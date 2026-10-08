package mcpoauth_test

// The MCP authorization server end to end over a migrated database
// (RFC-062): authorization request, consent, code redemption, refresh
// rotation, revocation and the resource-server check, with the attacks the
// design defends against: code reuse, PKCE mismatch, redirect URI
// tampering, refresh reuse, consent by someone else, cross-tenant use,
// scope escalation and wrong resource.
//
// DB-gated: DATABASE_URL must point at a migrated *_test database.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	mcpoauthdom "github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	issuer     = "https://openctem.example"
	resource   = issuer + "/api/v1/mcp"
	clientID   = "https://assistant.example/oauth/client.json"
	redirect   = "http://127.0.0.1:33418/callback"
	verifier   = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXkdBjftJeZ4CVP"
	verifier2  = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG9mcmVk"
	otherCIMD  = "https://other.example/client.json"
	otherRedir = "https://other.example/cb"
)

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// fakeFetcher serves fixed metadata documents.
type fakeFetcher map[string]*mcpoauthdom.Client

func (f fakeFetcher) Fetch(_ context.Context, id string) (*mcpoauthdom.Client, error) {
	c, ok := f[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *c
	return &cp, nil
}

// heldPerms is what each user holds; owners hold everything.
type heldPerms map[string][]string

func (h heldPerms) HeldPermissions(_ context.Context, _, userID shared.ID) (bool, []string, error) {
	p, ok := h[userID.String()]
	if !ok {
		return true, nil, nil
	}
	return false, p, nil
}

// fakePolicies is each organization's MCP policy (defaults when absent).
type fakePolicies map[string]tenantdom.MCPSettings

func (f fakePolicies) MCPPolicy(_ context.Context, id shared.ID) (tenantdom.MCPSettings, error) {
	return f[id.String()], nil
}

type harness struct {
	t        *testing.T
	db       *sql.DB
	svc      *mcpoauth.Service
	tenant   string
	other    string
	held     heldPerms
	policies fakePolicies
	cfg      mcpoauth.Config
}

// withTrustedHosts is the same authorization server with another platform
// list of trusted client hosts.
func (h *harness) withTrustedHosts(hosts []string) *mcpoauth.Service {
	h.t.Helper()
	cfg := h.cfg
	cfg.TrustedClientHosts = hosts
	svc, err := mcpoauth.NewService(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return svc
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	sqldb, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &postgres.DB{DB: sqldb}
	h := &harness{t: t, db: sqldb, held: heldPerms{}, policies: fakePolicies{}}
	h.tenant, h.other = h.newTenant(), h.newTenant()

	e, err := mcpoauthdom.NewEndpoints(issuer)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg = mcpoauth.Config{
		Repository:  postgres.NewMCPOAuthRepository(db),
		Connections: postgres.NewMCPOAuthRepository(db),
		Endpoints:   e,
		Pepper:      "mcp-oauth-test-pepper",
		Fetcher: fakeFetcher{
			clientID:  {ClientID: clientID, Kind: mcpoauthdom.ClientKindMetadataDocument, Name: "Desk Assistant", RedirectURIs: []string{redirect}},
			otherCIMD: {ClientID: otherCIMD, Kind: mcpoauthdom.ClientKindMetadataDocument, Name: "Other", RedirectURIs: []string{otherRedir}},
		},
		Members:     apikey.NewMembershipChecker(postgres.NewTenantRepository(db), postgres.NewUserRepository(db)),
		Permissions: h.held,
		Policies:    h.policies,
		// The default policy admits verified clients only: the platform
		// vouches for both test hosts.
		TrustedClientHosts: []string{"assistant.example", "https://other.example"},
		Logger:             logger.NewNop(),
	}
	h.svc, err = mcpoauth.NewService(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM mcp_oauth_clients WHERE client_id IN ($1, $2)`, clientID, otherCIMD)
	})
	return h
}

func (h *harness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *harness) newTenant() string {
	id := uuid.NewString()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'MCP OAuth IT', $2)`, id, "mcpoauth-"+strings.ReplaceAll(id[:13], "-", ""))
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM mcp_oauth_grants WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = h.db.ExecContext(ctx, q, id)
		}
	})
	return id
}

// member adds a user to tenant with role; perms (non-owner) is what they hold.
func (h *harness) member(tenant, role string, perms ...string) shared.ID {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'MCP OAuth IT')`, id, "mcpoauth-"+id[:8]+"@it.test")
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	h.join(tenant, id, role)
	if role != "owner" && role != "admin" {
		h.held[id] = perms
	}
	return shared.MustIDFromString(id)
}

func (h *harness) join(tenant, user, role string) {
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, $4)`, uuid.NewString(), user, tenant, role)
}

func authorizeQuery(overrides map[string]string) url.Values {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"code_challenge":        {challenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"st-1"},
		"resource":              {resource},
		"scope":                 {"mcp:findings.read mcp:pentest.read"},
	}
	for k, v := range overrides {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

// approve runs authorize + consent for user in tenant and returns the code.
func (h *harness) approve(user shared.ID, tenant string, q url.Values) string {
	h.t.Helper()
	ctx := context.Background()
	id, aerr := h.svc.StartAuthorization(ctx, q)
	if aerr != nil {
		h.t.Fatalf("authorize: %v", aerr)
	}
	to, err := h.svc.Approve(ctx, id, user, shared.MustIDFromString(tenant), mcpoauth.Actor{})
	if err != nil {
		h.t.Fatalf("approve: %v", err)
	}
	u, _ := url.Parse(to)
	if u.Query().Get("iss") != issuer || u.Query().Get("state") != q.Get("state") {
		h.t.Fatalf("redirect %s lacks iss/state", to)
	}
	return u.Query().Get("code")
}

func (h *harness) exchange(code, v string, overrides map[string]string) (*mcpoauth.TokenResponse, *mcpoauth.OAuthError) {
	f := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v},
		"client_id": {clientID}, "redirect_uri": {redirect}, "resource": {resource},
	}
	for k, val := range overrides {
		f.Set(k, val)
	}
	return h.svc.Token(context.Background(), f, mcpoauth.Actor{})
}

func (h *harness) refresh(rt string, extra map[string]string) (*mcpoauth.TokenResponse, *mcpoauth.OAuthError) {
	f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}}
	for k, v := range extra {
		f.Set(k, v)
	}
	return h.svc.Token(context.Background(), f, mcpoauth.Actor{})
}

func (h *harness) principal(at string) (*mcpoauth.Principal, error) {
	return h.svc.AuthenticateAccessToken(context.Background(), at, "198.51.100.1")
}

func TestFullFlowBindsTenantUserAndIntersectsPermissions(t *testing.T) {
	h := newHarness(t)
	// A member holding findings:read only: the pentest scope gives nothing.
	user := h.member(h.tenant, "member", "findings:read", "assets:read")
	code := h.approve(user, h.tenant, authorizeQuery(nil))
	tok, oerr := h.exchange(code, verifier, nil)
	if oerr != nil {
		t.Fatalf("exchange: %v", oerr)
	}
	if !strings.HasPrefix(tok.AccessToken, mcpoauthdom.AccessTokenPrefix) || !strings.HasPrefix(tok.RefreshToken, mcpoauthdom.RefreshTokenPrefix) {
		t.Fatalf("token formats: %+v", tok)
	}
	if tok.Scope != "mcp:findings.read" || tok.ExpiresIn != 600 || tok.TokenType != "Bearer" {
		t.Fatalf("token response: %+v (pentest must not be granted)", tok)
	}
	p, err := h.principal(tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if p.TenantID != h.tenant || p.UserID != user.String() || p.ClientID != clientID {
		t.Fatalf("principal %+v", p)
	}
	var lastIP sql.NullString
	if err := h.db.QueryRow(`SELECT last_used_ip FROM mcp_oauth_grants WHERE id = $1`, p.GrantID).Scan(&lastIP); err != nil || lastIP.String != "198.51.100.1" {
		t.Fatalf("last use not recorded: %v %v", lastIP, err)
	}
	// assets:read is held but not granted: not effective.
	if len(p.Permissions) != 1 || p.Permissions[0] != "findings:read" {
		t.Fatalf("effective permissions %v, want [findings:read]", p.Permissions)
	}

	// The user loses findings:read: the next request has nothing.
	h.held[user.String()] = []string{"assets:read"}
	p, err = h.principal(tok.AccessToken)
	if err != nil || len(p.Permissions) != 0 {
		t.Fatalf("after demotion: %v %v", p, err)
	}

	// Suspended membership: the token stops working at once.
	h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1`, user.String())
	if _, err := h.principal(tok.AccessToken); !errors.Is(err, mcpoauth.ErrInvalidToken) {
		t.Fatalf("suspended member's token accepted: %v", err)
	}
}

func TestCodeIsSingleUseAndReuseRevokesTheGrant(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	code := h.approve(user, h.tenant, authorizeQuery(nil))
	tok, oerr := h.exchange(code, verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if _, oerr := h.exchange(code, verifier, nil); oerr == nil || oerr.Code != "invalid_grant" {
		t.Fatalf("second redemption: %v", oerr)
	}
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("tokens of a reused code still work")
	}
	if _, oerr := h.refresh(tok.RefreshToken, nil); oerr == nil {
		t.Fatal("refresh token of a reused code still works")
	}
}

func TestPKCEAndRedirectAndResourceMismatchBurnTheCode(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	for name, tc := range map[string]struct {
		v         string
		overrides map[string]string
		want      string
	}{
		"wrong verifier":       {verifier2, nil, "invalid_grant"},
		"other redirect_uri":   {verifier, map[string]string{"redirect_uri": "http://127.0.0.1:1/callback"}, "invalid_grant"},
		"other client":         {verifier, map[string]string{"client_id": otherCIMD}, "invalid_grant"},
		"other resource":       {verifier, map[string]string{"resource": "https://evil.example/mcp"}, "invalid_target"},
		"plain short verifier": {"short", nil, "invalid_request"},
	} {
		code := h.approve(user, h.tenant, authorizeQuery(nil))
		if _, oerr := h.exchange(code, tc.v, tc.overrides); oerr == nil || oerr.Code != tc.want {
			t.Errorf("%s: %v, want %s", name, oerr, tc.want)
		}
		if tc.want == "invalid_grant" {
			if _, oerr := h.exchange(code, verifier, nil); oerr == nil {
				t.Errorf("%s: the code still worked after a failed redemption", name)
			}
		}
	}
}

func TestAuthorizeRefusals(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Errors that must never redirect: unknown client, unregistered redirect.
	for name, q := range map[string]url.Values{
		"unknown client":         authorizeQuery(map[string]string{"client_id": "https://unknown.example/c.json"}),
		"no client":              authorizeQuery(map[string]string{"client_id": ""}),
		"unregistered redirect":  authorizeQuery(map[string]string{"redirect_uri": "https://evil.example/cb"}),
		"redirect path added":    authorizeQuery(map[string]string{"redirect_uri": redirect + "/x"}),
		"redirect host switched": authorizeQuery(map[string]string{"redirect_uri": "http://localhost:33418/callback"}),
	} {
		if _, aerr := h.svc.StartAuthorization(ctx, q); aerr == nil || aerr.Redirect {
			t.Errorf("%s: %+v, want a non-redirecting error", name, aerr)
		}
	}
	// Errors sent back to the (registered) redirect URI.
	for name, tc := range map[string]struct {
		q    url.Values
		code string
	}{
		"plain PKCE":     {authorizeQuery(map[string]string{"code_challenge_method": "plain"}), "invalid_request"},
		"no PKCE":        {authorizeQuery(map[string]string{"code_challenge": ""}), "invalid_request"},
		"no resource":    {authorizeQuery(map[string]string{"resource": ""}), "invalid_target"},
		"other resource": {authorizeQuery(map[string]string{"resource": "https://openctem.example/api/v1/other"}), "invalid_target"},
		"token response": {authorizeQuery(map[string]string{"response_type": "token"}), "unsupported_response_type"},
		"unknown scope":  {authorizeQuery(map[string]string{"scope": "mcp:findings.read admin"}), "invalid_scope"},
		"silent":         {authorizeQuery(map[string]string{"prompt": "none"}), "consent_required"},
	} {
		_, aerr := h.svc.StartAuthorization(ctx, tc.q)
		if aerr == nil || !aerr.Redirect || aerr.Code != tc.code {
			t.Errorf("%s: %+v, want redirect with %s", name, aerr, tc.code)
			continue
		}
		u, _ := url.Parse(h.svc.AuthorizeErrorRedirect(aerr))
		if u.Query().Get("iss") != issuer || u.Query().Get("error") != tc.code {
			t.Errorf("%s: error redirect %s", name, u)
		}
	}
	// Repeated parameter.
	q := authorizeQuery(nil)
	q.Add("redirect_uri", "https://evil.example/cb")
	if _, aerr := h.svc.StartAuthorization(ctx, q); aerr == nil || aerr.Redirect {
		t.Errorf("repeated redirect_uri: %+v", aerr)
	}
	// Loopback: another port is the same redirect URI; uppercase resource host accepted.
	if _, aerr := h.svc.StartAuthorization(ctx, authorizeQuery(map[string]string{
		"redirect_uri": "http://127.0.0.1:50999/callback", "resource": "HTTPS://OpenCTEM.example/api/v1/mcp/",
	})); aerr != nil {
		t.Errorf("loopback other port / resource case: %+v", aerr)
	}
}

func TestConsentCannotBeAnsweredBySomeoneElse(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	alice := h.member(h.tenant, "owner")
	mallory := h.member(h.tenant, "owner")
	outsider := h.member(h.other, "owner")

	id, aerr := h.svc.StartAuthorization(ctx, authorizeQuery(nil))
	if aerr != nil {
		t.Fatal(aerr)
	}
	if _, err := h.svc.ConsentRequest(ctx, id, alice, shared.MustIDFromString(h.tenant)); err != nil {
		t.Fatal(err)
	}
	// Claimed by Alice: Mallory can neither see nor answer it.
	if _, err := h.svc.ConsentRequest(ctx, id, mallory, shared.MustIDFromString(h.tenant)); !errors.Is(err, mcpoauth.ErrConsentUnavailable) {
		t.Fatalf("other user read a claimed request: %v", err)
	}
	if _, err := h.svc.Approve(ctx, id, mallory, shared.MustIDFromString(h.tenant), mcpoauth.Actor{}); err == nil {
		t.Fatal("other user approved a claimed request")
	}
	// Alice cannot approve into an organization she is not a member of.
	if _, err := h.svc.Approve(ctx, id, alice, shared.MustIDFromString(h.other), mcpoauth.Actor{}); err == nil {
		t.Fatal("approved into a foreign organization")
	}
	_ = outsider
	// Deny: redirect carries access_denied; the request is then closed.
	to, err := h.svc.Deny(ctx, id, alice, shared.MustIDFromString(h.tenant), mcpoauth.Actor{})
	if err != nil || !strings.Contains(to, "error=access_denied") {
		t.Fatalf("deny: %s %v", to, err)
	}
	if _, err := h.svc.Approve(ctx, id, alice, shared.MustIDFromString(h.tenant), mcpoauth.Actor{}); err == nil {
		t.Fatal("approved a denied request")
	}
	// Nothing to grant: a member holding none of the requested access.
	viewer := h.member(h.tenant, "viewer")
	id2, _ := h.svc.StartAuthorization(ctx, authorizeQuery(map[string]string{"scope": "mcp:pentest.read"}))
	if _, err := h.svc.Approve(ctx, id2, viewer, shared.MustIDFromString(h.tenant), mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrNothingToGrant) {
		t.Fatalf("nothing to grant: %v", err)
	}
}

func TestRefreshRotatesAndReuseRevokesTheGrant(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	next, oerr := h.refresh(tok.RefreshToken, nil)
	if oerr != nil || next.RefreshToken == tok.RefreshToken {
		t.Fatalf("rotation: %+v %v", next, oerr)
	}
	if _, err := h.principal(next.AccessToken); err != nil {
		t.Fatalf("rotated access token: %v", err)
	}
	// Widening is refused; narrowing works.
	if _, oerr := h.refresh(next.RefreshToken, map[string]string{"scope": "mcp:findings.read mcp:assets.read"}); oerr == nil || oerr.Code != "invalid_scope" {
		t.Fatalf("widening: %v", oerr)
	}
	// The old refresh token presented again: the grant is revoked.
	if _, oerr := h.refresh(tok.RefreshToken, nil); oerr == nil || oerr.Code != "invalid_grant" {
		t.Fatalf("reuse: %v", oerr)
	}
	if _, err := h.principal(next.AccessToken); err == nil {
		t.Fatal("access token survived refresh reuse")
	}
	if _, oerr := h.refresh(next.RefreshToken, nil); oerr == nil {
		t.Fatal("refresh token survived refresh reuse")
	}
}

func TestRefreshByAnotherClientAndRevocation(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if _, oerr := h.refresh(tok.RefreshToken, map[string]string{"client_id": otherCIMD}); oerr == nil {
		t.Fatal("another client refreshed the grant")
	}
	// Another client cannot revoke it either.
	h.svc.Revoke(context.Background(), tok.AccessToken, otherCIMD, mcpoauth.Actor{})
	if _, err := h.principal(tok.AccessToken); err != nil {
		t.Fatalf("revoked by another client: %v", err)
	}
	h.svc.Revoke(context.Background(), tok.AccessToken, clientID, mcpoauth.Actor{})
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("token survived revocation")
	}
	if _, oerr := h.refresh(tok.RefreshToken, nil); oerr == nil {
		t.Fatal("refresh token survived revocation of the grant")
	}
}

func TestTokenIsBoundToItsTenant(t *testing.T) {
	h := newHarness(t)
	// One person in two organizations: the grant names the one approved.
	user := h.member(h.tenant, "owner")
	h.join(h.other, user.String(), "owner")
	tok, oerr := h.exchange(h.approve(user, h.other, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	p, err := h.principal(tok.AccessToken)
	if err != nil || p.TenantID != h.other {
		t.Fatalf("principal tenant %v %v, want %s", p, err, h.other)
	}
	// Leaving that organization ends the token, whatever the other one says.
	h.exec(`DELETE FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, user.String(), h.other)
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("token outlived the membership it was granted in")
	}
}

func TestBlockedClientStopsWorking(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	h.exec(`UPDATE mcp_oauth_clients SET blocked_at = now() WHERE client_id = $1`, clientID)
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("blocked client's token accepted")
	}
	if _, aerr := h.svc.StartAuthorization(context.Background(), authorizeQuery(nil)); aerr == nil || aerr.Redirect {
		t.Fatalf("blocked client authorized: %+v", aerr)
	}
}

func TestOnlyAccessTokensAuthenticate(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	for _, bad := range []string{tok.RefreshToken, "octm_at_" + strings.Repeat("A", 43), "oct_x", ""} {
		if _, err := h.principal(bad); err == nil {
			t.Errorf("%q authenticated", bad)
		}
	}
}
