package adminconsole

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/oidc"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// ---- fakes for the revision-4 repository methods ---------------------------

func (f *fakeAdmins) GetByIdPSubject(_ context.Context, issuer, subject string) (*admin.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.byID {
		st := a.SignInState()
		if st.IdPIssuer == issuer && st.IdPSubject == subject {
			return a, nil
		}
	}
	return nil, admin.ErrAdminNotFound
}

func (f *fakeAdmins) BindIdP(_ context.Context, id shared.ID, issuer, subject string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.byID {
		if st := a.SignInState(); st.IdPIssuer == issuer && st.IdPSubject == subject {
			return admin.ErrIdPBindingConflict
		}
	}
	a := f.byID[id.String()]
	st := a.SignInState()
	if st.BreakGlass || st.IdPSubject != "" {
		return admin.ErrIdPBindingConflict
	}
	now := time.Now()
	st.IdPIssuer, st.IdPSubject, st.IdPBoundAt = issuer, subject, &now
	a.WithSignInState(st)
	return nil
}

func (f *fakeAdmins) UnbindIdP(_ context.Context, id shared.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.byID[id.String()]
	st := a.SignInState()
	st.IdPIssuer, st.IdPSubject, st.IdPBoundAt = "", "", nil
	a.WithSignInState(st)
	return nil
}

func (f *fakeAdmins) SetPasswordChangeRequired(_ context.Context, id shared.ID, req bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.byID[id.String()]
	st := a.SignInState()
	st.PasswordChangeRequired = req
	a.WithSignInState(st)
	return nil
}

func (f *fakeAdmins) SetBreakGlassTestedAt(_ context.Context, id shared.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.byID[id.String()]
	st := a.SignInState()
	st.BreakGlassTestedAt = &at
	a.WithSignInState(st)
	return nil
}

func (f *fakeAdmins) ListActive(context.Context) ([]*admin.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*admin.AdminUser{}
	for _, a := range f.byID {
		if a.IsActive() {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeConsole) DeletePasswordSessionsExceptBreakGlass(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for h, s := range f.sessions {
		if s.AuthMethod == admin.AuthMethodPassword && (f.isBreakGlass == nil || !f.isBreakGlass(s.AdminID)) {
			delete(f.sessions, h)
			n++
		}
	}
	return n, nil
}

type fakeIdPRepo struct {
	mu     sync.Mutex
	admins *fakeAdmins
	cfg    *admin.PlatformIdP
	states map[string]*admin.IdPLoginState
}

func (r *fakeIdPRepo) Get(context.Context) (*admin.PlatformIdP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg == nil {
		return nil, admin.ErrPlatformIdPNotConfigured
	}
	cp := *r.cfg
	return &cp, nil
}

func (r *fakeIdPRepo) Save(ctx context.Context, p *admin.PlatformIdP, clearBindings bool) error {
	if p.Enforced() {
		active, _ := r.admins.ListActive(ctx)
		ok := false
		for _, a := range active {
			ok = ok || (a.IsBreakGlass() && a.Role() == admin.AdminRoleSuperAdmin)
		}
		if !ok {
			return admin.ErrLastLocalAdmin
		}
	}
	if clearBindings {
		active, _ := r.admins.ListActive(ctx)
		for _, a := range active {
			_ = r.admins.UnbindIdP(ctx, a.ID())
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *p
	r.cfg = &cp
	return nil
}

func (r *fakeIdPRepo) Delete(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = nil
	return nil
}

func (r *fakeIdPRepo) CreateLoginState(_ context.Context, s *admin.IdPLoginState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *s
	r.states[s.StateHash] = &cp
	return nil
}

func (r *fakeIdPRepo) ConsumeLoginState(_ context.Context, h string, now time.Time) (*admin.IdPLoginState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.states[h]
	delete(r.states, h)
	if !ok || !now.Before(s.ExpiresAt) {
		return nil, admin.ErrIdPLoginStateNotFound
	}
	return s, nil
}

func (r *fakeIdPRepo) DeleteExpiredLoginStates(context.Context, time.Time) error { return nil }

type fakeNotifier struct {
	alerts []BreakGlassAlert
}

func (n *fakeNotifier) NotifyBreakGlassSignIn(_ context.Context, a BreakGlassAlert) error {
	n.alerts = append(n.alerts, a)
	return nil
}

// auditEntries records full entries (severity included).
type auditEntries struct {
	fakeAudit
	entries []*admin.AuditLog
}

func (f *auditEntries) Create(ctx context.Context, l *admin.AuditLog) error {
	f.mu.Lock()
	f.entries = append(f.entries, l)
	f.mu.Unlock()
	return f.fakeAudit.Create(ctx, l)
}

func (f *auditEntries) find(action string) *admin.AuditLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.Action == action {
			return e
		}
	}
	return nil
}

// ---- a small OIDC provider -------------------------------------------------

type mockIdP struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string
	mu     sync.Mutex
	codes  map[string]jwtv5.MapClaims // code -> claims (nonce filled at authorize)
	// sub, email etc. for the next sign-in
	next jwtv5.MapClaims
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{t: t, key: key, codes: map[string]jwtv5.MapClaims{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": m.issuer, "authorization_endpoint": m.issuer + "/authorize",
			"token_endpoint": m.issuer + "/token", "jwks_uri": m.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		claims, ok := m.codes[r.PostForm.Get("code")]
		delete(m.codes, r.PostForm.Get("code"))
		m.mu.Unlock()
		if !ok || r.PostForm.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
		tok.Header["kid"] = "k1"
		s, _ := tok.SignedString(key)
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": s, "access_token": "x"})
	})
	m.srv = httptest.NewTLSServer(mux)
	m.issuer = m.srv.URL
	t.Cleanup(m.srv.Close)
	return m
}

// authorize plays the browser at the IdP: it reads the authorization URL,
// "signs the user in" and returns the code + state the IdP redirects with.
func (m *mockIdP) authorize(authURL string) (code, state string) {
	u, err := url.Parse(authURL)
	if err != nil {
		m.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		m.t.Fatalf("authorization request without PKCE: %s", authURL)
	}
	now := time.Now()
	claims := jwtv5.MapClaims{
		"iss": m.issuer, "aud": q.Get("client_id"), "nonce": q.Get("nonce"),
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range m.next {
		claims[k] = v
	}
	code, _ = oidc.RandomString(16)
	m.mu.Lock()
	m.codes[code] = claims
	m.mu.Unlock()
	return code, q.Get("state")
}

// ---- harness helpers --------------------------------------------------------

type bgHarness struct {
	*harness
	idp      *mockIdP
	idps     *fakeIdPRepo
	notifier *fakeNotifier
	entries  *auditEntries
}

func newBGHarness(t *testing.T) *bgHarness {
	t.Helper()
	h := newHarness(t)
	entries := &auditEntries{}
	h.svc.audit = entries
	h.audit = &entries.fakeAudit
	b := &bgHarness{harness: h, idp: newMockIdP(t), notifier: &fakeNotifier{}, entries: entries}
	b.idps = &fakeIdPRepo{admins: h.admins, states: map[string]*admin.IdPLoginState{}}
	h.svc.SetPlatformIdP(b.idps, oidc.NewClient(b.idp.srv.Client(), nil))
	h.svc.SetBreakGlassNotifier(b.notifier)
	h.console.isBreakGlass = func(id shared.ID) bool {
		a, err := h.admins.GetByID(context.Background(), id)
		return err == nil && a.IsBreakGlass()
	}
	return b
}

// addAdmin adds a linked administrator signed in on /login with a password.
func (b *bgHarness) addAdmin(t *testing.T, email string, role admin.AdminRole, breakGlass bool) (*admin.AdminUser, string) {
	t.Helper()
	uid := shared.NewID()
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), email, "X", role, true, &uid, nil, "", 0, nil, nil, "", now, nil, now)
	if breakGlass {
		if err := a.SetBreakGlass(true); err != nil {
			t.Fatal(err)
		}
	}
	b.admins.mu.Lock()
	b.admins.byID[a.ID().String()] = a
	b.admins.userLink[uid.String()] = a.ID().String()
	b.admins.mu.Unlock()
	token := "refresh-" + email
	b.accounts.mu.Lock()
	b.accounts.sessions[token] = &SignedInUser{UserID: uid, Email: email, Active: true, PasswordSignIn: true}
	b.accounts.passwords[uid.String()] = password
	b.accounts.mu.Unlock()
	return a, token
}

func (b *bgHarness) signIn(t *testing.T, refreshToken string) (string, error) {
	t.Helper()
	res, err := b.svc.Start(context.Background(), refreshToken, client)
	if err != nil {
		return "", err
	}
	code, _ := totp.Code(res.Secret, b.clock)
	token, _, err := b.svc.VerifyMFA(context.Background(), res.PendingToken, code, client)
	return token, err
}

func (b *bgHarness) configureIdP(t *testing.T, mutate func(*PlatformIdPInput)) {
	t.Helper()
	in := PlatformIdPInput{
		Enabled: true, DisplayName: "Corp SSO", Issuer: b.idp.issuer, ClientID: "console",
		ClientSecret: "s3cret", RedirectURI: "https://console.example/admin/login/callback",
	}
	if mutate != nil {
		mutate(&in)
	}
	if _, err := b.svc.SavePlatformIdP(context.Background(), b.admin, in, client); err != nil {
		t.Fatalf("save platform idp: %v", err)
	}
}

// idpSignIn runs start -> IdP -> callback with the given claims.
func (b *bgHarness) idpSignIn(t *testing.T, claims jwtv5.MapClaims) (*IdPLoginResult, error) {
	t.Helper()
	st, err := b.svc.StartIdPLogin(context.Background())
	if err != nil {
		t.Fatalf("start idp: %v", err)
	}
	b.idp.next = claims
	code, state := b.idp.authorize(st.AuthorizationURL)
	if state != st.State {
		t.Fatal("authorization URL does not carry the state")
	}
	return b.svc.CompleteIdPLogin(context.Background(), st.State, state, code, client)
}

// ---- break-glass -----------------------------------------------------------

func TestBreakGlassSignInIsAlerted(t *testing.T) {
	b := newBGHarness(t)
	bg, bgRefresh := b.addAdmin(t, "bg@acme.io", admin.AdminRoleSuperAdmin, true)
	b.addAdmin(t, "readonly@acme.io", admin.AdminRoleReadonly, false)

	if _, err := b.signIn(t, bgRefresh); err != nil {
		t.Fatalf("break-glass sign-in: %v", err)
	}
	e := b.entries.find(ActionBreakGlassSignIn)
	if e == nil || e.Severity != admin.SeverityHigh || e.AdminID == nil || *e.AdminID != bg.ID() {
		t.Fatalf("expected a high-severity break-glass audit row, got %+v", e)
	}
	if len(b.notifier.alerts) != 1 {
		t.Fatalf("expected one notification, got %d", len(b.notifier.alerts))
	}
	got := strings.Join(b.notifier.alerts[0].Recipients, ",")
	if strings.Contains(got, "bg@acme.io") || !strings.Contains(got, "ops@acme.io") || !strings.Contains(got, "readonly@acme.io") {
		t.Fatalf("recipients must be every other active admin, got %q", got)
	}

	// A normal admin's sign-in is not alerted.
	b.notifier.alerts = nil
	b.enroll(t)
	if len(b.notifier.alerts) != 0 {
		t.Fatal("a non-break-glass sign-in must not alert")
	}
}

func TestConfirmBreakGlassTest(t *testing.T) {
	b := newBGHarness(t)
	bg, bgRefresh := b.addAdmin(t, "bg@acme.io", admin.AdminRoleSuperAdmin, true)
	ctx := context.Background()

	if _, err := b.svc.ConfirmBreakGlassTest(ctx, b.admin, bg.ID(), client); !errors.Is(err, admin.ErrNoBreakGlassSignIn) {
		t.Fatalf("no sign-in yet: got %v", err)
	}
	if _, err := b.signIn(t, bgRefresh); err != nil {
		t.Fatal(err)
	}
	// RecordUsage is a no-op in the fake: set last-used like the repository does.
	used := b.clock.Add(-time.Minute)
	bg = admin.Reconstitute(bg.ID(), bg.Email(), bg.Name(), bg.Role(), true, bg.UserID(), &used, "", 0, nil, nil, "", bg.CreatedAt(), nil, bg.UpdatedAt()).
		WithSignInState(bg.SignInState())
	_ = b.admins.Update(ctx, bg)

	if _, err := b.svc.ConfirmBreakGlassTest(ctx, bg, bg.ID(), client); !errors.Is(err, admin.ErrCannotModifySelfBreakGlassTest) {
		t.Fatalf("self-confirmation must be refused, got %v", err)
	}
	if _, err := b.svc.ConfirmBreakGlassTest(ctx, b.admin, b.admin.ID(), client); err == nil {
		t.Fatal("confirming yourself must be refused")
	}
	got, err := b.svc.ConfirmBreakGlassTest(ctx, b.admin, bg.ID(), client)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if ts := got.SignInState().BreakGlassTestedAt; ts == nil || !ts.Equal(used) {
		t.Fatalf("tested_at must be the sign-in time, got %v", ts)
	}
	if got.BreakGlassTestOverdue(b.clock) {
		t.Fatal("just tested: not overdue")
	}
	if !got.BreakGlassTestOverdue(b.clock.Add(91 * 24 * time.Hour)) {
		t.Fatal("after 91 days the test is overdue")
	}

	other, _ := b.addAdmin(t, "plain@acme.io", admin.AdminRoleSuperAdmin, false)
	if _, err := b.svc.ConfirmBreakGlassTest(ctx, b.admin, other.ID(), client); !errors.Is(err, admin.ErrNotBreakGlass) {
		t.Fatalf("not break-glass: got %v", err)
	}
}

func TestProvisionSetsTemporaryPasswordMarker(t *testing.T) {
	b := newBGHarness(t)
	a, temp, err := b.svc.Provision(context.Background(), b.admin, ProvisionInput{
		Email: "new@acme.io", Name: "New", Role: admin.AdminRoleSuperAdmin, BreakGlass: true,
	}, client)
	if err != nil || temp == "" {
		t.Fatalf("provision: %v", err)
	}
	if !a.PasswordChangeRequired() || !a.IsBreakGlass() {
		t.Fatalf("expected break-glass with password change required: %+v", a.SignInState())
	}
	if e := b.entries.find(ActionAdminProvisioned); e == nil || e.Severity != admin.SeverityHigh {
		t.Fatal("provisioning a break-glass admin is a high-severity event")
	}
	if _, _, err := b.svc.Provision(context.Background(), b.admin, ProvisionInput{
		Email: "ro@acme.io", Name: "Ro", Role: admin.AdminRoleReadonly, BreakGlass: true,
	}, client); err == nil {
		t.Fatal("a break-glass admin must be a super admin")
	}
}

func TestPasswordChangeClearsMarker(t *testing.T) {
	b := newBGHarness(t)
	_ = b.admins.SetPasswordChangeRequired(context.Background(), b.admin.ID(), true)
	_, token := b.enroll(t)
	a, sess, err := b.svc.AuthenticateSession(context.Background(), token)
	if err != nil || !a.PasswordChangeRequired() || sess.AuthMethod != admin.AuthMethodPassword {
		t.Fatalf("expected a password session with the marker: %v %+v", err, sess)
	}
	if err := b.svc.ChangePassword(context.Background(), a, password, "Next-Pass-456!", client); err != nil {
		t.Fatal(err)
	}
	a, _ = b.admins.GetByID(context.Background(), a.ID())
	if a.PasswordChangeRequired() {
		t.Fatal("the marker must be cleared")
	}
}

// ---- platform IdP: configuration --------------------------------------------

func TestSavePlatformIdPValidatesAndEncrypts(t *testing.T) {
	b := newBGHarness(t)
	ctx := context.Background()
	base := PlatformIdPInput{Enabled: true, DisplayName: "SSO", Issuer: b.idp.issuer, ClientID: "c",
		ClientSecret: "s", RedirectURI: "https://console.example/admin/login/callback"}

	bad := map[string]func(*PlatformIdPInput){
		"http issuer":         func(i *PlatformIdPInput) { i.Issuer = "http://idp.example" },
		"no client id":        func(i *PlatformIdPInput) { i.ClientID = "" },
		"http redirect":       func(i *PlatformIdPInput) { i.RedirectURI = "http://console.example/cb" },
		"redirect w/ creds":   func(i *PlatformIdPInput) { i.RedirectURI = "https://u:p@console.example/cb" },
		"scopes w/o openid":   func(i *PlatformIdPInput) { i.Scopes = []string{"email"} },
		"no secret on create": func(i *PlatformIdPInput) { i.ClientSecret = "" },
		"unreachable issuer":  func(i *PlatformIdPInput) { i.Issuer = "https://127.0.0.1:1" },
		"bad acr value":       func(i *PlatformIdPInput) { i.TrustedACRValues = []string{"a b"} },
	}
	for name, m := range bad {
		in := base
		m(&in)
		if _, err := b.svc.SavePlatformIdP(ctx, b.admin, in, client); !shared.IsValidation(err) {
			t.Fatalf("%s: expected a validation error, got %v", name, err)
		}
	}

	in := base
	in.RedirectURI = "http://localhost:3000/admin/login/callback" // loopback http is allowed
	p, err := b.svc.SavePlatformIdP(ctx, b.admin, in, client)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if p.ClientSecretEncrypted == "" || p.ClientSecretEncrypted == "s" {
		t.Fatal("the client secret must be stored encrypted")
	}
	if p.TokenEndpoint != b.idp.issuer+"/token" || p.JWKSURI != b.idp.issuer+"/jwks" {
		t.Fatalf("endpoints must come from discovery: %+v", p)
	}
	if e := b.entries.find(ActionPlatformIdPSave); e == nil || e.Severity != admin.SeverityHigh {
		t.Fatal("config changes are audited with high severity")
	} else if raw, _ := json.Marshal(e.RequestBody); strings.Contains(string(raw), `"s"`) {
		t.Fatal("the audit row must not carry the secret")
	}

	// Update without a secret keeps the stored one.
	in.ClientSecret = ""
	in.DisplayName = "Renamed"
	p2, err := b.svc.SavePlatformIdP(ctx, b.admin, in, client)
	if err != nil || p2.ClientSecretEncrypted != p.ClientSecretEncrypted || p2.DisplayName != "Renamed" {
		t.Fatalf("update must keep the secret: %v", err)
	}
}

func TestRequireIdPNeedsABreakGlassAdmin(t *testing.T) {
	b := newBGHarness(t)
	in := func(i *PlatformIdPInput) { i.RequireIdP = true }
	_, err := b.svc.SavePlatformIdP(context.Background(), b.admin, PlatformIdPInput{
		Enabled: true, DisplayName: "SSO", Issuer: b.idp.issuer, ClientID: "c", ClientSecret: "s",
		RedirectURI: "https://console.example/cb", RequireIdP: true,
	}, client)
	if !errors.Is(err, admin.ErrLastLocalAdmin) {
		t.Fatalf("require IdP without a break-glass admin must be refused, got %v", err)
	}
	b.addAdmin(t, "bg@acme.io", admin.AdminRoleSuperAdmin, true)
	b.configureIdP(t, in)
}

func TestRequireIdPRefusesLocalPathExceptBreakGlass(t *testing.T) {
	b := newBGHarness(t)
	_, bgRefresh := b.addAdmin(t, "bg@acme.io", admin.AdminRoleSuperAdmin, true)
	_, token := b.enroll(t) // a live password session of a normal admin

	b.configureIdP(t, func(i *PlatformIdPInput) { i.RequireIdP = true })

	if _, err := b.svc.Authenticate(context.Background(), token); err == nil {
		t.Fatal("turning on require-IdP must end non-break-glass password sessions")
	}
	if _, err := b.svc.Start(context.Background(), refresh, client); !errors.Is(err, admin.ErrIdPSignInRequired) {
		t.Fatalf("local path must be refused, got %v", err)
	}
	if !b.audit.has(ActionLoginFailed) {
		t.Fatal("the refusal is audited")
	}
	if _, err := b.signIn(t, bgRefresh); err != nil {
		t.Fatalf("break-glass must still sign in locally: %v", err)
	}
}

// ---- platform IdP: sign-in -------------------------------------------------

func verifiedClaims(sub, email string) jwtv5.MapClaims {
	return jwtv5.MapClaims{"sub": sub, "email": email, "email_verified": true}
}

func TestIdPSignInBindsThenMatchesBySubject(t *testing.T) {
	b := newBGHarness(t)
	b.configureIdP(t, nil)
	ctx := context.Background()

	res, err := b.idpSignIn(t, verifiedClaims("sub-ops", "OPS@acme.io"))
	if err != nil {
		t.Fatalf("first IdP sign-in: %v", err)
	}
	// Default: the console TOTP is still required after the IdP.
	if res.Status != StatusMFAEnrollment || res.Second == nil || res.SessionToken != "" {
		t.Fatalf("expected the TOTP step, got %+v", res)
	}
	a, _ := b.admins.GetByID(ctx, b.admin.ID())
	if st := a.SignInState(); st.IdPSubject != "sub-ops" || st.IdPIssuer != b.idp.issuer {
		t.Fatalf("expected binding to (issuer, sub-ops), got %+v", st)
	}
	if !b.audit.has(ActionIdPBound) {
		t.Fatal("binding is audited")
	}
	code, _ := totp.Code(res.Second.Secret, b.clock)
	token, _, err := b.svc.VerifyMFA(ctx, res.Second.PendingToken, code, client)
	if err != nil {
		t.Fatalf("totp after IdP: %v", err)
	}
	_, sess, err := b.svc.AuthenticateSession(ctx, token)
	if err != nil || sess.AuthMethod != admin.AuthMethodIdP {
		t.Fatalf("session must record the IdP: %v %+v", err, sess)
	}

	// Later sign-ins match on (issuer, sub): a changed email still works...
	if _, err := b.idpSignIn(t, jwtv5.MapClaims{"sub": "sub-ops", "email": "renamed@other.io"}); err != nil {
		t.Fatalf("bound subject must sign in regardless of email: %v", err)
	}
	// ...and another subject with the admin's email does not.
	if _, err := b.idpSignIn(t, verifiedClaims("sub-attacker", "ops@acme.io")); !errors.Is(err, admin.ErrIdPSignInFailed) {
		t.Fatalf("a second subject for a bound admin must be refused, got %v", err)
	}
}

func TestIdPSignInRefusals(t *testing.T) {
	b := newBGHarness(t)
	b.addAdmin(t, "bg@acme.io", admin.AdminRoleSuperAdmin, true)
	b.configureIdP(t, nil)

	cases := map[string]jwtv5.MapClaims{
		"unverified email":    {"sub": "s1", "email": "ops@acme.io", "email_verified": false},
		"no email":            {"sub": "s2"},
		"unknown person":      verifiedClaims("s3", "stranger@acme.io"),
		"break-glass account": verifiedClaims("s4", "bg@acme.io"),
	}
	for name, claims := range cases {
		if _, err := b.idpSignIn(t, claims); !errors.Is(err, admin.ErrIdPSignInFailed) {
			t.Fatalf("%s: expected refusal, got %v", name, err)
		}
	}
	if _, err := b.admins.GetByEmail(context.Background(), "stranger@acme.io"); err == nil {
		t.Fatal("no administrator may be created from the IdP")
	}
	if e := b.entries.find(ActionIdPLoginFailed); e == nil || e.ErrorMessage == "" {
		t.Fatal("failures are audited with their reason")
	}

	// Inactive administrator.
	a, _ := b.admins.GetByID(context.Background(), b.admin.ID())
	a.Deactivate()
	if _, err := b.idpSignIn(t, verifiedClaims("s5", "ops@acme.io")); !errors.Is(err, admin.ErrIdPSignInFailed) {
		t.Fatalf("inactive admin: got %v", err)
	}
}

func TestIdPCallbackStateIsBoundAndSingleUse(t *testing.T) {
	b := newBGHarness(t)
	b.configureIdP(t, nil)
	ctx := context.Background()

	st, err := b.svc.StartIdPLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b.idp.next = verifiedClaims("sub-ops", "ops@acme.io")
	code, state := b.idp.authorize(st.AuthorizationURL)

	// Another browser (no / different cookie) cannot complete it.
	if _, err := b.svc.CompleteIdPLogin(ctx, "other-cookie", state, code, client); !errors.Is(err, admin.ErrIdPSignInFailed) {
		t.Fatalf("cookie mismatch must fail, got %v", err)
	}
	// The right browser can, once.
	if _, err := b.svc.CompleteIdPLogin(ctx, st.State, state, code, client); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if _, err := b.svc.CompleteIdPLogin(ctx, st.State, state, code, client); !errors.Is(err, admin.ErrIdPSignInFailed) {
		t.Fatalf("replayed state must fail, got %v", err)
	}
}

func TestIdPNonceMismatchIsRefused(t *testing.T) {
	b := newBGHarness(t)
	b.configureIdP(t, nil)
	b.idp.next = jwtv5.MapClaims{"sub": "sub-ops", "email": "ops@acme.io", "email_verified": true, "nonce": "forged"}
	st, _ := b.svc.StartIdPLogin(context.Background())
	code, state := b.idp.authorize(st.AuthorizationURL)
	if _, err := b.svc.CompleteIdPLogin(context.Background(), st.State, state, code, client); !errors.Is(err, admin.ErrIdPSignInFailed) {
		t.Fatalf("nonce mismatch must fail, got %v", err)
	}
}

func TestTrustedACRSkipsConsoleTOTP(t *testing.T) {
	b := newBGHarness(t)
	b.configureIdP(t, func(i *PlatformIdPInput) { i.TrustedACRValues = []string{"urn:corp:mfa"} })
	ctx := context.Background()

	st, _ := b.svc.StartIdPLogin(ctx)
	if !strings.Contains(st.AuthorizationURL, "acr_values=urn%3Acorp%3Amfa") {
		t.Fatalf("trusted acr must be requested: %s", st.AuthorizationURL)
	}

	// Without the acr: TOTP still required.
	res, err := b.idpSignIn(t, verifiedClaims("sub-ops", "ops@acme.io"))
	if err != nil || res.Status == StatusSignedIn {
		t.Fatalf("without trusted acr TOTP is required: %v %+v", err, res)
	}
	// With it: a verified IdP session directly.
	claims := verifiedClaims("sub-ops", "ops@acme.io")
	claims["acr"] = "urn:corp:mfa"
	res, err = b.idpSignIn(t, claims)
	if err != nil || res.Status != StatusSignedIn || res.SessionToken == "" {
		t.Fatalf("trusted acr must sign in: %v %+v", err, res)
	}
	if _, sess, err := b.svc.AuthenticateSession(ctx, res.SessionToken); err != nil || sess.AuthMethod != admin.AuthMethodIdP {
		t.Fatalf("session: %v", err)
	}
}

func TestIssuerChangeClearsBindings(t *testing.T) {
	b := newBGHarness(t)
	b.configureIdP(t, nil)
	if _, err := b.idpSignIn(t, verifiedClaims("sub-ops", "ops@acme.io")); err != nil {
		t.Fatal(err)
	}
	other := newMockIdP(t)
	b.configureIdP(t, func(i *PlatformIdPInput) { i.Issuer = other.issuer })
	a, _ := b.admins.GetByID(context.Background(), b.admin.ID())
	if a.IdPBound() {
		t.Fatal("changing the issuer must remove bindings")
	}
}

func TestPublicIdPInfo(t *testing.T) {
	b := newBGHarness(t)
	if b.svc.PublicIdP(context.Background()).Enabled {
		t.Fatal("not configured: not offered")
	}
	b.configureIdP(t, func(i *PlatformIdPInput) { i.Enabled = false })
	if b.svc.PublicIdP(context.Background()).Enabled {
		t.Fatal("disabled: not offered")
	}
	if _, err := b.svc.StartIdPLogin(context.Background()); !errors.Is(err, admin.ErrPlatformIdPNotConfigured) {
		t.Fatal("a disabled IdP cannot start a sign-in")
	}
	b.configureIdP(t, nil)
	if info := b.svc.PublicIdP(context.Background()); !info.Enabled || info.DisplayName != "Corp SSO" {
		t.Fatalf("got %+v", info)
	}
}
