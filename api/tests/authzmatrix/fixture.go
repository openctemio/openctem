//go:build authzmatrix

package authzmatrix

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq" // database/sql driver for the seeding tweaks

	"github.com/openctemio/openctem/api/internal/adminbootstrap"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// Seeding fixture. Everything a principal does goes through the API; the
// database is touched only where no API exists for a test-stack setting
// (the two-factor requirement of a new organization, the bootstrap of the
// platform administrator and the first owners, and backdating an expiry).
// All names are sample data: Acme, Globex, Initech and example.com.

// seedPassword is generated per run (upper, lower, digit and symbol so it meets
// the password policy); no credential lives in the source.
var seedPassword = func() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "Mx1!" + hex.EncodeToString(b)
}()

// codePermissionsStale is the 409 code for a token issued before the
// holder's grants changed (sign in again and retry).
const codePermissionsStale = "permissions_stale"

// Team role slugs.
const (
	teamOwner  = "owner"
	teamAdmin  = "admin"
	teamMember = "member"
)

// System role ids (pkg/domain/permission/system_roles.go).
const (
	roleOwner  = "00000000-0000-0000-0000-000000000001"
	roleAdmin  = "00000000-0000-0000-0000-000000000002"
	roleMember = "00000000-0000-0000-0000-000000000003"
	roleViewer = "00000000-0000-0000-0000-000000000004"
)

type kind string

const (
	kindUser     kind = "user"      // a signed-in member's tenant access token
	kindAPIKey   kind = "api_key"   // an oct_ key of a member or service account
	kindSensor   kind = "sensor"    // an organization sensor's key
	kindUnauth   kind = "anonymous" // no credential
	kindRevoked  kind = "revoked"   // a credential that must no longer work (suspended, offboarded, expired, creator gone)
	kindNoTenant kind = "no_tenant" // a signed-in account in no organization (the platform administrator's)
)

type tenant struct {
	Name, Slug, ID string
	owner          *principal
	// ids holds named resources: the victims the matrix may change or
	// delete, and the scoped / out-of-scope assets and findings.
	mu  sync.Mutex
	ids map[string]string
	// coll maps a GET collection template to one of its ids (harvest).
	coll map[string]string
	// markers identify the tenant in a response body: its id, slug, email
	// domain and every resource id harvested from it.
	markers map[string]bool
}

func (t *tenant) set(k, v string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ids[k] = v
	if len(v) >= 12 && !strings.HasPrefix(v, "00000000-0000-0000-0000-") {
		t.markers[v] = true
	}
}

func (t *tenant) get(k string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ids[k]
}

func (t *tenant) addMarker(v string) {
	if len(v) < 12 || strings.HasPrefix(v, "00000000-0000-0000-0000-") {
		return
	}
	t.mu.Lock()
	t.markers[v] = true
	t.mu.Unlock()
}

func (t *tenant) markerList() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.markers))
	for m := range t.markers {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

type principal struct {
	Name string
	T    *tenant
	Kind kind
	cred credential

	// What the fixture granted (the expectation source, never read back
	// from the server).
	perms       map[string]bool
	adminBypass bool
	teamRole    string // owner, admin, member, viewer
	fullData    bool
	// scoped principals see only the "scoped" asset and its findings.
	scoped bool

	userID, email, token string
	memberID             string // membership id (member routes take it)
	backdated            bool   // session aged past the step-up window (scenarios)
	issued               time.Time
}

func (p *principal) holds(perm string) bool { return p.adminBypass || p.perms[perm] }

type world struct {
	c        *client
	db       *sql.DB
	tenants  []*tenant
	byName   map[string]*principal
	order    []*principal
	adminTmp string // the platform administrator's temporary password
	// totpSecrets holds the authenticator secrets of accounts the
	// scenarios enrolled in two-factor authentication.
	totpSecrets map[string]string
}

func (w *world) add(p *principal) *principal {
	if w.byName == nil {
		w.byName = map[string]*principal{}
	}
	w.byName[p.Name] = p
	w.order = append(w.order, p)
	return p
}

func (w *world) tenant(name string) *tenant {
	for _, t := range w.tenants {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// must fails the test when the call errored or answered another status:
// must(t, "what")(c.do(...)).
func must(t testing.TB, what string, want ...int) func(response, error) response {
	return func(r response, err error) response {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if len(want) == 0 {
			want = []int{200, 201, 204}
		}
		for _, s := range want {
			if r.Status == s {
				return r
			}
		}
		t.Fatalf("%s: %s", what, r)
		return r
	}
}

func permSet(ps ...permission.Permission) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[string(p)] = true
	}
	return m
}

func systemRolePerms(slug string) (map[string]bool, bool) {
	for _, r := range permission.SystemRoles() {
		if r.Slug == slug {
			return permSet(r.Permissions...), r.HasFullDataAccess
		}
	}
	return map[string]bool{}, false
}

var tokenRe = regexp.MustCompile(`token=([A-Za-z0-9_\-]+)`)

// bootstrapTenant creates an organization and its owner with the same code
// the bootstrap-admin command runs, then signs the owner in.
func (w *world) bootstrapTenant(t testing.TB, name, slug string) *tenant {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var out bytes.Buffer
	ownerEmail := "owner@" + slug + ".example.com"
	err := adminbootstrap.Run(ctx, w.db, adminbootstrap.Options{
		Email: "platform-admin@example.com", Role: "super_admin", NoBackup: true,
		OrgName: name, OrgSlug: slug, OrgOwnerEmail: ownerEmail, OrgOwnerName: name + " Owner",
		UIBaseURL: "http://localhost", Logger: logger.New(logger.Config{Level: "error", Format: "text"}),
		Actor: adminbootstrap.Actor{OSUser: "authzmatrix", Hostname: "authzmatrix"},
	}, &out)
	if err != nil {
		t.Fatalf("bootstrap %s: %v", name, err)
	}
	if m := regexp.MustCompile(`Password:\s+(\S+)`).FindStringSubmatch(out.String()); m != nil {
		w.adminTmp = m[1]
	}
	m := tokenRe.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("bootstrap %s printed no set-password link", name)
	}
	// A new organization requires two-factor authentication for owners and
	// administrators; the matrix signs in with passwords only.
	if _, err := w.db.ExecContext(ctx, `UPDATE tenants SET settings = settings || jsonb_build_object('security',
		COALESCE(settings->'security','{}'::jsonb) || '{"mfa_required_for_admins": false}'::jsonb) WHERE slug = $1`, slug); err != nil {
		t.Fatalf("relax mfa for %s: %v", slug, err)
	}
	b := w.c.newBrowser()
	must(t, "set owner password")(b.do("POST", "/api/v1/auth/reset-password", map[string]string{"token": m[1], "new_password": seedPassword}))
	ten := &tenant{Name: name, Slug: slug, ids: map[string]string{}, markers: map[string]bool{}}
	ten.markers["@"+slug+".example.com"] = true
	owner := w.signIn(t, ten, name+"/owner", ownerEmail)
	ten.ID = ten.get("tenant")
	ten.markers[ten.ID] = true
	owner.adminBypass, owner.teamRole, owner.fullData = true, "owner", true
	owner.perms, _ = systemRolePerms("owner")
	ten.owner = owner
	w.tenants = append(w.tenants, ten)
	return ten
}

// signIn logs an account in, exchanges the session for a tenant access
// token and steps it up, returning the user principal.
func (w *world) signIn(t testing.TB, ten *tenant, name, email string) *principal {
	t.Helper()
	return w.add(w.signInOpts(t, ten, name, email, true))
}

func (w *world) signInOpts(t testing.TB, ten *tenant, name, email string, stepUp bool) *principal {
	t.Helper()
	b := w.c.newBrowser()
	r := must(t, "login "+email)(b.do("POST", "/api/v1/auth/login", map[string]string{"email": email, "password": seedPassword}))
	if tok := jsonID(r, "mfa_token"); tok != "" {
		secret := w.totpSecrets[email]
		if secret == "" {
			t.Fatalf("login %s: second factor asked, no secret known", email)
		}
		r = must(t, "mfa "+email)(b.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"mfa_token": tok, "code": freshTOTP(secret)}))
	}
	var login struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Tenants []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"tenants"`
	}
	_ = r.json(&login)
	tid := ""
	for _, x := range login.Tenants {
		if x.Slug == ten.Slug {
			tid = x.ID
		}
	}
	if tid == "" {
		t.Fatalf("login %s: tenant %s not listed: %s", email, ten.Slug, r)
	}
	ten.set("tenant", tid)
	r = must(t, "token "+email)(b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": tid}))
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = r.json(&tok)
	p := &principal{Name: name, T: ten, Kind: kindUser, cred: bearer(tok.AccessToken), token: tok.AccessToken,
		userID: login.User.ID, email: email, perms: map[string]bool{}}
	p.issued = time.Now()
	if stepUp {
		w.stepUp(t, p)
	}
	return p
}

func (w *world) stepUp(t testing.TB, p *principal) {
	t.Helper()
	body := map[string]string{"password": seedPassword}
	if secret := w.totpSecrets[p.email]; secret != "" {
		body = map[string]string{"code": freshTOTP(secret)}
	}
	r, err := w.c.do(withIP(p.cred, nextIP()), "POST", "/api/v1/auth/step-up", body)
	if err != nil || r.Status != 200 {
		t.Logf("step-up %s: %v %s", p.Name, err, r)
	}
}

// invite brings a new account into the tenant with the given roles through
// the invitation flow (the way in when public sign-up is off) and signs it in.
func (w *world) invite(t testing.TB, ten *tenant, local string, roleIDs []string) *principal {
	t.Helper()
	email := local + "@" + ten.Slug + ".example.com"
	r := must(t, "invite "+email)(w.as(t, ten.owner, "POST", "/api/v1/tenants/"+ten.Slug+"/invitations",
		map[string]any{"email": email, "role_ids": roleIDs}))
	var inv struct {
		Token string `json:"token"`
	}
	_ = r.json(&inv)
	return w.invite2(t, ten, email, inv.Token)
}

// invite2 registers the invited account, accepts the invitation and signs in.
func (w *world) invite2(t testing.TB, ten *tenant, email, token string) *principal {
	t.Helper()
	local := strings.SplitN(email, "@", 2)[0]
	b := w.c.newBrowser()
	// 409: a retried registration the stack had already completed.
	must(t, "register "+email, 200, 201, 409)(b.do("POST", "/api/v1/auth/register", map[string]string{"email": email, "password": seedPassword,
		"name": local, "invitation_token": token}))
	r := must(t, "login "+email)(b.do("POST", "/api/v1/auth/login", map[string]string{"email": email, "password": seedPassword}))
	var login struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = r.json(&login)
	must(t, "accept "+email)(b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": token, "refresh_token": login.RefreshToken}))
	return w.signIn(t, ten, ten.Name+"/"+local, email)
}

// createRole creates a custom role and returns its id.
func (w *world) createRole(t testing.TB, ten *tenant, slug string, fullData bool, perms []string, templateID string) string {
	t.Helper()
	body := map[string]any{"slug": slug, "name": slug, "description": "authz matrix", "hierarchy_level": 10,
		"has_full_data_access": fullData, "permissions": perms}
	if templateID != "" {
		body["template_id"] = templateID
	}
	r := must(t, "create role "+slug)(w.as(t, ten.owner, "POST", "/api/v1/roles", body))
	var role struct {
		ID          string   `json:"id"`
		Permissions []string `json:"permissions"`
	}
	_ = r.json(&role)
	if role.ID == "" {
		t.Fatalf("create role %s: no id: %s", slug, r)
	}
	ten.set("role."+slug, role.ID)
	return role.ID
}

func jsonID(r response, path ...string) string {
	var v any
	if json.Unmarshal(r.Body, &v) != nil {
		return ""
	}
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[p]
	}
	s, _ := v.(string)
	return s
}

var _ = fmt.Sprintf

// membershipID finds a user's membership id in the tenant (member routes
// take the membership, not the user).
func (w *world) membershipID(t testing.TB, ten *tenant, userID string) string {
	t.Helper()
	r := must(t, "list members")(w.as(t, ten.owner, "GET", "/api/v1/tenants/"+ten.Slug+"/members?per_page=200&limit=200", nil))
	var v any
	_ = json.Unmarshal(r.Body, &v)
	found := ""
	var walk func(any)
	walk = func(x any) {
		switch o := x.(type) {
		case map[string]any:
			if o["user_id"] == userID {
				if id, ok := o["id"].(string); ok {
					found = id
				}
			}
			for _, c := range o {
				walk(c)
			}
		case []any:
			for _, c := range o {
				walk(c)
			}
		}
	}
	walk(v)
	if found == "" {
		t.Fatalf("membership of %s not found: %s", userID, r)
	}
	return found
}

// resignIn gives a principal a fresh access token (after its grants
// changed, its old token is stale for writes by design).
func (w *world) resignIn(t testing.TB, p *principal) {
	t.Helper()
	fresh := w.signInOpts(t, p.T, p.Name+"#fresh", p.email, true)
	p.cred, p.token, p.issued = fresh.cred, fresh.token, fresh.issued
}

// tokenMaxAge is how long the suite uses an access token before signing in
// again (the stack's access tokens live 15 minutes).
const tokenMaxAge = 10 * time.Minute

// freshen signs a principal in again when its access token is getting old.
func (w *world) freshen(t testing.TB, p *principal) {
	if p.Kind != kindUser || p.T == nil || p.issued.IsZero() || time.Since(p.issued) < tokenMaxAge {
		return
	}
	w.resignIn(t, p)
	if p.backdated {
		w.backdate(t, p)
	}
}

var (
	totpMu   sync.Mutex
	totpSeen = map[string]string{}
)

// freshTOTP returns a code for the secret the server has not seen yet
// (codes are single use): the current one, or the next window's.
func freshTOTP(secret string) string {
	totpMu.Lock()
	defer totpMu.Unlock()
	for i := 0; i < 40; i++ {
		code, _ := totp.Code(secret, time.Now())
		if totpSeen[secret] != code {
			totpSeen[secret] = code
			return code
		}
		time.Sleep(time.Second)
	}
	return totpSeen[secret]
}

// enrollTOTP turns two-factor authentication on for a principal's account
// and keeps the secret. Enabling it ends the account's other sessions.
func (w *world) enrollTOTP(t testing.TB, p *principal) bool {
	t.Helper()
	r, err := w.c.do(p.cred, "POST", "/api/v1/users/me/2fa/setup", map[string]string{"password": seedPassword})
	secret := jsonID(r, "secret")
	if err != nil || secret == "" {
		t.Logf("enroll %s: setup %v %s", p.email, err, r)
		return false
	}
	r, err = w.c.do(p.cred, "POST", "/api/v1/users/me/2fa/enable", map[string]string{"password": seedPassword, "code": freshTOTP(secret)})
	if err != nil || r.Status != 200 {
		t.Logf("enroll %s: enable %v %s", p.email, err, r)
		return false
	}
	if w.totpSecrets == nil {
		w.totpSecrets = map[string]string{}
	}
	w.totpSecrets[p.email] = secret
	return true
}

// as sends a request as a signed-in principal; when its grants changed
// since the token was issued (409 permissions_stale), it signs in again as
// the web client does and retries once.
func (w *world) as(t testing.TB, p *principal, method, path string, body any) (response, error) {
	w.freshen(t, p)
	r, err := w.c.do(p.cred, method, path, body)
	if err == nil && r.Status == 409 && r.Code == codePermissionsStale && p.Kind == kindUser && p.T != nil {
		w.resignIn(t, p)
		if p.backdated {
			w.backdate(t, p)
		}
		r, err = w.c.do(p.cred, method, path, body)
	}
	return r, err
}

// backdate makes a principal's session look signed in two hours ago with
// no step-up, so step-up gates refuse it (a fresh sign-in counts as recent
// authentication). Test-stack database tweak: no API ages a session.
func (w *world) backdate(t testing.TB, p *principal) {
	t.Helper()
	parts := strings.Split(p.token, ".")
	if len(parts) != 3 {
		t.Fatalf("backdate %s: not a JWT", p.Name)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("backdate %s: %v", p.Name, err)
	}
	var claims struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(raw, &claims)
	if claims.SessionID == "" {
		t.Fatalf("backdate %s: no session id in the token", p.Name)
	}
	if _, err := w.db.Exec(`UPDATE sessions SET created_at = NOW() - INTERVAL '2 hours', step_up_at = NULL WHERE id = $1`, claims.SessionID); err != nil {
		t.Fatalf("backdate %s: %v", p.Name, err)
	}
	p.backdated = true
}
