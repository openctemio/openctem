//go:build authscenarios

package authscenarios

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/totp"
)

// System role ids (seeded, tenant_id NULL).
const (
	roleAdmin  = "00000000-0000-0000-0000-000000000002"
	roleMember = "00000000-0000-0000-0000-000000000003"
)

// world is the stack under test: the API, its database (for the seeding
// steps no API offers: an organization's rules, a federated session as its
// identity provider's callback leaves it) and the bootstrap tool.
type world struct {
	api       string
	db        *sql.DB
	bootstrap string
	password  string
	run       string

	bootMu sync.Mutex // bootstrap-admin runs one at a time
}

var (
	worldOnce sync.Once
	theWorld  *world
	worldErr  error
)

func getWorld(t *testing.T) *world {
	t.Helper()
	api, dsn, boot := os.Getenv("AUTHSCEN_API"), os.Getenv("AUTHSCEN_DATABASE_URL"), os.Getenv("AUTHSCEN_BOOTSTRAP")
	if api == "" || dsn == "" || boot == "" {
		t.Skip("AUTHSCEN_API, AUTHSCEN_DATABASE_URL and AUTHSCEN_BOOTSTRAP not set (run server/tests/authscenarios/ci/run.sh)")
	}
	worldOnce.Do(func() {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			worldErr = err
			return
		}
		db.SetMaxOpenConns(8)
		if err := db.Ping(); err != nil {
			worldErr = err
			return
		}
		theWorld = &world{api: api, db: db, bootstrap: boot, run: randHex(3),
			password: "Sc3n-" + randHex(8) + "-Pw!"}
	})
	if worldErr != nil {
		t.Fatalf("stack: %v", worldErr)
	}
	return theWorld
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (w *world) exec(t testing.TB, q string, args ...any) {
	t.Helper()
	if _, err := w.db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("sql %q: %v", q, err)
	}
}

// org is one organization of a scenario and its owner's signed-in profile.
type org struct {
	ID, Slug string
	owner    *browser
	ownerID  string
	ownerTOT string // the owner's authenticator secret, when enrolled
	ownerEml string
}

var tokenRe = regexp.MustCompile(`set-password#token=(\S+)`)

// newOrg creates an organization and its owner with bootstrap-admin, sets
// the owner's password and signs the owner in. A new organization requires
// two-factor authentication for owners and administrators; that default is
// turned off here, and each scenario then applies the rule it tests.
func (w *world) newOrg(t testing.TB, label string) *org {
	t.Helper()
	slug := fmt.Sprintf("as-%s-%s", w.run, randHex(4))
	email := "owner-" + slug + "@example.com"
	w.bootMu.Lock()
	cmd := exec.Command(w.bootstrap, "-print-secrets", "-email=admin-"+slug+"@example.com", "-no-backup",
		"-org-name=Scenario "+label+" "+slug, "-org-slug="+slug, "-org-owner-email="+email)
	cmd.Env = append(os.Environ(), "DATABASE_URL="+os.Getenv("AUTHSCEN_DATABASE_URL"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	w.bootMu.Unlock()
	if err != nil {
		t.Fatalf("bootstrap %s: %v\n%s", slug, err, out.String())
	}
	m := tokenRe.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("bootstrap %s printed no set-password link:\n%s", slug, out.String())
	}
	w.setRules(t, slug, rules{})
	o := &org{Slug: slug, ownerEml: email}
	if err := w.db.QueryRow(`SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&o.ID); err != nil {
		t.Fatalf("tenant id %s: %v", slug, err)
	}
	b := newBrowser(w.api)
	mustOK(t, "owner password", b.do("POST", "/api/v1/auth/reset-password", map[string]string{"token": m[1], "new_password": w.password}))
	o.owner = b
	r := w.passwordLogin(t, b, email, "")
	o.ownerID = r.field("user", "id")
	w.tenantToken(t, b, o)
	return o
}

// tenantToken exchanges the profile's refresh cookie for an organization's
// access token and keeps it as the profile's bearer.
func (w *world) tenantToken(t testing.TB, b *browser, o *org) {
	t.Helper()
	r := b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID})
	mustOK(t, "token for "+o.Slug, r)
	b.bearer = r.field("access_token")
}

// enrollOwnerTOTP turns two-factor authentication on for the owner (so the
// owner keeps acting in an organization that requires it) and signs the
// owner in again with the code.
func (w *world) enrollOwnerTOTP(t testing.TB, o *org) {
	t.Helper()
	o.ownerTOT = w.enrollTOTP(t, o.owner)
	o.owner = newBrowser(w.api)
	w.passwordLogin(t, o.owner, o.ownerEml, o.ownerTOT)
	w.tenantToken(t, o.owner, o)
}

// enrollTOTP turns 2FA on with the profile's current bearer (an account or
// organization token) and returns the secret.
func (w *world) enrollTOTP(t testing.TB, b *browser) string {
	t.Helper()
	r := b.do("POST", "/api/v1/users/me/2fa/setup", map[string]string{"password": w.password})
	mustOK(t, "2fa setup", r)
	secret := r.field("secret")
	if secret == "" {
		t.Fatalf("2fa setup returned no secret: %s", r)
	}
	mustOK(t, "2fa enable", b.do("POST", "/api/v1/users/me/2fa/enable", map[string]string{"password": w.password, "code": freshTOTP(secret)}))
	return secret
}

// passwordLogin signs in with the password, answering a verify challenge
// with the secret when one is asked. An enrollment challenge is returned to
// the caller as is (the caller decides whether that is expected).
func (w *world) passwordLogin(t testing.TB, b *browser, email, secret string) response {
	t.Helper()
	r := b.do("POST", "/api/v1/auth/login", map[string]string{"email": email, "password": w.password})
	if r.Status != 200 {
		t.Fatalf("login %s: %s", email, r)
	}
	if tok := r.field("mfa_token"); tok != "" && r.field("mfa_purpose") != "enroll" {
		if secret == "" {
			t.Fatalf("login %s: second factor asked, no secret: %s", email, r)
		}
		r = b.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"mfa_token": tok, "code": freshTOTP(secret)})
		mustOK(t, "mfa verify "+email, r)
	}
	return r
}

// invite creates an invitation of the organization and returns its token.
func (w *world) invite(t testing.TB, o *org, email, roleID string) string {
	t.Helper()
	r := o.owner.do("POST", "/api/v1/tenants/"+o.Slug+"/invitations", map[string]any{"email": email, "role_ids": []string{roleID}})
	mustOK(t, "invite "+email, r)
	tok := r.field("token")
	if tok == "" {
		tok = r.field("invitation", "token")
	}
	if tok == "" {
		t.Fatalf("invitation for %s returned no token: %s", email, r)
	}
	return tok
}

// rules is an organization's sign-in rule set (tenants.settings.security and
// the platform status).
type rules struct {
	MFARequired           bool
	MFARequiredForAdmins  bool
	SSOEnforced           bool
	SSORequireMFAEvidence bool
	IPAllowList           []string
	Suspended             bool
}

// setRules writes an organization's rules in the database: no API changes
// them for an owner who cannot pass them yet, and the suite needs every
// combination, including ones the settings page would ask a confirmation for.
func (w *world) setRules(t testing.TB, slug string, r rules) {
	t.Helper()
	ips := "[]"
	if len(r.IPAllowList) > 0 {
		ips = `["` + strings.Join(r.IPAllowList, `","`) + `"]`
	}
	sec := fmt.Sprintf(`{"mfa_required": %t, "mfa_required_for_admins": %t, "sso_enforced": %t, "sso_require_mfa_evidence": %t, "ip_whitelist": %s}`,
		r.MFARequired, r.MFARequiredForAdmins, r.SSOEnforced, r.SSORequireMFAEvidence, ips)
	w.exec(t, `UPDATE tenants SET settings = COALESCE(settings, '{}'::jsonb) || jsonb_build_object('security',
		COALESCE(settings->'security', '{}'::jsonb) || $2::jsonb) WHERE slug = $1`, slug, sec)
	if r.Suspended {
		w.exec(t, `UPDATE tenants SET status = 'suspended', suspended_at = now(), suspended_reason = 'scenario' WHERE slug = $1`, slug)
	}
}

// person is the account a scenario follows.
type person struct {
	Email  string
	ID     string
	Secret string // authenticator secret, when the account has a factor
	b      *browser
}

// newEmail is a fresh synthetic address.
func (w *world) newEmail(label string) string {
	return fmt.Sprintf("%s-%s-%s@example.com", label, w.run, randHex(4))
}

// register creates a password account and signs it in. Public sign-up is
// off (the default), so the account signs up with a pending invitation, as
// an invited person does; the invitation is not accepted here.
func (w *world) register(t testing.TB, email, invitation string) *person {
	t.Helper()
	p := &person{Email: email}
	p.b = newBrowser(w.api)
	r := p.b.do("POST", "/api/v1/auth/register", map[string]string{"email": p.Email, "password": w.password,
		"name": "Scenario person", "invitation_token": invitation})
	if r.Status != 200 && r.Status != 201 {
		t.Fatalf("register %s: %s", p.Email, r)
	}
	lr := w.passwordLogin(t, p.b, p.Email, "")
	p.ID = lr.field("user", "id")
	if p.ID == "" {
		t.Fatalf("login %s returned no user id: %s", p.Email, lr)
	}
	return p
}

// signInAgain opens a new password session in a new profile.
func (w *world) signInAgain(t testing.TB, p *person) response {
	t.Helper()
	p.b = newBrowser(w.api)
	return w.passwordLogin(t, p.b, p.Email, p.Secret)
}

// accountToken asks for the account-space token and keeps it as bearer.
func (w *world) accountToken(b *browser) response {
	r := b.do("POST", "/api/v1/auth/account-token", map[string]string{})
	if r.Status == 200 {
		b.bearer = r.field("access_token")
	}
	return r
}

// sessionID is the id of the session behind the profile's refresh cookie.
func (b *browser) sessionID(t testing.TB) string {
	t.Helper()
	sid := jwtClaim(b.cookie("refresh_token"), "session_id")
	if sid == "" {
		t.Fatalf("no session id in the refresh cookie")
	}
	return sid
}

// federate turns the profile's current session into the session a
// federated sign-in leaves behind, exactly as the callbacks write it:
// social sign-in = method sso and no issuing organization; an
// organization's OIDC or SAML provider = its method and that organization.
// The account becomes what that sign-in creates: social and IdP accounts
// have no password (provider google/github/microsoft, or oidc).
func (w *world) federate(t testing.TB, p *person, m method, idpOrg string, keepPassword bool) {
	t.Helper()
	sid := p.b.sessionID(t)
	authMethod, provider := "sso", ""
	switch m.kind {
	case kindSocial:
		provider = m.provider
	case kindOrgOIDC:
		provider = "oidc"
	case kindOrgSAML:
		authMethod, provider = "saml", "oidc"
	case kindOtherIdP:
		provider = "oidc"
	}
	var idp any
	if idpOrg != "" {
		idp = idpOrg
	}
	w.exec(t, `UPDATE sessions SET auth_method = $2, idp_tenant_id = $3, mfa_evidence = $4 WHERE id = $1`,
		sid, authMethod, idp, m.mfaEvidence)
	if !keepPassword {
		w.exec(t, `UPDATE users SET password_hash = NULL, auth_provider = $2 WHERE id = $1`, p.ID, provider)
	}
}

// --- TOTP --------------------------------------------------------------

var (
	totpMu   sync.Mutex
	totpSeen = map[string]string{}
)

// freshTOTP returns a code the server has not seen for this secret (codes
// are single use): the current one, or the next window's.
func freshTOTP(secret string) string {
	for i := 0; i < 40; i++ {
		code, _ := totp.Code(secret, time.Now())
		totpMu.Lock()
		fresh := totpSeen[secret] != code
		if fresh {
			totpSeen[secret] = code
		}
		totpMu.Unlock()
		if fresh {
			return code
		}
		time.Sleep(time.Second)
	}
	code, _ := totp.Code(secret, time.Now())
	return code
}

func mustOK(t testing.TB, what string, r response) {
	t.Helper()
	if r.Status < 200 || r.Status > 299 {
		t.Fatalf("%s: %s", what, r)
	}
}
