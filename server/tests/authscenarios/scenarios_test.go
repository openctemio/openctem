//go:build authscenarios

package authscenarios

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// step is one recorded request of a scenario.
type step struct {
	Name   string `json:"name"`
	Status int    `json:"status"`
	Code   string `json:"code,omitempty"`
}

// run is one scenario's record: its steps and the problems found.
type run struct {
	ID       string   `json:"id"`
	Expected string   `json:"expected"`
	Steps    []step   `json:"steps"`
	Problems []string `json:"problems,omitempty"`
}

func (r *run) rec(name string, resp response) response {
	r.Steps = append(r.Steps, step{Name: name, Status: resp.Status, Code: resp.Code})
	return resp
}

func (r *run) failf(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

func (r *run) trace() string {
	parts := make([]string, 0, len(r.Steps))
	for _, s := range r.Steps {
		c := ""
		if s.Code != "" {
			c = " " + s.Code
		}
		parts = append(parts, fmt.Sprintf("%s=%d%s", s.Name, s.Status, c))
	}
	return strings.Join(parts, " -> ")
}

func describe(e expectation) string {
	if e.admit {
		return "the organization opens at once"
	}
	s := "refused with a reason (" + strings.Join(e.codes, "|") + ")"
	if e.codes == nil {
		s = "refused with a reason code"
	}
	s += "; next step: " + e.remedy.String()
	if e.final {
		s += "; then the organization opens"
	}
	return s + "; never a dead end"
}

// TestSignInMatrix runs every (membership, method, rule) scenario: the
// person signs in with the method, meets the organization through the
// membership state, and the answers must match the specification (expect)
// and the invariants (checkInvariants).
func TestSignInMatrix(t *testing.T) {
	w := getWorld(t)
	known := loadKnownFailures(t)
	seen := map[string]bool{}
	for _, mb := range memberships {
		for _, m := range methods {
			for _, r := range orgRules {
				id := fmt.Sprintf("%s/%s/%s", mb, m.name, r.name)
				seen[id] = true
				t.Run(id, func(t *testing.T) {
					t.Parallel()
					rr := &run{ID: id, Expected: describe(expect(m, r))}
					w.scenario(t, rr, mb, m, r)
					report(rr)
					verdict(t, rr, known)
				})
			}
		}
	}
	t.Cleanup(func() { checkStaleKnown(t, known, seen, "TestSignInMatrix") })
}

// scenario plays one scenario and records what it saw.
func (w *world) scenario(t *testing.T, rr *run, mb membership, m method, r rule) {
	exp := expect(m, r)
	o := w.newOrg(t, "target")
	var p2 *org
	if mb == twoOrgs {
		p2 = w.newOrg(t, "plain")
	}
	idpOrg := ""
	switch m.kind {
	case kindOrgOIDC, kindOrgSAML:
		idpOrg = o.ID
	case kindOtherIdP:
		idpOrg = w.newOrg(t, "home").ID
	}

	role := roleMember
	if r.admin {
		role = roleAdmin
	}
	email := w.newEmail(strings.ReplaceAll(m.name, "-", ""))
	tokO := w.invite(t, o, email, role)
	p := w.register(t, email, tokO)
	if m.factor {
		w.accountToken(p.b)
		p.Secret = w.enrollTOTP(t, p.b)
		w.signInAgain(t, p)
	}
	if p2 != nil {
		mustOK(t, "accept plain org", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": w.invite(t, p2, p.Email, roleMember)}))
	}
	if mb != invited {
		mustOK(t, "accept target org", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": tokO}))
		// A returning member signs in again.
		w.signInAgain(t, p)
	}
	if m.federated() {
		w.federate(t, p, m, idpOrg, m.kind == kindOtherIdP)
	}
	w.setRules(t, o.Slug, r.set)
	// The suspension status (Redis) and the IP allow-list (per replica) are
	// cached for a bounded time; a change made in the database, as here,
	// takes effect when that bound passes (the console's own changes
	// invalidate at once).
	switch {
	case r.set.Suspended:
		time.Sleep(61 * time.Second)
	case len(r.set.IPAllowList) > 0:
		time.Sleep(31 * time.Second)
	}

	// 1. The first answer of the organization.
	var first response
	admittedO := false
	if mb == invited {
		first = rr.rec("accept", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": tokO}))
	}
	tok := rr.rec("token", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
	if mb != invited {
		first = tok
	}
	var pr response
	if tok.Status == 200 {
		admittedO, pr = w.probe(rr, "open", tok.field("access_token"), o)
	} else if first.Status == 200 && first.field("access_token") != "" {
		admittedO, pr = w.probe(rr, "open-after-accept", first.field("access_token"), o)
	}
	firstCode := first.Code
	if first.Status == 200 && !admittedO {
		firstCode = tok.Code
		if tok.Status == 200 {
			// The token was issued but the organization refuses it.
			firstCode = pr.Code
		}
	}

	// 2. What the session can still reach after the answer.
	var tokP response
	if p2 != nil {
		tokP = rr.rec("token-other-org", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": p2.ID}))
	}
	acct := rr.rec("account-token", w.accountToken(p.b))

	// 3. The specification.
	checkStatus(rr, first)
	checkStatus(rr, tok)
	if exp.admit && !admittedO {
		rr.failf("expected the organization to open, got %s", first)
	}
	if !exp.admit && admittedO {
		// Security: a session the organization's rules refuse was let in.
		rr.failf("BYPASS: the organization opened for a session its rules refuse (%s)", first)
	}
	if !exp.admit && !admittedO && exp.codes != nil && !slices.Contains(exp.codes, firstCode) {
		rr.failf("refusal code %q does not name the reason (want one of %v): %s", firstCode, exp.codes, first)
	}
	if !admittedO && firstCode == "" {
		rr.failf("refused without a reason code: %s", first)
	}
	if p2 != nil && tokP.Status != 200 && m.kind != kindOtherIdP {
		rr.failf("the other organization (open) no longer opens: %s", tokP)
	}

	// 4. The next step, played the way the console plays it.
	landed := admittedO || (p2 != nil && tokP.Status == 200) || acct.Status == 200
	finalOpen := admittedO
	if !admittedO {
		ok, started := w.playRemedy(t, rr, p, m, o, tokO, mb, firstCode, exp.remedy)
		finalOpen = ok
		landed = landed || started || ok
	}
	if !admittedO && exp.remedy == remedyExternal && r.name == "ip-allowlist" && firstCode != "" {
		// Nothing the person can do in the product: every request of the
		// organization says why (the console shows that reason).
		landed = true
	}
	if !admittedO && exp.final && !finalOpen {
		rr.failf("after the next step (%s) the organization still does not open", exp.remedy)
	}
	if !landed {
		rr.failf("DEAD END: refused (%s), no organization opens, no account-space token (%s), and no next step works", first, acct)
	}
}

// probe checks that an issued organization token really opens the
// organization (the organization's own record answers).
func (w *world) probe(rr *run, name, access string, o *org) (bool, response) {
	b := newBrowser(w.api)
	b.bearer = access
	r := rr.rec("probe-"+name, b.do("GET", "/api/v1/tenants/"+o.Slug+"/", nil))
	checkStatus(rr, r)
	if r.Status != 200 && r.Code == "" {
		rr.failf("an issued organization token is refused without a reason code: %s", r)
	}
	return r.Status == 200, r
}

// playRemedy follows the next step the refusal points to. It reports
// whether the organization opened, and whether the step itself started (the
// person is on a page with something to do).
func (w *world) playRemedy(t *testing.T, rr *run, p *person, m method, o *org, tokO string, mb membership, code string, want remedy) (opened, started bool) {
	t.Helper()
	// The console sends a MFA_ENROLLMENT_REQUIRED refusal to the second step
	// of this session, whatever the specification expects.
	if code == "MFA_ENROLLMENT_REQUIRED" || want == remedySecondFactor {
		ch := rr.rec("second-factor-start", p.b.do("POST", "/api/v1/auth/mfa/enroll/session", map[string]string{}))
		checkStatus(rr, ch)
		if ch.Status == 200 && ch.field("mfa_token") != "" {
			started = true
			if w.completeSecondFactor(t, rr, p, ch) && w.retryOrg(rr, p, o, tokO, mb) {
				return true, true
			}
		} else if want == remedySecondFactor {
			rr.failf("the second step cannot start in this session: %s", ch)
		}
	}
	switch want {
	case remedyPassword:
		if !m.hasPassword() {
			return false, started
		}
		ok := w.passwordAgain(t, rr, p)
		return ok && w.retryOrg(rr, p, o, tokO, mb), started || ok
	case remedyOrgIdP:
		// The organization's provider signs the person in (with the second
		// factor proven); the session is written as its callback writes it.
		if m.hasPassword() {
			if !w.passwordAgain(t, rr, p) {
				return false, started
			}
		}
		idp := method{name: "org-oidc-mfa", kind: kindOrgOIDC, mfaEvidence: true}
		w.federate(t, p, idp, o.ID, m.hasPassword())
		return w.retryOrg(rr, p, o, tokO, mb), true
	}
	return false, started
}

// completeSecondFactor finishes a second-step challenge: verify with the
// account's authenticator, or set one up.
func (w *world) completeSecondFactor(t *testing.T, rr *run, p *person, ch response) bool {
	t.Helper()
	tok := ch.field("mfa_token")
	purpose := ch.field("mfa_purpose")
	if purpose == "" {
		purpose = ch.field("purpose")
	}
	if purpose == "enroll" {
		st := rr.rec("second-factor-enroll-start", p.b.do("POST", "/api/v1/auth/mfa/enroll/start", map[string]string{"mfa_token": tok}))
		checkStatus(rr, st)
		secret := st.field("secret")
		if st.Status != 200 || secret == "" {
			rr.failf("enrollment did not start: %s", st)
			return false
		}
		p.Secret = secret
		cf := rr.rec("second-factor-enroll-confirm", p.b.do("POST", "/api/v1/auth/mfa/enroll/confirm", map[string]string{"mfa_token": tok, "code": freshTOTP(secret)}))
		checkStatus(rr, cf)
		return cf.Status == 200
	}
	if p.Secret == "" {
		rr.failf("a verify challenge was issued to an account without an authenticator: %s", ch)
		return false
	}
	vr := rr.rec("second-factor-verify", p.b.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"mfa_token": tok, "code": freshTOTP(p.Secret)}))
	checkStatus(rr, vr)
	return vr.Status == 200
}

// passwordAgain signs in again with the password in a new profile,
// answering the second step it asks for.
func (w *world) passwordAgain(t *testing.T, rr *run, p *person) bool {
	t.Helper()
	p.b = newBrowser(w.api)
	lr := rr.rec("sign-in-again", p.b.do("POST", "/api/v1/auth/login", map[string]string{"email": p.Email, "password": w.password}))
	checkStatus(rr, lr)
	if lr.Status != 200 {
		return false
	}
	if lr.field("mfa_token") != "" {
		return w.completeSecondFactor(t, rr, p, lr)
	}
	return true
}

// retryOrg asks for the organization again (accepting the invitation again
// first when the person was invited: a refused acceptance may not have
// created the membership).
func (w *world) retryOrg(rr *run, p *person, o *org, tokO string, mb membership) bool {
	if mb == invited {
		a := rr.rec("accept-again", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": tokO}))
		checkStatus(rr, a)
	}
	r := rr.rec("token-again", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
	checkStatus(rr, r)
	if r.Status != 200 {
		return false
	}
	ok, _ := w.probe(rr, "again", r.field("access_token"), o)
	return ok
}

// checkStatus: no answer of the sign-in path is a server error or a
// transport failure.
func checkStatus(rr *run, r response) {
	if r.Status == 0 || r.Status >= 500 {
		rr.failf("server error: %s", r)
	}
}

// verdict turns a run's problems into the test result, honouring the
// known-failures list: a listed scenario that fails is reported, not
// failed; a listed scenario that passes fails (remove it from the list).
func verdict(t *testing.T, rr *run, known map[string]string) {
	t.Helper()
	_, listed := known[rr.ID]
	switch {
	case len(rr.Problems) == 0 && listed:
		t.Errorf("listed in known-failures.txt but passes now: remove the line %q", rr.ID)
	case len(rr.Problems) == 0:
		return
	case listed:
		t.Logf("KNOWN FAILURE %s\n  expected: %s\n  trace:    %s\n  problems: %s", rr.ID, rr.Expected, rr.trace(), strings.Join(rr.Problems, "; "))
	default:
		t.Errorf("FAIL %s\n  expected: %s\n  trace:    %s\n  problems: %s", rr.ID, rr.Expected, rr.trace(), strings.Join(rr.Problems, "\n            "))
	}
}
