//go:build authscenarios

package authscenarios

import (
	"sync"
	"testing"
)

// event is a scenario where something changes while the person is signed
// in, or an invitation is not what it should be.
type event struct {
	id       string
	expected string
	play     func(t *testing.T, w *world, rr *run)
}

// TestWhileSignedIn runs the session events and invitation edge cases.
func TestWhileSignedIn(t *testing.T) {
	w := getWorld(t)
	known := loadKnownFailures(t)
	seen := map[string]bool{}
	for _, ev := range events() {
		seen[ev.id] = true
		t.Run(ev.id, func(t *testing.T) {
			t.Parallel()
			rr := &run{ID: ev.id, Expected: ev.expected}
			ev.play(t, w, rr)
			report(rr)
			verdict(t, rr, known)
		})
	}
	t.Cleanup(func() { checkStaleKnown(t, known, seen, "TestWhileSignedIn") })
}

// memberOf signs a new password account in and makes it a member of the
// organization, holding that organization's access token.
func (w *world) memberOf(t *testing.T, o *org, role string) *person {
	t.Helper()
	email := w.newEmail("member")
	tok := w.invite(t, o, email, role)
	p := w.register(t, email, tok)
	mustOK(t, "accept", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": tok}))
	w.tenantToken(t, p.b, o)
	return p
}

// landsSomewhere: after the change the session still reaches an
// organization or the account space, or ends with a reason code (the
// console then shows the sign-in page with that reason once).
func landsSomewhere(rr *run, w *world, p *person, orgs ...*org) {
	for _, o := range orgs {
		r := rr.rec("token-"+o.Slug[len(o.Slug)-4:], p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
		checkStatus(rr, r)
		if r.Status == 200 {
			return
		}
	}
	a := rr.rec("account-token", w.accountToken(p.b))
	checkStatus(rr, a)
	if a.Status == 200 {
		return
	}
	if a.Status == 401 && a.Code != "" {
		return
	}
	rr.failf("DEAD END: no organization, no account-space token and no reason to sign in again (%s)", a)
}

func events() []event {
	return []event{
		{
			id:       "event/suspended-member-mid-session",
			expected: "the old organization token is refused with a reason; the session lands in the account space (no logout loop)",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				p := w.memberOf(t, o, roleMember)
				mustOK(t, "suspend", o.owner.do("POST", "/api/v1/tenants/"+o.Slug+"/members/"+w.membershipID(t, o, p)+"/suspend", map[string]string{"reason": "scenario"}))
				pr := rr.rec("old-token", p.b.do("GET", "/api/v1/tenants/"+o.Slug+"/", nil))
				checkStatus(rr, pr)
				if pr.Status == 200 {
					rr.failf("BYPASS: a suspended member's token still opens the organization")
				} else if pr.Code == "" {
					rr.failf("refused without a reason code: %s", pr)
				}
				landsSomewhere(rr, w, p)
			},
		},
		{
			id:       "event/removed-member-mid-session",
			expected: "the old organization token is refused with a reason; the session lands in the account space",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				keep := w.newOrg(t, "keep")
				p := w.memberOf(t, o, roleMember)
				mustOK(t, "accept other", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": w.invite(t, keep, p.Email, roleMember)}))
				w.tenantToken(t, p.b, o)
				// Directory deprovisioning removes the membership row.
				w.exec(t, `DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, p.ID, o.ID)
				w.exec(t, `DELETE FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, p.ID, o.ID)
				pr := rr.rec("old-token", p.b.do("GET", "/api/v1/tenants/"+o.Slug+"/", nil))
				checkStatus(rr, pr)
				if pr.Status == 200 {
					rr.failf("BYPASS: a removed member's token still opens the organization")
				}
				r := rr.rec("token-removed-org", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
				checkStatus(rr, r)
				if r.Status == 200 {
					rr.failf("BYPASS: a removed member gets a new token for the organization")
				}
				landsSomewhere(rr, w, p, keep)
			},
		},
		{
			id:       "event/raised-to-admin-in-2fa-admins-org",
			expected: "the next token asks for the second step (MFA_ENROLLMENT_REQUIRED); setting it up in the session opens the organization",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				w.enrollOwnerTOTP(t, o)
				p := w.memberOf(t, o, roleMember)
				w.setRules(t, o.Slug, rules{MFARequiredForAdmins: true})
				mustOK(t, "raise", o.owner.do("PATCH", "/api/v1/tenants/"+o.Slug+"/members/"+w.membershipID(t, o, p), map[string]string{"role": "admin"}))
				w.followRuleChange(t, rr, p, o, method{name: "password", kind: kindPassword})
			},
		},
		{
			id:       "event/2fa-turned-on-password-member",
			expected: "the next request names the second step; setting it up in the session opens the organization",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				p := w.memberOf(t, o, roleMember)
				w.setRules(t, o.Slug, rules{MFARequired: true})
				w.followRuleChange(t, rr, p, o, method{name: "password", kind: kindPassword})
			},
		},
		{
			id:       "event/2fa-turned-on-google-member",
			expected: "the next request names the second step; the person can complete it from this session and the organization opens; never a logout loop",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				p := w.memberOf(t, o, roleMember)
				w.federate(t, p, method{name: "google", kind: kindSocial, provider: "google"}, "", false)
				w.tenantToken(t, p.b, o)
				w.setRules(t, o.Slug, rules{MFARequired: true})
				w.followRuleChange(t, rr, p, o, method{name: "google", kind: kindSocial, provider: "google"})
			},
		},
		{
			id:       "event/idp-required-turned-on-password-member",
			expected: "the next request names the identity provider sign-in; the person is not logged out silently and the organization's provider opens it",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				p := w.memberOf(t, o, roleMember)
				w.setRules(t, o.Slug, rules{SSOEnforced: true})
				pr := rr.rec("old-token", p.b.do("GET", "/api/v1/tenants/"+o.Slug+"/", nil))
				checkStatus(rr, pr)
				if pr.Status == 200 {
					rr.failf("BYPASS: a password session still opens an organization that now requires its identity provider")
				} else if pr.Code != "SSO_REQUIRED" {
					// The console can only send the person to the provider when
					// the per-request refusal says so, as the token refusal does.
					rr.failf("the per-request refusal does not name the identity provider (want SSO_REQUIRED as at token issuance): %s", pr)
				}
				tk := rr.rec("token", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
				checkStatus(rr, tk)
				if tk.Status == 200 {
					rr.failf("BYPASS: a password session gets a token for an organization that requires its identity provider")
				} else if tk.Code != "SSO_REQUIRED" {
					rr.failf("want SSO_REQUIRED at token issuance, got %s", tk)
				}
				w.federate(t, p, method{name: "org-oidc", kind: kindOrgOIDC}, o.ID, true)
				r := rr.rec("token-via-idp", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
				if r.Status != 200 {
					rr.failf("the organization's own provider does not open it: %s", r)
				}
			},
		},
		{
			id:       "event/two-tabs-switch-organizations",
			expected: "two tabs of one browser open two organizations at the same time; both get a token and the session stays alive",
			play: func(t *testing.T, w *world, rr *run) {
				a, b := w.newOrg(t, "a"), w.newOrg(t, "b")
				p := w.memberOf(t, a, roleMember)
				mustOK(t, "accept b", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": w.invite(t, b, p.Email, roleMember)}))
				tab2 := p.b.clone()
				var ra, rb response
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					ra = p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID})
				}()
				go func() {
					defer wg.Done()
					rb = tab2.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": b.ID})
				}()
				wg.Wait()
				rr.rec("tab1-token-a", ra)
				rr.rec("tab2-token-b", rb)
				checkStatus(rr, ra)
				checkStatus(rr, rb)
				if ra.Status != 200 || rb.Status != 200 {
					rr.failf("a tab switching organizations in parallel was refused (%s / %s)", ra, rb)
				}
				again := rr.rec("tab1-token-a-again", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID}))
				if again.Status != 200 {
					rr.failf("the session did not survive two tabs: %s", again)
				}
			},
		},
		{
			id:       "event/stale-tab-after-rotation",
			expected: "a tab that missed a rotation gets a token (grace) or a reason code, and the other tab's session stays alive",
			play: func(t *testing.T, w *world, rr *run) {
				a := w.newOrg(t, "a")
				p := w.memberOf(t, a, roleMember)
				tab2 := p.b.clone()
				r1 := rr.rec("tab1-token", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID}))
				r2 := rr.rec("tab2-stale-token", tab2.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID}))
				checkStatus(rr, r1)
				checkStatus(rr, r2)
				if r2.Status != 200 && r2.Code == "" {
					rr.failf("the stale tab was refused without a reason code: %s", r2)
				}
				again := rr.rec("tab1-token-again", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID}))
				if again.Status != 200 {
					rr.failf("a stale second tab ended the first tab's session: %s", again)
				}
			},
		},
		{
			id:       "event/logout-in-other-tab",
			expected: "after sign-out in one tab the other tab's next exchange is a 401 with a reason code (one trip to the sign-in page)",
			play: func(t *testing.T, w *world, rr *run) {
				a := w.newOrg(t, "a")
				p := w.memberOf(t, a, roleMember)
				tab2 := p.b.clone()
				lo := rr.rec("logout", p.b.do("POST", "/api/v1/auth/logout", map[string]string{}))
				checkStatus(rr, lo)
				r := rr.rec("tab2-token", tab2.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID}))
				checkStatus(rr, r)
				if r.Status == 200 {
					rr.failf("the session still mints tokens after sign-out")
				} else if r.Status != 401 || r.Code == "" {
					rr.failf("want 401 with a reason code, got %s", r)
				}
				ac := rr.rec("tab2-account-token", tab2.do("POST", "/api/v1/auth/account-token", map[string]string{}))
				if ac.Status == 200 {
					rr.failf("the account space opens after sign-out")
				}
			},
		},
		{
			id:       "event/account-blocked-mid-session",
			expected: "a blocked account gets a reason code on its next exchange; nothing opens",
			play: func(t *testing.T, w *world, rr *run) {
				a := w.newOrg(t, "a")
				p := w.memberOf(t, a, roleMember)
				w.exec(t, `UPDATE users SET status = 'suspended', blocked_at = now(), blocked_reason = 'scenario' WHERE id = $1`, p.ID)
				r := rr.rec("token", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID}))
				checkStatus(rr, r)
				if r.Status == 200 {
					rr.failf("BYPASS: a blocked account still gets an organization token")
				} else if r.Code == "" {
					rr.failf("refused without a reason code: %s", r)
				}
				ac := rr.rec("account-token", p.b.do("POST", "/api/v1/auth/account-token", map[string]string{}))
				checkStatus(rr, ac)
				if ac.Status == 200 {
					rr.failf("BYPASS: a blocked account opens the account space")
				}
			},
		},
		{
			id:       "event/session-expired",
			expected: "an expired session answers 401 with a reason code everywhere",
			play: func(t *testing.T, w *world, rr *run) {
				a := w.newOrg(t, "a")
				p := w.memberOf(t, a, roleMember)
				w.exec(t, `UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE id = $1`, p.b.sessionID(t))
				r := rr.rec("token", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": a.ID}))
				checkStatus(rr, r)
				if r.Status != 401 || r.Code == "" {
					rr.failf("want 401 with a reason code, got %s", r)
				}
			},
		},
		// --- invitations ---------------------------------------------------
		{
			id:       "invitation/expired",
			expected: "a reason code; no membership; the session keeps the account space",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				email := w.newEmail("invexp")
				tok := w.invite(t, o, email, roleMember)
				p := w.register(t, email, tok)
				w.exec(t, `UPDATE tenant_invitations SET expires_at = now() - interval '1 hour' WHERE tenant_id = $1 AND lower(email) = lower($2)`, o.ID, p.Email)
				w.refusedInvitation(t, rr, p, o, tok)
			},
		},
		{
			id:       "invitation/revoked",
			expected: "a reason code; no membership; the session keeps the account space",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				email := w.newEmail("invrev")
				tok := w.invite(t, o, email, roleMember)
				p := w.register(t, email, tok)
				var invID string
				if err := w.db.QueryRow(`SELECT id FROM tenant_invitations WHERE tenant_id = $1 AND lower(email) = lower($2)`, o.ID, p.Email).Scan(&invID); err != nil {
					t.Fatal(err)
				}
				mustOK(t, "revoke", o.owner.do("DELETE", "/api/v1/tenants/"+o.Slug+"/invitations/"+invID, nil))
				w.refusedInvitation(t, rr, p, o, tok)
			},
		},
		{
			id:       "invitation/for-another-email",
			expected: "a reason code naming the mismatch; no membership for the signed-in account; its session keeps the account space",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				p := w.invitedAccount(t, "invother")
				tok := w.invite(t, o, "someone-else-"+randHex(3)+"@example.com", roleMember)
				w.refusedInvitation(t, rr, p, o, tok)
			},
		},
		{
			id:       "invitation/unknown-token",
			expected: "a reason code (no server error); the session keeps the account space",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				p := w.invitedAccount(t, "invunknown")
				w.refusedInvitation(t, rr, p, o, randHex(24))
			},
		},
		{
			id:       "invitation/accepted-twice",
			expected: "the second acceptance is harmless: success or a reason code, and the organization still opens",
			play: func(t *testing.T, w *world, rr *run) {
				o := w.newOrg(t, "target")
				email := w.newEmail("invtwice")
				tok := w.invite(t, o, email, roleMember)
				p := w.register(t, email, tok)
				a1 := rr.rec("accept", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": tok}))
				a2 := rr.rec("accept-again", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": tok}))
				checkStatus(rr, a1)
				checkStatus(rr, a2)
				if a2.Status != 200 && a2.Code == "" {
					rr.failf("second acceptance refused without a reason code: %s", a2)
				}
				r := rr.rec("token", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
				if r.Status != 200 {
					rr.failf("the organization does not open after accepting twice: %s", r)
				}
			},
		},
		{
			id:       "invitation/new-account-no-org-lands-in-account-space",
			expected: "a new account with no organization and no invitation gets the account-space token",
			play: func(t *testing.T, w *world, rr *run) {
				p := w.invitedAccount(t, "noorg")
				a := rr.rec("account-token", w.accountToken(p.b))
				if a.Status != 200 {
					rr.failf("a new account without an organization has nowhere to land: %s", a)
				}
			},
		},
		{
			id:       "invitation/google-new-account-no-org",
			expected: "a new social account with no organization gets the account-space token",
			play: func(t *testing.T, w *world, rr *run) {
				p := w.invitedAccount(t, "googlenoorg")
				w.federate(t, p, method{name: "google", kind: kindSocial, provider: "google"}, "", false)
				a := rr.rec("account-token", w.accountToken(p.b))
				if a.Status != 200 {
					rr.failf("a new social account without an organization has nowhere to land: %s", a)
				}
			},
		},
	}
}

// followRuleChange checks what a member sees after the organization's rule
// changed under them: the current token is refused with the reason, the next
// exchange names the second step, and that step opens the organization.
func (w *world) followRuleChange(t *testing.T, rr *run, p *person, o *org, m method) {
	t.Helper()
	pr := rr.rec("old-token", p.b.do("GET", "/api/v1/tenants/"+o.Slug+"/", nil))
	checkStatus(rr, pr)
	if pr.Status == 200 {
		rr.failf("BYPASS: the old token still opens the organization after the rule changed")
	} else if pr.Code == "" {
		rr.failf("refused without a reason code: %s", pr)
	}
	r := rr.rec("token", p.b.do("POST", "/api/v1/auth/token", map[string]string{"tenant_id": o.ID}))
	checkStatus(rr, r)
	if r.Status == 200 {
		rr.failf("BYPASS: a session without a second factor gets a token after the rule changed")
		return
	}
	if r.Code != "MFA_ENROLLMENT_REQUIRED" {
		rr.failf("want MFA_ENROLLMENT_REQUIRED, got %s", r)
	}
	opened, started := w.playRemedy(t, rr, p, m, o, "", member, r.Code, remedySecondFactor)
	if !opened {
		rr.failf("the second step did not open the organization")
	}
	if !opened && !started {
		a := rr.rec("account-token", w.accountToken(p.b))
		if a.Status != 200 {
			rr.failf("DEAD END: refused, the second step cannot start and the account space is refused (%s)", a)
		}
	}
}

// refusedInvitation checks a refused acceptance: a reason code, no
// membership, and the session still lands in the account space.
func (w *world) refusedInvitation(t *testing.T, rr *run, p *person, o *org, tok string) {
	t.Helper()
	a := rr.rec("accept", p.b.do("POST", "/api/v1/invitations/accept-with-refresh", map[string]string{"token": tok}))
	checkStatus(rr, a)
	if a.Status == 200 {
		rr.failf("BYPASS: the invitation was accepted: %s", a)
	} else if a.Code == "" {
		rr.failf("refused without a reason code: %s", a)
	}
	var n int
	_ = w.db.QueryRow(`SELECT count(*) FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, p.ID, o.ID).Scan(&n)
	if n != 0 {
		rr.failf("BYPASS: a refused acceptance left a membership")
	}
	ac := rr.rec("account-token", w.accountToken(p.b))
	if ac.Status != 200 {
		rr.failf("DEAD END: after a refused invitation the session has nowhere to land: %s", ac)
	}
}

// invitedAccount is an account with no organization: it signed up with an
// invitation of a throwaway organization that it never accepted.
func (w *world) invitedAccount(t *testing.T, label string) *person {
	t.Helper()
	o := w.newOrg(t, "throwaway")
	email := w.newEmail(label)
	return w.register(t, email, w.invite(t, o, email, roleMember))
}

// membershipID is the id of the person's membership row (member routes take
// the membership, not the user).
func (w *world) membershipID(t *testing.T, o *org, p *person) string {
	t.Helper()
	var id string
	if err := w.db.QueryRow(`SELECT id FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, p.ID, o.ID).Scan(&id); err != nil {
		t.Fatalf("membership of %s: %v", p.Email, err)
	}
	return id
}
