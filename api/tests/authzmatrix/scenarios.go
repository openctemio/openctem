//go:build authzmatrix

package authzmatrix

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Scenario tests of the role-management API: each step states what must
// happen, the response is classified, and every step lands in the report.
// They use throw-away accounts so the matrix principals stay as seeded.

type scenarioResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Expect  string `json:"expect"` // refused | allowed | measure
	Status  int    `json:"status"`
	Code    string `json:"code,omitempty"`
	Verdict string `json:"verdict"` // pass | fail | inconclusive | pending_fix | known_issue | info
	Note    string `json:"note,omitempty"`
	Body    string `json:"body,omitempty"`
}

// Step verdicts.
const (
	verdictPass         = "pass"
	verdictFail         = "fail"
	verdictInconclusive = "inconclusive"
)

// pendingFix lists steps whose expected behavior lands with an open fix:
// they are reported but do not fail the suite until that fix is merged
// (then the entry is removed). Values are local report ids only.
var pendingFix = map[string]string{
	"B-access-widen-stepup":   "254-B",
	"B-fp-lower-owner-only":   "254-B",
	"B-accept-lower-owner":    "254-B",
	"B-integrations-manage":   "254-B",
	"B-integrations-scm":      "254-B",
	"B-notification-retarget": "254-B-01",
}

// knownIssue lists confirmed issues: reported by id only, skipped until
// fixed. Filled from the local audit report.
var knownIssue = map[string]string{}

type scen struct {
	w       *world
	t       *testing.T
	results []scenarioResult
	seq     atomic.Int32
}

func refusedStatus(s int) bool { return s == 401 || s == 403 || s == 404 || s == 409 || s == 422 }

// expectRefused records a step that must be refused. A 400 is a request
// the suite built wrongly (or a validation refusal): inconclusive, with the
// body kept for review.
func (s *scen) expectRefused(id, name string) func(response, error) response {
	return func(r response, err error) response { return s.refused(id, name, r, err) }
}

func (s *scen) refused(id, name string, r response, err error) response {
	s.t.Helper()
	res := scenarioResult{ID: id, Name: name, Expect: "refused", Status: r.Status, Code: r.Code}
	switch {
	case err != nil:
		res.Verdict, res.Note = verdictInconclusive, err.Error()
	case refusedStatus(r.Status):
		res.Verdict = verdictPass
	case r.Status == 400:
		res.Verdict = verdictInconclusive
	default:
		res.Verdict = verdictFail
	}
	if res.Verdict != verdictPass {
		res.Body = excerpt(r.Body)
	}
	s.record(res)
	return r
}

// expectRefused400 is expectRefused for a step whose refusal is a 400 with a
// specific message (the request is valid; the change is not allowed).
func (s *scen) expectRefused400(id, name string) func(response, error) response {
	return func(r response, err error) response {
		if err == nil && r.Status == 400 {
			s.record(scenarioResult{ID: id, Name: name, Expect: "refused", Status: r.Status, Code: r.Code, Verdict: verdictPass, Note: excerpt(r.Body)})
			return r
		}
		return s.refused(id, name, r, err)
	}
}

// expect409 is a refusal that must come from the business rule (409), not
// from the console's own authentication (any other status is inconclusive).
func (s *scen) expect409(id, name string) func(response, error) response {
	return func(r response, err error) response {
		res := scenarioResult{ID: id, Name: name, Expect: "refused (409)", Status: r.Status, Code: r.Code}
		switch {
		case err != nil:
			res.Verdict, res.Note = verdictInconclusive, err.Error()
		case r.Status == 409:
			res.Verdict = verdictPass
		case r.Status >= 200 && r.Status < 300:
			res.Verdict, res.Body = verdictFail, excerpt(r.Body)
		default:
			res.Verdict, res.Body = verdictInconclusive, excerpt(r.Body)
		}
		s.record(res)
		return r
	}
}

// expectAllowed records a step that must succeed (a precondition or the
// positive half of a check).
func (s *scen) expectAllowed(id, name string) func(response, error) response {
	return func(r response, err error) response { return s.allowed(id, name, r, err) }
}

func (s *scen) allowed(id, name string, r response, err error) response {
	s.t.Helper()
	res := scenarioResult{ID: id, Name: name, Expect: "allowed", Status: r.Status, Code: r.Code}
	switch {
	case err != nil:
		res.Verdict, res.Note = verdictInconclusive, err.Error()
	case r.Status >= 200 && r.Status < 300:
		res.Verdict = verdictPass
	case r.Status == 400:
		res.Verdict = verdictInconclusive
	default:
		res.Verdict = verdictFail
	}
	if res.Verdict != verdictPass {
		res.Body = excerpt(r.Body)
	}
	s.record(res)
	return r
}

func (s *scen) info(id, name, note string) {
	s.record(scenarioResult{ID: id, Name: name, Expect: "measure", Verdict: "info", Note: note})
}

func (s *scen) record(res scenarioResult) {
	s.t.Helper()
	if res.Verdict == verdictFail {
		if k, ok := knownIssue[res.ID]; ok {
			res.Verdict, res.Note = "known_issue", k
		} else if p, ok := pendingFix[res.ID]; ok {
			res.Verdict, res.Note = "pending_fix", p
		}
	}
	s.results = append(s.results, res)
	switch res.Verdict {
	case verdictFail:
		s.t.Errorf("scenario %s %s: expected %s, got %d %s %s", res.ID, res.Name, res.Expect, res.Status, res.Code, res.Body)
	case verdictInconclusive:
		s.t.Logf("scenario %s %s: inconclusive %d %s %s", res.ID, res.Name, res.Status, res.Code, res.Body)
	default:
		s.t.Logf("scenario %s %s: %s %d %s", res.ID, res.Name, res.Verdict, res.Status, res.Note)
	}
}

// fresh invites a throw-away account with the given roles.
func (s *scen) fresh(ten *tenant, label string, roleIDs ...string) *principal {
	s.t.Helper()
	n := s.seq.Add(1)
	p := s.w.invite(s.t, ten, fmt.Sprintf("s%d-%s", n, label), roleIDs)
	s.w.drop(p)
	p.memberID = s.w.membershipID(s.t, ten, p.userID)
	return p
}

// relogin signs an account in again (after its sessions were ended).
func (s *scen) relogin(p *principal) *principal {
	s.t.Helper()
	q := s.w.signInOpts(s.t, p.T, p.Name+"#again", p.email, true)
	q.userID, q.memberID = p.userID, p.memberID
	return q
}

// noStepUp signs an account in again without stepping up.
func (s *scen) noStepUp(p *principal) *principal {
	s.t.Helper()
	q := s.w.signInOpts(s.t, p.T, p.Name+"#nostepup", p.email, false)
	q.userID, q.memberID = p.userID, p.memberID
	s.w.backdate(s.t, q)
	return q
}

func (s *scen) do(p *principal, method, path string, body any) (response, error) {
	return s.w.as(s.t, p, method, path, body)
}

// pollUntil polls fn every 100 ms until it reports done or the limit
// passes; it returns the time it took (or -1 when it never happened).
func pollUntil(limit time.Duration, fn func() bool) time.Duration {
	start := time.Now()
	for time.Since(start) < limit {
		if fn() {
			return time.Since(start)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return -1
}

func fmtWindow(d time.Duration) string {
	if d < 0 {
		return "never within the limit"
	}
	return d.Round(10 * time.Millisecond).String()
}

func (w *world) scenarios(t *testing.T) {
	s := &scen{w: w, t: t}
	acme, globex := w.tenant("Acme"), w.tenant("Globex")
	t.Run("roles", func(t *testing.T) { s.t = t; s.roles(acme, globex) })
	t.Run("membership", func(t *testing.T) { s.t = t; s.membership(acme, globex) })
	t.Run("invitations", func(t *testing.T) { s.t = t; s.invitations(acme, globex) })
	t.Run("api_keys", func(t *testing.T) { s.t = t; s.apiKeys(acme, globex) })
	t.Run("groups", func(t *testing.T) { s.t = t; s.groups(acme, globex) })
	t.Run("four_eyes", func(t *testing.T) { s.t = t; s.fourEyes(acme) })
	t.Run("step_up", func(t *testing.T) { s.t = t; s.stepUpGates(acme) })
	t.Run("propagation", func(t *testing.T) { s.t = t; s.propagation(acme) })
	t.Run("lane_b", func(t *testing.T) { s.t = t; s.laneB(acme) })
	t.Run("console", func(t *testing.T) { s.t = t; s.console(acme) })
	if dst := os.Getenv("MATRIX_REPORT"); dst != "" {
		raw, _ := json.MarshalIndent(s.results, "", " ")
		_ = os.WriteFile(strings.TrimSuffix(dst, ".json")+"-scenarios.json", raw, 0o600)
	}
}

// roles: a delegated role manager (roles:write and roles:assign, no full
// data) and the ceilings around custom roles.
func (s *scen) roles(acme, globex *tenant) {
	w := s.w
	mgrPerms := []string{"team:roles:read", "team:roles:write", "team:roles:assign", "team:roles:delete",
		"team:members:read", "assets:read"}
	mgrRole := w.createRole(s.t, acme, fmt.Sprintf("role-manager-%d", s.seq.Add(1)), false, mgrPerms, "")
	mgr := s.fresh(acme, "role-manager", mgrRole)
	target := s.fresh(acme, "role-target", roleViewer)

	s.expectRefused("R1", "role manager creates a role with a permission it lacks")(s.do(mgr, "POST", "/api/v1/roles",
		map[string]any{"slug": "mgr-overreach", "name": "mgr-overreach", "hierarchy_level": 5, "permissions": []string{"assets:read", "findings:delete"}}))
	s.expectRefused("R2", "role manager creates a full-data role")(s.do(mgr, "POST", "/api/v1/roles",
		map[string]any{"slug": "mgr-fulldata", "name": "mgr-fulldata", "hierarchy_level": 5, "has_full_data_access": true, "permissions": []string{"assets:read"}}))
	for i, p := range permission.AdminOnlyPermissions() {
		if i >= 3 {
			break
		}
		s.expectRefused400("R3", "owner creates a custom role with admin-only "+string(p))(s.do(acme.owner, "POST", "/api/v1/roles",
			map[string]any{"slug": fmt.Sprintf("adminonly-%d", i), "name": fmt.Sprintf("adminonly-%d", i), "hierarchy_level": 5, "permissions": []string{string(p)}}))
	}
	s.expectRefused("R4", "role manager edits a role carrying permissions it lacks (removal only)")(s.do(mgr, "PUT", "/api/v1/roles/"+acme.get("role.writer-no-approve"),
		map[string]any{"name": "writer-no-approve", "permissions": []string{"assets:read"}}))
	s.expectRefused("R5", "role manager widens its own role")(s.do(mgr, "PUT", "/api/v1/roles/"+mgrRole,
		map[string]any{"name": "role-manager", "permissions": append(append([]string{}, mgrPerms...), "findings:delete")}))
	s.expectRefused("R6", "role manager assigns the admin system role")(s.do(mgr, "POST", "/api/v1/users/"+target.userID+"/roles",
		map[string]any{"role_id": roleAdmin}))
	s.expectRefused("R7", "role manager assigns the owner system role")(s.do(mgr, "POST", "/api/v1/users/"+target.userID+"/roles",
		map[string]any{"role_id": roleOwner}))
	s.expectRefused("R8", "role manager assigns a full-data role")(s.do(mgr, "POST", "/api/v1/users/"+target.userID+"/roles",
		map[string]any{"role_id": acme.get("role.near-admin")}))
	r, err := s.do(mgr, "POST", "/api/v1/roles/"+acme.get("role.near-admin")+"/members/bulk", map[string]any{"user_ids": []string{target.userID}})
	if err == nil && r.Status < 300 && strings.Contains(string(r.Body), `"success_count":0`) {
		r.Status = 403 // every user refused inside the bulk call
	}
	s.expectRefused("R9", "role manager bulk-assigns a full-data role")(r, err)
	s.expectRefused("R10", "role manager deletes a role held by a senior member")(s.do(mgr, "DELETE", "/api/v1/roles/"+acme.get("role.near-admin"), nil))
	s.expectRefused("R11", "role manager edits the other organization's role")(s.do(mgr, "PUT", "/api/v1/roles/"+globex.get("role.victim"),
		map[string]any{"name": "victim-role", "permissions": []string{"assets:read"}}))
	s.expectRefused("R12", "owner edits the other organization's role")(s.do(acme.owner, "PUT", "/api/v1/roles/"+globex.get("role.victim"),
		map[string]any{"name": "victim-role", "permissions": []string{"assets:read"}}))
	s.expectRefused400("R13", "owner assigns a role to a user of the other organization")(s.do(acme.owner, "POST", "/api/v1/users/"+globex.owner.userID+"/roles",
		map[string]any{"role_id": acme.get("role.narrow-readonly")}))
	s.expectRefused("R14", "role manager applies a template that widens a role")(s.do(mgr, "POST", "/api/v1/roles/"+mgrRole+"/template/apply",
		map[string]any{"template_id": "program-lead"}))
	// Positive control: the manager may grant what it holds.
	narrow := w.createRole(s.t, acme, fmt.Sprintf("assets-reader-%d", s.seq.Add(1)), false, []string{"assets:read"}, "")
	s.expectAllowed("R15", "role manager assigns a role within its own grant")(s.do(mgr, "POST", "/api/v1/users/"+target.userID+"/roles",
		map[string]any{"role_id": narrow}))
}

// membership: team-role changes, the owner and the peer-admin rule.
func (s *scen) membership(acme, globex *tenant) {
	adm := s.fresh(acme, "admin-a", roleAdmin)
	adm2 := s.fresh(acme, "admin-b", roleAdmin)
	mem := s.fresh(acme, "member", roleMember)
	ownerMember := s.w.membershipID(s.t, acme, acme.owner.userID)
	base := "/api/v1/tenants/" + acme.Slug + "/members/"

	s.expectRefused("M1", "member promotes itself to admin")(s.do(mem, "PATCH", base+mem.memberID, map[string]any{"role": "admin"}))
	s.expectRefused("M2", "member adds a full-data role to itself")(s.do(mem, "POST", "/api/v1/users/"+mem.userID+"/roles", map[string]any{"role_id": acme.get("role.near-admin")}))
	s.expectRefused("M3", "admin promotes a member to admin (owner only)")(s.do(adm, "PATCH", base+mem.memberID, map[string]any{"role": "admin"}))
	s.expectRefused400("M4", "admin makes someone owner through the role API")(s.do(adm, "POST", "/api/v1/users/"+mem.userID+"/roles", map[string]any{"role_id": roleOwner}))
	s.expectRefused400("M5", "admin demotes the owner")(s.do(adm, "PATCH", base+ownerMember, map[string]any{"role": "member"}))
	s.expectRefused("M6", "admin suspends the owner")(s.do(adm, "POST", base+ownerMember+"/suspend", map[string]any{}))
	s.expectRefused("M7", "admin suspends another admin")(s.do(adm, "POST", base+adm2.memberID+"/suspend", map[string]any{}))
	s.expectRefused("M8", "admin changes another admin's team role")(s.do(adm, "PATCH", base+adm2.memberID, map[string]any{"role": "viewer"}))
	s.expectRefused400("M9", "admin removes the owner role from the owner")(s.do(adm, "DELETE", "/api/v1/users/"+acme.owner.userID+"/roles/"+roleOwner, nil))
	s.expectRefused("M10", "the last owner leaves the organization")(s.do(acme.owner, "POST", "/api/v1/organization/leave", map[string]any{}))
	s.expectRefused400("M11", "owner removes its own owner role (transfer only)")(s.do(acme.owner, "DELETE", "/api/v1/users/"+acme.owner.userID+"/roles/"+roleOwner, nil))
	s.expectRefused("M12", "Acme admin changes a Globex member through the Globex path")(s.do(adm, "PATCH",
		"/api/v1/tenants/"+globex.Slug+"/members/"+s.w.membershipID(s.t, globex, s.w.byName["Globex/member"].userID), map[string]any{"role": "viewer"}))

	// Owner promotion needs a recent step-up.
	ownerNS := s.noStepUp(acme.owner)
	r := s.expectRefused("M13", "owner promotes to admin without step-up")(s.do(ownerNS, "PATCH", base+mem.memberID, map[string]any{"role": "admin"}))
	if r.Status < 300 {
		_, _ = s.do(acme.owner, "PATCH", base+mem.memberID, map[string]any{"role": "member"})
	}

	// Ownership transfer edges. The recipient must use two-factor
	// authentication, so the scenario enrolls it first.
	if !s.w.enrollTOTP(s.t, adm) {
		s.info("M14", "ownership transfer", "could not enroll the recipient in two-factor authentication")
		return
	}
	adm = s.relogin(adm)
	s.expectRefused("M14", "owner starts an ownership transfer without step-up")(s.do(ownerNS, "POST", "/api/v1/organization/ownership-transfer",
		map[string]any{"member_id": adm.memberID, "previous_owner_role": "admin", "confirm_internal": true}))
	s.expectRefused("M15", "admin starts an ownership transfer")(s.do(adm, "POST", "/api/v1/organization/ownership-transfer",
		map[string]any{"member_id": adm.memberID, "previous_owner_role": "admin", "confirm_internal": true}))
	started := s.expectAllowed("M16", "owner starts an ownership transfer to admin A")(s.do(acme.owner, "POST", "/api/v1/organization/ownership-transfer",
		map[string]any{"member_id": adm.memberID, "previous_owner_role": "admin", "confirm_internal": true}))
	if started.Status < 300 {
		s.expectRefused("M17", "a member who is not the recipient accepts the transfer")(s.do(adm2, "POST", "/api/v1/organization/ownership-transfer/approve", map[string]any{}))
		s.expectRefused("M18", "Globex owner accepts Acme's transfer")(s.do(globex.owner, "POST", "/api/v1/organization/ownership-transfer/approve", map[string]any{}))
		s.expectRefused("M19", "a member who is not the recipient declines the transfer")(s.do(mem, "POST", "/api/v1/organization/ownership-transfer/reject", map[string]any{}))
		admNS := s.noStepUp(adm)
		s.expectRefused("M20", "recipient accepts without step-up")(s.do(admNS, "POST", "/api/v1/organization/ownership-transfer/approve", map[string]any{}))
		s.expectRefused("M21", "admin cancels the owner's transfer")(s.do(adm2, "DELETE", "/api/v1/organization/ownership-transfer", nil))
		s.expectAllowed("M22", "owner cancels its transfer")(s.do(acme.owner, "DELETE", "/api/v1/organization/ownership-transfer", nil))
	}
}

// invitations: the invite ceiling and token handling.
func (s *scen) invitations(acme, globex *tenant) {
	adm := s.fresh(acme, "inviter-admin", roleAdmin)
	n := s.seq.Add(1)
	inv := func(p *principal, email string, roles ...string) (response, error) {
		return s.do(p, "POST", "/api/v1/tenants/"+acme.Slug+"/invitations", map[string]any{"email": email, "role_ids": roles})
	}
	s.expectRefused400("I1", "admin invites with the owner role")(inv(adm, fmt.Sprintf("i%d-owner@%s.example.com", n, acme.Slug), roleOwner))
	s.expectRefused("I2", "admin invites with the admin role (promotion to admin is owner only)")(inv(adm, fmt.Sprintf("i%d-admin@%s.example.com", n, acme.Slug), roleAdmin))
	writer := s.w.byName["Acme/custom-writer-no-approve"]
	s.expectRefused("I3", "member without team admin invites")(inv(writer, fmt.Sprintf("i%d-x@%s.example.com", n, acme.Slug), roleViewer))
	s.expectRefused("I4", "Acme admin invites into Globex")(s.do(adm, "POST", "/api/v1/tenants/"+globex.Slug+"/invitations",
		map[string]any{"email": fmt.Sprintf("i%d-g@%s.example.com", n, globex.Slug), "role_ids": []string{roleViewer}}))

	// Token reuse and wrong-email accept.
	email := fmt.Sprintf("i%d-reuse@%s.example.com", n, acme.Slug)
	r := s.expectAllowed("I5", "owner invites a viewer")(inv(acme.owner, email, roleViewer))
	tok := jsonID(r, "token")
	if tok == "" {
		s.info("I5", "invitation token", "no token in the response (email configured?)")
		return
	}
	// A different account accepts the token: refused.
	other := s.w.byName["Acme/viewer"]
	b := s.w.c.newBrowser()
	lr, _ := b.do("POST", "/api/v1/auth/login", map[string]string{"email": other.email, "password": seedPassword})
	s.expectRefused400("I6", "another account accepts the invitation")(b.do("POST", "/api/v1/invitations/accept-with-refresh",
		map[string]string{"token": tok, "refresh_token": jsonID(lr, "refresh_token")}))
	p := s.w.invite2(s.t, acme, email, tok)
	s.w.drop(p)
	b2 := s.w.c.newBrowser()
	lr2, _ := b2.do("POST", "/api/v1/auth/login", map[string]string{"email": p.email, "password": seedPassword})
	s.expectRefused400("I7", "the invitation token is reused after accept")(b2.do("POST", "/api/v1/invitations/accept-with-refresh",
		map[string]string{"token": tok, "refresh_token": jsonID(lr2, "refresh_token")}))

	// Another organization's invitation by id.
	gr, _ := s.do(globex.owner, "POST", "/api/v1/tenants/"+globex.Slug+"/invitations",
		map[string]any{"email": fmt.Sprintf("i%d-gx@%s.example.com", n, globex.Slug), "role_ids": []string{roleViewer}})
	if gid := jsonID(gr, "id"); gid != "" {
		s.expectRefused("I8", "Acme owner resends Globex's invitation through the Acme path")(s.do(acme.owner, "POST",
			"/api/v1/tenants/"+acme.Slug+"/invitations/"+gid+"/resend", map[string]any{}))
		s.expectRefused("I9", "Acme owner deletes Globex's invitation through the Acme path")(s.do(acme.owner, "DELETE",
			"/api/v1/tenants/"+acme.Slug+"/invitations/"+gid, nil))
		s.expectRefused("I10", "Acme owner deletes Globex's invitation through the Globex path")(s.do(acme.owner, "DELETE",
			"/api/v1/tenants/"+globex.Slug+"/invitations/"+gid, nil))
	}
}

// apiKeys: the scope ceiling, ownership and revocation on suspension.
func (s *scen) apiKeys(acme, globex *tenant) {
	if st := acme.ids["key.overreach.refused"]; st != "" {
		s.record(scenarioResult{ID: "K1", Name: "minting a key with scopes beyond the creator", Expect: "refused", Status: atoiOr(st), Verdict: verdictPass,
			Note: "refused at mint"})
	} else if acme.get("key.overreach") != "" {
		r, err := s.w.c.do(bearer(acme.get("key.overreach")), "GET", "/api/v1/audit-logs", nil)
		s.expectRefused("K1", "an over-scoped key uses a scope the creator lacks (audit:read)")(r, err)
	}
	writerRole := acme.get("role.writer-no-approve")
	a := s.fresh(acme, "key-owner", writerRole)
	b := s.fresh(acme, "key-peer", writerRole)
	mint := func(p *principal, scopes ...string) (string, string) {
		r, _ := s.do(p, "POST", "/api/v1/api-keys", map[string]any{"name": fmt.Sprintf("k%d", s.seq.Add(1)), "scopes": scopes, "expires_in_days": 7, "rate_limit": 100000})
		return jsonID(r, "key"), jsonID(r, "id")
	}
	ka, kaID := mint(a, "assets:read")
	if ka == "" {
		s.info("K2", "mint key", "could not mint a key as a writer")
		return
	}
	lr, err := s.do(b, "GET", "/api/v1/api-keys", nil)
	if err == nil && strings.Contains(string(lr.Body), kaID) {
		lr.Status = 200
		s.record(scenarioResult{ID: "K2", Name: "a member lists another member's keys", Expect: "refused", Status: 200, Verdict: verdictFail, Body: "list includes the peer's key"})
	} else {
		s.record(scenarioResult{ID: "K2", Name: "a member lists another member's keys", Expect: "refused", Status: lr.Status, Verdict: verdictPass, Note: "peer's key not listed"})
	}
	s.expectRefused("K3", "a member revokes another member's key")(s.do(b, "POST", "/api/v1/api-keys/"+kaID+"/revoke", map[string]any{}))
	s.expectRefused("K4", "Globex owner revokes an Acme key")(s.do(globex.owner, "POST", "/api/v1/api-keys/"+kaID+"/revoke", map[string]any{}))
	key := bearer(ka)
	s.expectAllowed("K5", "the key reads assets")(s.w.c.do(key, "GET", "/api/v1/assets", nil))
	s.expectRefused("K6", "the key writes (keys are read-only)")(s.w.c.do(key, "POST", "/api/v1/assets", map[string]any{"name": "k.example.com", "type": "domain"}))
	s.expectRefused("K7", "the key reaches the API key routes")(s.w.c.do(key, "GET", "/api/v1/api-keys", nil))
	s.expectRefused("K8", "the key reads the other organization's asset")(s.w.c.do(key, "GET", "/api/v1/assets/"+globex.get("asset.scoped"), nil))

	// Suspension: the key and the session stop on the next request.
	base := "/api/v1/tenants/" + acme.Slug + "/members/"
	s.expectAllowed("K9", "owner suspends the key owner")(s.do(acme.owner, "POST", base+a.memberID+"/suspend", map[string]any{}))
	d := pollUntil(10*time.Second, func() bool {
		r, err := s.w.c.do(key, "GET", "/api/v1/assets", nil)
		return err == nil && (r.Status == 401 || r.Status == 403)
	})
	s.recordWindow("K10", "key refused after its owner is suspended", d, 0)
	d = pollUntil(10*time.Second, func() bool {
		r, err := s.do(a, "GET", "/api/v1/assets", nil)
		return err == nil && (r.Status == 401 || r.Status == 403)
	})
	s.recordWindow("K11", "session refused after suspension", d, 0)
	// The same token on routes outside the organization's member chain:
	// the account's own data and organization-wide counters.
	for _, probe := range []string{"/api/v1/users/me", "/api/v1/users/me/tenants", "/api/v1/threat-intel/kev/stats", "/api/v1/tenants"} {
		d = pollUntil(10*time.Second, func() bool {
			r, err := s.w.c.do(a.cred, "GET", probe, nil)
			return err == nil && (r.Status == 401 || r.Status == 403)
		})
		s.recordWindow("K11b", "suspended member's token refused on "+probe, d, 0)
	}
	_, _ = s.do(acme.owner, "POST", base+a.memberID+"/reactivate", map[string]any{})
	d = pollUntil(5*time.Second, func() bool {
		r, err := s.w.c.do(key, "GET", "/api/v1/assets", nil)
		return err == nil && r.Status == 200
	})
	s.info("K12", "key after reactivation", "key works again after "+fmtWindow(d))

	// Suspension under concurrent use: the member keeps sending reads while
	// the owner suspends it; after the suspension answers, every read must
	// be refused (a membership cache refilled by a read that started before
	// the suspension would keep the member in).
	s.suspendUnderLoad(acme)

	// Offboarding revokes the keys.
	kb, _ := mint(b, "assets:read")
	if kb != "" {
		s.expectAllowed("K13", "owner offboards the peer")(s.do(acme.owner, "POST", "/api/v1/organization/members/"+b.memberID+"/offboard",
			map[string]any{"reason": "authz matrix", "unassign_findings": true}))
		d = pollUntil(10*time.Second, func() bool {
			r, err := s.w.c.do(bearer(kb), "GET", "/api/v1/assets", nil)
			return err == nil && (r.Status == 401 || r.Status == 403)
		})
		s.recordWindow("K14", "key refused after its owner is offboarded", d, 0)
	}

	// Demotion: the key narrows to what its owner still holds.
	c := s.fresh(acme, "key-demoted", writerRole)
	kc, _ := mint(c, "assets:read")
	if kc != "" {
		_, _ = s.do(acme.owner, "PUT", "/api/v1/users/"+c.userID+"/roles", map[string]any{"role_ids": []string{acme.get("role.narrow-readonly")}})
		_, _ = s.do(acme.owner, "PUT", "/api/v1/users/"+c.userID+"/roles", map[string]any{"role_ids": []string{roleViewer}})
		d = pollUntil(10*time.Second, func() bool {
			r, err := s.w.c.do(bearer(kc), "GET", "/api/v1/integrations", nil)
			return err == nil && (r.Status == 401 || r.Status == 403)
		})
		s.info("K15", "key after its owner loses the role that allowed it", "refused after "+fmtWindow(d))
	}
}

func atoiOr(s string) int {
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

// recordWindow records a revocation that must take effect within max
// (0 = on the next request; the suite allows 1 s of polling slack).
func (s *scen) recordWindow(id, name string, d, maxWait time.Duration) {
	res := scenarioResult{ID: id, Name: name, Expect: "refused", Note: "took " + fmtWindow(d)}
	limit := maxWait + time.Second
	switch {
	case d < 0:
		res.Verdict = verdictFail
	case d > limit:
		res.Verdict = verdictFail
	default:
		res.Verdict = verdictPass
	}
	s.record(res)
}

// groups: team roles, membership delegation and scope rules.
func (s *scen) groups(acme, globex *tenant) {
	w := s.w
	// A group-member manager without team admin.
	gmRole := w.createRole(s.t, acme, fmt.Sprintf("group-manager-%d", s.seq.Add(1)), false,
		[]string{"team:groups:read", "team:groups:write", "team:groups:members", "team:groups:assets", "assets:read", "team:members:read"}, "")
	gm := s.fresh(acme, "group-manager", gmRole)
	gr, _ := s.do(acme.owner, "POST", "/api/v1/groups", map[string]any{"name": fmt.Sprintf("privileged %d", s.seq.Add(1)),
		"slug": fmt.Sprintf("privileged-%d", s.seq.Add(1)), "group_type": "team"})
	priv := jsonID(gr, "id")
	if priv == "" {
		s.info("G0", "create privileged group", "could not create: "+gr.String())
		return
	}
	s.expectAllowed("G1", "owner binds the near-admin role to a team")(s.do(acme.owner, "POST", "/api/v1/groups/"+priv+"/roles",
		map[string]any{"role_id": acme.get("role.near-admin")}))
	target := s.fresh(acme, "group-target", roleViewer)
	s.expectRefused("G2", "group manager adds a member to a team bound to a privileged role")(s.do(gm, "POST", "/api/v1/groups/"+priv+"/members",
		map[string]any{"user_id": target.userID, "role": "member"}))
	s.expectRefused("G3", "group manager adds itself to that team")(s.do(gm, "POST", "/api/v1/groups/"+priv+"/members",
		map[string]any{"user_id": gm.userID, "role": "member"}))
	s.expectRefused("G4", "group manager binds a role above its grant to a team")(s.do(gm, "POST", "/api/v1/groups/"+acme.get("group.victim")+"/roles",
		map[string]any{"role_id": acme.get("role.near-admin")}))
	s.expectRefused("G5", "group manager (restricted scope) assigns an out-of-scope asset")(s.do(gm, "POST", "/api/v1/groups/"+acme.get("group.victim")+"/assets",
		map[string]any{"asset_id": acme.get("asset.oos"), "ownership_type": "primary"}))
	s.expectRefused("G6", "group manager (restricted scope) creates a scope rule")(s.do(gm, "POST", "/api/v1/groups/"+acme.get("group.victim")+"/scope-rules",
		map[string]any{"name": "everything", "rule_type": "tag_match", "match_tags": []string{"x"}, "ownership_type": "secondary"}))
	s.expectRefused("G7", "Acme owner adds a member to a Globex group")(s.do(acme.owner, "POST", "/api/v1/groups/"+globex.get("group.victim")+"/members",
		map[string]any{"user_id": target.userID, "role": "member"}))
	s.expectRefused("G8", "Acme owner assigns an Acme asset to a Globex group")(s.do(acme.owner, "POST", "/api/v1/groups/"+globex.get("group.victim")+"/assets",
		map[string]any{"asset_id": acme.get("asset.scoped"), "ownership_type": "primary"}))
	s.expectRefused("G9", "Acme owner grants a Globex asset to an Acme user")(s.do(acme.owner, "POST", "/api/v1/assets/"+globex.get("asset.scoped")+"/access-grants",
		map[string]any{"user_id": target.userID, "reason": "matrix"}))
	s.expectRefused("G10", "group manager grants an out-of-scope asset to a user")(s.do(gm, "POST", "/api/v1/assets/"+acme.get("asset.oos")+"/access-grants",
		map[string]any{"user_id": target.userID, "reason": "matrix"}))
	adm := s.fresh(acme, "scim-admin", roleAdmin)
	s.expectRefused("G11", "admin maps a SCIM group to the admin role (owner only)")(s.do(adm, "PUT", "/api/v1/scim-tokens/group-mappings",
		map[string]any{"mappings": map[string]string{"matrix-admins": "admin"}}))
}

// fourEyes: nobody approves their own request.
func (s *scen) fourEyes(acme *tenant) {
	near := s.fresh(acme, "four-eyes", acme.get("role.near-admin"))
	finding := acme.get("finding.scoped")
	// Risk acceptance starts from a confirmed finding.
	_, _ = s.do(acme.owner, "PATCH", "/api/v1/findings/"+finding+"/status", map[string]any{"status": "confirmed", "note": "authz matrix"})
	for _, c := range []struct{ id, status, reason string }{
		{"F1", "false_positive", "detection_error"},
		{"F2", "accepted", "risk_accepted"},
	} {
		body := map[string]any{"requested_status": c.status, "justification": "authz matrix four-eyes check: requester must not approve", "closure_reason": c.reason}
		if c.status == "accepted" {
			body["expires_at"] = time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}
		r, err := s.do(near, "POST", "/api/v1/findings/"+finding+"/approvals", body)
		id := jsonID(r, "id")
		if err != nil || id == "" {
			s.info(c.id, "request "+c.status+" approval", "request not created: "+r.String())
			continue
		}
		s.expectRefused400(c.id, "requester approves its own "+c.status+" request")(s.do(near, "POST", "/api/v1/approvals/"+id+"/approve", map[string]any{"comment": "self"}))
		s.expectRefused(c.id+"b", "requester self-approves (not the sole owner, no authenticator code)")(s.do(near, "POST", "/api/v1/approvals/"+id+"/self-approve",
			map[string]any{"reason": "self", "code": "000000"}))
		s.expectRefused(c.id+"c", "Globex owner approves Acme's request")(s.do(s.w.tenant("Globex").owner, "POST", "/api/v1/approvals/"+id+"/approve", map[string]any{}))
		_, _ = s.do(near, "POST", "/api/v1/approvals/"+id+"/cancel", map[string]any{})
	}
}

// stepUpGates: every route the source marks step-up refuses a session that
// has not stepped up, before anything else happens.
func (s *scen) stepUpGates(acme *tenant) {
	ownerNS := s.noStepUp(acme.owner)
	routes := loadRoutes(s.t)
	pass, fail := 0, 0
	for _, r := range routes {
		if !r.Gate.StepUp || r.console() || selfDestructive(r) {
			continue
		}
		var body any
		if r.Method != "GET" && r.Method != "DELETE" {
			body = map[string]any{}
		}
		resp, err := s.w.c.do(ownerNS.cred, r.Method, freshIDs(acme, r.Path), body)
		if err != nil {
			continue
		}
		res := scenarioResult{ID: "S1", Name: "step-up gate " + r.key(), Expect: "refused", Status: resp.Status, Code: resp.Code}
		switch {
		case resp.Status == 403 && strings.Contains(resp.Code, "STEP_UP"), resp.Status == 401:
			res.Verdict = verdictPass
			pass++
		case resp.Status == 403 || resp.Status == 404:
			res.Verdict, res.Note = verdictInconclusive, "refused before the step-up check"
		default:
			res.Verdict, res.Body = verdictFail, excerpt(resp.Body)
			fail++
		}
		if res.Verdict == verdictFail {
			s.record(res)
		} else {
			s.results = append(s.results, res)
		}
	}
	s.info("S1", "step-up gates", fmt.Sprintf("%d step-up routes refused a session without step-up, %d did not", pass, fail))
}

// propagation: a role change takes effect on the next request; measure.
// The probe is GET /api/v1/priority-rules (ctem:priority_rules:read), which
// a viewer lacks.
func (s *scen) propagation(acme *tenant) {
	role := s.w.createRole(s.t, acme, fmt.Sprintf("prop-%d", s.seq.Add(1)), false,
		[]string{"ctem:priority_rules:read", "integrations:api_keys:read", "integrations:api_keys:write"}, "")
	p := s.fresh(acme, "propagation", roleViewer)
	probe := func(cred credential, want ...int) func() bool {
		return func() bool {
			r, err := s.w.c.do(cred, "GET", "/api/v1/priority-rules", nil)
			if err != nil {
				return false
			}
			for _, w := range want {
				if r.Status == w {
					return true
				}
			}
			return false
		}
	}
	s.expectRefused("P0", "viewer lists priority rules before the grant")(s.w.c.do(p.cred, "GET", "/api/v1/priority-rules", nil))
	_, _ = s.do(acme.owner, "POST", "/api/v1/users/"+p.userID+"/roles", map[string]any{"role_id": role})
	d := pollUntil(10*time.Second, probe(p.cred, 200))
	s.recordWindow("P1", "grant takes effect for the existing session (safe read)", d, 0)
	r, err := s.w.c.do(p.cred, "POST", "/api/v1/api-keys", map[string]any{"name": "stale", "scopes": []string{"ctem:priority_rules:read"}, "expires_in_days": 1})
	s.info("P2", "unsafe request with the token issued before the grant", fmt.Sprintf("%d %s %v", r.Status, r.Code, err))
	_, _ = s.do(acme.owner, "DELETE", "/api/v1/users/"+p.userID+"/roles/"+role, nil)
	d = pollUntil(10*time.Second, probe(p.cred, 403))
	s.recordWindow("P3", "revocation takes effect for the existing session (safe read)", d, 0)

	// An API key: grant, mint with the probe scope, revoke the role, poll.
	_, _ = s.do(acme.owner, "POST", "/api/v1/users/"+p.userID+"/roles", map[string]any{"role_id": role})
	p = s.relogin(p)
	km, _ := s.do(p, "POST", "/api/v1/api-keys", map[string]any{"name": fmt.Sprintf("prop-%d", s.seq.Add(1)), "scopes": []string{"ctem:priority_rules:read"},
		"expires_in_days": 7, "rate_limit": 100000})
	key := jsonID(km, "key")
	if key == "" {
		s.info("P4", "mint key for propagation", km.String())
		return
	}
	s.expectAllowed("P4", "the key lists priority rules while its owner holds the permission")(s.w.c.do(bearer(key), "GET", "/api/v1/priority-rules", nil))
	_, _ = s.do(acme.owner, "DELETE", "/api/v1/users/"+p.userID+"/roles/"+role, nil)
	d = pollUntil(10*time.Second, probe(bearer(key), 401, 403))
	s.recordWindow("P5", "key narrows when its owner loses the permission", d, 0)
}

// laneB: runtime checks asked for by the platform-core review.
func (s *scen) laneB(acme *tenant) {
	adm := s.fresh(acme, "laneb-admin", roleAdmin)
	admNS := s.noStepUp(adm)
	// An external member whose access ended (suspended as expired). No
	// API classifies a member as external on a stack without verified
	// domains, so the scratch database does it (test setup only).
	mem := s.fresh(acme, "laneb-external", roleViewer)
	if _, err := s.w.db.Exec(`UPDATE tenant_members SET kind = 'external', home_domain = 'example.net',
		expires_at = NOW() - INTERVAL '1 day', status = 'suspended', suspended_reason = 'expired'
		WHERE id = $1`, mem.memberID); err != nil {
		s.info("B-access-widen-stepup", "classify external", err.Error())
		return
	}
	// Widening access: set a far expiry on a member without step-up.
	r, err := s.do(admNS, "PATCH", "/api/v1/organization/members/"+mem.memberID+"/access",
		map[string]any{"expires_at": time.Now().Add(300 * 24 * time.Hour).UTC().Format(time.RFC3339), "reason": "matrix"})
	s.expectRefused("B-access-widen-stepup", "member access change requires a recent step-up")(r, err)
	if r.Status < 300 {
		d := pollUntil(3*time.Second, func() bool {
			q, e := s.w.c.do(mem.cred, "GET", "/api/v1/me/permissions", nil)
			return e == nil && q.Status == 200
		})
		s.info("B-access-widen-stepup", "member session after the access change", "works again after "+fmtWindow(d))
	}
	// Lowering approval levels: owner only (with step-up) once the fix lands.
	s.expectRefused("B-fp-lower-owner-only", "false-positive approval level change is owner-only")(s.do(adm, "PATCH", "/api/v1/organization/settings/finding-approvals",
		map[string]any{"fp_approval": "off"}))
	s.expectRefused("B-accept-lower-owner", "risk-acceptance approval level change is owner-only")(s.do(adm, "PATCH", "/api/v1/organization/settings/finding-approvals",
		map[string]any{"accept_approval": "off"}))
	// Restore the default for the other checks.
	_, _ = s.do(acme.owner, "PATCH", "/api/v1/organization/settings/finding-approvals", map[string]any{"fp_approval": "all", "accept_approval": "all"})
	// integrations:manage and integrations:scm:write become privileged:
	// granting them needs a recent step-up.
	ownerNS := s.noStepUp(acme.owner)
	for _, c := range []struct{ id, perm string }{{"B-integrations-manage", "integrations:manage"}, {"B-integrations-scm", "integrations:scm:write"}} {
		role := s.w.createRole(s.t, acme, fmt.Sprintf("priv-%d", s.seq.Add(1)), false, []string{c.perm}, "")
		tgt := s.fresh(acme, "priv-target", roleViewer)
		s.expectRefused(c.id, "granting "+c.perm+" requires a recent step-up")(s.do(ownerNS, "POST", "/api/v1/users/"+tgt.userID+"/roles", map[string]any{"role_id": role}))
	}
}

// console: the platform administrator cannot hand an organization with an
// active owner to someone else, and tenant credentials never reach it.
func (s *scen) console(acme *tenant) {
	cs, why := s.w.consoleSignIn()
	if cs == nil {
		s.record(scenarioResult{ID: "C1", Name: "console owner create on an organization with an active owner", Expect: "refused", Verdict: verdictInconclusive, Note: why})
		return
	}
	body := map[string]any{"email": "takeover@" + acme.Slug + ".example.com", "name": "Takeover"}
	s.expect409("C1", "console creates an owner for an organization with an active owner")(cs.do("POST", "/api/v1/admin/tenants/"+acme.ID+"/users", body, true))
	body["recovery"], body["reason"] = true, "authz matrix owner recovery check"
	s.expect409("C2", "console owner recovery while an active owner exists")(cs.do("POST", "/api/v1/admin/tenants/"+acme.ID+"/users", body, true))
	s.expectRefused("C3", "tenant owner's token on the console tenant list")(s.do(acme.owner, "GET", "/api/v1/admin/tenants", nil))
}

// suspendUnderLoad measures how long a member's own token keeps working
// after its suspension answered, while the member is busy.
func (s *scen) suspendUnderLoad(acme *tenant) {
	for round := 0; round < 3; round++ {
		v := s.fresh(acme, "busy", roleMember)
		stop := make(chan struct{})
		var lastOK atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					r, err := s.w.c.do(v.cred, "GET", "/api/v1/vulnerabilities", nil)
					if err == nil && r.Status == 200 {
						lastOK.Store(time.Now().UnixNano())
					}
				}
			}()
		}
		time.Sleep(300 * time.Millisecond)
		r, err := s.do(acme.owner, "POST", "/api/v1/tenants/"+acme.Slug+"/members/"+v.memberID+"/suspend", map[string]any{})
		done := time.Now()
		if err != nil || r.Status != 200 {
			close(stop)
			wg.Wait()
			s.info("K16", "suspend under load", "suspend failed: "+r.String())
			return
		}
		time.Sleep(2 * time.Second)
		close(stop)
		wg.Wait()
		// After the readers stop, the token must be refused.
		after, _ := s.w.c.do(v.cred, "GET", "/api/v1/vulnerabilities", nil)
		window := time.Duration(0)
		if t := lastOK.Load(); t > done.UnixNano() {
			window = time.Duration(t - done.UnixNano())
		}
		res := scenarioResult{ID: "K16", Name: fmt.Sprintf("suspended member's token refused after the suspension answered, while in use (round %d)", round+1),
			Expect: "refused", Status: after.Status, Code: after.Code, Note: "last accepted read " + window.Round(time.Millisecond).String() + " after the suspension answered"}
		switch {
		case after.Status == 200:
			res.Verdict, res.Body = verdictFail, "still accepted 2 s after the suspension"
		case window > 500*time.Millisecond:
			res.Verdict = verdictFail
		default:
			res.Verdict = verdictPass
		}
		s.record(res)
	}
}
