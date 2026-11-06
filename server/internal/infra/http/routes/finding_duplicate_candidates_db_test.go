package routes

// GET /api/v1/findings/{id}/duplicate-candidates over the real routes,
// handler, service, repository and a migrated database: the matching rules,
// the order, "known before the report", and that the answer never reveals a
// finding outside the caller's data scope or tenant.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type candidatesBody struct {
	FindingID         string     `json:"finding_id"`
	ReportSubmittedAt *time.Time `json:"report_submitted_at"`
	KnownSince        *time.Time `json:"known_since"`
	KnownBeforeReport *bool      `json:"known_before_report"`
	Candidates        []struct {
		FindingID         string    `json:"finding_id"`
		Source            string    `json:"source"`
		Status            string    `json:"status"`
		AssetID           string    `json:"asset_id"`
		FirstDetectedAt   time.Time `json:"first_detected_at"`
		MatchedOn         []string  `json:"matched_on"`
		KnownBeforeReport *bool     `json:"known_before_report"`
	} `json:"candidates"`
	Limit int `json:"limit"`
}

type candFixture struct {
	h                       *dsHarness
	host                    string
	x1, x2, x3              shared.ID // x1, x3 in memberA's scope; x2 not
	seed                    shared.ID
	early, resolved, onHost shared.ID // expected for memberA
	outOfScope, folded      shared.ID
	noSignal, otherTenant   shared.ID
	otherTenantID           shared.ID
	submitted, earlyAt      time.Time
}

func (c *candFixture) asset(tenant shared.ID, name string, inScope bool) shared.ID {
	id := shared.NewID()
	c.h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, id.String(), tenant.String(), name)
	if inScope {
		c.h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			c.h.memberA.String(), tenant.String(), id.String())
	}
	return id
}

func (c *candFixture) finding(tenant, asset shared.ID, source, status string, cwes string, firstSeen time.Time, metadata string) shared.ID {
	id := shared.NewID()
	c.h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cwe_ids, first_detected_at, metadata)
		VALUES ($1::uuid, $2, $3, $4, 'cand-tool', 'candidate finding', 'high', $1::text, $5, $6::text[], $7, $8::jsonb)`,
		id.String(), tenant.String(), asset.String(), source, status, cwes, firstSeen, metadata)
	return id
}

func newCandFixture(t *testing.T) *candFixture {
	h := newDSHarness(t)
	now := time.Now().UTC().Truncate(time.Second)
	c := &candFixture{h: h, host: "shop-" + shared.NewID().String()[:8] + ".example.com",
		submitted: now.Add(-24 * time.Hour), earlyAt: now.Add(-30 * 24 * time.Hour)}
	c.x1 = c.asset(h.tenant, c.host, true)
	c.x2 = c.asset(h.tenant, "https://"+c.host+"/admin", false)
	c.x3 = c.asset(h.tenant, "https://"+c.host+":8443/app", true)

	report := `{"bounty_report": {"intake": "vdp", "ref": "R-9", "weakness": "CWE-79", "endpoint_path": "/search", "submitted_at": "` +
		c.submitted.Format(time.RFC3339) + `"}}`
	c.seed = c.finding(h.tenant, c.x1, "bug_bounty", "new", "{}", now, report)

	c.early = c.finding(h.tenant, c.x1, "dast", "confirmed", "{CWE-79}", c.earlyAt, "{}")
	c.resolved = c.finding(h.tenant, c.x1, "sast", "resolved", "{CWE-79}", now.Add(-10*24*time.Hour), "{}")
	c.onHost = c.finding(h.tenant, c.x3, "dast", "new", "{}", now, "{}")
	h.exec(`INSERT INTO finding_injection_points (finding_id, tenant_id, asset_id, kind, point_key, origin, path, method)
		VALUES ($1, $2, $3, 'dast', 'GET /search q', 'https://`+c.host+`:8443', '/search', 'GET')`,
		c.onHost.String(), h.tenant.String(), c.x3.String())

	c.outOfScope = c.finding(h.tenant, c.x2, "dast", "new", "{CWE-79}", c.earlyAt.Add(-time.Hour), "{}")
	c.noSignal = c.finding(h.tenant, c.x1, "sast", "new", "{CWE-89}", now, "{}")
	c.folded = c.finding(h.tenant, c.x1, "dast", "new", "{CWE-79}", now, "{}")
	h.exec(`UPDATE findings SET status = 'duplicate', duplicate_of = $2 WHERE id = $1`, c.folded.String(), c.early.String())

	// Another tenant with the same host and CWE.
	c.otherTenantID = shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, c.otherTenantID.String(), "ds-cand-"+c.otherTenantID.String())
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, c.otherTenantID.String()) })
	otherAsset := c.asset(c.otherTenantID, c.host, false)
	c.otherTenant = c.finding(c.otherTenantID, otherAsset, "dast", "new", "{CWE-79}", c.earlyAt.Add(-2*time.Hour), "{}")
	return c
}

func (c *candFixture) get(user shared.ID, admin bool, perms []string, id shared.ID) (int, candidatesBody, string) {
	c.h.t.Helper()
	path := "/api/v1/findings/" + id.String() + "/duplicate-candidates"
	var status int
	var raw string
	if perms != nil {
		status, raw = c.h.doWithPerms(user, perms, http.MethodGet, path, nil)
	} else {
		status, raw = c.h.do(user, admin, http.MethodGet, path, nil)
	}
	var b candidatesBody
	if status == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &b); err != nil {
			c.h.t.Fatalf("decode: %v (%s)", err, raw)
		}
	}
	return status, b, raw
}

func candIDs(b candidatesBody) []string {
	out := make([]string, 0, len(b.Candidates))
	for _, c := range b.Candidates {
		out = append(out, c.FindingID)
	}
	return out
}

func TestDuplicateCandidates_RulesOrderAndKnownSince_DB(t *testing.T) {
	c := newCandFixture(t)
	status, b, raw := c.get(c.h.memberA, false, nil, c.seed)
	if status != http.StatusOK {
		t.Fatalf("memberA = %d %.300s", status, raw)
	}
	want := []string{c.early.String(), c.resolved.String(), c.onHost.String()}
	got := candIDs(b)
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v (early, resolved, same-host path)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates order = %v, want %v", got, want)
		}
	}
	first, last := b.Candidates[0], b.Candidates[2]
	if first.KnownBeforeReport == nil || !*first.KnownBeforeReport || last.KnownBeforeReport == nil || *last.KnownBeforeReport {
		t.Fatalf("known_before_report per candidate wrong: %+v / %+v", first, last)
	}
	if b.KnownBeforeReport == nil || !*b.KnownBeforeReport || b.KnownSince == nil || !b.KnownSince.Equal(c.earlyAt) {
		t.Fatalf("known_since = %v known_before_report = %v, want %v and true", b.KnownSince, b.KnownBeforeReport, c.earlyAt)
	}
	if b.ReportSubmittedAt == nil || !b.ReportSubmittedAt.Equal(c.submitted) || b.Limit != 20 {
		t.Fatalf("report_submitted_at = %v limit = %d", b.ReportSubmittedAt, b.Limit)
	}
	if m := last.MatchedOn; len(m) != 2 || m[0] != "same_host" || m[1] != "path" {
		t.Fatalf("matched_on of the same-host candidate = %v", m)
	}
	if m := first.MatchedOn; len(m) != 2 || m[0] != "same_asset" || m[1] != "cwe" {
		t.Fatalf("matched_on of the same-asset candidate = %v", m)
	}
	if b.Candidates[1].Status != "resolved" {
		t.Fatalf("a resolved finding is a candidate too: %+v", b.Candidates[1])
	}
}

// A restricted member learns nothing outside their scope: the same-host
// finding on an asset they cannot see is left out (and its earlier date
// does not leak through known_since), while the owner sees it. No caller
// ever sees another tenant's finding.
func TestDuplicateCandidates_NoOracleOutsideScope_DB(t *testing.T) {
	c := newCandFixture(t)
	_, member, _ := c.get(c.h.memberA, false, nil, c.seed)
	for _, id := range candIDs(member) {
		if id == c.outOfScope.String() || id == c.otherTenant.String() || id == c.folded.String() || id == c.noSignal.String() {
			t.Fatalf("memberA got %s, which must not be a candidate for them: %v", id, candIDs(member))
		}
	}
	if member.KnownSince == nil || !member.KnownSince.Equal(c.earlyAt) {
		t.Fatalf("known_since for memberA = %v, want %v (not the out-of-scope finding's earlier date)", member.KnownSince, c.earlyAt)
	}

	status, owner, raw := c.get(c.h.owner, true, nil, c.seed)
	if status != http.StatusOK {
		t.Fatalf("owner = %d %.300s", status, raw)
	}
	seen := map[string]bool{}
	for _, id := range candIDs(owner) {
		seen[id] = true
	}
	if !seen[c.outOfScope.String()] {
		t.Fatalf("owner should see the same-host finding on the unscoped asset: %v", candIDs(owner))
	}
	if seen[c.otherTenant.String()] || seen[c.folded.String()] {
		t.Fatalf("owner got another tenant's or a folded finding: %v", candIDs(owner))
	}

	// The seed finding itself: out of scope, no scope at all, another
	// tenant's id: 404.
	if status, _, _ := c.get(c.h.memberA, false, nil, c.outOfScope); status != http.StatusNotFound {
		t.Fatalf("memberA on an out-of-scope finding = %d, want 404", status)
	}
	if status, _, _ := c.get(c.h.memberFree, false, nil, c.seed); status != http.StatusNotFound {
		t.Fatalf("member with no scope = %d, want 404", status)
	}
	if status, _, _ := c.get(c.h.owner, true, nil, c.otherTenant); status != http.StatusNotFound {
		t.Fatalf("another tenant's finding id = %d, want 404", status)
	}
	// findings:triage is required.
	if status, _, _ := c.get(c.h.memberA, false, []string{permission.FindingsRead.String(), permission.FindingsWrite.String()}, c.seed); status != http.StatusForbidden {
		t.Fatalf("no findings:triage = %d, want 403", status)
	}
}
