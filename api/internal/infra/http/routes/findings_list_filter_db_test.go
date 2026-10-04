package routes

// GET /findings on the list query contract (RFC-048), over the real routes,
// handler, service, compiler and a migrated database: every filter narrows
// within the caller's data scope (never widens it), pentest findings stay
// hidden from non-members, other tenants' rows never match, old param names
// still work with deprecation headers, and bad filters are 400
// INVALID_FILTER.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type flResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Total int64 `json:"total"`
}

type flCaller struct {
	name  string
	user  shared.ID
	admin bool
}

func (h *gsHarness) listFindings(t *testing.T, c flCaller, query string) (int, http.Header, string) {
	t.Helper()
	return h.listFindingsPath(t, c, "/api/v1/findings?"+query)
}

func (h *gsHarness) listFindingsPath(t *testing.T, c flCaller, path string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", c.user.String())
	if c.admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(body)
}

func (h *gsHarness) listIDs(t *testing.T, c flCaller, query string) ([]string, int64, string) {
	t.Helper()
	status, _, body := h.listFindings(t, c, query)
	if status != http.StatusOK {
		t.Fatalf("%s GET /findings?%s = %d: %.300s", c.name, query, status, body)
	}
	var out flResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ids := make([]string, 0, len(out.Data))
	for _, d := range out.Data {
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	return ids, out.Total, body
}

func TestFindingsList_FiltersNarrowWithinScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.exec(`UPDATE assets SET tags = ARRAY['prod'] WHERE id = $1`, h.assetA.String())
	h.exec(`UPDATE assets SET tags = ARRAY['dev'] WHERE id = $1`, h.assetB.String())

	fa, fb, fb2, fp := h.findingA.String(), h.findingB.String(), h.findingB2.String(), h.findingP.String()
	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	free := flCaller{"member without group", h.memberFree, false}

	cases := []struct {
		query                string
		admin, memberA, free []string
	}{
		{"", sorted(fa, fb, fb2, fp), sorted(fa), sorted(fa, fb, fb2)},
		{"asset_id=" + h.assetB.String(), sorted(fb, fb2), nil, sorted(fb, fb2)},
		{"severities=critical", sorted(fb), nil, sorted(fb)},
		{"severity=high&source=sast", sorted(fa, fb2), sorted(fa), sorted(fa, fb2)},
		{"source=pentest", sorted(fp), nil, nil},
		{"sources=pentest", sorted(fp), nil, nil},
		{"id=" + fb, sorted(fb), nil, sorted(fb)},
		{"finding_ids=" + fb + "," + fa, sorted(fa, fb), sorted(fa), sorted(fa, fb)},
		{"cve_id=" + h.cveB, sorted(fb), nil, sorted(fb)},
		{"cve_ids=" + h.cveA + "," + h.cveB2, sorted(fa, fb2), sorted(fa), sorted(fa, fb2)},
		// asset_tags was accepted and silently ignored by the list before.
		{"asset_tags=prod", sorted(fa, fp), sorted(fa), sorted(fa)},
		{"asset_tag=dev", sorted(fb, fb2), nil, sorted(fb, fb2)},
		{"asset_tag_not=prod", sorted(fb, fb2), nil, sorted(fb, fb2)},
		{"finding_type=secret", sorted(fb), nil, sorted(fb)},
		{"component_id=" + h.componentA.String(), sorted(fa, fb2), sorted(fa), sorted(fa, fb2)},
		{"status_not=confirmed", nil, nil, nil},
		{"exclude_statuses=resolved&severity_not=critical", sorted(fa, fb2, fp), sorted(fa), sorted(fa, fb2)},
		{"created_at_gte=-P1D", sorted(fa, fb, fb2, fp), sorted(fa), sorted(fa, fb, fb2)},
		{"created_at_lt=2000-01-01", nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			for _, who := range []struct {
				caller flCaller
				want   []string
			}{{admin, c.admin}, {memberA, c.memberA}, {free, c.free}} {
				ids, total, body := h.listIDs(t, who.caller, c.query)
				if strings.Join(ids, ",") != strings.Join(who.want, ",") || total != int64(len(who.want)) {
					t.Errorf("%s ?%s = %v (total %d), want %v", who.caller.name, c.query, ids, total, who.want)
				}
				if who.caller == memberA {
					for _, leak := range []string{dsMarkerFindingB, dsMarkerAssetB, fb, fb2, fp} {
						// The pagination links echo the caller's own query.
						if !strings.Contains(c.query, leak) && strings.Contains(body, leak) {
							t.Errorf("memberA ?%s leaked %q", c.query, leak)
						}
					}
				}
			}
		})
	}
}

func TestFindingsList_RelatedToMe(t *testing.T) {
	h := newGroupScopeHarness(t)
	memberA := flCaller{"memberA", h.memberA, false}
	// memberA is a primary owner of A1 (seedGroups); FP is on A1 but pentest.
	for _, q := range []string{"related_to=me", "assigned_to_me=true"} {
		if ids, _, _ := h.listIDs(t, memberA, q); strings.Join(ids, ",") != h.findingA.String() {
			t.Errorf("memberA ?%s = %v, want [FA]", q, ids)
		}
	}
	// ownerB owns B1, and the related-to rule applies inside the data scope:
	// an unrestricted member sees B's findings, nobody else's.
	ownerB := flCaller{"ownerB", h.ownerB, false}
	if ids, _, _ := h.listIDs(t, ownerB, "related_to=me"); strings.Join(ids, ",") != strings.Join(sorted(h.findingB.String(), h.findingB2.String()), ",") {
		t.Errorf("ownerB related_to=me = %v", ids)
	}
	if ids, _, _ := h.listIDs(t, memberA, "assigned_to_me=false"); len(ids) != 1 {
		t.Errorf("assigned_to_me=false must not filter: %v", ids)
	}
}

func TestFindingsList_StrictPolicyAndOtherTenant(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.setPolicy(tenant.MembersWithoutGroupSeeNothing)
	strict := flCaller{"member without group (nothing)", h.memberStrict, false}
	for _, q := range []string{"", "asset_id=" + h.assetA.String(), "id=" + h.findingA.String()} {
		if ids, total, _ := h.listIDs(t, strict, q); len(ids) != 0 || total != 0 {
			t.Errorf("strict member ?%s = %v (total %d), want none", q, ids, total)
		}
	}

	// A finding in another tenant never matches, even by id, even for an admin.
	other, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "fl-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'fl-other.example', 'domain')`, otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'fl other tenant', 'critical', $1::text, 'confirmed')`,
		otherFinding.String(), other.String(), otherAsset.String())
	admin := flCaller{"owner", h.owner, true}
	for _, q := range []string{"id=" + otherFinding.String(), "asset_id=" + otherAsset.String()} {
		if ids, total, _ := h.listIDs(t, admin, q); len(ids) != 0 || total != 0 {
			t.Errorf("admin ?%s returned another tenant's finding: %v", q, ids)
		}
	}
}

func TestFindingsList_ContractHeadersAndErrors(t *testing.T) {
	h := newGroupScopeHarness(t)
	admin := flCaller{"owner", h.owner, true}

	// Old name: works, with Deprecation, Sunset and a Warning naming the new one.
	status, hdr, _ := h.listFindings(t, admin, "severities=high")
	if status != http.StatusOK || hdr.Get("Deprecation") == "" || hdr.Get("Sunset") == "" ||
		!strings.Contains(hdr.Get("Warning"), "use severity") {
		t.Errorf("alias: %d %v", status, hdr)
	}

	// Unknown param (the web's source_id): ignored in the warn window, named
	// in a Warning, never echoed with its value.
	status, hdr, _ = h.listFindings(t, admin, "source_id=secret-value&severity=high")
	warn := strings.Join(hdr.Values("Warning"), " ")
	if status != http.StatusOK || !strings.Contains(warn, "source_id") || strings.Contains(warn, "secret-value") || hdr.Get("Deprecation") == "" {
		t.Errorf("unknown param: %d %v", status, hdr)
	}

	for q, param := range map[string]string{
		"severity=urgent":       "severity",
		"severities=urgent":     "severities",
		"is_in_kev=yes":         "is_in_kev",
		"epss_score_gte=high":   "epss_score_gte",
		"sort=-title":           "sort",
		"asset_id=not-a-uuid":   "asset_id",
		"branch_status=bogus":   "branch_status",
		"page=0":                "page",
		"page=200&per_page=100": "page",
	} {
		status, _, body := h.listFindings(t, admin, q)
		var e struct {
			Code    string `json:"code"`
			Details []struct {
				Param string `json:"param"`
			} `json:"details"`
		}
		_ = json.Unmarshal([]byte(body), &e)
		if status != http.StatusBadRequest || e.Code != "INVALID_FILTER" || len(e.Details) == 0 || e.Details[0].Param != param {
			t.Errorf("?%s = %d %s, want 400 INVALID_FILTER on %s", q, status, body, param)
		}
	}

	// branch_id + branch_status maps onto the per-state branch fields.
	if status, _, body := h.listFindings(t, admin, "branch_id="+url.QueryEscape(shared.NewID().String())+"&branch_status=open"); status != http.StatusOK {
		t.Errorf("branch_status=open: %d %s", status, body)
	}
}

// The research 17 filters (Tenable.sc parity) narrow inside the caller's
// scope like every other field.
func TestFindingsList_Research17Filters(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa, fb, fb2, fp := h.findingA.String(), h.findingB.String(), h.findingB2.String(), h.findingP.String()
	h.exec(`UPDATE findings SET cvss_score = 9.8, network_port = 443, network_transport = 'tcp', network_service = 'https',
		assigned_to = $2, exploit_available = true, family = 'CGI abuses', cve_ids = ARRAY['CVE-2099-0001'],
		last_seen_at = now() - interval '2 days',
		first_detected_at = now() - interval '40 days' WHERE id = $1`, fa, h.memberA.String())
	h.exec(`UPDATE findings SET cvss_score = 5.0, network_port = 22, network_transport = 'tcp', network_service = 'ssh',
		family = 'General', last_seen_at = now() - interval '90 days', first_detected_at = now() - interval '100 days' WHERE id = $1`, fb)
	h.exec(`UPDATE findings SET last_seen_at = now() - interval '200 days', first_detected_at = now() - interval '300 days' WHERE id IN ($1, $2)`, fb2, fp)
	h.exec(`UPDATE assets SET criticality = 'critical' WHERE id = $1`, h.assetB.String())

	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	cases := []struct {
		query          string
		admin, memberA []string
	}{
		{"cvss_score_gte=9", sorted(fa), sorted(fa)},
		{"cvss_score_lt=9", sorted(fb), nil},
		{"cvss_score_gte=4&cvss_score_lte=6", sorted(fb), nil},
		{"last_seen_at_gte=-P30D", sorted(fa), sorted(fa)},
		{"last_seen_at_lt=-P60D", sorted(fb, fb2, fp), nil},
		{"first_detected_at_lte=-P50D", sorted(fb, fb2, fp), nil},
		{"network_port=443,22", sorted(fa, fb), sorted(fa)},
		{"network_port_gte=100", sorted(fa), sorted(fa)},
		{"network_transport=tcp", sorted(fa, fb), sorted(fa)},
		{"network_service=ssh", sorted(fb), nil},
		{"assigned_to=" + h.memberA.String(), sorted(fa), sorted(fa)},
		{"assigned_to_null=false", sorted(fa), sorted(fa)},
		{"assigned_to_null=true", sorted(fb, fb2, fp), nil},
		{"asset_criticality=critical", sorted(fb, fb2), nil},
		{"asset_criticality=high", sorted(fa, fp), sorted(fa)},
		{"asset_criticality_not=critical", sorted(fa, fp), sorted(fa)},
		{"exploit_available=true", sorted(fa), sorted(fa)},
		{"exploit_available=false", sorted(fb, fb2, fp), nil},
		{"family=CGI+abuses", sorted(fa), sorted(fa)},
		{"family=General", sorted(fb), nil},
		{"family_not=General", sorted(fa, fb2, fp), sorted(fa)},
		{"cve_id=CVE-2099-0001", sorted(fa), sorted(fa)},
		{"cve_id_not=CVE-2099-0001", sorted(fb, fb2, fp), nil},
		{"sort=family", sorted(fa, fb, fb2, fp), sorted(fa)},
		{"sort=-cvss_score", sorted(fa, fb, fb2, fp), sorted(fa)},
		{"sort=-last_seen_at,network_port", sorted(fa, fb, fb2, fp), sorted(fa)},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			for _, who := range []struct {
				caller flCaller
				want   []string
			}{{admin, c.admin}, {memberA, c.memberA}} {
				ids, total, _ := h.listIDs(t, who.caller, c.query)
				if strings.Join(ids, ",") != strings.Join(who.want, ",") || total != int64(len(who.want)) {
					t.Errorf("%s ?%s = %v (total %d), want %v", who.caller.name, c.query, ids, total, who.want)
				}
			}
		})
	}
	// Sort order really follows the key: highest CVSS first, unscored last.
	status, _, body := h.listFindings(t, admin, "sort=-cvss_score&source_not=pentest")
	var out flResponse
	if err := json.Unmarshal([]byte(body), &out); status != http.StatusOK || err != nil || len(out.Data) < 2 || out.Data[0].ID != fa || out.Data[1].ID != fb {
		t.Errorf("sort=-cvss_score order: %d %s", status, body)
	}
}

// /findings/related-cves takes the list's filter (RFC-048): the filter
// narrows the related findings, never the visibility rule of the source
// CVE, and a bad filter is 400 INVALID_FILTER.
func TestFindingsRelatedCVEs_TakesTheListFilter(t *testing.T) {
	h := newGroupScopeHarness(t)
	admin := flCaller{"owner", h.owner, true}
	// FA (cveA) and FB2 (cveB2) share component A; FB2 is high, out of memberA's scope.
	path := "/api/v1/findings/related-cves/" + url.PathEscape(h.cveA) + "?"
	status, _, body := h.listFindingsPath(t, admin, path)
	if status != http.StatusOK || !strings.Contains(body, h.cveB2) {
		t.Fatalf("admin related CVEs: %d %.300s", status, body)
	}
	if _, _, body := h.listFindingsPath(t, admin, path+"severity=critical"); strings.Contains(body, h.cveB2) {
		t.Errorf("severity=critical should exclude the high CVE: %.300s", body)
	}
	if _, _, body := h.listFindingsPath(t, admin, path+"asset_id="+h.assetB.String()); !strings.Contains(body, h.cveB2) {
		t.Errorf("asset_id=B1 should keep the CVE on B1: %.300s", body)
	}
	memberA := flCaller{"memberA", h.memberA, false}
	if _, _, body := h.listFindingsPath(t, memberA, path+"asset_id="+h.assetB.String()); strings.Contains(body, h.cveB2) {
		t.Errorf("a filter must not widen memberA's scope: %.300s", body)
	}
	if status, _, body := h.listFindingsPath(t, admin, path+"severity=urgent"); status != http.StatusBadRequest || !strings.Contains(body, "INVALID_FILTER") {
		t.Errorf("bad filter: %d %.200s", status, body)
	}
}
