package routes

// Saved views: negative authorisation tests over the real routes and a
// migrated database. A view the caller may not see answers 404 with a body
// that carries nothing of the view (not its name, owner, query or group); a
// view of another tenant is never reachable, the tenant coming from the
// authenticated principal; a view shared with the whole organization is
// readable by members and changed only by its owner.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const (
	svSecretName  = "Quarterly-Payroll-Exposure"
	svSecretQuery = "source=sast&sort=-severity"
)

// svSharePerms is the default member set plus the right to share a view with
// the whole organization.
func svSharePerms() []string {
	return append([]string{permission.FindingsViewsShare.String()}, dsMemberPerms...)
}

// doAs sends a request as user of tenant with the given permissions (nil =
// the default member set) and returns status and the raw body.
func (h *gsHarness) doAs(user shared.ID, tenant string, perms []string, method, path string, body any) (int, string) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Tenant", tenant)
	if len(perms) > 0 {
		req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// viewRowDigest fingerprints the whole stored row, so "unchanged" means every
// column, including updated_at.
func (h *gsHarness) viewRowDigest(id string) string {
	h.t.Helper()
	var d string
	if err := h.db.QueryRowContext(context.Background(), `SELECT md5(sv::text) FROM saved_views sv WHERE id = $1`, id).Scan(&d); err != nil {
		h.t.Fatalf("view row %s: %v", id, err)
	}
	return d
}

// assertNoViewLeak fails when the raw body carries anything of the view.
func assertNoViewLeak(t *testing.T, what, body string, owner shared.ID, extra ...string) {
	t.Helper()
	for _, s := range append([]string{svSecretName, svSecretQuery, "sast", "-severity", owner.String()}, extra...) {
		if strings.Contains(body, s) {
			t.Errorf("%s: body leaks %q: %s", what, s, body)
		}
	}
}

type svRequest struct {
	method string
	body   any
}

func svWriteRequests() []svRequest {
	return []svRequest{
		{http.MethodGet, nil},
		{http.MethodPut, map[string]any{"name": "hijack", "query": "severity=low"}},
		{http.MethodDelete, nil},
	}
}

func TestSavedViews_PrivateViewIsInvisibleToOtherUsersOfTheTenant(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	status, v, raw := h.createView(t, h.memberA, map[string]any{"page": "findings", "name": svSecretName, "query": svSecretQuery})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, raw)
	}
	before := h.viewRowDigest(v.ID)
	path := "/api/v1/views/" + v.ID

	// Another member of the same tenant: GET, PUT and DELETE are 404 (never
	// 403 or success) and the stored view does not change. There is no PATCH
	// route: it must not succeed either. The body carries nothing of the view.
	others := []shared.ID{h.memberStrict, h.memberFree, h.memberFull}
	for _, other := range others {
		for _, req := range svWriteRequests() {
			status, body := h.doAs(other, ten, nil, req.method, path, req.body)
			if status != http.StatusNotFound {
				t.Errorf("%s by another member = %d, want 404 (%s)", req.method, status, body)
			}
			assertNoViewLeak(t, req.method+" by another member", body, h.memberA, "hijack")
		}
		status, body := h.doAs(other, ten, nil, http.MethodPatch, path, map[string]any{"name": "hijack"})
		if status < 400 || status == http.StatusForbidden {
			t.Errorf("PATCH by another member = %d, want a 4xx that is not 403", status)
		}
		assertNoViewLeak(t, "PATCH by another member", body, h.memberA, "hijack")
	}
	if h.viewRowDigest(v.ID) != before {
		t.Error("another member changed the private view")
	}

	// A hidden view answers exactly as a missing one: nothing tells them apart.
	missingStatus, missing := h.doAs(h.memberStrict, ten, nil, http.MethodGet, "/api/v1/views/"+shared.NewID().String(), nil)
	hiddenStatus, hidden := h.doAs(h.memberStrict, ten, nil, http.MethodGet, path, nil)
	if missingStatus != hiddenStatus || missing != hidden {
		t.Errorf("hidden view answers differently from a missing one:\n%d %s\n%d %s", hiddenStatus, hidden, missingStatus, missing)
	}

	// Listing never returns another user's private view.
	for _, other := range others {
		status, body := h.doAs(other, ten, nil, http.MethodGet, "/api/v1/views?page=findings", nil)
		if status != http.StatusOK {
			t.Fatalf("list: %d %s", status, body)
		}
		assertNoViewLeak(t, "list", body, h.memberA)
		if strings.Contains(body, v.ID) {
			t.Errorf("list carries the private view id: %s", body)
		}
	}
	// The owner still sees it, so the checks above are not vacuous.
	if got := h.listViews(t, h.memberA); len(got) != 1 || got[0].Name != svSecretName {
		t.Errorf("owner list = %+v", got)
	}
}

func TestSavedViews_ViewOfAnotherTenantIsNotFoundOverHTTP(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	status, v, raw := h.createView(t, h.memberA, map[string]any{"page": "findings", "name": svSecretName, "query": svSecretQuery})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, raw)
	}
	// A view shared with the organization too: isolation holds for it as well.
	perms := svSharePerms()
	st, body := h.doAs(h.memberA, ten, perms, http.MethodPost, "/api/v1/views",
		map[string]any{"page": "findings", "name": svSecretName + "-org", "query": svSecretQuery, "share_with_org": true})
	if st != http.StatusCreated {
		t.Fatalf("create org view: %d %s", st, body)
	}
	var org svResp
	_ = json.Unmarshal([]byte(body), &org)

	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "sv-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	digests := map[string]string{v.ID: h.viewRowDigest(v.ID), org.ID: h.viewRowDigest(org.ID)}

	// The caller may even carry the owner's user id (a person in two
	// organizations) or be a stranger: only the tenant of the principal counts.
	for _, caller := range []shared.ID{h.memberA, shared.NewID()} {
		for id := range digests {
			for _, req := range svWriteRequests() {
				status, body := h.doAs(caller, other.String(), perms, req.method, "/api/v1/views/"+id, req.body)
				if status != http.StatusNotFound {
					t.Errorf("%s of another tenant's view = %d, want 404 (%s)", req.method, status, body)
				}
				assertNoViewLeak(t, req.method+" cross-tenant", body, h.memberA, "hijack")
			}
		}
		status, body := h.doAs(caller, other.String(), perms, http.MethodGet, "/api/v1/views?page=findings", nil)
		if status != http.StatusOK {
			t.Fatalf("cross-tenant list: %d %s", status, body)
		}
		assertNoViewLeak(t, "cross-tenant list", body, h.memberA)
	}
	for id, d := range digests {
		if h.viewRowDigest(id) != d {
			t.Errorf("view %s changed by a caller of another tenant", id)
		}
	}
}

func TestSavedViews_OrgSharedViewReadableByMembersWritableByOwnerOnly(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	share := svSharePerms()

	// Sharing with the organization needs findings:views:share (negative).
	status, body := h.doAs(h.memberA, ten, nil, http.MethodPost, "/api/v1/views",
		map[string]any{"page": "findings", "name": "org-no-perm", "query": "", "share_with_org": true})
	if status != http.StatusForbidden {
		t.Errorf("share without findings:views:share = %d, want 403 (%s)", status, body)
	}

	status, body = h.doAs(h.memberA, ten, share, http.MethodPost, "/api/v1/views",
		map[string]any{"page": "findings", "name": "Org SAST", "query": "source=sast", "share_with_org": true})
	if status != http.StatusCreated {
		t.Fatalf("create org view: %d %s", status, body)
	}
	var v svResp
	_ = json.Unmarshal([]byte(body), &v)
	path := "/api/v1/views/" + v.ID

	// Positive: every member reads and lists it, and sees they are not the owner.
	for _, other := range []shared.ID{h.memberStrict, h.memberFree} {
		status, body := h.doAs(other, ten, nil, http.MethodGet, path, nil)
		var got svResp
		_ = json.Unmarshal([]byte(body), &got)
		if status != http.StatusOK || got.Name != "Org SAST" || got.IsOwner {
			t.Errorf("member read of an org view: %d %s", status, body)
		}
		found := false
		for _, lv := range h.listViews(t, other) {
			found = found || lv.ID == v.ID
		}
		if !found {
			t.Error("org view missing from a member's list")
		}
	}

	// Negative: a member, even one holding the share permission, can neither
	// edit nor delete it (403: they may see it), and the row is unchanged.
	before := h.viewRowDigest(v.ID)
	for _, perms := range [][]string{nil, share} {
		if status, body := h.doAs(h.memberFree, ten, perms, http.MethodPut, path,
			map[string]any{"name": "hijack", "query": "", "share_with_org": true}); status != http.StatusForbidden {
			t.Errorf("member PUT of an org view = %d, want 403 (%s)", status, body)
		}
		if status, body := h.doAs(h.memberFree, ten, perms, http.MethodDelete, path, nil); status != http.StatusForbidden {
			t.Errorf("member DELETE of an org view = %d, want 403 (%s)", status, body)
		}
	}
	if h.viewRowDigest(v.ID) != before {
		t.Error("a non-owner changed the org-shared view")
	}

	// Positive: the owner edits and deletes it.
	if status, body := h.doAs(h.memberA, ten, share, http.MethodPut, path,
		map[string]any{"name": "Org SAST v2", "query": "source=sast", "share_with_org": true}); status != http.StatusOK {
		t.Errorf("owner PUT = %d %s", status, body)
	}
	if status, body := h.doAs(h.memberA, ten, share, http.MethodDelete, path, nil); status != http.StatusNoContent {
		t.Errorf("owner DELETE = %d %s", status, body)
	}
}
