package routes

// GET and PUT /api/v1/me/pins over the real routes and a migrated database:
// pins belong to one member in one organization; a saved view pin needs a
// view the member can see, and drops out when they no longer can; counts are
// the member's own list counts (their data scope); refs are validated so a
// pin can never become an outside link.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type pinsResp struct {
	Data []struct {
		Kind   string `json:"kind"`
		Ref    string `json:"ref"`
		Name   string `json:"name"`
		Params string `json:"params"`
		Count  *int64 `json:"count"`
	} `json:"data"`
	Max int `json:"max"`
}

func (h *gsHarness) pins(t *testing.T, user shared.ID, method string, body any) (int, pinsResp, string) {
	t.Helper()
	status, raw := h.do(user, false, method, "/api/v1/me/pins", body)
	var out pinsResp
	_ = json.Unmarshal([]byte(raw), &out)
	return status, out, raw
}

func pinList(pins ...[2]string) map[string]any {
	out := make([]map[string]string, len(pins))
	for i, p := range pins {
		out[i] = map[string]string{"kind": p[0], "ref": p[1]}
	}
	return map[string]any{"pins": out}
}

func TestNavPins_OwnListScopedCountsAndVisibility(t *testing.T) {
	h := newGroupScopeHarness(t)
	status, view, raw := h.createView(t, h.memberA, map[string]any{"page": "findings", "name": "My SAST", "query": "source=sast"})
	if status != http.StatusCreated {
		t.Fatalf("create view: %d %s", status, raw)
	}

	status, got, raw := h.pins(t, h.memberA, http.MethodPut, pinList(
		[2]string{"page", "/my-work"},
		[2]string{"quick_view", "needs_triage"},
		[2]string{"saved_view", view.ID},
	))
	if status != http.StatusOK || len(got.Data) != 3 || got.Max != 12 {
		t.Fatalf("PUT = %d %s", status, raw)
	}
	if got.Data[0].Kind != "page" || got.Data[0].Count != nil {
		t.Errorf("page pin = %+v", got.Data[0])
	}
	// The saved view's count is memberA's own list count (data scope applies).
	_, total, _ := h.listIDs(t, flCaller{"memberA", h.memberA, false}, "source=sast")
	sv := got.Data[2]
	if sv.Name != "My SAST" || sv.Count == nil || *sv.Count != total {
		t.Errorf("saved view pin = %+v, want name and count %d", sv, total)
	}
	qv := got.Data[1]
	if qv.Params == "" || qv.Count == nil {
		t.Fatalf("quick view pin = %+v", qv)
	}
	q, _ := url.ParseQuery(qv.Params)
	_, qtotal, _ := h.listIDs(t, flCaller{"memberA", h.memberA, false}, q.Encode())
	if *qv.Count != qtotal {
		t.Errorf("quick view count %d, list total %d", *qv.Count, qtotal)
	}

	// The session bootstrap carries the same pins and counts for memberA, and
	// none of them for anyone else.
	bstatus, braw := h.do(h.memberA, false, http.MethodGet, "/api/v1/test/bootstrap-pins", nil)
	var boot pinsResp
	if err := json.Unmarshal([]byte(braw), &boot); bstatus != http.StatusOK || err != nil || len(boot.Data) != 3 {
		t.Fatalf("bootstrap pins = %d %s", bstatus, braw)
	}
	for i := range boot.Data {
		if boot.Data[i].Ref != got.Data[i].Ref || (boot.Data[i].Count == nil) != (got.Data[i].Count == nil) ||
			(boot.Data[i].Count != nil && *boot.Data[i].Count != *got.Data[i].Count) {
			t.Errorf("bootstrap pin %d = %+v, GET /me/pins = %+v", i, boot.Data[i], got.Data[i])
		}
	}
	var other pinsResp
	if bstatus, braw := h.do(h.ownerB, false, http.MethodGet, "/api/v1/test/bootstrap-pins", nil); bstatus != http.StatusOK {
		t.Errorf("ownerB bootstrap pins = %d %s", bstatus, braw)
	} else if err := json.Unmarshal([]byte(braw), &other); err != nil || len(other.Data) != 0 {
		t.Errorf("ownerB bootstrap pins = %s, want empty", braw)
	}

	// Another member sees none of memberA's pins and cannot pin their view.
	if status, other, _ := h.pins(t, h.ownerB, http.MethodGet, nil); status != http.StatusOK || len(other.Data) != 0 {
		t.Errorf("ownerB GET = %d %+v, want empty", status, other.Data)
	}
	if status, _, _ := h.pins(t, h.memberFree, http.MethodPut, pinList([2]string{"saved_view", view.ID})); status != http.StatusNotFound {
		t.Errorf("pinning someone else's private view = %d, want 404", status)
	}

	// A deleted view drops out of the list.
	if status, raw := h.do(h.memberA, false, http.MethodDelete, "/api/v1/views/"+view.ID, nil); status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("delete view: %d %s", status, raw)
	}
	_, got, _ = h.pins(t, h.memberA, http.MethodGet, nil)
	for _, p := range got.Data {
		if p.Kind == "saved_view" {
			t.Errorf("deleted view still pinned: %+v", p)
		}
	}
}

func TestNavPins_RefusesBadRefs(t *testing.T) {
	h := newGroupScopeHarness(t)
	for name, body := range map[string]map[string]any{
		"outside link":       pinList([2]string{"page", "https://evil.example/"}),
		"protocol relative":  pinList([2]string{"page", "//evil.example"}),
		"traversal":          pinList([2]string{"page", "/findings/../admin"}),
		"unknown quick view": pinList([2]string{"quick_view", "everything"}),
		"unknown kind":       pinList([2]string{"script", "/"}),
		"bad view id":        pinList([2]string{"saved_view", "x"}),
		"too many": pinList([2]string{"page", "/a"}, [2]string{"page", "/b"}, [2]string{"page", "/c"},
			[2]string{"page", "/d"}, [2]string{"page", "/e"}, [2]string{"page", "/f"}, [2]string{"page", "/g"},
			[2]string{"page", "/h"}, [2]string{"page", "/i"}, [2]string{"page", "/j"}, [2]string{"page", "/k"},
			[2]string{"page", "/l"}, [2]string{"page", "/m"}),
	} {
		if status, _, raw := h.pins(t, h.memberA, http.MethodPut, body); status != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d %s, want 400", name, status, raw)
		}
	}
	// Nothing was stored by the refused writes.
	if _, got, _ := h.pins(t, h.memberA, http.MethodGet, nil); len(got.Data) != 0 {
		t.Errorf("refused writes stored pins: %+v", got.Data)
	}
}

func TestNavPins_PerOrganization(t *testing.T) {
	h := newGroupScopeHarness(t)
	if status, _, raw := h.pins(t, h.memberA, http.MethodPut, pinList([2]string{"page", "/my-work"})); status != http.StatusOK {
		t.Fatalf("PUT = %d %s", status, raw)
	}
	// The row is keyed by this organization; another organization's id
	// matches nothing.
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM nav_pins WHERE user_id = $1 AND tenant_id = $2`,
		h.memberA.String(), h.tenant.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("own tenant rows = %d (%v)", n, err)
	}
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM nav_pins WHERE user_id = $1 AND tenant_id <> $2`,
		h.memberA.String(), h.tenant.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("other tenant rows = %d (%v)", n, err)
	}
}
