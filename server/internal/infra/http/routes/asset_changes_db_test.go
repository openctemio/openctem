package routes

// Asset change timeline (RFC-069 §11) over HTTP: one asset's timeline is
// readable only for assets in the caller's data scope (another is 404); the
// organization feed lists only in-scope assets; another tenant's asset is
// not found; pages follow the cursor; bad filters are 400.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type changePage struct {
	Items []struct {
		AssetID   string  `json:"asset_id"`
		AssetName string  `json:"asset_name"`
		Attribute string  `json:"attribute"`
		OldValue  string  `json:"old_value"`
		NewValue  string  `json:"new_value"`
		Reason    string  `json:"reason"`
		ActorID   *string `json:"actor_id"`
		Source    struct {
			Kind string `json:"kind"`
		} `json:"source"`
	} `json:"items"`
	NextCursor string `json:"next_cursor"`
}

func (h *dsHarness) changes(user shared.ID, admin bool, path string) (int, changePage, string) {
	h.t.Helper()
	status, body := h.do(user, admin, http.MethodGet, path, nil)
	var p changePage
	if status == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			h.t.Fatalf("decode %s: %v", path, err)
		}
	}
	return status, p, body
}

func (h *dsHarness) lockCriticality(user shared.ID, admin bool, assetID, value string) {
	h.t.Helper()
	path := "/api/v1/assets/" + assetID + "/attribute-sources/criticality/lock"
	if status, body := h.do(user, admin, http.MethodPut, path, map[string]any{"value": value}); status != http.StatusOK {
		h.t.Fatalf("lock %s = %d (%.200s)", assetID, status, body)
	}
}

func TestAssetChanges_TimelineAndFeedFollowTheDataScope(t *testing.T) {
	h := newDSHarness(t)
	a, b := h.assetA.String(), h.assetB.String()
	h.lockCriticality(h.memberA, false, a, "critical")
	h.lockCriticality(h.memberA, false, a, "low")
	h.lockCriticality(h.owner, true, b, "critical")

	status, page, body := h.changes(h.memberA, false, "/api/v1/assets/"+a+"/changes")
	if status != http.StatusOK || len(page.Items) != 2 {
		t.Fatalf("timeline = %d, %d items (body %.300s)", status, len(page.Items), body)
	}
	newest := page.Items[0]
	if newest.NewValue != "low" || newest.OldValue != "critical" || newest.Reason != "manual_lock" ||
		newest.Source.Kind != "manual" || newest.ActorID == nil || *newest.ActorID != h.memberA.String() {
		t.Fatalf("newest event = %+v", newest)
	}

	// Pages: one at a time, then the rest.
	_, p1, _ := h.changes(h.memberA, false, "/api/v1/assets/"+a+"/changes?limit=1")
	if len(p1.Items) != 1 || p1.NextCursor == "" {
		t.Fatalf("page 1 = %+v", p1)
	}
	_, p2, _ := h.changes(h.memberA, false, "/api/v1/assets/"+a+"/changes?limit=1&cursor="+url.QueryEscape(p1.NextCursor))
	if len(p2.Items) != 1 || p2.NextCursor != "" || p2.Items[0].NewValue != "critical" {
		t.Fatalf("page 2 = %+v", p2)
	}

	// Out of the member's scope: 404 without revealing the asset.
	status, _, body = h.changes(h.memberA, false, "/api/v1/assets/"+b+"/changes")
	if status != http.StatusNotFound || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("out-of-scope timeline = %d (body %.200s)", status, body)
	}

	// The feed: the member sees only in-scope assets; the owner sees both.
	_, feed, _ := h.changes(h.memberA, false, "/api/v1/assets/changes")
	for _, it := range feed.Items {
		if it.AssetID == b {
			t.Fatalf("the feed showed an out-of-scope asset: %+v", it)
		}
	}
	if len(feed.Items) != 2 {
		t.Fatalf("member feed = %d items, want 2", len(feed.Items))
	}
	_, all, _ := h.changes(h.owner, true, "/api/v1/assets/changes?source_kind=manual")
	seenB := false
	for _, it := range all.Items {
		seenB = seenB || it.AssetID == b
	}
	if !seenB {
		t.Fatal("the owner's feed misses an asset")
	}

	// Read-only callers may read; the gate is assets:read.
	ro := []string{permission.AssetsRead.String()}
	if status, body := h.doWithPerms(h.memberA, ro, http.MethodGet, "/api/v1/assets/"+a+"/changes", nil); status != http.StatusOK {
		t.Errorf("read-only timeline = %d (body %.200s)", status, body)
	}
	if status, _ := h.doWithPerms(h.memberA, []string{permission.FindingsRead.String()}, http.MethodGet, "/api/v1/assets/changes", nil); status != http.StatusForbidden {
		t.Errorf("feed without assets:read = %d, want 403", status)
	}
}

func TestAssetChanges_BadFiltersAndOtherTenant(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()
	for _, q := range []string{"limit=0", "limit=x", "attribute=name", "source_kind=sensor", "cursor=%25%25", "tag=" + strings.Repeat("x", 101)} {
		if status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/assets/"+a+"/changes?"+q, nil); status != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400 (body %.200s)", q, status, body)
		}
	}
	other, foreign := shared.NewID().String(), shared.NewID().String()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other, "ch-other-"+other)
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality) VALUES ($1, $2, 'ch-foreign.example.com', 'domain', 'high')`,
		foreign, other)
	if status, body := h.do(h.owner, true, http.MethodGet, "/api/v1/assets/"+foreign+"/changes", nil); status != http.StatusNotFound || strings.Contains(body, "ch-foreign") {
		t.Errorf("cross-tenant timeline = %d, want a bare 404 (body %.200s)", status, body)
	}
}
