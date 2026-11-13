package routes

// Saving an asset's tags never removes a tag the editor did not remove:
// an edit is a change (tags_add / tags_remove) applied to the stored list,
// so tags a sensor, an import, a rule or another person set after the form
// was opened stay. The bulk tag action changes only the named tag on each
// asset, and nothing else about it.

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func (h *dsHarness) setTags(id shared.ID, tags ...string) {
	h.t.Helper()
	h.exec(`UPDATE assets SET tags = $1 WHERE id = $2`, pq.Array(tags), id.String())
}

func (h *dsHarness) tagsOf(id shared.ID) []string {
	h.t.Helper()
	var tags []string
	if err := h.db.QueryRowContext(context.Background(), `SELECT COALESCE(tags, '{}') FROM assets WHERE id = $1`, id.String()).
		Scan(pq.Array(&tags)); err != nil {
		h.t.Fatal(err)
	}
	return tags
}

func wantTags(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	g, w := slices.Clone(got), slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	if !slices.Equal(g, w) {
		t.Errorf("%s: tags = %v, want %v", what, got, want)
	}
}

// The edit form showed [team:web]; a sensor stored scanner:nuclei before the
// person saved. The old request (the whole list the form held) drops the
// sensor's tag; the change request keeps it.
func TestAssetTags_EditKeepsTagsSetSinceTheFormOpened(t *testing.T) {
	h := newDSHarness(t)
	path := "/api/v1/assets/" + h.assetA.String()

	// The reported failure: a replacement list built from the form's copy.
	h.setTags(h.assetA, "team:web", "scanner:nuclei")
	if status, body := h.do(h.owner, true, http.MethodPut, path, map[string]any{"tags": []string{"team:web", "pci"}}); status != http.StatusOK {
		t.Fatalf("replace = %d (%.200s)", status, body)
	}
	wantTags(t, "replacement list (documented: replaces)", h.tagsOf(h.assetA), "team:web", "pci")

	// The fix: the form sends what the person changed.
	h.setTags(h.assetA, "team:web", "scanner:nuclei")
	if status, body := h.do(h.owner, true, http.MethodPut, path, map[string]any{
		"tags_add": []string{"pci"}, "description": "edited",
	}); status != http.StatusOK {
		t.Fatalf("add = %d (%.200s)", status, body)
	}
	wantTags(t, "after tags_add", h.tagsOf(h.assetA), "team:web", "scanner:nuclei", "pci")

	// Removing names only the removed tag; a tag the asset lacks is ignored.
	if status, body := h.do(h.owner, true, http.MethodPut, path, map[string]any{
		"tags_remove": []string{"team:web", "never-there"},
	}); status != http.StatusOK {
		t.Fatalf("remove = %d (%.200s)", status, body)
	}
	wantTags(t, "after tags_remove", h.tagsOf(h.assetA), "scanner:nuclei", "pci")

	// An edit that touches no tag keeps every tag.
	if status, body := h.do(h.owner, true, http.MethodPut, path, map[string]any{"description": "again"}); status != http.StatusOK {
		t.Fatalf("plain edit = %d (%.200s)", status, body)
	}
	wantTags(t, "after an edit without tags", h.tagsOf(h.assetA), "scanner:nuclei", "pci")

	// Who added and removed which tag is in the audit trail (the removal is
	// the third edit's entry).
	found := false
	for _, r := range h.auditRows("asset.updated") {
		if r.ResourceID == h.assetA.String() && strings.Contains(r.Metadata, `"tags_removed": ["team:web"]`) && r.Actor == h.owner.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("no asset.updated entry names the removed tag: %+v", h.auditRows("asset.updated"))
	}
	h.wantAudit("asset.updated", h.assetA.String(), `"tags_added"`, "pci")
}

func TestAssetTags_ChangeRequestRefusals(t *testing.T) {
	h := newDSHarness(t)
	path := "/api/v1/assets/" + h.assetA.String()
	h.setTags(h.assetA, "keep")
	for name, body := range map[string]map[string]any{
		"list and change":    {"tags": []string{"a"}, "tags_add": []string{"b"}},
		"added and removed":  {"tags_add": []string{"x"}, "tags_remove": []string{"x"}},
		"reserved namespace": {"tags_add": []string{"system:root"}},
		"markup":             {"tags_add": []string{"<b>"}},
		"longer than 50":     {"tags_add": []string{strings.Repeat("x", 51)}},
	} {
		status, resp := h.do(h.owner, true, http.MethodPut, path, body)
		if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d (%.200s), want a validation error", name, status, resp)
		}
	}
	wantTags(t, "after refused changes", h.tagsOf(h.assetA), "keep")
}

// Two people edit the same asset from the same loaded copy: one removes a
// tag, the other adds one. Neither loses the other's change, in whichever
// order and even at the same moment.
func TestAssetTags_ConcurrentEditorsKeepBothChanges(t *testing.T) {
	h := newDSHarness(t)
	path := "/api/v1/assets/" + h.assetA.String()
	for round := range 20 {
		h.setTags(h.assetA, "shared", "old")
		var wg sync.WaitGroup
		errs := make(chan string, 2)
		for _, body := range []map[string]any{
			{"tags_remove": []string{"old"}},
			{"tags_add": []string{"new"}},
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if status, resp := h.do(h.owner, true, http.MethodPut, path, body); status != http.StatusOK {
					errs <- resp
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Fatalf("round %d: %s", round, e)
		}
		got := h.tagsOf(h.assetA)
		if !slices.Equal(sortedCopy(got), []string{"new", "shared"}) {
			t.Fatalf("round %d: tags = %v, want [shared new]", round, got)
		}
	}
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

func TestAssetTags_IsolationAndScope(t *testing.T) {
	h := newDSHarness(t)

	// Another organization's asset: 404, untouched.
	other := shared.NewID()
	otherAsset := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "ds-tags-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, tags) VALUES ($1, $2, 'other-tags.example.com', 'domain', 'low', '{theirs}')`,
		otherAsset.String(), other.String())
	if status, _ := h.do(h.owner, true, http.MethodPut, "/api/v1/assets/"+otherAsset.String(), map[string]any{"tags_remove": []string{"theirs"}}); status != http.StatusNotFound {
		t.Errorf("other organization's asset: %d, want 404", status)
	}
	wantTags(t, "other organization's asset", h.tagsOf(otherAsset), "theirs")

	// memberA's scope is asset A only.
	h.setTags(h.assetB, "b-only")
	if status, _ := h.do(h.memberA, false, http.MethodPut, "/api/v1/assets/"+h.assetB.String(), map[string]any{"tags_remove": []string{"b-only"}}); status != http.StatusNotFound {
		t.Errorf("out-of-scope asset: %d, want 404", status)
	}
	wantTags(t, "out-of-scope asset", h.tagsOf(h.assetB), "b-only")

	// Bulk: only the in-scope, own-organization asset changes.
	h.setTags(h.assetA, "a-only")
	status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/assets/bulk/tags", map[string]any{
		"asset_ids": []string{h.assetA.String(), h.assetB.String(), otherAsset.String()}, "add": []string{"bulk"},
	})
	if status != http.StatusOK {
		t.Fatalf("bulk = %d (%.200s)", status, body)
	}
	if !strings.Contains(body, `"updated":1`) || !strings.Contains(body, `"failed":2`) {
		t.Errorf("bulk result = %s, want 1 updated and 2 failed", body)
	}
	wantTags(t, "in-scope asset", h.tagsOf(h.assetA), "a-only", "bulk")
	wantTags(t, "out-of-scope asset after bulk", h.tagsOf(h.assetB), "b-only")
	wantTags(t, "other organization's asset after bulk", h.tagsOf(otherAsset), "theirs")
}

// Assets with different tags; one tag added in bulk, then removed in bulk:
// every other tag and every other field stays as it was.
func TestAssetTags_BulkChangesOnlyTheNamedTag(t *testing.T) {
	h := newDSHarness(t)
	h.setTags(h.assetA, "a1", "shared")
	h.setTags(h.assetB, "b1", "sensor:x")
	h.exec(`UPDATE assets SET description = 'kept', criticality = 'critical' WHERE id = $1`, h.assetB.String())
	ids := []string{h.assetA.String(), h.assetB.String()}

	status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/assets/bulk/tags", map[string]any{"asset_ids": ids, "add": []string{"shared"}})
	if status != http.StatusOK {
		t.Fatalf("bulk add = %d (%.200s)", status, body)
	}
	if !strings.Contains(body, `"updated":1`) || !strings.Contains(body, `"unchanged":1`) {
		t.Errorf("bulk add result = %s, want 1 updated, 1 unchanged", body)
	}
	wantTags(t, "A after bulk add", h.tagsOf(h.assetA), "a1", "shared")
	wantTags(t, "B after bulk add", h.tagsOf(h.assetB), "b1", "sensor:x", "shared")

	status, body = h.do(h.owner, true, http.MethodPost, "/api/v1/assets/bulk/tags", map[string]any{"asset_ids": ids, "remove": []string{"shared"}})
	if status != http.StatusOK {
		t.Fatalf("bulk remove = %d (%.200s)", status, body)
	}
	wantTags(t, "A after bulk remove", h.tagsOf(h.assetA), "a1")
	wantTags(t, "B after bulk remove", h.tagsOf(h.assetB), "b1", "sensor:x")

	var desc, crit string
	if err := h.db.QueryRowContext(context.Background(), `SELECT description, criticality FROM assets WHERE id = $1`, h.assetB.String()).Scan(&desc, &crit); err != nil {
		t.Fatal(err)
	}
	if desc != "kept" || crit != "critical" {
		t.Errorf("bulk tag change touched other fields: description %q criticality %q", desc, crit)
	}
	if rows := h.auditRows("asset.bulk_tags_changed"); len(rows) != 2 || !strings.Contains(rows[0].Metadata, "shared") {
		t.Errorf("bulk tag audit = %+v, want two entries naming the tag", rows)
	}

	for name, req := range map[string]map[string]any{
		"no change":           {"asset_ids": ids},
		"added and removed":   {"asset_ids": ids, "add": []string{"x"}, "remove": []string{"x"}},
		"invalid tag":         {"asset_ids": ids, "add": []string{"=cmd"}},
		"no assets":           {"asset_ids": []string{}, "add": []string{"x"}},
		"over 100 assets":     {"asset_ids": manyIDs(101), "add": []string{"x"}},
		"malformed asset ids": {"asset_ids": []string{"not-a-uuid"}, "add": []string{"x"}},
	} {
		if status, resp := h.do(h.owner, true, http.MethodPost, "/api/v1/assets/bulk/tags", req); status != http.StatusBadRequest &&
			status != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d (%.200s), want a validation error", name, status, resp)
		}
	}
	wantTags(t, "A after refused bulk", h.tagsOf(h.assetA), "a1")
}

func manyIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = shared.NewID().String()
	}
	return out
}
