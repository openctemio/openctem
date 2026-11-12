package routes

// GET /findings row facts for the list cells: duplicates_marked counts only
// the duplicates the caller can read (a duplicate outside their data scope
// is neither shown nor counted), and the asset carries its crown-jewel and
// internet-facing flags.

import (
	"encoding/json"
	"net/http"
	"testing"
)

type rowFactsResponse struct {
	Data []struct {
		ID               string `json:"id"`
		DuplicatesMarked int    `json:"duplicates_marked"`
		Asset            *struct {
			ID                   string `json:"id"`
			IsCrownJewel         bool   `json:"is_crown_jewel"`
			IsInternetAccessible bool   `json:"is_internet_accessible"`
		} `json:"asset"`
	} `json:"data"`
}

func (h *gsHarness) rowFacts(t *testing.T, c flCaller) rowFactsResponse {
	t.Helper()
	status, _, body := h.listFindings(t, c, "")
	if status != http.StatusOK {
		t.Fatalf("%s GET /findings = %d: %.300s", c.name, status, body)
	}
	var out rowFactsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestFindingsList_DuplicatesMarkedFollowScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	// Both duplicates of FA live on asset B, outside memberA's scope.
	h.exec(`UPDATE findings SET duplicate_of = $1, status = 'duplicate' WHERE id IN ($2, $3)`,
		h.findingA.String(), h.findingB.String(), h.findingB2.String())

	dupOf := func(c flCaller, id string) (int, bool) {
		for _, d := range h.rowFacts(t, c).Data {
			if d.ID == id {
				return d.DuplicatesMarked, true
			}
		}
		return 0, false
	}
	fa := h.findingA.String()
	if n, ok := dupOf(flCaller{"owner", h.owner, true}, fa); !ok || n != 2 {
		t.Errorf("owner FA duplicates_marked = %d (listed %v), want 2", n, ok)
	}
	if n, ok := dupOf(flCaller{"full-data role", h.memberFull, false}, fa); !ok || n != 2 {
		t.Errorf("full-data FA duplicates_marked = %d (listed %v), want 2", n, ok)
	}
	// memberA reads FA but neither duplicate: not counted.
	if n, ok := dupOf(flCaller{"memberA", h.memberA, false}, fa); !ok || n != 0 {
		t.Errorf("memberA FA duplicates_marked = %d (listed %v), want 0", n, ok)
	}
	// A finding with no duplicates has none.
	if n, _ := dupOf(flCaller{"owner", h.owner, true}, h.findingB.String()); n != 0 {
		t.Errorf("owner FB duplicates_marked = %d, want 0", n)
	}
}

func TestFindingsList_AssetCrownJewelAndInternetFacing(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.exec(`UPDATE assets SET is_crown_jewel = true, exposure = 'public' WHERE id = $1`, h.assetA.String())
	h.exec(`UPDATE assets SET is_crown_jewel = false, exposure = 'private', is_internet_accessible = false WHERE id = $1`, h.assetB.String())
	for _, d := range h.rowFacts(t, flCaller{"owner", h.owner, true}).Data {
		if d.Asset == nil {
			continue
		}
		switch d.Asset.ID {
		case h.assetA.String():
			if !d.Asset.IsCrownJewel || !d.Asset.IsInternetAccessible {
				t.Errorf("asset A row %s: crown %v internet %v, want both", d.ID, d.Asset.IsCrownJewel, d.Asset.IsInternetAccessible)
			}
		case h.assetB.String():
			if d.Asset.IsCrownJewel || d.Asset.IsInternetAccessible {
				t.Errorf("asset B row %s: crown %v internet %v, want neither", d.ID, d.Asset.IsCrownJewel, d.Asset.IsInternetAccessible)
			}
		}
	}
}
