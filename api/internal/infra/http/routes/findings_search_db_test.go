package routes

// POST /findings/search (RFC-048 FilterDocument) over the real routes: the
// document compiles through the same registry and caller-bound compiler as
// GET /findings, so OR groups and long id lists never reach outside the
// caller's scope, and bad documents are 400 INVALID_FILTER with a JSON path.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *gsHarness) search(t *testing.T, c flCaller, doc any) (int, string, []string, int64) {
	t.Helper()
	status, body := h.do(c.user, c.admin, http.MethodPost, "/api/v1/findings/search", doc)
	if status != http.StatusOK {
		return status, body, nil, 0
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
	return status, body, ids, out.Total
}

func TestFindingsSearch_DocumentWithinScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa, fb, fb2, fp := h.findingA.String(), h.findingB.String(), h.findingB2.String(), h.findingP.String()
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, fb)
	h.exec(`UPDATE findings SET epss_score = 0.5 WHERE id = $1`, fa)

	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}

	// 150 ids (more than GET allows) including every seeded finding.
	ids := []any{fa, fb, fb2, fp}
	for len(ids) < 150 {
		ids = append(ids, shared.NewID().String())
	}
	or := map[string]any{"v": 1, "filter": map[string]any{"any": []any{
		map[string]any{"field": "is_in_kev", "op": "eq", "value": true},
		map[string]any{"field": "epss_score", "op": "gte", "value": 0.1},
	}}}
	cases := []struct {
		name           string
		doc            any
		admin, memberA []string
	}{
		{"kev or epss", or, sorted(fa, fb), sorted(fa)},
		{"150 ids", map[string]any{"filter": map[string]any{"field": "id", "op": "in", "value": ids}}, sorted(fa, fb, fb2, fp), sorted(fa)},
		{"not", map[string]any{"filter": map[string]any{"not": map[string]any{"field": "severity", "op": "in", "value": []any{"critical"}}}}, sorted(fa, fb2, fp), sorted(fa)},
		{"shorthand", map[string]any{"filter": map[string]any{"source": []any{"sast"}, "severity": "high"}}, sorted(fa, fb2), sorted(fa)},
		{"out-of-scope asset", map[string]any{"filter": map[string]any{"asset_id": []any{h.assetB.String()}}}, sorted(fb, fb2), nil},
		{"empty", map[string]any{}, sorted(fa, fb, fb2, fp), sorted(fa)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, who := range []struct {
				caller flCaller
				want   []string
			}{{admin, c.admin}, {memberA, c.memberA}} {
				status, body, got, total := h.search(t, who.caller, c.doc)
				if status != http.StatusOK || strings.Join(got, ",") != strings.Join(who.want, ",") || total != int64(len(who.want)) {
					t.Errorf("%s %s = %d %v (total %d), want %v: %.200s", who.caller.name, c.name, status, got, total, who.want, body)
				}
				if who.caller == memberA {
					for _, leak := range []string{dsMarkerFindingB, dsMarkerAssetB} {
						if strings.Contains(body, leak) {
							t.Errorf("memberA %s leaked %q", c.name, leak)
						}
					}
				}
			}
		})
	}

	// The document and the equivalent GET return the same total.
	_, _, _, docTotal := h.search(t, admin, map[string]any{"filter": map[string]any{"severity": []any{"high"}, "status_not": "resolved"}})
	if _, getTotal, _ := h.listIDs(t, admin, "severity=high&status_not=resolved"); docTotal != getTotal {
		t.Errorf("document total %d != GET total %d", docTotal, getTotal)
	}
}

func TestFindingsSearch_BadDocuments(t *testing.T) {
	h := newGroupScopeHarness(t)
	for name, c := range map[string]struct {
		doc  any
		path string
	}{
		"unknown field": {map[string]any{"filter": map[string]any{"field": "is_kev", "op": "eq", "value": true}}, "filter.field"},
		"bad op":        {map[string]any{"filter": map[string]any{"field": "severity", "op": "gte", "value": "high"}}, "filter.op"},
		"unknown key":   {map[string]any{"filters": map[string]any{}}, "filters"},
		"deep":          {map[string]any{"filter": map[string]any{"all": []any{map[string]any{"any": []any{map[string]any{"not": map[string]any{"all": []any{map[string]any{"field": "severity", "op": "in", "value": []any{"high"}}}}}}}}}}, "filter.all[0].any[0].not"},
		"too big":       {map[string]any{"q": strings.Repeat("a", 40<<10)}, "$"},
	} {
		status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/findings/search", c.doc)
		var e struct {
			Code    string `json:"code"`
			Details []struct {
				Path string `json:"path"`
			} `json:"details"`
		}
		_ = json.Unmarshal([]byte(body), &e)
		if status != http.StatusBadRequest || e.Code != "INVALID_FILTER" || len(e.Details) == 0 || e.Details[0].Path != c.path {
			t.Errorf("%s: %d %.300s, want 400 INVALID_FILTER at %s", name, status, body, c.path)
		}
	}
}

func TestFindingFilterMeta(t *testing.T) {
	h := newGroupScopeHarness(t)
	status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/meta/filters/findings", nil)
	if status != http.StatusOK {
		t.Fatalf("meta: %d %s", status, body)
	}
	var out struct {
		Contract struct {
			Resource string `json:"resource"`
			Fields   []struct {
				Name string `json:"name"`
			} `json:"fields"`
			Aliases map[string]string `json:"aliases"`
		} `json:"contract"`
		Schema map[string]any `json:"document_schema"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Contract.Resource != "findings" || len(out.Contract.Fields) < 20 || out.Contract.Aliases["severities"] != "severity" || out.Schema["title"] != "FilterDocument" {
		t.Errorf("meta body: %.400s", body)
	}
}
