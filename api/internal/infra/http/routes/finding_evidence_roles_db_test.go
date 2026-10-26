package routes

// Evidence roles, reader order and the finding's evidence version
// (docs/architecture/finding-evidence.md) over the real route registration,
// middleware chain and a migrated database:
//   - a new item is supporting at position 0 and every evidence change
//     (insert, role, order, delete) bumps findings.evidence_version, without
//     touching findings.row_version;
//   - changing a role or order needs findings:write, an item of the named
//     finding, and the finding in the caller's tenant and data scope;
//   - a pentest finding's evidence changes only through the campaign gate.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// storeAt puts one HTTP exchange for path on the finding; each path is a distinct item.
func (h *evHarness) storeAt(tenant, finding shared.ID, path string) {
	h.t.Helper()
	items := evidencedom.FromToolProperties(map[string]any{
		"request":  "GET " + path + " HTTP/1.1\r\nHost: a1.example.com\r\n\r\n",
		"response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody of " + path,
	}, "https://a1.example.com"+path, "nuclei "+path)
	h.svc.StoreDetections(context.Background(), tenant, []evidenceapp.Detection{
		{Fingerprint: finding.String(), Items: items, Meta: evidenceapp.Meta{ToolName: "nuclei", RuleID: "r" + path}},
	})
}

func (h *evHarness) versions(finding shared.ID) (evidence, row int64) {
	h.t.Helper()
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT evidence_version, row_version FROM findings WHERE id = $1`, finding.String()).Scan(&evidence, &row); err != nil {
		h.t.Fatal(err)
	}
	return evidence, row
}

func (h *evHarness) patchItem(user shared.ID, perms []permission.Permission, finding shared.ID, item, body string) evResp {
	return h.do(user, perms, http.MethodPatch, "/api/v1/findings/"+finding.String()+"/evidence-items/"+item, body, false)
}

func (h *evHarness) putOrder(user shared.ID, perms []permission.Permission, finding shared.ID, ids ...string) evResp {
	b, _ := json.Marshal(map[string]any{"item_ids": ids})
	return h.do(user, perms, http.MethodPut, "/api/v1/findings/"+finding.String()+"/evidence-items/order", string(b), false)
}

var evWrite = []permission.Permission{permission.FindingsRead, permission.FindingsWrite}

func TestEvidenceRoles_DefaultsVersionAndRowVersion(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	_, row0 := h.versions(h.findingA1)
	h.storeAt(h.tenantA, h.findingA1, "/one")
	h.storeAt(h.tenantA, h.findingA1, "/two")

	if v, row := h.versions(h.findingA1); v != 2 || row != row0 {
		t.Fatalf("after two inserts evidence_version = %d (want 2), row_version %d -> %d (want unchanged)", v, row0, row)
	}
	r, out := h.list(h.reader, h.findingA1)
	if r.code != http.StatusOK || len(out.Data) != 2 || out.EvidenceVersion != 2 || out.ProofCount != 0 {
		t.Fatalf("list = %d %s", r.code, r.body)
	}
	for _, it := range out.Data {
		if it.Role != "supporting" || it.Position != 0 {
			t.Errorf("new item = role %q position %d, want supporting 0", it.Role, it.Position)
		}
	}

	// Deleting an item is an evidence change too.
	h.exec(`DELETE FROM finding_evidence WHERE id = $1`, out.Data[0].ID)
	if v, row := h.versions(h.findingA1); v != 3 || row != row0 {
		t.Fatalf("after delete evidence_version = %d (want 3), row_version %d -> %d", v, row0, row)
	}
	// Another finding's version is untouched.
	if v, _ := h.versions(h.findingA2); v != 0 {
		t.Errorf("unrelated finding evidence_version = %d, want 0", v)
	}
}

func TestEvidenceRoles_PatchRoleAndOrder(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.storeAt(h.tenantA, h.findingA1, "/one")
	h.storeAt(h.tenantA, h.findingA1, "/two")
	h.storeAt(h.tenantA, h.findingA1, "/three")
	_, out := h.list(h.reader, h.findingA1)
	ids := []string{out.Data[0].ID, out.Data[1].ID, out.Data[2].ID}

	v0, row0 := h.versions(h.findingA1)
	r := h.patchItem(h.reader, evWrite, h.findingA1, ids[2], `{"role":"proof"}`)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"role":"proof"`) {
		t.Fatalf("patch role = %d %s", r.code, r.body)
	}
	if v, row := h.versions(h.findingA1); v != v0+1 || row != row0 {
		t.Errorf("role change: evidence_version %d -> %d, row_version %d -> %d", v0, v, row0, row)
	}
	if _, out := h.list(h.reader, h.findingA1); out.ProofCount != 1 {
		t.Errorf("proof_count = %d, want 1", out.ProofCount)
	}
	// A role set to the value it has changes nothing, and so no version.
	h.patchItem(h.reader, evWrite, h.findingA1, ids[2], `{"role":"proof"}`)
	if v, _ := h.versions(h.findingA1); v != v0+1 {
		t.Errorf("same role again bumped the version to %d", v)
	}

	// Validation.
	for _, body := range []string{`{}`, `{"role":"star"}`, `{"position":-1}`, `{"position":1001}`, `{"x":1}`} {
		if r := h.patchItem(h.reader, evWrite, h.findingA1, ids[0], body); r.code != http.StatusBadRequest {
			t.Errorf("patch %s = %d, want 400", body, r.code)
		}
	}

	// Reorder: the listed order wins, the version moves once.
	want := []string{ids[1], ids[2], ids[0]}
	v1, _ := h.versions(h.findingA1)
	if r := h.putOrder(h.reader, evWrite, h.findingA1, want...); r.code != http.StatusNoContent {
		t.Fatalf("reorder = %d %s", r.code, r.body)
	}
	if v, _ := h.versions(h.findingA1); v != v1+1 {
		t.Errorf("reorder: evidence_version %d -> %d, want one bump", v1, v)
	}
	_, out = h.list(h.reader, h.findingA1)
	for i, it := range out.Data {
		if it.ID != want[i] || it.Position != i {
			t.Errorf("item %d = %s at %d, want %s at %d", i, it.ID, it.Position, want[i], i)
		}
	}
	// The same order again moves nothing.
	if r := h.putOrder(h.reader, evWrite, h.findingA1, want...); r.code != http.StatusNoContent {
		t.Fatalf("reorder again = %d", r.code)
	}
	if v, _ := h.versions(h.findingA1); v != v1+1 {
		t.Errorf("an unchanged order bumped the version to %d", v)
	}
	// A repeated id, an unknown id and an empty list are refused.
	if r := h.putOrder(h.reader, evWrite, h.findingA1, ids[0], ids[0]); r.code != http.StatusBadRequest {
		t.Errorf("repeated id = %d, want 400", r.code)
	}
	if r := h.putOrder(h.reader, evWrite, h.findingA1); r.code != http.StatusBadRequest {
		t.Errorf("empty order = %d, want 400", r.code)
	}
	if r := h.putOrder(h.reader, evWrite, h.findingA1, shared.NewID().String()); r.code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", r.code)
	}
}

func TestEvidenceRoles_Isolation(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.storeAt(h.tenantA, h.findingA1, "/a1")
	h.storeAt(h.tenantA, h.findingA2, "/a2")
	h.storeAt(h.tenantB, h.findingB, "/b")
	_, a1 := h.list(h.reader, h.findingA1)
	_, a2 := h.list(h.reader, h.findingA2)
	var bItem string
	if err := h.db.QueryRow(`SELECT id FROM finding_evidence WHERE finding_id = $1`, h.findingB.String()).Scan(&bItem); err != nil {
		t.Fatal(err)
	}
	a1Item, a2Item := a1.Data[0].ID, a2.Data[0].ID
	vB, _ := h.versions(h.findingB)

	// Without findings:write.
	if r := h.patchItem(h.reader, []permission.Permission{permission.FindingsRead}, h.findingA1, a1Item, `{"role":"proof"}`); r.code != http.StatusForbidden {
		t.Errorf("patch without findings:write = %d, want 403", r.code)
	}
	if r := h.putOrder(h.reader, []permission.Permission{permission.FindingsRead}, h.findingA1, a1Item); r.code != http.StatusForbidden {
		t.Errorf("order without findings:write = %d, want 403", r.code)
	}
	// Another tenant's finding and item: 404, nothing changes.
	if r := h.patchItem(h.reader, evWrite, h.findingB, bItem, `{"role":"proof"}`); r.code != http.StatusNotFound {
		t.Errorf("another tenant's finding = %d, want 404", r.code)
	}
	if r := h.putOrder(h.reader, evWrite, h.findingB, bItem); r.code != http.StatusNotFound {
		t.Errorf("order on another tenant's finding = %d, want 404", r.code)
	}
	// Another tenant's item named under my finding: 404.
	if r := h.patchItem(h.reader, evWrite, h.findingA1, bItem, `{"role":"proof"}`); r.code != http.StatusNotFound {
		t.Errorf("another tenant's item = %d, want 404", r.code)
	}
	if r := h.putOrder(h.reader, evWrite, h.findingA1, a1Item, bItem); r.code != http.StatusNotFound {
		t.Errorf("order with another tenant's item = %d, want 404", r.code)
	}
	// My other finding's item under this finding: 404.
	if r := h.patchItem(h.reader, evWrite, h.findingA1, a2Item, `{"role":"proof"}`); r.code != http.StatusNotFound {
		t.Errorf("another finding's item = %d, want 404", r.code)
	}
	// Out of data scope: 404 on the finding itself.
	if r := h.patchItem(h.scoped, evWrite, h.findingA2, a2Item, `{"role":"proof"}`); r.code != http.StatusNotFound {
		t.Errorf("out-of-scope finding = %d, want 404", r.code)
	}
	if r := h.putOrder(h.scoped, evWrite, h.findingA2, a2Item); r.code != http.StatusNotFound {
		t.Errorf("order out of scope = %d, want 404", r.code)
	}
	// In scope works.
	if r := h.patchItem(h.scoped, evWrite, h.findingA1, a1Item, `{"role":"baseline"}`); r.code != http.StatusOK {
		t.Errorf("in-scope patch = %d %s", r.code, r.body)
	}
	if n := h.count(`SELECT count(*) FROM finding_evidence WHERE role <> 'supporting' AND finding_id IN ($1, $2)`,
		h.findingA2.String(), h.findingB.String()); n != 0 {
		t.Errorf("%d items of other findings were changed", n)
	}
	if v, _ := h.versions(h.findingB); v != vB {
		t.Errorf("another tenant's evidence_version moved %d -> %d", vB, v)
	}
	// The change is audited and on the timeline, and holds no value.
	if n := h.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.evidence_updated'`, h.tenantA.String()); n < 1 {
		t.Errorf("no audit row for the role change")
	}
}

type fakePentestGate struct{ err error }

func (g fakePentestGate) CheckFindingEvidenceWrite(context.Context, string, string, string, bool) error {
	return g.err
}

func TestEvidenceRoles_PentestFindingFollowsCampaignGate(t *testing.T) {
	h := newEvidenceAuthzHarness(t)
	h.storeAt(h.tenantA, h.findingA1, "/p")
	h.exec(`UPDATE findings SET source = 'pentest' WHERE id = $1`, h.findingA1.String())
	h.asAdmin = true // an administrator passes the campaign visibility guard; the gate still decides
	r, out := h.list(h.reader, h.findingA1)
	if len(out.Data) == 0 {
		t.Fatalf("list = %d %s", r.code, r.body)
	}
	item := out.Data[0].ID
	body := `{"role":"proof"}`

	// No gate wired: refused.
	if r := h.patchItem(h.reader, evWrite, h.findingA1, item, body); r.code != http.StatusForbidden {
		t.Fatalf("pentest finding without a gate = %d, want 403", r.code)
	}
	for _, tc := range []struct {
		err  error
		want int
	}{
		{shared.ErrForbidden, http.StatusForbidden},
		{shared.ErrNotFound, http.StatusNotFound},
		{errors.New("boom"), http.StatusInternalServerError},
		{nil, http.StatusOK},
	} {
		h.evHandler.SetPentestGate(fakePentestGate{err: tc.err})
		if r := h.patchItem(h.reader, evWrite, h.findingA1, item, body); r.code != tc.want {
			t.Errorf("gate err %v = %d, want %d", tc.err, r.code, tc.want)
		}
	}
	var _ handler.PentestEvidenceGate = fakePentestGate{}
}
