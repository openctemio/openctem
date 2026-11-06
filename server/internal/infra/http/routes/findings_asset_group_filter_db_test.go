package routes

// GET /api/v1/findings?asset_group_id= narrows to the findings on the
// group's members (it used to be ignored and return every finding), inside
// the caller's data scope, and never matches another tenant's group.
// Requires DATABASE_URL.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestFindingsList_AssetGroupFilter(t *testing.T) {
	h := newDSHarness(t)
	fa, fb := h.findingA.String(), h.findingB.String()
	// A second group holding only B1.
	onlyB := shared.NewID()
	h.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'ds-group-b')`, onlyB.String(), h.tenant.String())
	h.exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, onlyB.String(), h.assetB.String())
	// A group of another tenant naming this tenant's asset (bad data).
	other, foreign := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "agf-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'foreign')`, foreign.String(), other.String())
	h.exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, foreign.String(), h.assetA.String())

	list := func(user shared.ID, admin bool, group shared.ID) string {
		t.Helper()
		status, body := h.do(user, admin, http.MethodGet, "/api/v1/findings/?asset_group_id="+group.String(), nil)
		if status != http.StatusOK {
			t.Fatalf("list ?asset_group_id = %d %.300s", status, body)
		}
		return body
	}
	has := func(body string, ids ...string) bool {
		for _, id := range ids {
			if !strings.Contains(body, id) {
				return false
			}
		}
		return true
	}

	if b := list(h.owner, true, h.group); !has(b, fa, fb) {
		t.Errorf("owner, group of A1+B1: want both findings (%.300s)", b)
	}
	if b := list(h.owner, true, onlyB); !has(b, fb) || strings.Contains(b, fa) {
		t.Errorf("owner, group of B1: want only FB (%.300s)", b)
	}
	// The data scope still applies: memberA sees only A1 of the group.
	if b := list(h.memberA, false, h.group); !has(b, fa) || strings.Contains(b, fb) {
		t.Errorf("memberA, group of A1+B1: want only FA (%.300s)", b)
	}
	if b := list(h.memberA, false, onlyB); strings.Contains(b, fb) || strings.Contains(b, fa) {
		t.Errorf("memberA, group of B1: want nothing (%.300s)", b)
	}
	// Another tenant's group never matches.
	if b := list(h.owner, true, foreign); strings.Contains(b, fa) || strings.Contains(b, fb) {
		t.Errorf("another tenant's group matched (%.300s)", b)
	}
}
