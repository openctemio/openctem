package routes

// Bulk routes need the single-item permission as well as
// findings:bulk_update: a custom role with bulk_update but without
// findings:status cannot change a status in bulk, and one without
// findings:assign cannot assign in bulk. Over the real routes, middleware,
// services and a migrated database.

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func TestBulkRoutes_NeedTheSingleItemPermission(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.vuln.SetAssigneeChecker(postgres.NewAccessControlRepository(&postgres.DB{DB: h.db}))
	fa := h.findingA.String()
	h.exec(`UPDATE findings SET status = 'new', assigned_to = NULL WHERE id = $1`, fa)

	noStatus := []string{
		permission.FindingsRead.String(), permission.FindingsBulkUpdate.String(), permission.FindingsAssign.String(),
	}
	noAssign := []string{
		permission.FindingsRead.String(), permission.FindingsBulkUpdate.String(), permission.FindingsStatus.String(),
	}
	noBulk := []string{
		permission.FindingsRead.String(), permission.FindingsStatus.String(), permission.FindingsAssign.String(),
	}
	statusBody := map[string]any{"finding_ids": []string{fa}, "status": "confirmed"}
	assignBody := map[string]any{"finding_ids": []string{fa}, "user_id": h.memberA.String()}

	for _, c := range []struct {
		name, path string
		perms      []string
		body       any
	}{
		{"bulk status without findings:status", "/api/v1/findings/bulk/status", noStatus, statusBody},
		{"bulk status without findings:bulk_update", "/api/v1/findings/bulk/status", noBulk, statusBody},
		{"bulk assign without findings:assign", "/api/v1/findings/bulk/assign", noAssign, assignBody},
		{"bulk assign without findings:bulk_update", "/api/v1/findings/bulk/assign", noBulk, assignBody},
	} {
		if status, body := h.doPerms(h.memberA, c.perms, http.MethodPost, c.path, c.body); status != http.StatusForbidden {
			t.Errorf("%s = %d %.300s, want 403", c.name, status, body)
		}
	}
	var st string
	var assignee *string
	if err := h.db.QueryRow(`SELECT status, assigned_to::text FROM findings WHERE id = $1`, fa).Scan(&st, &assignee); err != nil {
		t.Fatal(err)
	}
	if st != "new" || assignee != nil {
		t.Fatalf("a refused bulk request changed the finding: status=%s assignee=%v", st, assignee)
	}

	// Holding both permissions, the same requests go through.
	both := append(append([]string{}, noStatus...), permission.FindingsStatus.String())
	if status, body := h.doPerms(h.memberA, both, http.MethodPost, "/api/v1/findings/bulk/status", statusBody); status != http.StatusOK {
		t.Fatalf("bulk status with both permissions = %d %.300s, want 200", status, body)
	}
	if status, body := h.doPerms(h.memberA, both, http.MethodPost, "/api/v1/findings/bulk/assign", assignBody); status != http.StatusOK {
		t.Fatalf("bulk assign with both permissions = %d %.300s, want 200", status, body)
	}
	if err := h.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, fa).Scan(&st); err != nil || st != "confirmed" {
		t.Fatalf("status after the allowed bulk = %q, %v; want confirmed", st, err)
	}
}
