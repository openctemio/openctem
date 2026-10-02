package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Approve on a review id that does not exist in the caller's tenant returned
// 500 ("failed to execute merge"), and Reject on the same id returned 200
// {"status":"rejected"} although nothing was updated. Both must say 404, and a
// review owned by another tenant must be left exactly as it was.
func TestDedupReviewApproveRejectUnknownOrForeignIs404(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	owner := createTestTenant(t, db, "dedup-owner")
	other := createTestTenant(t, db, "dedup-other")
	keep := createTestAsset(t, db, owner, "dedup-keep")
	merge := createTestAsset(t, db, owner, "dedup-merge")
	reviewID := shared.NewID()
	if _, err := db.Exec(`
		INSERT INTO asset_dedup_review (id, tenant_id, normalized_name, asset_type,
			keep_asset_id, keep_asset_name, merge_asset_ids, merge_asset_names, status)
		VALUES ($1,$2,'dedup','repository',$3,'dedup-keep',ARRAY[$4]::uuid[],ARRAY['dedup-merge'],'pending')`,
		reviewID.String(), owner.String(), keep.String(), merge.String()); err != nil {
		t.Fatalf("insert review: %v", err)
	}
	t.Cleanup(func() {
		for _, tid := range []shared.ID{owner, other} {
			_, _ = db.Exec(`DELETE FROM asset_dedup_review WHERE tenant_id=$1`, tid.String())
			_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tid.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tid.String())
		}
	})

	pg := &postgres.DB{DB: db}
	h := handler.NewAdminDedupHandler(postgres.NewAssetDedupRepository(pg), postgres.NewFindingRepository(pg), logger.NewNop())

	call := func(action func(http.ResponseWriter, *http.Request), tenant shared.ID, id string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/dedup/reviews/"+id+"/x", nil)
		req.SetPathValue("id", id)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
		ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
		rec := httptest.NewRecorder()
		action(rec, req.WithContext(ctx))
		return rec.Code
	}

	unknown := shared.NewID().String()
	for name, tc := range map[string]struct {
		action func(http.ResponseWriter, *http.Request)
		tenant shared.ID
		id     string
	}{
		"approve unknown":          {h.Approve, owner, unknown},
		"reject unknown":           {h.Reject, owner, unknown},
		"approve another tenant's": {h.Approve, other, reviewID.String()},
		"reject another tenant's":  {h.Reject, other, reviewID.String()},
	} {
		if got := call(tc.action, tc.tenant, tc.id); got != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", name, got)
		}
	}

	var status string
	if err := db.QueryRow(`SELECT status FROM asset_dedup_review WHERE id=$1`, reviewID.String()).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("another tenant's call changed the review to %q", status)
	}

	// The owner can still act on it, and a second decision is a conflict.
	if got := call(h.Reject, owner, reviewID.String()); got != http.StatusOK {
		t.Fatalf("owner reject: got %d, want 200", got)
	}
	if got := call(h.Approve, owner, reviewID.String()); got != http.StatusConflict {
		t.Fatalf("approve after reject: got %d, want 409", got)
	}
}
