package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TestFindingApprovalRepository_List pins the approvals list: the status
// filter, the per-status counts, tenant isolation, and the data scope (a
// restricted user sees, counts and pages only approvals for findings on
// assets in their scope).
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestFindingApprovalRepository_List(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	newTenant := func(name string) shared.ID {
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
			id.String(), name, name+"-"+id.String()[28:])
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, id.String()) })
		return id
	}
	newFinding := func(tenant shared.ID, assetName string) (assetID, findingID shared.ID) {
		assetID, findingID = shared.NewID(), shared.NewID()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,$3,'domain')`,
			assetID.String(), tenant.String(), assetName)
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'appr-tool', 'm', 'high', $1::text, 'new')`,
			findingID.String(), tenant.String(), assetID.String())
		return assetID, findingID
	}
	newApproval := func(tenant, finding shared.ID, status string) {
		mustExec(t, db, `INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, justification, status)
			VALUES ($1,$2,$3,'false_positive','reviewed',$4)`,
			shared.NewID().String(), tenant.String(), finding.String(), status)
	}

	tenant := newTenant("appr-list")
	inAsset, inFinding := newFinding(tenant, "in-scope.example.com")
	_, outFinding := newFinding(tenant, "out-of-scope.example.com")
	newApproval(tenant, inFinding, "pending")
	newApproval(tenant, inFinding, "approved")
	newApproval(tenant, inFinding, "rejected")
	newApproval(tenant, outFinding, "pending")
	newApproval(tenant, outFinding, "approved")

	// Another tenant's approvals never show up.
	other := newTenant("appr-other")
	_, otherFinding := newFinding(other, "other.example.com")
	newApproval(other, otherFinding, "pending")
	newApproval(other, otherFinding, "approved")

	// A restricted user who sees only inAsset.
	userID := shared.NewID()
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`,
		userID.String(), userID.String()+"@example.com")
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, userID.String()) })
	mustExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1,$2,$3)`,
		userID.String(), tenant.String(), inAsset.String())
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM user_accessible_assets WHERE user_id=$1`, userID.String())
	})

	repo := NewFindingApprovalRepository(&DB{DB: db})
	page := pagination.New(1, 50)

	t.Run("unrestricted: status filter and counts", func(t *testing.T) {
		res, err := repo.List(ctx, tenant, vulnerability.ApprovalFilter{Status: vulnerability.ApprovalStatusApproved}, page, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 2 || len(res.Data) != 2 {
			t.Fatalf("approved: total=%d len=%d, want 2", res.Total, len(res.Data))
		}
		for _, a := range res.Data {
			if a.Status != vulnerability.ApprovalStatusApproved || a.TenantID != tenant {
				t.Fatalf("unexpected approval %+v", a)
			}
		}
		want := map[vulnerability.ApprovalStatus]int64{"pending": 2, "approved": 2, "rejected": 1}
		for st, n := range want {
			if res.StatusCounts[st] != n {
				t.Errorf("count %s = %d, want %d", st, res.StatusCounts[st], n)
			}
		}
	})

	t.Run("no status lists every status of the tenant only", func(t *testing.T) {
		res, err := repo.List(ctx, tenant, vulnerability.ApprovalFilter{}, page, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 5 || len(res.Data) != 5 {
			t.Fatalf("all: total=%d len=%d, want 5", res.Total, len(res.Data))
		}
	})

	t.Run("data scope: only approvals for in-scope findings, counted the same way", func(t *testing.T) {
		scope := &shared.DataScope{TenantID: tenant, UserID: userID}
		res, err := repo.List(ctx, tenant, vulnerability.ApprovalFilter{}, page, scope)
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 3 || len(res.Data) != 3 {
			t.Fatalf("scoped: total=%d len=%d, want 3", res.Total, len(res.Data))
		}
		for _, a := range res.Data {
			if a.FindingID != inFinding {
				t.Fatalf("out-of-scope approval leaked: %+v", a)
			}
		}
		if res.StatusCounts[vulnerability.ApprovalStatusPending] != 1 || res.StatusCounts[vulnerability.ApprovalStatusApproved] != 1 {
			t.Fatalf("scoped counts leak out-of-scope approvals: %v", res.StatusCounts)
		}
	})

	t.Run("a scope row in another tenant grants nothing here", func(t *testing.T) {
		scope := &shared.DataScope{TenantID: other, UserID: userID}
		res, err := repo.List(ctx, other, vulnerability.ApprovalFilter{}, page, scope)
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 0 || len(res.Data) != 0 {
			t.Fatalf("cross-tenant scope: total=%d len=%d, want 0", res.Total, len(res.Data))
		}
	})

	t.Run("pagination pages under the filter", func(t *testing.T) {
		res, err := repo.List(ctx, tenant, vulnerability.ApprovalFilter{}, pagination.New(2, 2), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 5 || len(res.Data) != 2 {
			t.Fatalf("page 2: total=%d len=%d, want 5/2", res.Total, len(res.Data))
		}
	})
}
