package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// The ?search= filter must actually filter (it was silently ignored end-to-end).
func TestFindingList_SearchFilter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tenantID := createTestTenant(t, db, "search-tenant")
	assetID := createTestAsset(t, db, tenantID, "search-asset")
	defer cleanupTestData(db, tenantID)

	insert := func(title, desc string) {
		id := shared.NewID()
		_, err := db.Exec(`
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, title, description, message, severity, status, fingerprint, created_at, updated_at)
			VALUES ($1,$2,$3,'manual','t',$4,$5,$6,'high','new',$7,NOW(),NOW())`,
			id.String(), tenantID.String(), assetID.String(), title, desc, title, fmt.Sprintf("fp-%s", id.String()))
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}
	insert("SQL injection in login", "tainted query param")
	insert("Reflected XSS in search box", "unescaped output")

	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})
	ctx := context.Background()

	// Search by a term only in the first finding's title.
	res, err := repo.List(ctx,
		vulnerability.NewFindingFilter().WithTenantID(tenantID).WithSearch("injection"),
		vulnerability.NewFindingListOptions(), pagination.New(1, 20))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Data) != 1 {
		t.Fatalf("search 'injection' expected 1 finding, got %d", len(res.Data))
	}
	if res.Data[0].Title() != "SQL injection in login" {
		t.Errorf("wrong finding matched: %q", res.Data[0].Title())
	}

	// Search by a term in the second finding's description.
	res2, err := repo.List(ctx,
		vulnerability.NewFindingFilter().WithTenantID(tenantID).WithSearch("unescaped"),
		vulnerability.NewFindingListOptions(), pagination.New(1, 20))
	if err != nil {
		t.Fatalf("List2: %v", err)
	}
	if len(res2.Data) != 1 || res2.Data[0].Title() != "Reflected XSS in search box" {
		t.Fatalf("search 'unescaped' expected the XSS finding, got %d results", len(res2.Data))
	}
}
