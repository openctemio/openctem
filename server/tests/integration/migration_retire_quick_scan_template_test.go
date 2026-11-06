package integration

// Migration retire_quick_scan_template: the system workflow "Quick Scan Template"
// leaves the workflow list (it can never run), the row stays so runs of quick
// scans keep their parent, and down puts it back.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestMigrationRetireQuickScanTemplate(t *testing.T) {
	const (
		dir        = "../../migrations"
		templateID = "00000000-0000-0000-0000-000000000001"
	)
	db := testdb.PrivateDatabase(t, "migquickscan", dir)
	v := testdb.MigrationVersion(t, dir, "retire_quick_scan_template")
	ctx := context.Background()
	repo := postgres.NewScanWorkflowRepository(&postgres.DB{DB: db})

	var tenant string
	if err := db.QueryRow(`INSERT INTO tenants (name, slug) VALUES ('qs', 'qs-mig') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tid, _ := shared.IDFromString(tenant)

	listed := func() bool {
		t.Helper()
		res, err := repo.ListWithSystemTemplates(ctx, tid, scanworkflow.Filter{}, pagination.New(1, 500))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range res.Data {
			if w.ID.String() == templateID {
				return true
			}
		}
		return false
	}
	active := func() bool {
		t.Helper()
		var a bool
		if err := db.QueryRow(`SELECT is_active FROM scan_workflows WHERE id = $1 AND is_system_template`, templateID).Scan(&a); err != nil {
			t.Fatalf("the template row must still exist: %v", err)
		}
		return a
	}

	if active() || listed() {
		t.Fatal("after up: the Quick Scan Template is still active or listed")
	}
	testdb.Migrate(t, db, dir, v, v, true)
	if !active() || !listed() {
		t.Fatal("after down: the template is not back in the list")
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if active() || listed() {
		t.Fatal("after up again: the template is active or listed")
	}
}
