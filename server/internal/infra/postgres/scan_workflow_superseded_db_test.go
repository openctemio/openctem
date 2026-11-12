package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// A retired system workflow (inactive) is hidden from the list unless asked
// for, and carries the name of the workflow that replaced it.
func TestListWithSystemTemplates_RetiredHiddenByDefault(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanWorkflowRepository(&DB{DB: db})
	tenant := seedScanTriggerTenant(ctx, t, db)

	sysTenant := "00000000-0000-0000-0000-000000000000"
	newID := func() string { return shared.NewID().String() }
	current, old := newID(), newID()
	ins := `INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags, superseded_by)
	        VALUES ($1, $2, $3, '', 1, '[]', '{}', $4, true, '{}', $5)`
	if _, err := db.ExecContext(ctx, ins, current, sysTenant, "Current "+current[:8], true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, ins, old, sysTenant, "Old "+old[:8], false, current); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_workflows WHERE id IN ($1, $2)`, old, current)
	})

	has := func(f scanworkflow.Filter, id string) *scanworkflow.Workflow {
		t.Helper()
		res, err := repo.ListWithSystemTemplates(ctx, tenant, f, pagination.New(1, 500))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range res.Data {
			if w.ID.String() == id {
				return w
			}
		}
		return nil
	}

	if has(scanworkflow.Filter{}, old) != nil {
		t.Fatal("a retired system workflow is listed by default")
	}
	if has(scanworkflow.Filter{}, current) == nil {
		t.Fatal("an active system workflow is not listed")
	}
	w := has(scanworkflow.Filter{IncludeRetired: true}, old)
	if w == nil {
		t.Fatal("IncludeRetired does not list the retired workflow")
	}
	if !w.IsRetiredSystem() || w.SupersededBy == nil || w.SupersededBy.String() != current || w.SupersededByName != "Current "+current[:8] {
		t.Fatalf("retired workflow = %+v, want superseded by the current one", w)
	}
}
