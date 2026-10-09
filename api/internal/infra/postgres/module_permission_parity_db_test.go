package postgres

import (
	"context"
	"testing"
)

// Every active permission belongs to an active module. The role editor lists
// permissions grouped under their module and drops any whose module is NULL
// or inactive (ListModulesWithPermissions), so such a permission cannot be
// granted from the console: scope, cycle, business-service and priority-rule
// permissions were in that state until migration 001524.
func TestModuleCatalog_EveryPermissionHasALiveModule(t *testing.T) {
	db := openModuleCatalogDB(t)
	catalog := loadModuleCatalog(t, db)

	rows, err := db.QueryContext(context.Background(),
		`SELECT id, COALESCE(module_id, '') FROM permissions WHERE is_active = TRUE`)
	if err != nil {
		t.Fatalf("query permissions: %v", err)
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id, moduleID string
		if err := rows.Scan(&id, &moduleID); err != nil {
			t.Fatalf("scan: %v", err)
		}
		n++
		row, ok := catalog[moduleID]
		switch {
		case moduleID == "":
			t.Errorf("permission %q has no module: the role editor cannot show it", id)
		case !ok || !row.isActive:
			t.Errorf("permission %q belongs to module %q, which is not an active module", id, moduleID)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate permissions: %v", err)
	}
	requireDerivedNonEmpty(t, "active permissions", n)
}
