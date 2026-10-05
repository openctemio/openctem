package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every platform tool the migrations seed must read back through the
// repository: one row it cannot scan (e.g. a NULL install_method, which it
// reads into a non-null string) breaks the whole tool list and every scan
// that names that tool.
func TestToolCatalog_SeededToolsReadBack(t *testing.T) {
	db := catalogTestDB(t)
	repo := NewToolRepository(&DB{DB: db})
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `SELECT name FROM tools WHERE tenant_id IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Skip("no seeded tools (migrations not applied)")
	}
	for _, n := range names {
		if _, err := repo.GetByName(ctx, shared.ID{}, n); err != nil {
			t.Errorf("GetByName(%q): %v", n, err)
		}
	}

	// The asset collectors (migration 000265) are in the catalog as collectors.
	for _, n := range []string{"gcp-dns", "vcenter", "ldap", "splunk", "prtg"} {
		tl, err := repo.GetByName(ctx, shared.ID{}, n)
		if err != nil {
			t.Errorf("collector %q: %v", n, err)
			continue
		}
		if !tl.IsCollector() || !tl.IsActive || !tl.IsPlatformTool() {
			t.Errorf("collector %q: IsCollector=%v active=%v platform=%v", n, tl.IsCollector(), tl.IsActive, tl.IsPlatformTool())
		}
	}
}
