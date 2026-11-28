package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/simulation"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// One framework under several spellings is one card and one filter: "CIS"
// and "cis" rows (stored before names were made canonical) group together,
// the filter by any spelling finds both, and another tenant's rows are never
// counted or listed. Requires DATABASE_URL.
func TestControlTestFrameworkOneName_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'ct-fw', $2)`, id.String(), "ctfw-"+id.String()[24:]); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	a, b := newTenant(), newTenant()
	ins := func(tid shared.ID, framework, status string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO control_tests (id, tenant_id, name, framework, control_id, status,
			control_name, category, test_procedure, expected_result, evidence, notes)
			VALUES ($1, $2, 'c', $3, 'x', $4, '', '', '', '', '', '')`, shared.NewID().String(), tid.String(), framework, status); err != nil {
			t.Fatal(err)
		}
	}
	ins(a, "Internal", "pass")
	ins(a, "internal", "fail")
	ins(a, "ISO 27001", "untested")
	ins(b, "internal", "pass")

	repo := NewControlTestRepository(&DB{DB: db})
	stats, err := repo.GetStatsByFramework(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("want 2 frameworks, got %+v", stats)
	}
	var internal simulation.FrameworkStats
	for _, s := range stats {
		if simulation.FrameworkKey(s.Framework) == "internal" {
			internal = s
		}
	}
	if internal.Total != 2 || internal.Passed != 1 || internal.Failed != 1 {
		t.Fatalf("internal stats = %+v (tenant B row must not count)", internal)
	}

	fw := "iso27001"
	page, err := repo.List(ctx, simulation.ControlTestFilter{TenantID: &a, Framework: &fw}, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("filter by another spelling: total = %d, want 1", page.Total)
	}
	fw = "INTERNAL"
	page, err = repo.List(ctx, simulation.ControlTestFilter{TenantID: &b, Framework: &fw}, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("tenant B sees %d rows, want only its own 1", page.Total)
	}
}
