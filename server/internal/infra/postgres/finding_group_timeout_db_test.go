package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// The grouped view runs under the interactive read timeout: a grouping that
// cannot finish stops after interactiveReadTimeout with the typed timeout
// (503 QUERY_TIMEOUT), instead of holding a pool connection for as long as
// the database role allows. A filter that sleeps per row stands in for a
// grouping too broad for the tenant. Requires DATABASE_URL.
func TestFindingGroups_StopAtReadTimeout(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	tenant := shared.NewID()
	asset := shared.NewID()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant.String(), "fg-"+tenant.String())
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant.String())
	})
	mustExec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'fg.example.com', 'domain')`, asset.String(), tenant.String())
	mustExec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status)
		VALUES ($1, $2, 'sca', 'fg', 'fg', 'fg', 'high', $3, 'new')`, tenant.String(), asset.String(), shared.NewID().String())

	f := vulnerability.NewFindingFilter()
	tid := tenant
	f.TenantID = &tid
	f.Compiled = &filterspec.Where{
		SQL:   vulnerability.FindingFieldsF.TenantSQL + " = $2 AND (SELECT true FROM pg_sleep(30))",
		Args:  []any{tenant.String()},
		First: 2, NextArg: 3, OrderBy: "f.id",
	}
	repo := NewFindingRepository(&DB{DB: sqlDB})
	start := time.Now()
	_, err := repo.ListFindingGroups(ctx, tenant, "severity", f, pagination.New(1, 10))
	took := time.Since(start)
	if !errors.Is(err, vulnerability.ErrFindingQueryTimeout) || !errors.Is(err, shared.ErrQueryTimeout) {
		t.Fatalf("grouping past the timeout = %v, want ErrFindingQueryTimeout", err)
	}
	if took > interactiveReadTimeout+3*time.Second {
		t.Fatalf("the grouping held its connection for %s, past the %s timeout", took, interactiveReadTimeout)
	}
}
