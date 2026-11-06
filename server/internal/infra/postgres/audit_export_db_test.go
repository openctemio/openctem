package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The audit export pages newest first with a keyset cursor, applies the list's
// filters, and never returns another tenant's (or a system) row. Requires
// DATABASE_URL.
func TestAuditRepository_ExportBatch_OrderPagingFiltersAndTenantIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewAuditRepository(&DB{DB: sqlDB})
	a := seedTestTenant(ctx, t, sqlDB)
	b := seedTestTenant(ctx, t, sqlDB)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	insert := func(tenant *shared.ID, action string, sev string, at time.Time, name string) {
		t.Helper()
		var tid any
		if tenant != nil {
			tid = tenant.String()
		}
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, actor_email, action, resource_type, resource_id, resource_name, result, severity, message, logged_at)
			VALUES ($1, $2, 'x@example.com', $3, 'settings', 'r', $4, 'success', $5, 'm', $6)`,
			shared.NewID().String(), tid, action, name, sev, at); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// Tenant A: 7 rows, two of them at the same instant (the id breaks the tie).
	for i := 0; i < 5; i++ {
		insert(&a, "settings.updated", "low", base.Add(time.Duration(i)*time.Second), fmt.Sprintf("a-%d", i))
	}
	insert(&a, "auth.login", "high", base.Add(10*time.Second), "a-login")
	insert(&a, "auth.login", "high", base.Add(10*time.Second), "a-login-same-instant")
	// Another tenant and a system row.
	insert(&b, "settings.updated", "low", base.Add(20*time.Second), "b-secret")
	insert(nil, "settings.updated", "low", base.Add(30*time.Second), "system-secret")

	filter := auditdom.NewFilter().WithTenantID(a)
	var got []string
	var after *auditdom.ExportCursor
	var last time.Time
	for {
		batch, err := repo.ExportBatch(ctx, filter, after, 3) // pages of 3 over 7 rows
		if err != nil {
			t.Fatalf("export batch: %v", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, l := range batch {
			if l.TenantID() == nil || *l.TenantID() != a {
				t.Fatalf("row of another tenant in the export: %s", l.ResourceName())
			}
			if !last.IsZero() && l.Timestamp().After(last) {
				t.Fatal("rows are not newest first")
			}
			last = l.Timestamp()
			got = append(got, l.ResourceName())
		}
		tail := batch[len(batch)-1]
		after = &auditdom.ExportCursor{LoggedAt: tail.Timestamp(), ID: tail.ID().String()}
	}
	if len(got) != 7 {
		t.Fatalf("exported %d rows %v, want 7 (no duplicates, no gaps across pages)", len(got), got)
	}
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n] || n == "b-secret" || n == "system-secret" {
			t.Fatalf("duplicate or foreign row %q in %v", n, got)
		}
		seen[n] = true
	}

	// Filters narrow the export like the list.
	hi, err := repo.ExportBatch(ctx, filter.WithSeverities(auditdom.SeverityHigh), nil, 100)
	if err != nil || len(hi) != 2 {
		t.Fatalf("severity filter: %d rows, %v", len(hi), err)
	}
	win, err := repo.ExportBatch(ctx, filter.WithSince(base.Add(3*time.Second)).WithUntil(base.Add(4*time.Second)), nil, 100)
	if err != nil || len(win) != 2 {
		t.Fatalf("time window: %d rows, %v", len(win), err)
	}

	// Truncation probe: more than n rows?
	if more, err := repo.HasMoreThan(ctx, filter, 6); err != nil || !more {
		t.Fatalf("more than 6: %v %v", more, err)
	}
	if more, err := repo.HasMoreThan(ctx, filter, 7); err != nil || more {
		t.Fatalf("more than 7: %v %v", more, err)
	}

	// No tenant, no export.
	if _, err := repo.ExportBatch(ctx, auditdom.NewFilter(), nil, 10); err == nil {
		t.Fatal("an export without a tenant must be refused")
	}
	if _, err := repo.HasMoreThan(ctx, auditdom.NewFilter(), 10); err == nil {
		t.Fatal("a size probe without a tenant must be refused")
	}
}
