package scan_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The seeded system scan profiles live under the system tenant with
// is_system = true. Lookups that expected tenant_id IS NULL never found them,
// so a tenant could list them but not open, clone or attach them (settings
// audit SC-M6). They are now readable and clonable by every tenant (the clone
// belongs to the caller) and still never editable or deletable.
func TestSystemScanProfiles_ReadableClonableNotEditable(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	var systemID string
	if err := raw.QueryRowContext(ctx, `SELECT id FROM scan_profiles WHERE is_system = true ORDER BY name LIMIT 1`).Scan(&systemID); err != nil {
		t.Skipf("no seeded system profile: %v", err)
	}
	tenant := shared.NewID()
	if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant.String(), "sp-"+tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = raw.ExecContext(bg, `DELETE FROM scan_profiles WHERE tenant_id = $1`, tenant.String())
		_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tenant.String())
	})

	repo := postgres.NewScanProfileRepository(&postgres.DB{DB: raw})
	svc := scanapp.NewScanProfileService(repo, logger.NewNop())

	got, err := svc.GetScanProfile(ctx, tenant.String(), systemID)
	if err != nil || !got.IsSystem {
		t.Fatalf("open system profile: %+v, %v", got, err)
	}
	sysID, _ := shared.IDFromString(systemID)
	if _, err := repo.GetAccessibleByID(ctx, tenant, sysID); err != nil {
		t.Fatalf("attach system profile to a scan: %v", err)
	}

	clone, err := svc.CloneScanProfile(ctx, scanapp.CloneScanProfileInput{
		TenantID: tenant.String(), ProfileID: systemID, NewName: "my copy",
	})
	if err != nil {
		t.Fatalf("clone system profile: %v", err)
	}
	if clone.TenantID != tenant || clone.IsSystem {
		t.Fatalf("clone tenant = %s system = %v, want the caller's own profile", clone.TenantID, clone.IsSystem)
	}

	if _, err := svc.UpdateScanProfile(ctx, scanapp.UpdateScanProfileInput{
		TenantID: tenant.String(), ProfileID: systemID, Name: "hijacked",
	}); err == nil {
		t.Fatalf("a tenant edited a system profile")
	}
	if err := svc.DeleteScanProfile(ctx, tenant.String(), systemID); err == nil {
		t.Fatalf("a tenant deleted a system profile")
	}
	var name string
	_ = raw.QueryRowContext(ctx, `SELECT name FROM scan_profiles WHERE id = $1`, systemID).Scan(&name)
	if name == "hijacked" {
		t.Fatalf("system profile was renamed")
	}

	// Another tenant's own profile stays invisible.
	other := shared.NewID()
	if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "sp-"+other.String()); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = raw.ExecContext(bg, `DELETE FROM scan_profiles WHERE tenant_id = $1`, other.String())
		_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	foreign, err := svc.CloneScanProfile(ctx, scanapp.CloneScanProfileInput{TenantID: other.String(), ProfileID: systemID, NewName: "theirs"})
	if err != nil {
		t.Fatalf("other tenant clone: %v", err)
	}
	if _, err := svc.GetScanProfile(ctx, tenant.String(), foreign.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("read another tenant's profile: err = %v, want ErrNotFound", err)
	}
	if _, err := repo.GetAccessibleByID(ctx, tenant, foreign.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("attach another tenant's profile: err = %v, want ErrNotFound", err)
	}
}
