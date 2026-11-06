package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// A tenant tool config or an integration is read, changed and deleted only
// through its own tenant: another tenant's id finds nothing and changes
// nothing (defense in depth under the callers' own tenant checks).
func TestTenantScopedWrites_ForeignTenantFindsNothing(t *testing.T) {
	raw := openSensorDB(t)
	db := &DB{DB: raw}
	ctx := context.Background()

	mk := func(label string) shared.ID {
		id := shared.NewID()
		if _, err := raw.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`, id.String(), label, label+"-"+id.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM tenants WHERE id=$1`, id.String()) })
		return id
	}
	owner, foreign := mk("scoped-owner"), mk("scoped-foreign")

	var toolID string
	if err := raw.QueryRow(`SELECT id FROM tools LIMIT 1`).Scan(&toolID); err != nil {
		t.Skipf("no tool seeded: %v", err)
	}
	tid, _ := shared.IDFromString(toolID)

	// Tool config.
	cfgRepo := NewTenantToolConfigRepository(db)
	cfg, err := tool.NewTenantToolConfig(owner, tid, map[string]any{"k": "v"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfgRepo.Create(ctx, cfg); err != nil {
		t.Fatalf("create config: %v", err)
	}
	if _, err := cfgRepo.GetByID(ctx, foreign, cfg.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign GetByID err = %v, want not found", err)
	}
	if err := cfgRepo.Delete(ctx, foreign, cfg.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign Delete err = %v, want not found", err)
	}
	other := *cfg
	other.TenantID = foreign
	other.IsEnabled = !cfg.IsEnabled
	if err := cfgRepo.Update(ctx, &other); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign Update err = %v, want not found", err)
	}
	got, err := cfgRepo.GetByID(ctx, owner, cfg.ID)
	if err != nil || got.IsEnabled != cfg.IsEnabled {
		t.Fatalf("owner read after foreign attempts: %v %+v", err, got)
	}
	if err := cfgRepo.Delete(ctx, owner, cfg.ID); err != nil {
		t.Fatalf("owner Delete: %v", err)
	}

	// Integration.
	intgID := shared.NewID()
	if _, err := raw.Exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status)
		VALUES ($1,$2,'scoped','ticketing','jira','connected')`, intgID.String(), owner.String()); err != nil {
		t.Fatalf("seed integration: %v", err)
	}
	intgRepo := NewIntegrationRepository(db)
	if err := intgRepo.Delete(ctx, foreign, intgID); !errors.Is(err, integration.ErrIntegrationNotFound) {
		t.Fatalf("foreign integration Delete err = %v, want not found", err)
	}
	var n int
	_ = raw.QueryRow(`SELECT count(*) FROM integrations WHERE id=$1`, intgID.String()).Scan(&n)
	if n != 1 {
		t.Fatal("a foreign delete removed the integration")
	}
	if err := intgRepo.Delete(ctx, owner, intgID); err != nil {
		t.Fatalf("owner integration Delete: %v", err)
	}
}
