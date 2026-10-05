package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Capability usage stats used to count and name every tool and sensor in the
// database that carries the capability, whatever tenant owned it. A viewer in
// one organization saw another organization's sensor names and custom tool
// names (and the counts), and another tenant's rows could block deleting a
// capability. The stats now cover the caller's own tools and sensors plus the
// platform tool catalog (tenant_id IS NULL), which every tenant may read.
func TestCapabilityUsageStats_TenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewCapabilityRepository(&DB{DB: db})

	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)

	capID := shared.NewID()
	capName := "usage-" + capID.String()[:8]
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// A platform capability, so both tenants may ask for its stats.
	exec(`INSERT INTO capabilities (id, tenant_id, name, display_name, is_builtin) VALUES ($1, NULL, $2, $2, true)`,
		capID.String(), capName)
	platformTool := shared.NewID()
	exec(`INSERT INTO tools (id, tenant_id, name, display_name, capabilities, is_builtin) VALUES ($1, NULL, $2, $2, ARRAY[$3]::text[], true)`,
		platformTool.String(), "plat-"+capID.String()[:8], capName)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tools WHERE id = $1`, platformTool.String())
		_, _ = db.ExecContext(context.Background(), `DELETE FROM capabilities WHERE id = $1`, capID.String())
	})

	seedTool := func(tenant shared.ID, name string, viaJunction bool) {
		t.Helper()
		id := shared.NewID()
		if viaJunction {
			exec(`INSERT INTO tools (id, tenant_id, name, display_name) VALUES ($1, $2, $3, $3)`, id.String(), tenant.String(), name)
			exec(`INSERT INTO tool_capabilities (tool_id, capability_id) VALUES ($1, $2)`, id.String(), capID.String())
			return
		}
		exec(`INSERT INTO tools (id, tenant_id, name, display_name, capabilities) VALUES ($1, $2, $3, $3, ARRAY[$4]::text[])`,
			id.String(), tenant.String(), name, capName)
	}
	seedSensor := func(tenant shared.ID, name string) {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status, capabilities)
			VALUES ($1, $2, $3, $4, 'p', 'active', ARRAY[$5]::text[])`,
			id.String(), tenant.String(), name, "h-"+id.String(), capName)
	}

	seedTool(tenantA, "a-tool", false)
	seedSensor(tenantA, "a-sensor")
	seedTool(tenantB, "b-secret-tool-array", false)
	seedTool(tenantB, "b-secret-tool-junction", true)
	seedSensor(tenantB, "b-secret-sensor-1")
	seedSensor(tenantB, "b-secret-sensor-2")

	platformName := "plat-" + capID.String()[:8]

	t.Run("single", func(t *testing.T) {
		stats, err := repo.GetUsageStats(ctx, tenantA, capID)
		if err != nil {
			t.Fatal(err)
		}
		wantTools := []string{"a-tool", platformName}
		if got := slices.Sorted(slices.Values(stats.ToolNames)); !slices.Equal(got, wantTools) {
			t.Errorf("tenant A tool names = %v, want %v (another tenant's tools must never appear)", got, wantTools)
		}
		if !slices.Equal(stats.SensorNames, []string{"a-sensor"}) {
			t.Errorf("tenant A sensor names = %v, want [a-sensor]", stats.SensorNames)
		}
		if stats.ToolCount != 2 || stats.SensorCount != 1 {
			t.Errorf("tenant A counts = %d tools / %d sensors, want 2 / 1", stats.ToolCount, stats.SensorCount)
		}

		statsB, err := repo.GetUsageStats(ctx, tenantB, capID)
		if err != nil {
			t.Fatal(err)
		}
		if statsB.ToolCount != 3 || statsB.SensorCount != 2 {
			t.Errorf("tenant B counts = %d tools / %d sensors, want 3 / 2", statsB.ToolCount, statsB.SensorCount)
		}
		for _, n := range append(statsB.ToolNames, statsB.SensorNames...) {
			if n == "a-tool" || n == "a-sensor" {
				t.Errorf("tenant B sees tenant A's %q", n)
			}
		}
	})

	t.Run("batch", func(t *testing.T) {
		got, err := repo.GetUsageStatsBatch(ctx, tenantA, []shared.ID{capID})
		if err != nil {
			t.Fatal(err)
		}
		s := got[capID]
		if s == nil || s.ToolCount != 2 || s.SensorCount != 1 {
			t.Fatalf("tenant A batch stats = %+v, want 2 tools / 1 sensor", s)
		}
		gotB, err := repo.GetUsageStatsBatch(ctx, tenantB, []shared.ID{capID})
		if err != nil {
			t.Fatal(err)
		}
		if s := gotB[capID]; s == nil || s.ToolCount != 3 || s.SensorCount != 2 {
			t.Fatalf("tenant B batch stats = %+v, want 3 tools / 2 sensors", s)
		}
	})

	t.Run("tenant with no usage sees only the platform catalog", func(t *testing.T) {
		tenantC := seedTestTenant(ctx, t, db)
		stats, err := repo.GetUsageStats(ctx, tenantC, capID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(stats.ToolNames, []string{platformName}) || len(stats.SensorNames) != 0 {
			t.Errorf("tenant C sees tools %v sensors %v, want only the platform tool", stats.ToolNames, stats.SensorNames)
		}
	})
}

// The effective config of another tenant's custom tool is not-found at the
// repository too (defense in depth under the service check).
func TestTenantToolEffectiveConfig_OtherTenantsCustomToolNotFound(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewTenantToolConfigRepository(&DB{DB: db})
	owner := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	toolID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tools (id, tenant_id, name, display_name, default_config)
		VALUES ($1, $2, 'owner-tool', 'owner-tool', '{"token":"owner-only"}')`, toolID.String(), owner.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetEffectiveConfig(ctx, other, toolID); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("other tenant: err = %v, want not found", err)
	}
	cfg, err := repo.GetEffectiveConfig(ctx, owner, toolID)
	if err != nil || cfg["token"] != "owner-only" {
		t.Errorf("owner: cfg = %v, err = %v", cfg, err)
	}
}

// GET /capabilities/categories listed the categories of every tenant's custom
// capabilities. A tenant now sees platform categories and its own only.
func TestCapabilityCategories_TenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewCapabilityRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	suffix := shared.NewID().String()[:8]
	for _, row := range []struct {
		tenant   shared.ID
		name     string
		category string
	}{
		{tenantA, "cap-a-" + suffix, "a-category-" + suffix},
		{tenantB, "cap-b-" + suffix, "b-secret-category-" + suffix},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO capabilities (tenant_id, name, display_name, category) VALUES ($1, $2, $2, $3)`,
			row.tenant.String(), row.name, row.category); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.GetCategories(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, "a-category-"+suffix) {
		t.Errorf("tenant A does not see its own category: %v", got)
	}
	if slices.Contains(got, "b-secret-category-"+suffix) {
		t.Errorf("tenant A sees tenant B's custom category: %v", got)
	}
}
