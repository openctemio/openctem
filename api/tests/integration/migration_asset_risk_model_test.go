package integration

// Migration asset_risk_model: organizations on the built-in risk settings
// (no section, "legacy" or "default") move to the likelihood-impact default
// preset with every other key kept; an organization with its own preset keeps
// it. Runs on a private database: everything up, the migration down, seed,
// the migration up.

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestMigrationAssetRiskModelMovesBuiltInSettings(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migriskmodel", dir)
	v := testdb.MigrationVersion(t, dir, "asset_risk_model")
	testdb.Migrate(t, db, dir, v, v, true)

	const (
		empty   = "a1111111-1111-4111-8111-111111111111"
		legacy  = "a2222222-2222-4222-8222-222222222222"
		banking = "a3333333-3333-4333-8333-333333333333"
	)
	legacyJSON, _ := json.Marshal(map[string]any{
		"risk_scoring": func() map[string]any {
			b, _ := json.Marshal(tenant.LegacyRiskScoringSettings())
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			m["floor_unowned_at_p2"] = true
			return m
		}(),
		"general": map[string]any{"timezone": "Asia/Ho_Chi_Minh"},
	})
	bankingJSON, _ := json.Marshal(map[string]any{"risk_scoring": tenant.AllRiskScoringPresets["banking"]})
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug, settings) VALUES
		($1, 'e', 'mig-risk-e', '{}'), ($2, 'l', 'mig-risk-l', $4), ($3, 'b', 'mig-risk-b', $5)`,
		empty, legacy, banking, string(legacyJSON), string(bankingJSON)); err != nil {
		t.Fatal(err)
	}

	testdb.Migrate(t, db, dir, v, v, false)

	read := func(id string) (tenant.RiskScoringSettings, map[string]any) {
		t.Helper()
		var raw []byte
		if err := db.QueryRow(`SELECT settings FROM tenants WHERE id = $1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var all map[string]any
		if err := json.Unmarshal(raw, &all); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(all["risk_scoring"])
		var rs tenant.RiskScoringSettings
		if err := json.Unmarshal(b, &rs); err != nil {
			t.Fatal(err)
		}
		return rs, all
	}

	want := tenant.DefaultRiskScoringPreset()
	if got, _ := read(empty); !reflect.DeepEqual(got, want) {
		t.Fatalf("empty settings migrated to %+v, want the default preset %+v", got, want)
	}
	got, all := read(legacy)
	if !got.FloorUnownedAtP2 {
		t.Fatal("floor_unowned_at_p2 was lost")
	}
	got.FloorUnownedAtP2 = false
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy settings migrated to %+v, want the default preset", got)
	}
	if g, _ := all["general"].(map[string]any); g["timezone"] != "Asia/Ho_Chi_Minh" {
		t.Fatalf("other sections changed: %+v", all)
	}
	if got, _ := read(banking); !reflect.DeepEqual(got, tenant.AllRiskScoringPresets["banking"]) {
		t.Fatalf("a chosen preset was overwritten: %+v", got)
	}
	if err := want.Validate(); err != nil {
		t.Fatalf("default preset does not validate: %v", err)
	}
}
