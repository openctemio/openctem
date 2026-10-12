package postgres

import (
	"context"
	"database/sql"
	"regexp"
	"slices"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The database half of the asset-types drift check (RFC-042 §6.3.3): the
// migrated schema must agree with the generated registry. Skipped unless
// DATABASE_URL is set.

func openRegistryDB(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db, ctx
}

var quoted = regexp.MustCompile(`'([a-z0-9_]+)'`)

func checkValues(ctx context.Context, t *testing.T, db *sql.DB, name string) []string {
	t.Helper()
	var def string
	if err := db.QueryRowContext(ctx,
		`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = $1`, name).Scan(&def); err != nil {
		t.Fatalf("constraint %s: %v", name, err)
	}
	var out []string
	for _, m := range quoted.FindAllStringSubmatch(def, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return out
}

func TestAssetTypeRegistry_SchemaMatchesRegistry(t *testing.T) {
	db, ctx := openRegistryDB(t)

	var classes, lenses []string
	for _, c := range asset.AllClasses() {
		classes = append(classes, string(c))
	}
	for _, l := range asset.AllLenses() {
		lenses = append(lenses, string(l))
	}
	slices.Sort(classes)
	slices.Sort(lenses)
	if got := checkValues(ctx, t, db, "chk_asset_types_class"); !slices.Equal(got, classes) {
		t.Errorf("chk_asset_types_class allows %v, registry has %v", got, classes)
	}
	if got := checkValues(ctx, t, db, "chk_asset_types_lens"); !slices.Equal(got, lenses) {
		t.Errorf("chk_asset_types_lens allows %v, registry has %v", got, lenses)
	}

	rows, err := db.QueryContext(ctx,
		`SELECT code, class, COALESCE(lens, ''), COALESCE(alias_of, ''), COALESCE(alias_sub_type, '') FROM asset_types`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[asset.AssetType]bool{}
	for rows.Next() {
		var code, class, lens, aliasOf, aliasSub string
		if err := rows.Scan(&code, &class, &lens, &aliasOf, &aliasSub); err != nil {
			t.Fatal(err)
		}
		d, ok := asset.LookupType(asset.AssetType(code))
		if !ok {
			// A legacy code kept for the assets FK.
			if class != string(asset.ClassOther) || lens != "" || aliasOf != "" {
				t.Errorf("legacy code %q: class %q lens %q alias %q, want other/none", code, class, lens, aliasOf)
			}
			continue
		}
		seen[d.Type] = true
		var wantAlias, wantSub string
		if d.AliasOf != nil {
			wantAlias, wantSub = string(d.AliasOf.Type), d.AliasOf.SubType
		}
		if class != string(d.Class) || lens != string(d.Lens) || aliasOf != wantAlias || aliasSub != wantSub {
			t.Errorf("asset_types %q = (%s, %s, %s/%s), registry says (%s, %s, %s/%s)",
				code, class, lens, aliasOf, aliasSub, d.Class, d.Lens, wantAlias, wantSub)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, d := range asset.RegistryDocument().Types {
		if !seen[d.Type] {
			t.Errorf("registry type %q has no asset_types row (the assets FK would reject it)", d.Type)
		}
	}
}

// storedPairs returns every (asset_type, sub_type) the trigger must classify:
// each core type as itself, and each alias as the pair it is stored as.
func storedPairs() []asset.TypeRef {
	var pairs []asset.TypeRef
	for _, d := range asset.RegistryDocument().Types {
		// Only core types are stored (chk_assets_core_type, 000684): an
		// alias appears as the pair it stands for.
		if d.AliasOf != nil {
			pairs = append(pairs, *d.AliasOf)
			continue
		}
		pairs = append(pairs, asset.TypeRef{Type: d.Type})
	}
	return pairs
}

func TestAssetTypeRegistry_TriggerDerivesClassAndLens(t *testing.T) {
	db, ctx := openRegistryDB(t)
	tenantID := seedTestTenant(ctx, t, db)

	for _, p := range storedPairs() {
		var sub any
		if p.SubType != "" {
			sub = p.SubType
		}
		var id shared.ID
		var class string
		var lens sql.NullString
		err := db.QueryRowContext(ctx, `
			INSERT INTO assets (tenant_id, name, asset_type, sub_type)
			VALUES ($1, $2, $3, $4)
			RETURNING id, asset_class, asset_lens`,
			tenantID.String(), "registry-trigger-"+shared.NewID().String(), string(p.Type), sub,
		).Scan(&id, &class, &lens)
		if err != nil {
			t.Fatalf("insert %v: %v", p, err)
		}
		if want := asset.ClassOf(p.Type, p.SubType); class != string(want) {
			t.Errorf("insert %s/%s: asset_class %q, Go ClassOf %q", p.Type, p.SubType, class, want)
		}
		if want := asset.LensOf(p.Type, p.SubType); lens.String != string(want) || lens.Valid != (want != "") {
			t.Errorf("insert %s/%s: asset_lens %v, Go LensOf %q", p.Type, p.SubType, lens, want)
		}
	}

	// A sub_type change re-derives; a direct write to the columns is undone.
	var hostID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, 'registry-trigger-host', 'host')
		RETURNING id`, tenantID.String()).Scan(&hostID); err != nil {
		t.Fatal(err)
	}
	var class string
	if err := db.QueryRowContext(ctx,
		`UPDATE assets SET sub_type = 'serverless' WHERE id = $1 RETURNING asset_class`, hostID).Scan(&class); err != nil || class != "function" {
		t.Errorf("sub_type -> serverless: class %q, err %v; want function", class, err)
	}
	if err := db.QueryRowContext(ctx,
		`UPDATE assets SET asset_class = 'network', asset_lens = 'code' WHERE id = $1 RETURNING asset_class`, hostID).Scan(&class); err != nil || class != "function" {
		t.Errorf("direct write: class %q, err %v; want it re-derived to function", class, err)
	}
}

// asset_registry_backfill repairs rows whose class or lens is missing or out
// of date, in id-ordered batches, and leaves correct rows alone. The rows are
// broken with triggers off (session_replication_role, superuser only) inside a
// transaction that is rolled back, so other tests never see them.
func TestAssetTypeRegistry_BackfillRepairsRows(t *testing.T) {
	db, ctx := openRegistryDB(t)
	tenantID := seedTestTenant(ctx, t, db)

	pairs := storedPairs()
	ids := make([]string, len(pairs))
	for i, p := range pairs {
		var sub any
		if p.SubType != "" {
			sub = p.SubType
		}
		if err := db.QueryRowContext(ctx, `
			INSERT INTO assets (tenant_id, name, asset_type, sub_type) VALUES ($1, $2, $3, $4) RETURNING id`,
			tenantID.String(), "registry-backfill-"+shared.NewID().String(), string(p.Type), sub,
		).Scan(&ids[i]); err != nil {
			t.Fatalf("insert %v: %v", p, err)
		}
	}

	// Breaking rows with triggers off needs a superuser
	// (session_replication_role); the app role cannot, by design (D-6).
	tx, err := testdb.OpenAdmin(t).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Skipf("cannot disable triggers (needs superuser): %v", err)
	}
	// Half the rows lose their class (as before the migration), half get a
	// wrong one (as after a registry change).
	if _, err := tx.ExecContext(ctx, `
		UPDATE assets SET asset_class = CASE WHEN random() < 0.5 THEN NULL ELSE 'network' END,
		                  asset_lens  = 'code'
		WHERE tenant_id = $1`, tenantID.String()); err != nil {
		t.Fatal(err)
	}

	var cursor sql.NullString
	batches, fixed := 0, 0
	for {
		var updated int
		if err := tx.QueryRowContext(ctx,
			`SELECT last_id, updated FROM asset_registry_backfill($1, 10)`, cursor).Scan(&cursor, &updated); err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if !cursor.Valid {
			break
		}
		batches++
		fixed += updated
	}
	if batches < 2 {
		t.Errorf("backfill ran %d batches; the batch size is 10, so it should page", batches)
	}
	if fixed < len(pairs) {
		t.Errorf("backfill fixed %d rows, want at least the %d broken ones", fixed, len(pairs))
	}

	for i, p := range pairs {
		var class string
		var lens sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT asset_class, asset_lens FROM assets WHERE id = $1`, ids[i]).Scan(&class, &lens); err != nil {
			t.Fatal(err)
		}
		if want := asset.ClassOf(p.Type, p.SubType); class != string(want) {
			t.Errorf("%s/%s after backfill: class %q, want %q", p.Type, p.SubType, class, want)
		}
		if want := asset.LensOf(p.Type, p.SubType); lens.String != string(want) {
			t.Errorf("%s/%s after backfill: lens %q, want %q", p.Type, p.SubType, lens.String, want)
		}
	}

	// A second pass finds nothing to do.
	var again sql.NullString
	var total int
	for {
		var updated int
		if err := tx.QueryRowContext(ctx,
			`SELECT last_id, updated FROM asset_registry_backfill($1, 500)`, again).Scan(&again, &updated); err != nil {
			t.Fatal(err)
		}
		if !again.Valid {
			break
		}
		total += updated
	}
	if total != 0 {
		t.Errorf("second backfill pass updated %d rows, want 0", total)
	}
}

// RFC-042 §6.3.8: the closed sub-type lists, the storable flag and the input
// map in the database are the registry's.
func TestAssetTypeRegistry_InputsAndSubTypesMatchRegistry(t *testing.T) {
	db, ctx := openRegistryDB(t)

	rows, err := db.QueryContext(ctx, `SELECT code, sub_types, is_storable FROM asset_types`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	seen := 0
	for rows.Next() {
		var code string
		var subs []string
		var storable bool
		if err := rows.Scan(&code, pq.Array(&subs), &storable); err != nil {
			t.Fatal(err)
		}
		typ := asset.AssetType(code)
		if storable != typ.IsStored() {
			t.Errorf("%s: is_storable = %v, registry stored = %v", code, storable, typ.IsStored())
		}
		want := asset.SubTypesOf(typ)
		if want == nil {
			want = []string{}
		}
		if subs == nil {
			subs = []string{}
		}
		if !slices.Equal(subs, want) {
			t.Errorf("%s: sub_types = %v, registry %v", code, subs, want)
		}
		if typ.IsStored() {
			seen++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != len(asset.StoredAssetTypes()) {
		t.Errorf("%d storable rows, registry has %d core types", seen, len(asset.StoredAssetTypes()))
	}
}

// RFC-042 §6.3.8 T3: after the normalisation every stored type is a core type,
// and chk_assets_core_type lists exactly the registry's stored types.
func TestAssetTypeRegistry_OnlyCoreTypesAreStored(t *testing.T) {
	db, ctx := openRegistryDB(t)

	want := make([]string, 0)
	for _, s := range asset.StoredAssetTypes() {
		want = append(want, string(s))
	}
	slices.Sort(want)
	if got := checkValues(ctx, t, db, "chk_assets_core_type"); !slices.Equal(got, want) {
		t.Errorf("chk_assets_core_type = %v, registry stored types = %v", got, want)
	}
	var outside int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM assets WHERE NOT (asset_type = ANY ($1))`, pq.Array(want)).Scan(&outside); err != nil {
		t.Fatal(err)
	}
	if outside != 0 {
		t.Errorf("%d asset row(s) hold a type that is not a core type", outside)
	}
	tenantID := seedTestTenant(ctx, t, db)
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, $2, 'website')`,
		tenantID.String(), "t3-alias-"+shared.NewID().String()); err == nil {
		t.Error("an alias type was stored; chk_assets_core_type must refuse it")
	}
}

// O3 (RFC-042 §6.3.8): one web sub-type. No threat-model row is keyed by
// (application, web_application).
func TestAssetTypeRegistry_OneWebSubType(t *testing.T) {
	db, ctx := openRegistryDB(t)
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM technique_applicability WHERE asset_type = 'application' AND sub_type = 'web_application'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d technique_applicability row(s) still keyed by application/web_application", n)
	}
}
