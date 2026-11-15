package postgres

// The assets list reads a page's ids first and joins the per-asset columns
// (the open-findings counts) for those ids only (buildAssetPageQuery). The
// pages of a range filter under a member's data scope are the same rows,
// in the same order, as the whole filtered list; another tenant's asset in
// the range never shows; the counts are right; a sort on the open-findings
// count keeps working.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/assetlist"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

func TestAssetListWhere_PageIDsFirst_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	// Seven hosts with an address in 10.77.0.0/16 (by name or recorded
	// address), created a day apart; host i has i open findings. One more
	// host outside the range, and another tenant's host inside it.
	type seeded struct {
		id       string
		findings int
	}
	var inRange []seeded
	add := func(tn shared.ID, name, props string, age time.Duration, open int) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, properties, created_at)
			VALUES ($1, $2, $3, 'host', $4::jsonb, $5)`, id, tn.String(), name, props, time.Now().Add(-age)); err != nil {
			t.Fatal(err)
		}
		for range open {
			if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
				VALUES (gen_random_uuid(), $1, $2, 'sca', 'page-test', 'm', 'high', gen_random_uuid()::text, 'new')`, tn.String(), id); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	for i := 0; i < 7; i++ {
		name, props := "h"+string(rune('a'+i))+".example.com", `{"ip_addresses": ["10.77.0.`+string(rune('1'+i))+`"]}`
		if i == 3 {
			name, props = "10.77.1.1", `{}`
		}
		inRange = append(inRange, seeded{add(tenant, name, props, time.Duration(i)*24*time.Hour, i), i})
	}
	add(tenant, "outside.example.com", `{"ip_addresses": ["10.78.0.1"]}`, time.Hour, 1)
	add(other, "ha.example.com", `{"ip_addresses": ["10.77.0.1"]}`, time.Minute, 1)

	// A member who sees five of the seven.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'u')`, user.String(), user.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	var visible []seeded
	for i, s := range inRange {
		if i == 1 || i == 4 {
			continue
		}
		visible = append(visible, s)
		if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
			user.String(), tenant.String(), s.id); err != nil {
			t.Skipf("user_accessible_assets is not writable here: %v", err)
		}
	}
	member, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: tenant, UserID: user}})
	if err != nil {
		t.Fatal(err)
	}

	pages := func(actor filterspec.Actor, sort []filterspec.SortKey, perPage int) ([]string, map[string]int) {
		t.Helper()
		spec, err := filterspec.ParseDocumentValue(leafDoc("ip", "in", []any{"10.77.0.0/16"}), assetlist.Fields, filterspec.Options{})
		if err != nil {
			t.Fatal(err)
		}
		spec.Sort = sort
		w, err := filterspec.Compile(spec, assetlist.Fields, actor)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		counts := map[string]int{}
		for page := 1; page <= 10; page++ {
			res, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, Page: page, PerPage: perPage})
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range res.Data {
				ids = append(ids, a.ID().String())
				counts[a.ID().String()] = a.FindingCount()
			}
			if len(res.Data) < perPage {
				break
			}
		}
		return ids, counts
	}

	// Default order (newest first), two rows a page: exactly the member's
	// five, newest first, each once, with its open-findings count.
	ids, counts := pages(member, nil, 2)
	want := make([]string, 0, len(visible))
	for _, s := range visible {
		want = append(want, s.id)
	}
	if !slices.Equal(ids, want) {
		t.Fatalf("member pages = %v, want %v (newest first, scope only)", ids, want)
	}
	for _, s := range visible {
		if counts[s.id] != s.findings {
			t.Errorf("asset %s: finding count %d, want %d", s.id, counts[s.id], s.findings)
		}
	}

	// The tenant's own view, sorted by the open-findings count (the
	// one-statement form): all seven, most findings first.
	ids, _ = pages(filterspec.SystemActor(tenant, "page test"), []filterspec.SortKey{{Field: "finding_count", Desc: true}}, 3)
	want = want[:0]
	for i := len(inRange) - 1; i >= 0; i-- {
		want = append(want, inRange[i].id)
	}
	if !slices.Equal(ids, want) {
		t.Fatalf("finding_count pages = %v, want %v", ids, want)
	}
}
