package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Program data scope (RFC-065 §7): a researcher sees the assets of the
// programs they belong to and nothing else of the organization; programs
// are isolated from each other and from the organization's own inventory;
// a program exclusion keeps a name out; removing an entry removes access.
// Requires DATABASE_URL.
func TestProgramAssignment_DataScope(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	other := seedBatchTenant(t, db)
	repo := NewBountyProgramRepository(pdb)

	member := func(email string) shared.ID {
		u := seedGroupsUser(ctx, t, db, email)
		if _, err := db.ExecContext(ctx, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`,
			u.String(), tenant.String()); err != nil {
			t.Fatal(err)
		}
		return u
	}
	alice, bob := member("bb-a.example"), member("bb-b.example")

	asset := func(tid shared.ID, name, typ string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, $4)`,
			id.String(), tid.String(), name, typ); err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
		return id
	}
	acmeApp := asset(tenant, "app.acme.example", "domain")
	acmeAdmin := asset(tenant, "admin.acme.example", "domain") // out of scope for the program
	acmeIP := asset(tenant, "192.0.2.10", "ip_address")
	betaApp := asset(tenant, "www.beta.example", "domain")
	owned := asset(tenant, "intranet.corp.example", "domain") // the organization's own
	foreign := asset(other, "app2.acme.example", "domain")    // another tenant

	importProgram := func(name, scopeText string, who shared.ID) *bountyprogram.Program {
		items, err := bountyprogram.ParseScope(scopeText)
		if err != nil {
			t.Fatal(err)
		}
		plan := bountyprogram.PlanScope(items)
		now := time.Now().UTC()
		p := &bountyprogram.Program{ID: shared.NewID(), TenantID: tenant, Name: name, ProgramURL: "https://p.example/" + name,
			Status: bountyprogram.StatusActive, ScopeSource: bountyprogram.ScopeSourcePaste, ScopeItems: items,
			TermsSHA256: bountyprogram.NewTerms("https://p.example/"+name, bountyprogram.Rules{}, items).SHA256(),
			AcceptedBy:  &who, AcceptedAt: &now, CreatedAt: now, UpdatedAt: now}
		var entries []*scope.Target
		for _, e := range plan.Entries {
			st, err := scope.NewEntry(tenant, e.TargetType, e.Pattern, "", who.String(), scope.EntryOptions{MaxTier: scope.TierActive})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.SetAuthorization(scope.AuthProgram, &p.ID); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, st)
		}
		var ex []bountyprogram.Exclusion
		for _, x := range plan.Exclusions {
			ex = append(ex, bountyprogram.Exclusion{ID: shared.NewID(), TenantID: tenant, ProgramID: p.ID,
				TargetType: x.TargetType, Pattern: x.Pattern, Reason: x.Reason, CreatedAt: now})
		}
		if err := repo.Import(ctx, bountyprogram.ImportWrite{Program: p,
			Group:   bountyprogram.NewGroup{ID: shared.NewID(), Name: "Program: " + name, Slug: "program-" + p.ID.String()[:13], Member: &who},
			Entries: entries, Exclusions: ex}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	acme := importProgram("Acme", "*.acme.example\nacme.example\n192.0.2.0/24\n-admin.acme.example\n", alice)
	beta := importProgram("Beta", "*.beta.example\nbeta.example\n", bob)

	if _, err := repo.AssignTenantPrograms(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	sees := func(u, a shared.ID) bool {
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM user_accessible_assets WHERE user_id = $1 AND tenant_id = $2 AND asset_id = $3)`,
			u.String(), tenant.String(), a.String()).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, c := range []struct {
		who   shared.ID
		asset shared.ID
		name  string
		want  bool
	}{
		{alice, acmeApp, "alice: her program's name", true},
		{alice, acmeIP, "alice: her program's address", true},
		{alice, acmeAdmin, "alice: out of scope for her program", false},
		{alice, betaApp, "alice: another program", false},
		{alice, owned, "alice: the organization's own inventory", false},
		{alice, foreign, "alice: another tenant", false},
		{bob, betaApp, "bob: his program", true},
		{bob, acmeApp, "bob: another program", false},
		{bob, owned, "bob: the organization's own inventory", false},
	} {
		if got := sees(c.who, c.asset); got != c.want {
			t.Errorf("%s: sees=%v, want %v", c.name, got, c.want)
		}
	}

	// Idempotent.
	if n, err := repo.AssignTenantPrograms(ctx, tenant); err != nil || n != 0 {
		t.Fatalf("second pass changed %d: %v", n, err)
	}

	// Pausing the program takes access away on the next pass.
	acme.Status = bountyprogram.StatusPaused
	if err := repo.SetStatus(ctx, acme, scope.StatusInactive); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.AssignProgramAssets(ctx, tenant, acme.ID); err != nil {
		t.Fatal(err)
	}
	if sees(alice, acmeApp) {
		t.Fatal("a paused program's assets must leave the researcher's scope")
	}
	// A manual assignment of the same group is never removed by the pass.
	var gid sql.NullString
	_ = db.QueryRowContext(ctx, `SELECT group_id::text FROM bounty_programs WHERE id = $1`, beta.ID.String()).Scan(&gid)
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_owners (asset_id, group_id, ownership_type, assignment_source) VALUES ($1, $2, 'secondary', 'manual')`,
		owned.String(), gid.String); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.AssignProgramAssets(ctx, tenant, beta.ID); err != nil {
		t.Fatal(err)
	}
	if !sees(bob, owned) {
		t.Fatal("a manual assignment must survive the program pass")
	}
	// Another tenant's id finds nothing.
	if _, _, err := repo.AssignProgramAssets(ctx, other, beta.ID); err == nil {
		t.Fatal("another tenant's program must not be found")
	}
}
