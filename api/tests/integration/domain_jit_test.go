package integration

// Several SSO domains per organization (RFC-058): each domain carries its own
// just-in-time provisioning, and a domain whose proof lapsed is flagged on the
// members it covered and stops email-only password resets.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestDomainJITAndLapse(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pdb := &postgres.DB{DB: db}
	vdRepo := postgres.NewVerifiedDomainRepository(pdb)
	svc := domainverify.NewService(vdRepo, nil, logger.NewNop())

	tn := createTestTenant(t, db, "jit-org")
	stamp := shared.NewID().String()[:8]
	main := "acme-" + stamp + ".example"
	sub := "sub-" + stamp + ".example"
	old := "old-" + stamp + ".example"
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM verified_domains WHERE tenant_id = $1`, tn.String())
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenant_members WHERE tenant_id = $1`, tn.String())
		cleanupTestData(db, tn)
	})
	rows := map[string]*verifieddomain.VerifiedDomain{}
	for _, d := range []string{main, sub, old} {
		row, err := verifieddomain.New(shared.NewID(), tn, d, "tok-"+d)
		if err != nil {
			t.Fatal(err)
		}
		row.WithPurpose(verifieddomain.PurposeSSO)
		if err := vdRepo.Create(ctx, row); err != nil {
			t.Fatal(err)
		}
		row.MarkVerified(time.Now())
		if err := vdRepo.Update(ctx, row); err != nil {
			t.Fatal(err)
		}
		rows[d] = row
	}

	// Per-domain JIT: main default; sub as viewer; old no newcomers.
	if _, err := svc.ChangeJIT(ctx, tn, rows[sub].ID(), true, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeJIT(ctx, tn, rows[old].ID(), false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeJIT(ctx, tn, rows[main].ID(), true, "admin"); err == nil {
		t.Fatal("administrators are never provisioned: jit_role admin must be refused")
	}
	check := func(domain string, wantOn bool, wantRole string) {
		on, role, err := svc.DomainJITPolicy(ctx, tn.String(), domain)
		if err != nil || on != wantOn || role != wantRole {
			t.Fatalf("%s: on=%v role=%q err=%v, want %v %q", domain, on, role, err, wantOn, wantRole)
		}
	}
	check(main, true, "")
	check(sub, true, "viewer")
	check(old, false, "")
	check("unrelated.example", false, "")
	// Another organization never gets this one's JIT.
	if on, _, _ := svc.DomainJITPolicy(ctx, shared.NewID().String(), main); on {
		t.Fatal("JIT must be per organization")
	}

	// sub's DNS proof lapses.
	rows[sub].MarkChecked(time.Now())
	if err := vdRepo.Update(ctx, rows[sub]); err != nil {
		t.Fatal(err)
	}
	if rows[sub].IsVerified() {
		t.Fatal("precondition: a re-check without the record downgrades the claim")
	}
	check(sub, false, "")
	if lapsed, err := svc.IsLapsedSSODomain(ctx, sub); err != nil || !lapsed {
		t.Fatalf("sub must be lapsed: %v %v", lapsed, err)
	}
	if lapsed, _ := svc.IsLapsedSSODomain(ctx, main); lapsed {
		t.Fatal("main is still held")
	}

	// A member on the lapsed domain is flagged in the members list.
	u := createTestUser(t, db, "minh-"+stamp+"@"+sub, "Minh")
	v := createTestUser(t, db, "an-"+stamp+"@"+main, "An")
	createTestMembership(t, db, tn, u, "member")
	createTestMembership(t, db, tn, v, "member")
	list, err := postgres.NewTenantRepository(pdb).ListMembersWithUserInfo(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	flags := map[shared.ID]bool{}
	for _, m := range list {
		flags[m.UserID] = m.DomainLapsed
	}
	if !flags[u] || flags[v] {
		t.Fatalf("domain_lapsed flags: lapsed member %v, held member %v", flags[u], flags[v])
	}
}
