package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sla"
)

// A tenant has one default per practice: a compliance default sits beside
// the vulnerability default, the vulnerability lookups never return it, and
// making a compliance policy the default leaves the vulnerability default.
func TestSLAPolicy_PracticeDefaults_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	vuln, err := sla.NewDefaultPolicy(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, vuln); err != nil {
		t.Fatal(err)
	}
	comp, _ := sla.NewPolicy(tenant, "Compliance")
	if err := comp.SetPractice(sla.PracticeCompliance); err != nil {
		t.Fatal(err)
	}
	comp.SetDefault(true)
	if err := repo.Create(ctx, comp); err != nil {
		t.Fatalf("a compliance default beside the vulnerability default: %v", err)
	}
	got, err := repo.GetTenantDefault(ctx, tenant)
	if err != nil || got.ID() != vuln.ID() {
		t.Fatalf("GetTenantDefault = %v, %v; want the vulnerability default", got, err)
	}
	asset := seedTestAsset(ctx, t, db, tenant)
	if got, err := repo.GetByAsset(ctx, tenant, asset); err != nil || got.ID() != vuln.ID() {
		t.Fatalf("GetByAsset = %v, %v; want the vulnerability default", got, err)
	}
	back, err := repo.GetByTenantAndID(ctx, tenant, comp.ID())
	if err != nil || back.Practice() != sla.PracticeCompliance || back.P2Days() != 90 || back.KEVCapDays() != 0 {
		t.Fatalf("compliance policy read back = %+v, %v", back, err)
	}

	// A second compliance policy made the default replaces only the
	// compliance default.
	comp2, _ := sla.NewPolicy(tenant, "Compliance 2")
	_ = comp2.SetPractice(sla.PracticeCompliance)
	if err := repo.Create(ctx, comp2); err != nil {
		t.Fatal(err)
	}
	comp2.SetDefault(true)
	if err := repo.UpdateMakingDefault(ctx, comp2); err != nil {
		t.Fatal(err)
	}
	var joined string
	if err := db.QueryRowContext(ctx, `SELECT string_agg(COALESCE(practice, '') || ':' || name, ',' ORDER BY 1)
		FROM sla_policies WHERE tenant_id = $1 AND is_default`, tenant.String()).Scan(&joined); err != nil {
		t.Fatal(err)
	}
	defaults := strings.Split(joined, ",")
	if len(defaults) != 2 || defaults[0] != ":Default SLA Policy" || defaults[1] != "compliance:Compliance 2" {
		t.Fatalf("defaults = %v", defaults)
	}

	// The CHECK refuses any other practice.
	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET practice = 'aspm' WHERE id = $1`, comp.ID().String()); err == nil {
		t.Fatal("practice aspm accepted")
	}
}
