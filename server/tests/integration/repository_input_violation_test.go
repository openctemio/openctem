package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/simulation"
	"github.com/openctemio/openctem/api/pkg/domain/threatactor"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// A value the database rejects because the CALLER sent it — longer than its
// column, outside a CHECK, or pointing at a row that does not exist — is a bad
// request, not a server fault. These repositories returned the raw pq error,
// which every handler above them turns into a 500. The v0.9.0 API crawl hit
// each one with an ordinary request body:
//
//	POST/PUT /simulations       mitre_technique_id longer than varchar(20)
//	POST/PUT /pentest/templates cwe_id longer than varchar(20)
//	POST     /threat-actors     mitre_group_id longer than varchar(20)
//	POST     /tools             category_id that does not exist (FK)
func TestRepositoriesReportCallerInputViolationsAsValidation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "input-violation")
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM attack_simulations WHERE tenant_id=$1`,
			`DELETE FROM pentest_finding_templates WHERE tenant_id=$1`,
			`DELETE FROM threat_actors WHERE tenant_id=$1`,
			`DELETE FROM tools WHERE tenant_id=$1`,
			`DELETE FROM tenants WHERE id=$1`,
		} {
			_, _ = db.Exec(q, tenant.String())
		}
	})
	pg := &postgres.DB{DB: db}
	tooLong := strings.Repeat("x", 36)

	sim, err := simulation.NewSimulation(tenant, "too-long-technique", simulation.SimulationTypeAtomic)
	if err != nil {
		t.Fatal(err)
	}
	sim.SetMITRE("execution", tooLong, "Command and Scripting Interpreter")

	tmpl, err := pentest.NewTemplate(tenant, "too-long-cwe", pentest.FindingSeverityHigh)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SetCWEID(tooLong)

	actor, err := threatactor.NewThreatActor(tenant, "too-long-group", threatactor.ActorTypeAPT)
	if err != nil {
		t.Fatal(err)
	}
	actor.SetIntel("advanced", "financial", "VN", tooLong)

	missingCategory := shared.NewID()
	customTool, err := tool.NewTenantCustomTool(tenant, shared.ID{}, "dangling-category", "Dangling", &missingCategory, tool.InstallGo)
	if err != nil {
		t.Fatal(err)
	}

	for name, write := range map[string]func() error{
		"simulation create":       func() error { return postgres.NewSimulationRepository(pg).Create(ctx, sim) },
		"pentest template create": func() error { return postgres.NewPentestTemplateRepository(pg).Create(ctx, tmpl) },
		"threat actor create":     func() error { return postgres.NewThreatActorRepository(pg).Create(ctx, actor) },
		"tool create":             func() error { return postgres.NewToolRepository(pg).Create(ctx, customTool) },
	} {
		err := write()
		if err == nil {
			t.Errorf("%s: the database accepted a value it should reject", name)
			continue
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: got %v — want a shared.ErrValidation so the handler answers 400, not 500", name, err)
		}
	}
}
