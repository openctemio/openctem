package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// agentRowRepo serves only GetByID (the gate's lookup for async-ingest agents);
// any other call panics via the nil embedded interface.
type agentRowRepo struct {
	agent.Repository
	rows map[shared.ID]*agent.Agent
}

func (r *agentRowRepo) GetByID(_ context.Context, id shared.ID) (*agent.Agent, error) {
	if a, ok := r.rows[id]; ok {
		return a, nil
	}
	return nil, shared.ErrNotFound
}

func gateService(rows ...*agent.Agent) *Service {
	repo := &agentRowRepo{rows: map[shared.ID]*agent.Agent{}}
	for _, a := range rows {
		repo.rows[a.ID] = a
	}
	return &Service{logger: logger.NewNop(), agentRepo: repo}
}

func TestAgentMayAutoResolveTool(t *testing.T) {
	tid := shared.NewID()
	declared := &agent.Agent{ID: shared.NewID(), TenantID: &tid, Tools: []string{"semgrep", "Trivy"}}
	legacy := &agent.Agent{ID: shared.NewID(), TenantID: &tid}
	svc := gateService(declared)

	cases := []struct {
		name string
		agt  *agent.Agent
		tool string
		want bool
	}{
		// Legit flows keep working.
		{"declared tool", declared, "semgrep", true},
		{"declared tool, case-insensitive", declared, "trivy", true},
		{"legacy agent without declared tools (backward compat)", legacy, "nuclei", true},
		{"server-side synthetic ingest", &agent.Agent{TenantID: &tid}, "tenable", true},
		{"server-side synthetic ingest, defectdojo", &agent.Agent{TenantID: &tid}, "defectdojo", true},

		// Attacks: an agent claiming another tool's name.
		{"tool not declared by the agent", declared, "nuclei", false},
		{"reserved tool name from declared agent", declared, "defectdojo", false},
		{"reserved tool name from legacy agent", legacy, "pentest-manual", false},
		{"reserved tool name, case/space variant", legacy, " Burp_Suite ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := svc.agentMayAutoResolveTool(context.Background(), tc.agt, tc.tool); got != tc.want {
				t.Fatalf("agentMayAutoResolveTool(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}

// The async ingest worker rebuilds the agent from the job with only ID +
// tenant; the gate must load the declared tools from the agent row instead of
// treating it as a legacy (unrestricted) agent.
func TestAgentMayAutoResolveTool_AsyncJobAgentLoadsDeclaredTools(t *testing.T) {
	tid := shared.NewID()
	stored := &agent.Agent{ID: shared.NewID(), TenantID: &tid, Tools: []string{"gitleaks"}}
	svc := gateService(stored)
	jobAgent := &agent.Agent{ID: stored.ID, TenantID: &tid, Status: agent.AgentStatusActive}

	if svc.agentMayAutoResolveTool(context.Background(), jobAgent, "semgrep") {
		t.Fatal("async-ingested report for an undeclared tool must not auto-resolve")
	}
	if !svc.agentMayAutoResolveTool(context.Background(), jobAgent, "gitleaks") {
		t.Fatal("async-ingested report for a declared tool must auto-resolve")
	}
}
