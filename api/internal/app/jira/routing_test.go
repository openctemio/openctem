package jira

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ParseMappingConfig reads routing rules: match conditions (string or array),
// project_key, issue_type; rules without a project_key are dropped.
func TestParseMappingConfig_Routing(t *testing.T) {
	m := ParseMappingConfig(map[string]any{
		"ticketing": map[string]any{
			"routing": []any{
				map[string]any{
					"match":       map[string]any{"asset_group": []any{"Payments"}, "severity": "Critical"},
					"project_key": "PAY",
					"issue_type":  "Bug",
				},
				map[string]any{
					"match":       map[string]any{"scope": []any{"external", "cloud"}},
					"project_key": "EXT",
				},
				// dropped: no project_key
				map[string]any{"match": map[string]any{"severity": "low"}},
			},
		},
	})
	if len(m.Routing) != 2 {
		t.Fatalf("expected 2 usable rules (1 dropped), got %d: %+v", len(m.Routing), m.Routing)
	}
	r0 := m.Routing[0]
	if r0.ProjectKey != "PAY" || r0.IssueType != "Bug" {
		t.Fatalf("rule0 = %+v", r0)
	}
	// values lower-cased + normalized
	if len(r0.Severity) != 1 || r0.Severity[0] != "critical" {
		t.Fatalf("rule0 severity not normalized: %+v", r0.Severity)
	}
	if len(r0.AssetGroup) != 1 || r0.AssetGroup[0] != "payments" {
		t.Fatalf("rule0 asset_group not normalized: %+v", r0.AssetGroup)
	}
	if len(m.Routing[1].Scope) != 2 {
		t.Fatalf("rule1 scope = %+v", m.Routing[1].Scope)
	}
}

func TestRouteFor_Matching(t *testing.T) {
	m := MappingConfig{Routing: []RoutingRule{
		{Severity: []string{"critical"}, Scope: []string{"external"}, ProjectKey: "CRIT-EXT"},
		{Tag: []string{"pci"}, ProjectKey: "PCI"},
		{Scope: []string{"external"}, ProjectKey: "EXT"},
		{ProjectKey: "CATCHALL"}, // wildcard
	}}

	cases := []struct {
		name string
		rc   RouteContext
		want string
	}{
		// AND across dims: critical AND external → first rule.
		{"critical+external", RouteContext{Severity: "critical", Scope: "external"}, "CRIT-EXT"},
		// critical but internal → first rule fails (scope), falls to catch-all
		// (no tag, scope internal so EXT fails too).
		{"critical+internal", RouteContext{Severity: "critical", Scope: "internal"}, "CATCHALL"},
		// tag overlap wins rule 2 before the broader scope rule.
		{"pci tag", RouteContext{Severity: "low", Tags: []string{"pci", "web"}}, "PCI"},
		// plain external (non-critical, no tag) → rule 3.
		{"external only", RouteContext{Severity: "medium", Scope: "external"}, "EXT"},
		// nothing distinctive → catch-all.
		{"nothing", RouteContext{Severity: "info", Scope: "isolated"}, "CATCHALL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, ok := m.RouteFor(tc.rc)
			if !ok {
				t.Fatalf("expected a match for %+v", tc.rc)
			}
			if rule.ProjectKey != tc.want {
				t.Fatalf("RouteFor(%+v) → %q, want %q", tc.rc, rule.ProjectKey, tc.want)
			}
		})
	}
}

func TestRouteFor_NoMatch(t *testing.T) {
	m := MappingConfig{Routing: []RoutingRule{
		{Severity: []string{"critical"}, ProjectKey: "CRIT"},
	}}
	if _, ok := m.RouteFor(RouteContext{Severity: "low"}); ok {
		t.Fatal("expected no match when no rule applies")
	}
}

// stubAssetRoute returns fixed asset context for routing-by-asset tests.
type stubAssetRoute struct {
	scope, criticality string
	groups             []string
}

func (s stubAssetRoute) ResolveAssetRoute(_ context.Context, _, _ shared.ID) (string, string, []string, error) {
	return s.scope, s.criticality, s.groups, nil
}

// When no explicit project is given, a matching routing rule (on the asset's
// scope, via the resolver) chooses the destination project + issue type.
func TestCreateTicketFromFinding_RoutesByAssetScope(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{finding: buildFinding(t)} // SeverityHigh
	s := newSync(repo, client)
	mapping := DefaultMappingConfig()
	mapping.DefaultProjectKey = "FALLBACK"
	mapping.Routing = []RoutingRule{
		{Scope: []string{"external"}, ProjectKey: "EXT", IssueType: "Security Bug"},
	}
	s.SetMappingResolver(stubMappingResolver{mapping: mapping})
	s.SetAssetRouteResolver(stubAssetRoute{scope: "external", criticality: "high"})

	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
	}); err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.lastInput.ProjectKey != "EXT" {
		t.Fatalf("ProjectKey = %q, want EXT (routed by external scope)", client.lastInput.ProjectKey)
	}
	if client.lastInput.IssueType != "Security Bug" {
		t.Fatalf("IssueType = %q, want 'Security Bug' (route override)", client.lastInput.IssueType)
	}
}

// No routing match → falls through to the default project.
func TestCreateTicketFromFinding_RoutingFallsThroughToDefault(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{finding: buildFinding(t)}
	s := newSync(repo, client)
	mapping := DefaultMappingConfig()
	mapping.DefaultProjectKey = "FALLBACK"
	mapping.Routing = []RoutingRule{
		{Scope: []string{"internal"}, ProjectKey: "INT"}, // won't match external
	}
	s.SetMappingResolver(stubMappingResolver{mapping: mapping})
	s.SetAssetRouteResolver(stubAssetRoute{scope: "external"})

	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
	}); err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.lastInput.ProjectKey != "FALLBACK" {
		t.Fatalf("ProjectKey = %q, want FALLBACK (no routing match)", client.lastInput.ProjectKey)
	}
}

// An explicit request project_key wins over routing rules.
func TestCreateTicketFromFinding_ExplicitWinsOverRouting(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{finding: buildFinding(t)}
	s := newSync(repo, client)
	mapping := DefaultMappingConfig()
	mapping.Routing = []RoutingRule{{Scope: []string{"external"}, ProjectKey: "EXT"}}
	s.SetMappingResolver(stubMappingResolver{mapping: mapping})
	s.SetAssetRouteResolver(stubAssetRoute{scope: "external"})

	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:   shared.NewID().String(),
		FindingID:  shared.NewID().String(),
		ProjectKey: "MANUAL",
	}); err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.lastInput.ProjectKey != "MANUAL" {
		t.Fatalf("ProjectKey = %q, want MANUAL (explicit wins)", client.lastInput.ProjectKey)
	}
}
