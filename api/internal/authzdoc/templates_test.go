package authzdoc

import (
	"slices"
	"testing"
)

// serviceChecked are permissions a service or handler checks inside a route
// rather than in the route gate, so no gate names them.
var serviceChecked = map[string]string{
	"findings:views:share":    "savedview service: share a view with the whole organization",
	"scans:tenant_tools:read": "tool and capability handlers: tenant settings and availability includes",
	"reports:manage":          "report schedule handler: other members' schedules",
}

func templateRoles(t *testing.T, ref *Reference) map[string]RoleInfo {
	t.Helper()
	out := map[string]RoleInfo{}
	for _, r := range ref.Roles {
		if r.Kind == "template" {
			out[r.ID] = r
		}
	}
	return out
}

func gateNames(g Gate, p string) bool {
	if slices.Contains(g.Permissions, p) {
		return true
	}
	for _, grp := range g.AnyOf {
		if slices.Contains(grp, p) {
			return true
		}
	}
	return false
}

// Every permission a template grants opens at least one route the template
// passes (or is checked inside a handler). A permission that only works
// together with another one the template lacks is dead weight that misleads
// whoever reads the role.
func TestRoleTemplates_EveryGrantOpensSomething(t *testing.T) {
	ref := buildRef(t)
	for id, role := range templateRoles(t, ref) {
		for _, p := range role.Permissions {
			if _, ok := serviceChecked[p]; ok {
				continue
			}
			used := false
			for _, f := range ref.Features {
				for _, r := range f.Routes {
					if gateNames(r.Gate, p) && role.Passes(r.Gate) {
						used = true
						break
					}
				}
				if used {
					break
				}
			}
			if !used {
				t.Errorf("%s: %s opens no route the template passes", id, p)
			}
		}
	}
}

// templateFlows are the routes each template's people need every day (must)
// and the ones separation of duties keeps from them (mustNot). A route that
// moves or changes its gate fails here, so the template is reviewed with it.
// Campaign routes also check the caller's campaign role, which a template
// cannot grant; only their permission part is checked here.
var templateFlows = map[string]struct{ must, mustNot []string }{
	"program-lead": {
		must: []string{
			"POST /api/v1/ctem-cycles", "PUT /api/v1/priority-rules/{id}", "PUT /api/v1/sla-policies/{id}",
			"POST /api/v1/approvals/{id}/approve", "POST /api/v1/suppressions/{id}/approve",
			"POST /api/v1/exposures/{id}/accept", "POST /api/v1/scope/targets/{id}/approve",
			"POST /api/v1/scan-approvals/{id}/approve", "POST /api/v1/organization/dashboards",
		},
		mustNot: []string{"POST /api/v1/scope/targets", "PATCH /api/v1/findings/{id}/status", "POST /api/v1/scans"},
	},
	"security-analyst": {
		must: []string{
			"PATCH /api/v1/findings/{id}/status", "PATCH /api/v1/findings/{id}/severity", "POST /api/v1/findings/{id}/assign",
			"POST /api/v1/findings/{id}/duplicates", "POST /api/v1/findings/{id}/comments", "POST /api/v1/findings/{id}/evidence",
			"POST /api/v1/findings/{id}/retests", "POST /api/v1/findings/actions/verify", "POST /api/v1/findings/{id}/approvals",
			"POST /api/v1/findings/{id}/create-ticket", "POST /api/v1/exposures/{id}/resolve",
		},
		mustNot: []string{"POST /api/v1/approvals/{id}/approve", "POST /api/v1/exposures/{id}/accept", "POST /api/v1/findings/actions/fix-applied"},
	},
	"vulnerability-manager": {
		must: []string{
			"POST /api/v1/assignment-rules", "POST /api/v1/remediation/campaigns", "POST /api/v1/remediation/tasks",
			"POST /api/v1/scans", "POST /api/v1/scans/{id}/trigger", "POST /api/v1/findings/bulk/assign",
			"POST /api/v1/findings/export", "POST /api/v1/reports/schedules",
		},
		mustNot: []string{"POST /api/v1/approvals/{id}/approve", "POST /api/v1/suppressions/{id}/approve"},
	},
	"remediation-owner": {
		must: []string{
			"POST /api/v1/findings/{id}/comments", "POST /api/v1/findings/{id}/evidence", "POST /api/v1/findings/{id}/remediation/steps",
			"POST /api/v1/findings/{id}/create-ticket", "POST /api/v1/findings/{id}/ticket-links",
			"POST /api/v1/findings/actions/fix-applied", "POST /api/v1/findings/{id}/approvals",
			"GET /api/v1/pentest/campaigns/{id}/findings", "POST /api/v1/pentest/findings/{id}/request-retest",
		},
		mustNot: []string{
			"POST /api/v1/findings/actions/verify", "PATCH /api/v1/findings/{id}/severity", "POST /api/v1/approvals/{id}/approve",
			"POST /api/v1/remediation/tasks/{task_id}/resolve",
		},
	},
	"remediation-lead": {
		must: []string{
			"POST /api/v1/remediation/tasks", "PATCH /api/v1/remediation/tasks/{task_id}", "POST /api/v1/remediation/tasks/{task_id}/splits",
			"POST /api/v1/remediation/tasks/{task_id}/resolve", "POST /api/v1/remediation/tasks/{task_id}/exception",
			"POST /api/v1/remediation/tasks/{task_id}/ticket-links", "POST /api/v1/findings/{id}/assign", "POST /api/v1/findings/bulk/status",
		},
		mustNot: []string{"POST /api/v1/findings/actions/verify", "PATCH /api/v1/findings/{id}/severity", "POST /api/v1/approvals/{id}/approve"},
	},
	"appsec-engineer": {
		must: []string{
			"POST /api/v1/scans", "POST /api/v1/scans/{id}/trigger", "PATCH /api/v1/findings/{id}/status", "POST /api/v1/findings/actions/verify",
			"POST /api/v1/scope/check", "POST /api/v1/findings/{id}/ai-triage",
		},
		mustNot: []string{"POST /api/v1/approvals/{id}/approve"},
	},
	"scan-operator": {
		must:    []string{"POST /api/v1/scans", "POST /api/v1/scans/{id}/trigger", "POST /api/v1/scans/quick", "GET /api/v1/content/packages"},
		mustNot: []string{"POST /api/v1/scope/targets", "PATCH /api/v1/findings/{id}/status", "POST /api/v1/scan-approvals/{id}/approve"},
	},
	"validation-engineer": {
		must: []string{
			"POST /api/v1/pentest/campaigns", "POST /api/v1/pentest/campaigns/{id}/findings", "POST /api/v1/pentest/findings/{findingId}/retests",
			"POST /api/v1/pentest/campaigns/{id}/reports", "POST /api/v1/simulations/{id}/run", "PATCH /api/v1/control-tests/{id}/result",
			"POST /api/v1/scans/quick", "POST /api/v1/findings/actions/verify",
		},
		mustNot: []string{"POST /api/v1/scope/targets", "POST /api/v1/approvals/{id}/approve", "POST /api/v1/pentest/checklist-templates"},
	},
	"validation-lead": {
		must: []string{
			"POST /api/v1/pentest/checklist-templates", "POST /api/v1/attacker-profiles", "POST /api/v1/scope/targets",
			"POST /api/v1/scope/letters", "POST /api/v1/pentest/campaigns",
		},
		mustNot: []string{"POST /api/v1/scope/targets/{id}/approve", "POST /api/v1/scope/exclusions/{id}/approve", "POST /api/v1/approvals/{id}/approve"},
	},
	"detection-engineer": {
		must: []string{
			"GET /api/v1/simulations", "GET /api/v1/control-tests", "POST /api/v1/compensating-controls/{id}/test",
			"POST /api/v1/findings/{id}/comments", "GET /api/v1/pentest/campaigns/{id}/findings",
		},
		mustNot: []string{"POST /api/v1/simulations/{id}/run", "POST /api/v1/scans/quick", "PATCH /api/v1/findings/{id}/status"},
	},
	"external-tester": {
		must: []string{
			"GET /api/v1/pentest/campaigns", "POST /api/v1/pentest/campaigns/{id}/findings", "POST /api/v1/attachments",
			"POST /api/v1/pentest/findings/{findingId}/retests",
		},
		mustNot: []string{"GET /api/v1/findings", "GET /api/v1/simulations", "POST /api/v1/pentest/campaigns"},
	},
	"bounty-triager": {
		must:    []string{"PATCH /api/v1/findings/{id}/status", "POST /api/v1/findings/{id}/duplicates", "PUT /api/v1/findings/{id}/bounty-report"},
		mustNot: []string{"POST /api/v1/approvals/{id}/approve", "PUT /api/v1/programs/{id}/scope"},
	},
	"threat-intel-analyst": {
		must:    []string{"POST /api/v1/attacker-profiles", "POST /api/v1/iocs", "POST /api/v1/credentials/import", "POST /api/v1/emerging-threats/{id}/state"},
		mustNot: []string{"POST /api/v1/credentials/{id}/reveal"},
	},
	"risk-approver": {
		must: []string{
			"POST /api/v1/approvals/{id}/approve", "POST /api/v1/suppressions/{id}/approve", "POST /api/v1/exposures/{id}/accept",
			"POST /api/v1/compliance/controls/{id}/assess",
		},
		mustNot: []string{"PATCH /api/v1/findings/{id}/status", "POST /api/v1/findings/{id}/approvals", "POST /api/v1/exposures/{id}/resolve", "POST /api/v1/suppressions"},
	},
	"auditor": {
		must:    []string{"GET /api/v1/audit-logs", "POST /api/v1/findings/export", "GET /api/v1/simulations"},
		mustNot: []string{"POST /api/v1/findings/{id}/comments", "PATCH /api/v1/findings/{id}/status"},
	},
}

func TestRoleTemplates_PersonaFlows(t *testing.T) {
	ref := buildRef(t)
	gates := map[string]Gate{}
	for _, f := range ref.Features {
		for _, r := range f.Routes {
			gates[r.Method+" "+r.Path] = r.Gate
		}
	}
	roles := templateRoles(t, ref)
	for id, flow := range templateFlows {
		role, ok := roles[id]
		if !ok {
			t.Errorf("no template %s", id)
			continue
		}
		for _, key := range flow.must {
			g, ok := gates[key]
			if !ok {
				t.Errorf("%s: route %s not found", id, key)
				continue
			}
			if !role.Passes(g) {
				t.Errorf("%s cannot %s (gate %+v)", id, key, g)
			}
		}
		for _, key := range flow.mustNot {
			g, ok := gates[key]
			if !ok {
				t.Errorf("%s: route %s not found", id, key)
				continue
			}
			if role.Passes(g) {
				t.Errorf("%s can %s", id, key)
			}
		}
	}
}
