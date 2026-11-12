package server

// The negative matrix: organization B's owner names organization A's ids on
// bulk and by-id routes. See xorg_stack_db_test.go for the contract.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// xoCase is one request. $1, $2 in path and body stand for the ids setup
// returns; the same request with fresh random ids is the "unknown" answer B's
// answer must equal.
type xoCase struct {
	name   string
	method string
	path   string
	body   string
	setup  func(h *xoStack) []string
	// controlSetup, when set, seeds what A's control uses: a case that mixes
	// B's own row with A's id has no A-only equivalent to reuse.
	controlSetup func(h *xoStack) []string
	// foreign lists the 1-based positions of the ids that belong to A; the
	// "unknown" request replaces only those (all when empty).
	foreign []int
	// controlStatus is what A gets for the same request; zero means any 2xx.
	// A control that fails means the request itself is wrong (vacuous case).
	controlStatus []int
	// controlMayMissRow lets A's control answer "not found" (a route that
	// reports a different missing thing); the case is then weaker.
	controlMayMissRow bool
	// area counts the case in the report ("bulk", "detail", "untraced").
	area string
}

func (c xoCase) render(s string, ids []string) string {
	for i, id := range ids {
		s = strings.ReplaceAll(s, "$"+string(rune('1'+i)), id)
	}
	return s
}

func xoIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = shared.NewID().String()
	}
	return out
}

func xoRunMatrix(t *testing.T, cases []xoCase) {
	t.Helper()
	h := newXOStack(t)
	victims := make([][]string, len(cases))
	controls := make([][]string, len(cases))
	for i, c := range cases {
		victims[i] = c.setup(h)
		controls[i] = victims[i]
		if c.controlSetup != nil {
			controls[i] = c.controlSetup(h)
		}
	}
	before := h.tenantDigest(h.tenantA)
	if len(before) == 0 {
		t.Fatal("fixture: organization A owns no rows")
	}

	for i, c := range cases {
		t.Run("B/"+c.name, func(t *testing.T) {
			vIDs := victims[i]
			uIDs := xoIDs(len(vIDs))
			if len(c.foreign) > 0 {
				uIDs = append([]string(nil), vIDs...)
				for _, p := range c.foreign {
					uIDs[p-1] = shared.NewID().String()
				}
			}
			vs, vb := h.call(h.tokenB, c.method, c.render(c.path, vIDs), c.render(c.body, vIDs))
			us, ub := h.call(h.tokenB, c.method, c.render(c.path, uIDs), c.render(c.body, uIDs))
			t.Logf("B with A's id: %d %.400s", vs, vb)
			if strings.Contains(vb, xoMarker) {
				t.Errorf("B received A's data: %.300s", vb)
			}
			if vs != us || xoNormalize(vb) != xoNormalize(ub) {
				t.Errorf("A's id answered %d %.200s, an unknown id %d %.200s: B must not tell them apart", vs, vb, us, ub)
			}
			if us == http.StatusForbidden || us == http.StatusUnauthorized || us >= 500 {
				t.Errorf("unknown id answered %d %.200s: the case never reached the tenant-scoped lookup", us, ub)
			}
			if d := xoDiffDigest(before, h.tenantDigest(h.tenantA)); len(d) > 0 {
				t.Errorf("A's rows changed in tables %v after B's request", d)
				before = h.tenantDigest(h.tenantA)
			}
		})
	}

	// The controls run after every B attempt: A can reach each row, so a 404
	// for B was isolation and not a malformed request.
	for i, c := range cases {
		t.Run("A/"+c.name, func(t *testing.T) {
			vIDs := controls[i]
			status, body := h.call(h.tokenA, c.method, c.render(c.path, vIDs), c.render(c.body, vIDs))
			t.Logf("A with its own id: %d %.400s", status, body)
			ok := status/100 == 2
			if len(c.controlStatus) > 0 {
				ok = false
				for _, w := range c.controlStatus {
					ok = ok || status == w
				}
			}
			lower := strings.ToLower(body)
			if (strings.Contains(lower, "not found") && !c.controlMayMissRow) || strings.Contains(lower, "invalid request body") {
				ok = false
			}
			if !ok {
				t.Errorf("control: A's own request answered %d %.300s: the case does not exercise the route", status, body)
			}
		})
	}
}

func xoOne(f func(h *xoStack) string) func(h *xoStack) []string {
	return func(h *xoStack) []string { return []string{f(h)} }
}

func xoSeq(fs ...func(h *xoStack) string) func(h *xoStack) []string {
	return func(h *xoStack) []string {
		out := make([]string, len(fs))
		for i, f := range fs {
			out[i] = f(h)
		}
		return out
	}
}

func (h *xoStack) scanA() string       { return h.seedScan(h.tenantA) }
func (h *xoStack) assetA() string      { return h.seedAsset(h.tenantA) }
func (h *xoStack) findingA() string    { return h.seedFinding(h.tenantA, h.seedAsset(h.tenantA)) }
func (h *xoStack) groupA() string      { return h.seedAssetGroup(h.tenantA) }
func (h *xoStack) targetA() string     { return h.seedScopeTarget(h.tenantA) }
func (h *xoStack) exclusionA() string  { return h.seedScopeExclusion(h.tenantA) }
func (h *xoStack) taskA() string       { return h.seedRemediationTask(h.tenantA) }
func (h *xoStack) suggestionA() string { return h.seedSuggestion(h.tenantA) }

func TestCrossOrg_Matrix_Bulk(t *testing.T) {
	scan, asset, finding := xoOne((*xoStack).scanA), xoOne((*xoStack).assetA), xoOne((*xoStack).findingA)
	group, target, excl := xoOne((*xoStack).groupA), xoOne((*xoStack).targetA), xoOne((*xoStack).exclusionA)
	cases := []xoCase{
		{name: "scans bulk activate", method: "POST", path: "/api/v1/scans/bulk/activate", body: `{"scan_ids":["$1"]}`, setup: scan},
		{name: "scans bulk pause", method: "POST", path: "/api/v1/scans/bulk/pause", body: `{"scan_ids":["$1"]}`, setup: scan},
		{name: "scans bulk disable", method: "POST", path: "/api/v1/scans/bulk/disable", body: `{"scan_ids":["$1"]}`, setup: scan},
		{name: "scans bulk delete", method: "POST", path: "/api/v1/scans/bulk/delete", body: `{"scan_ids":["$1"]}`, setup: scan},
		{name: "asset groups bulk update", method: "PATCH", path: "/api/v1/asset-groups/bulk", body: `{"group_ids":["$1"],"update":{"criticality":"high"}}`, setup: group},
		{name: "asset groups bulk delete", method: "DELETE", path: "/api/v1/asset-groups/bulk", body: `{"group_ids":["$1"]}`, setup: group},
		{name: "scope targets bulk delete", method: "POST", path: "/api/v1/scope/targets/bulk/delete", body: `{"target_ids":["$1"]}`, setup: target},
		{name: "scope exclusions bulk delete", method: "POST", path: "/api/v1/scope/exclusions/bulk/delete", body: `{"exclusion_ids":["$1"]}`, setup: excl},
		{name: "findings bulk status", method: "POST", path: "/api/v1/findings/bulk/status", body: `{"finding_ids":["$1"],"status":"in_progress"}`, setup: finding},
		{name: "findings bulk assign", method: "POST", path: "/api/v1/findings/bulk/assign", body: `{"finding_ids":["$1"],"user_id":"@self"}`, setup: finding},
		{name: "assets bulk status", method: "POST", path: "/api/v1/assets/bulk/status", body: `{"asset_ids":["$1"],"status":"inactive"}`, setup: asset},
		{name: "assets bulk sync", method: "POST", path: "/api/v1/assets/bulk/sync", body: `{"asset_ids":["$1"]}`, setup: asset},
		{name: "remediation suggestions bulk approve", method: "POST", path: "/api/v1/remediation/suggestions/approve", body: `{"ids":["$1"]}`, setup: xoOne((*xoStack).suggestionA)},
	}
	for i := range cases {
		cases[i].area = "bulk"
	}
	xoRunMatrix(t, cases)
}

func TestCrossOrg_Matrix_Detail(t *testing.T) {
	scan, asset, finding := xoOne((*xoStack).scanA), xoOne((*xoStack).assetA), xoOne((*xoStack).findingA)
	group := xoOne((*xoStack).groupA)
	task := xoOne((*xoStack).taskA)
	view := xoOne(func(h *xoStack) string { return h.seedSavedView(h.tenantA, h.userA) })
	dash := xoOne(func(h *xoStack) string { return h.seedDashboard(h.tenantA, h.userA) })
	key := xoOne(func(h *xoStack) string { return h.seedAPIKey(h.tenantA, h.userA) })
	scanRun := xoSeq((*xoStack).scanA, func(h *xoStack) string { return "" })
	_ = scanRun
	cases := []xoCase{
		{name: "finding get", method: "GET", path: "/api/v1/findings/$1", setup: finding},
		{name: "finding status", method: "PATCH", path: "/api/v1/findings/$1/status", body: `{"status":"in_progress"}`, setup: finding},
		{name: "finding assign", method: "POST", path: "/api/v1/findings/$1/assign", body: `{"user_id":"@self"}`, setup: finding},
		{name: "finding severity", method: "PATCH", path: "/api/v1/findings/$1/severity", body: `{"severity":"low","reason":"xo test reason"}`, setup: finding},
		{name: "finding delete", method: "DELETE", path: "/api/v1/findings/$1", setup: finding},
		{name: "asset get", method: "GET", path: "/api/v1/assets/$1", setup: asset},
		{name: "asset update", method: "PUT", path: "/api/v1/assets/$1", body: `{"name":"xo-renamed.example.com"}`, setup: asset},
		{name: "asset crown jewel", method: "PATCH", path: "/api/v1/assets/$1/crown-jewel", body: `{"is_crown_jewel":true}`, setup: asset},
		{name: "asset archive", method: "POST", path: "/api/v1/assets/$1/archive", setup: asset},
		{name: "asset delete", method: "DELETE", path: "/api/v1/assets/$1", setup: asset},
		{name: "asset group get", method: "GET", path: "/api/v1/asset-groups/$1", setup: group},
		{name: "asset group update", method: "PUT", path: "/api/v1/asset-groups/$1", body: `{"name":"xo-renamed-group"}`, setup: group},
		{name: "asset group delete", method: "DELETE", path: "/api/v1/asset-groups/$1", setup: group},
		{name: "scan get", method: "GET", path: "/api/v1/scans/$1", setup: scan},
		{name: "scan update", method: "PUT", path: "/api/v1/scans/$1", body: `{"name":"xo-renamed-scan"}`, setup: scan},
		{name: "scan pause", method: "POST", path: "/api/v1/scans/$1/pause", setup: scan},
		{name: "scan delete", method: "DELETE", path: "/api/v1/scans/$1", setup: scan},
		{name: "remediation task get", method: "GET", path: "/api/v1/remediation/tasks/$1", setup: task},
		{name: "remediation task update", method: "PATCH", path: "/api/v1/remediation/tasks/$1", body: `{"title":"xo-renamed-task","version":1}`, setup: task},
		{name: "saved view get", method: "GET", path: "/api/v1/views/$1", setup: view},
		{name: "saved view update", method: "PUT", path: "/api/v1/views/$1", body: `{"name":"xo-renamed-view"}`, setup: view},
		{name: "saved view delete", method: "DELETE", path: "/api/v1/views/$1", setup: view},
		{name: "personal dashboard get", method: "GET", path: "/api/v1/me/dashboards/$1", setup: dash},
		{name: "personal dashboard update", method: "PUT", path: "/api/v1/me/dashboards/$1", body: `{"name":"xo-renamed-dash"}`, setup: dash},
		{name: "personal dashboard delete", method: "DELETE", path: "/api/v1/me/dashboards/$1", setup: dash},
		{name: "api key get", method: "GET", path: "/api/v1/api-keys/$1", setup: key},
		{name: "api key revoke", method: "POST", path: "/api/v1/api-keys/$1/revoke", setup: key},
		{name: "api key delete", method: "DELETE", path: "/api/v1/api-keys/$1", setup: key},
	}
	for i := range cases {
		cases[i].area = "detail"
	}
	xoRunMatrix(t, cases)
}

func TestCrossOrg_Matrix_Untraced(t *testing.T) {
	lead := xoOne(func(h *xoStack) string { return h.seedLead(h.tenantA, h.seedAsset(h.tenantA)) })
	waiting := xoOne(func(h *xoStack) string { return h.seedWaitingLead(h.tenantA, h.seedAsset(h.tenantA)) })
	evidence := func(h *xoStack) []string {
		f := h.findingA()
		return []string{f, h.seedEvidenceItem(h.tenantA, f)}
	}
	policy := xoOne(func(h *xoStack) string { return h.seedScanWindowPolicy(h.tenantA) })
	override := xoOne(func(h *xoStack) string { return h.seedScanWindowOverride(h.tenantA) })
	connector := func(h *xoStack) []string { return []string{h.seedConnector(h.tenantA), h.assetA()} }
	cases := []xoCase{
		{name: "lead get", method: "GET", path: "/api/v1/exploration/leads/$1", setup: lead},
		{name: "lead dismiss", method: "POST", path: "/api/v1/exploration/leads/reject", body: `{"ids":["$1"],"reason":"xo"}`, setup: lead},
		{name: "lead approve", method: "POST", path: "/api/v1/exploration/leads/approve", body: `{"ids":["$1"]}`, setup: waiting},

		{name: "evidence items list", method: "GET", path: "/api/v1/findings/$1/evidence-items", setup: evidence},
		{name: "evidence item update", method: "PATCH", path: "/api/v1/findings/$1/evidence-items/$2", body: `{"role":"proof"}`, setup: evidence},
		{name: "evidence items reorder", method: "PUT", path: "/api/v1/findings/$1/evidence-items/order", body: `{"item_ids":["$2"]}`, setup: evidence},
		{name: "evidence item reveal", method: "POST", path: "/api/v1/findings/$1/evidence-items/$2/reveal", body: `{"placeholders":["x"]}`, setup: evidence, controlStatus: []int{400, 404, 410}, controlMayMissRow: true},

		{name: "scan window policy get", method: "GET", path: "/api/v1/scan-window-policies/$1", setup: policy},
		{name: "scan window policy update", method: "PATCH", path: "/api/v1/scan-window-policies/$1", body: `{"description":"xo"}`, setup: policy},
		{name: "scan window policy delete", method: "DELETE", path: "/api/v1/scan-window-policies/$1", setup: policy},
		{name: "scan window override revoke", method: "DELETE", path: "/api/v1/scan-window-overrides/$1", setup: override},
		{name: "scan window evaluate asset", method: "POST", path: "/api/v1/scan-windows/preview", body: `{"asset_ids":["$1"]}`, setup: xoOne((*xoStack).assetA)},
		{name: "scan window override on a policy", method: "POST", path: "/api/v1/scan-window-overrides", body: `{"policy_id":"$1","reason":"xo test reason long","duration_minutes":30,"totp_code":"000000"}`,
			setup: policy, controlStatus: []int{400, 403, 422}},
		{name: "scan window policy selecting a group", method: "POST", path: "/api/v1/scan-window-policies",
			body:  `{"name":"xo-policy-$1","kind":"blackout","timezone":"UTC","selector":{"asset_group_ids":["$1"]},"slots":[{"days":[1],"start":"00:00","end":"01:00"}]}`,
			setup: xoOne((*xoStack).groupA)},

		{name: "connector scan now of another organization's connector", method: "POST", path: "/api/v1/integrations/$1/scans/run", body: `{"asset_ids":["$2"]}`,
			setup: connector, controlStatus: []int{200, 201, 400, 409, 422, 503}},
		// B's own connector, A's asset: the connector resolves, the asset must not.
		{name: "connector scan now of another organization's asset", method: "POST", path: "/api/v1/integrations/$1/scans/run", body: `{"asset_ids":["$2"]}`,
			setup:        func(h *xoStack) []string { return []string{h.seedConnector(h.tenantB), h.assetA()} },
			controlSetup: connector, foreign: []int{2}, controlStatus: []int{200, 201, 400, 409, 422, 503}},
		// B's own finding with A's evidence item.
		{name: "evidence item of another organization's finding", method: "PATCH", path: "/api/v1/findings/$1/evidence-items/$2", body: `{"role":"proof"}`,
			setup: func(h *xoStack) []string {
				return []string{h.seedFinding(h.tenantB, h.seedAsset(h.tenantB)), h.seedEvidenceItem(h.tenantA, h.findingA())}
			},
			controlSetup: evidence, foreign: []int{2}},
	}
	for i := range cases {
		cases[i].area = "untraced"
	}
	xoRunMatrix(t, cases)
}

func TestCrossOrg_Matrix_RunsApprovalsWebhooks(t *testing.T) {
	run := func(h *xoStack) []string { s := h.scanA(); return []string{h.seedScanRun(h.tenantA, s)} }
	scanRun := func(h *xoStack) []string { s := h.scanA(); return []string{s, h.seedScanRun(h.tenantA, s)} }
	approval := xoOne(func(h *xoStack) string {
		return h.seedApproval(h.tenantA, h.findingA(), h.userA)
	})
	batch := xoOne(func(h *xoStack) string { return h.seedApprovalBatch(h.tenantA, h.userA) })
	jira := xoOne(func(h *xoStack) string { return h.seedIntegration(h.tenantA, "ticketing", "jira") })
	github := xoOne(func(h *xoStack) string { return h.seedIntegration(h.tenantA, "scm", "github") })
	notif := xoOne(func(h *xoStack) string { return h.seedIntegration(h.tenantA, "notification", "webhook") })
	role := xoOne(func(h *xoStack) string { return h.seedRole(h.tenantA) })
	group := xoOne((*xoStack).seedAccessGroupA)
	cases := []xoCase{
		{name: "scan run get", method: "GET", path: "/api/v1/scan-runs/$1", setup: run},
		{name: "scan run tasks", method: "GET", path: "/api/v1/scan-runs/$1/tasks", setup: run},
		{name: "scan run stages", method: "GET", path: "/api/v1/scan-runs/$1/stages", setup: run},
		{name: "scan run events", method: "GET", path: "/api/v1/scan-runs/$1/events", setup: run},
		{name: "scan run map", method: "GET", path: "/api/v1/scan-runs/$1/map", setup: run},
		{name: "scan run outputs", method: "GET", path: "/api/v1/scan-runs/$1/outputs?step_key=xo", setup: run, controlStatus: []int{200, 404}, controlMayMissRow: true},
		{name: "scan run scope snapshot", method: "GET", path: "/api/v1/scan-runs/$1/scope-snapshot", setup: run, controlStatus: []int{200, 204, 404}, controlMayMissRow: true},
		{name: "scan run cancel", method: "POST", path: "/api/v1/scan-runs/$1/cancel", setup: func(h *xoStack) []string {
			s := h.scanA()
			id := h.seedScanRun(h.tenantA, s)
			h.exec(`UPDATE scan_runs SET status = 'running', started_at = now() WHERE id = $1`, id)
			return []string{id}
		}},
		{name: "scan runs of a scan", method: "GET", path: "/api/v1/scans/$1/runs", setup: scanRun},
		{name: "scan run through its scan", method: "GET", path: "/api/v1/scans/$1/runs/$2", setup: scanRun},
		// B's own scan, A's run.
		{name: "scan run of another organization through B's scan", method: "GET", path: "/api/v1/scans/$1/runs/$2",
			setup:        func(h *xoStack) []string { return []string{h.seedScan(h.tenantB), h.seedScanRun(h.tenantA, h.scanA())} },
			controlSetup: scanRun, foreign: []int{2}},

		{name: "approval reject", method: "POST", path: "/api/v1/approvals/$1/reject", body: `{"reason":"xo"}`, setup: approval},
		{name: "approval cancel", method: "POST", path: "/api/v1/approvals/$1/cancel", setup: approval},
		{name: "approval remind", method: "POST", path: "/api/v1/approvals/$1/remind", setup: approval, controlStatus: []int{200, 202, 204, 400, 409, 429}},
		{name: "approval batch get", method: "GET", path: "/api/v1/approvals/batches/$1", setup: batch},
		{name: "approval batch reject", method: "POST", path: "/api/v1/approvals/batches/$1/reject", body: `{"reason":"xo"}`, setup: batch},
		{name: "approval batch cancel", method: "POST", path: "/api/v1/approvals/batches/$1/cancel", setup: batch},
		{name: "remediation task exception preview", method: "POST", path: "/api/v1/remediation/tasks/$1/exception/preview", body: `{"version":1,"requested_status":"accepted","closure_reason":"risk_accepted","justification":"xo justification of more than twenty characters"}`, setup: xoOne((*xoStack).taskA), controlStatus: []int{200, 400, 409, 422}},
		{name: "remediation task members", method: "GET", path: "/api/v1/remediation/tasks/$1/members", setup: xoOne((*xoStack).taskA)},
		{name: "remediation task timeline", method: "GET", path: "/api/v1/remediation/tasks/$1/timeline", setup: xoOne((*xoStack).taskA)},
		{name: "remediation suggestion approve", method: "POST", path: "/api/v1/remediation/suggestions/$1/approve", body: `{"version":1}`, setup: xoOne((*xoStack).suggestionA), controlStatus: []int{200, 201, 400, 409, 422}},

		{name: "jira webhook config", method: "GET", path: "/api/v1/integrations/$1/jira-webhook", setup: jira},
		{name: "jira webhook secret rotate", method: "POST", path: "/api/v1/integrations/$1/jira-webhook/secret/rotate", setup: jira},
		{name: "github webhook config", method: "GET", path: "/api/v1/integrations/$1/github-webhook", setup: github},
		{name: "github webhook secret rotate", method: "POST", path: "/api/v1/integrations/$1/github-webhook/secret/rotate", setup: github},
		{name: "signing secret read", method: "GET", path: "/api/v1/integrations/$1/signing-secret", setup: notif},
		{name: "signing secret rotate", method: "POST", path: "/api/v1/integrations/$1/signing-secret/rotate", setup: notif},
		{name: "integration get", method: "GET", path: "/api/v1/integrations/$1", setup: notif},
		{name: "integration test notification", method: "POST", path: "/api/v1/integrations/$1/test-notification", setup: notif, controlStatus: []int{200, 202, 400, 409, 422, 500, 502}},

		{name: "role get", method: "GET", path: "/api/v1/roles/$1", setup: role},
		{name: "role members bulk", method: "POST", path: "/api/v1/roles/$1/members/bulk", body: `{"user_ids":["@self"]}`, setup: role, controlStatus: []int{200, 400, 409}},
		{name: "access group get", method: "GET", path: "/api/v1/groups/$1", setup: group},
		{name: "access group assets bulk", method: "POST", path: "/api/v1/groups/$1/assets/bulk", body: `{"asset_ids":["$2"],"ownership_type":"secondary"}`,
			setup: func(h *xoStack) []string { return []string{h.seedAccessGroup(h.tenantA), h.assetA()} }, controlStatus: []int{200}},
		// B's own team, A's asset.
		{name: "asset of another organization into B's team", method: "POST", path: "/api/v1/groups/$1/assets/bulk", body: `{"asset_ids":["$2"],"ownership_type":"secondary"}`,
			setup:        func(h *xoStack) []string { return []string{h.seedAccessGroup(h.tenantB), h.assetA()} },
			controlSetup: func(h *xoStack) []string { return []string{h.seedAccessGroup(h.tenantA), h.assetA()} }, foreign: []int{2}},
	}
	for i := range cases {
		cases[i].area = "detail"
	}
	xoRunMatrix(t, cases)
}

func TestCrossOrg_Matrix_FindingBulkByFilter(t *testing.T) {
	// The filter names A's asset: B's count of matches is zero, which is what
	// an unknown asset gives too.
	asset := func(h *xoStack) []string {
		a := h.assetA()
		h.seedFinding(h.tenantA, a)
		return []string{a}
	}
	cases := []xoCase{
		{name: "findings bulk status by filter", method: "POST", path: "/api/v1/findings/bulk/by-filter/status",
			body: `{"filter":{"asset_id":"$1"},"expected_count":1,"status":"in_progress"}`, setup: asset, controlStatus: []int{200, 202}},
		{name: "findings bulk assignee by filter", method: "POST", path: "/api/v1/findings/bulk/by-filter/assignee",
			body: `{"filter":{"asset_id":"$1"},"expected_count":1,"user_id":"@self"}`, setup: asset, controlStatus: []int{200, 202}},
		{name: "findings ai triage bulk", method: "POST", path: "/api/v1/findings/ai-triage/bulk", body: `{"finding_ids":["$1"]}`,
			setup:         func(h *xoStack) []string { h.enableAITriage(h.tenantA, h.tenantB); return []string{h.findingA()} },
			controlStatus: []int{200, 202, 400, 409, 422, 503}, controlMayMissRow: true},
	}
	for i := range cases {
		cases[i].area = "bulk"
	}
	xoRunMatrix(t, cases)
}

// Branches are keyed by repository, not by tenant: the repository asset's
// ownership decides. The service takes bare ids, so the routes are the proof.
func TestCrossOrg_Matrix_Branches(t *testing.T) {
	branch := func(h *xoStack) []string {
		r := h.seedRepository(h.tenantA)
		return []string{r, h.seedBranch(r, false)}
	}
	defaultBranch := func(h *xoStack) []string {
		r := h.seedRepository(h.tenantA)
		h.seedBranch(r, true)
		return []string{r, h.seedBranch(r, false)}
	}
	cases := []xoCase{
		{name: "branch get", method: "GET", path: "/api/v1/repositories/$1/branches/$2", setup: branch},
		{name: "branch update", method: "PUT", path: "/api/v1/repositories/$1/branches/$2", body: `{"is_protected":true}`, setup: branch},
		{name: "branch delete", method: "DELETE", path: "/api/v1/repositories/$1/branches/$2", setup: branch},
		{name: "branch list", method: "GET", path: "/api/v1/repositories/$1/branches", setup: branch},
		{name: "default branch get", method: "GET", path: "/api/v1/repositories/$1/branches/default", setup: defaultBranch},
		{name: "default branch set", method: "PUT", path: "/api/v1/repositories/$1/branches/$2/default", setup: defaultBranch},
		// B's own repository, A's branch id.
		{name: "branch of another organization through B's repository", method: "GET", path: "/api/v1/repositories/$1/branches/$2",
			setup: func(h *xoStack) []string {
				return []string{h.seedRepository(h.tenantB), h.seedBranch(h.seedRepository(h.tenantA), false)}
			},
			controlSetup: branch, foreign: []int{2}},
		{name: "branch delete of another organization through B's repository", method: "DELETE", path: "/api/v1/repositories/$1/branches/$2",
			setup: func(h *xoStack) []string {
				return []string{h.seedRepository(h.tenantB), h.seedBranch(h.seedRepository(h.tenantA), false)}
			},
			controlSetup: branch, foreign: []int{2}},
	}
	for i := range cases {
		cases[i].area = "detail"
	}
	xoRunMatrix(t, cases)
}
