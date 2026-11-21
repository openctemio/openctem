package routes

// GET /api/v1/commands: a command about a finding (an AI analysis job, a
// validate job, a retest's check) lists without its payload and result when
// the caller may not read that finding (findings:read and the finding in the
// caller's data scope), the same rule as its logs. The AI run routes answer
// 404 for such a finding; the commands list must not be a way around them.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

func TestCommands_ListPayloadFollowsFindingScope_DB(t *testing.T) {
	h := newCommandLogsReadHarness(t)
	tid := h.tenant()
	admin := h.member(tid, "admin")
	scoped := h.member(tid, "member")
	h.customRoleMember(scoped, tid, permission.CommandsRead, permission.FindingsRead)
	h.mintToken(&scoped, tid)
	noFindings := h.member(tid, "member")
	h.customRoleMember(noFindings, tid, permission.CommandsRead)
	h.mintToken(&noFindings, tid)

	finding, asset := h.scopedFinding(tid)

	// An AI analysis job: the finding's text travels in its payload, the
	// worker's answer in its result.
	analyze := uuid.NewString()
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, result, status)
	        VALUES ($1, $2, 'analyze', $3::jsonb, $4::jsonb, 'completed')`, analyze, tid,
		`{"job":{"bundle":{"text":"ANALYZE-BUNDLE-MARKER"}},"required_capabilities":["analyze.triage"]}`,
		`{"verdict":"ANALYZE-RESULT-MARKER"}`)
	h.exec(`INSERT INTO ai_runs (tenant_id, use_case, kind, subject_type, subject_id, executor, status, command_id)
	        VALUES ($1, 'triage', 'triage.v1', 'finding', $2, 'tenant_worker', 'failed', $3)`, tid, finding, analyze)
	// An analysis job whose run cannot be found is shown to nobody.
	orphan := uuid.NewString()
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status)
	        VALUES ($1, $2, 'analyze', $3::jsonb, 'completed')`, orphan, tid, `{"job":{"bundle":{"text":"ORPHAN-MARKER"}}}`)
	// A validate job names its finding in the payload.
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status) VALUES ($1, $2, 'validate', $3::jsonb, 'completed')`,
		uuid.NewString(), tid, `{"finding_id":"`+finding+`","note":"VALIDATE-MARKER"}`)
	// A retest's check command is a scan command tied to the finding.
	retest := uuid.NewString()
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status) VALUES ($1, $2, 'scan', $3::jsonb, 'completed')`,
		retest, tid, `{"scanner":"nuclei","target":"RETEST-MARKER"}`)
	h.exec(`INSERT INTO finding_retests (id, tenant_id, finding_id, trigger, prior_status, template_id, target, deadline_at, check_command_id)
	        VALUES ($1, $2, $3, 'manual', 'confirmed', 'tpl', 'https://a.example', now() + interval '1 hour', $4)`,
		uuid.NewString(), tid, finding, retest)
	// A command about no finding keeps its payload for every reader.
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status) VALUES ($1, $2, 'health_check', $3::jsonb, 'completed')`,
		uuid.NewString(), tid, `{"probe":"HEALTH-MARKER"}`)

	const path = "/api/v1/commands?per_page=100"
	findingMarkers := []string{"ANALYZE-BUNDLE-MARKER", "ANALYZE-RESULT-MARKER", "VALIDATE-MARKER", "RETEST-MARKER"}
	check := func(who string, body string, wantFinding bool) {
		t.Helper()
		if !strings.Contains(body, analyze) || !strings.Contains(body, retest) {
			t.Fatalf("%s: the commands themselves are not listed: %s", who, body)
		}
		if !strings.Contains(body, "HEALTH-MARKER") {
			t.Fatalf("%s: a command about no finding lost its payload", who)
		}
		for _, m := range findingMarkers {
			if got := strings.Contains(body, m); got != wantFinding {
				t.Fatalf("%s: %s shown = %v, want %v", who, m, got, wantFinding)
			}
		}
		if strings.Contains(body, "ORPHAN-MARKER") {
			t.Fatalf("%s: an analysis job without its run shows its payload", who)
		}
	}

	// SECURITY: outside the caller's data scope, or without findings:read,
	// the finding's content is not in the list.
	check("member out of scope", h.expect(scoped, http.MethodGet, path, "", http.StatusOK), false)
	check("member without findings:read", h.expect(noFindings, http.MethodGet, path, "", http.StatusOK), false)

	check("admin", h.expect(admin, http.MethodGet, path, "", http.StatusOK), true)

	// In scope: shown.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`, scoped.id, tid, asset)
	check("member in scope", h.expect(scoped, http.MethodGet, path, "", http.StatusOK), true)

	// The logs of the analysis job follow the same rule.
	h.expect(noFindings, http.MethodGet, "/api/v1/commands/"+analyze+"/logs", "", http.StatusNotFound)
}
