package handler

// Guardrails against real Postgres (RFC-125 D9, D14):
//   - a request action only creates a pending request: with the
//     organization's false-positive level off, a person holding the approve
//     permission decides their own false positive at once (control), while
//     the same request made by their live automation waits for a person;
//     the finding's status never changes;
//   - update_status refuses closing targets on save;
//   - a live run pauses at its change cap and continues on resume.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fpLevelOff struct{}

func (fpLevelOff) GetFindingApprovalSettings(context.Context, string) (*tenantdom.FindingApprovalSettings, error) {
	return &tenantdom.FindingApprovalSettings{FPApproval: tenantdom.FPApprovalOff}, nil
}

func TestWorkflowGuardrails_DB(t *testing.T) {
	f := newWFDB(t)
	f.vuln.SetApprovalRepository(postgres.NewFindingApprovalRepository(&postgres.DB{DB: f.raw}))
	f.vuln.SetSoloApproval(nil, nil, fpLevelOff{})
	// The level is read again from the organization's settings when a decision is written.
	f.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{finding_approvals}', '{"fp_approval":"off"}'::jsonb) WHERE id = $1`, f.tenantA)
	reason := string(vulnerability.PersonClosureReasons(vulnerability.FindingStatusFalsePositive)[0])
	statusOf := func(id string) string {
		var s string
		if err := f.raw.QueryRow(`SELECT status FROM findings WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// An internal, low-criticality asset: nothing makes its finding material.
	assetLow, fIn2 := shared.NewID().String(), shared.NewID().String()
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'private', 'low')`,
		assetLow, f.tenantA, "wfd-low-"+assetLow+".example.com")
	f.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		VALUES ($1, $2, $3, 'manual', 'wfd', 'low', 'wfd', $4)`, fIn2, f.tenantA, assetLow, "wfd-"+fIn2)

	t.Run("control: a person decides their own false positive at level off", func(t *testing.T) {
		ctx := f.as(f.admin, http.MethodPost, "", nil).Context()
		a, err := f.vuln.RequestApproval(ctx, findingapp.RequestApprovalInput{
			TenantID: f.tenantA, FindingID: fIn2, RequestedStatus: "false_positive", Justification: "scanner noise on a test host",
			RequestedBy: f.admin, ClosureReason: reason, CanApprove: true,
		})
		if err != nil {
			t.Fatalf("person's request: %v", err)
		}
		if a.Status != vulnerability.ApprovalStatusApproved || statusOf(fIn2) != "false_positive" {
			t.Fatalf("control: approval %s finding %s, want decided at once", a.Status, statusOf(fIn2))
		}
	})

	t.Run("a rule's request waits for a person even at level off", func(t *testing.T) {
		nodes := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
			{"node_key":"r","node_type":"action","name":"r","config":{"action_type":"request_false_positive","action_config":{"closure_reason":"` + reason + `","justification":"automation: scanner noise on a test host"}}}]`
		wf := f.create(nodes, `[{"source_node_key":"t","target_node_key":"r"}]`)
		f.stepUp.set(f.admin, true)
		defer f.stepUp.set(f.admin, false)
		s, b := f.call(f.h.Publish, f.as(f.admin, http.MethodPost, `{}`, map[string]string{"id": wf}))
		if s != http.StatusAccepted {
			t.Fatalf("request actions are high risk: publish = %d %s, want 202", s, b)
		}
		var pending PublishPendingResponse
		_ = json.Unmarshal([]byte(b), &pending)
		// A second person approves; the version goes live and acts as the
		// publisher (the admin, who holds findings:approve).
		f.stepUp.set(f.operator, true)
		if s, b := f.call(f.h.ApproveVersion, f.as(f.operator, http.MethodPost, `{"digest":"`+pending.Version.Digest+`"}`,
			map[string]string{"id": wf, "versionId": pending.Version.ID})); s != http.StatusOK {
			t.Fatalf("approve = %d %s", s, b)
		}
		run := f.eventRun(wf, f.fIn)
		if st := f.execute(run.ID); st != "completed" {
			var msg string
			_ = f.raw.QueryRow(`SELECT COALESCE(string_agg(error_message, '; '), '') FROM automation_run_steps WHERE automation_run_id = $1`, run.ID.String()).Scan(&msg)
			t.Fatalf("live run = %s (%s)", st, msg)
		}
		var status string
		if err := f.raw.QueryRow(`SELECT status FROM finding_status_approvals WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 1`, f.fIn).Scan(&status); err != nil {
			t.Fatalf("read the request: %v", err)
		}
		if status != "pending" {
			t.Fatalf("a rule's false-positive request is %s at level off, want pending: an automation never closes risk", status)
		}
		if statusOf(f.fIn) == "false_positive" {
			t.Fatal("the rule changed the finding's status")
		}
	})

	t.Run("update_status refuses closing targets", func(t *testing.T) {
		for _, target := range []string{"false_positive", "accepted", "resolved", "duplicate"} {
			nodes := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"manual"}},
				{"node_key":"s","node_type":"action","name":"s","config":{"action_type":"update_status","action_config":{"status":"` + target + `"}}}]`
			s, b := f.call(f.h.CreateWorkflow, f.as(f.admin, http.MethodPost,
				`{"name":"st `+target+`","nodes":`+nodes+`,"edges":[{"source_node_key":"t","target_node_key":"s"}]}`, nil))
			if s != http.StatusBadRequest || !strings.Contains(b, "AUTOMATION_STATUS_NOT_ALLOWED") {
				t.Errorf("update_status %s = %d %s, want 400 AUTOMATION_STATUS_NOT_ALLOWED", target, s, b)
			}
		}
	})

	t.Run("a live run pauses at its change cap and continues on resume", func(t *testing.T) {
		nodes := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
			{"node_key":"a1","node_type":"action","name":"a1","config":{"action_type":"add_tags","action_config":{"tags":["c1"]}}},
			{"node_key":"a2","node_type":"action","name":"a2","config":{"action_type":"add_tags","action_config":{"tags":["c2"]}}}]`
		s, b := f.call(f.h.CreateWorkflow, f.as(f.admin, http.MethodPost, `{"name":"cap","max_changes_per_run":1,"nodes":`+nodes+
			`,"edges":[{"source_node_key":"t","target_node_key":"a1"},{"source_node_key":"a1","target_node_key":"a2"}]}`, nil))
		if s != http.StatusCreated {
			t.Fatalf("create = %d %s", s, b)
		}
		var wfResp WorkflowResponse
		_ = json.Unmarshal([]byte(b), &wfResp)
		if wfResp.MaxChangesPerRun != 1 {
			t.Fatalf("max_changes_per_run = %d", wfResp.MaxChangesPerRun)
		}
		if s, b := f.call(f.h.Publish, f.as(f.admin, http.MethodPost, `{}`, map[string]string{"id": wfResp.ID})); s != http.StatusOK {
			t.Fatalf("publish = %d %s", s, b)
		}
		f.exec(`UPDATE findings SET tags = '{}' WHERE id = $1`, f.fIn)
		run := f.eventRun(wfResp.ID, f.fIn)
		if st := f.execute(run.ID); st != "paused" {
			t.Fatalf("run at its cap = %s, want paused", st)
		}
		if tags := f.tagsOf(f.fIn); !slices.Equal(tags, []string{"c1"}) {
			t.Fatalf("tags at the cap = %v, want only the first change", tags)
		}
		_, gb := f.call(f.h.GetRun, f.as(f.admin, http.MethodGet, "", map[string]string{"id": run.ID.String()}))
		if !strings.Contains(gb, `"pause_reason":"blast_radius"`) {
			t.Fatalf("paused run = %s", gb)
		}
		if err := f.svc.ResumeRun(f.ctx, shared.MustIDFromString(f.tenantA), shared.MustIDFromString(f.admin), run.ID); err != nil {
			t.Fatalf("resume: %v", err)
		}
		if st := f.execute(run.ID); st != "completed" {
			t.Fatalf("resumed run = %s", st)
		}
		if tags := f.tagsOf(f.fIn); !slices.Equal(tags, []string{"c1", "c2"}) {
			t.Fatalf("tags after resume = %v", tags)
		}
		if err := f.svc.ResumeRun(f.ctx, shared.MustIDFromString(f.tenantA), shared.MustIDFromString(f.admin), run.ID); err == nil {
			t.Fatal("a finished run resumed")
		}
	})
}
