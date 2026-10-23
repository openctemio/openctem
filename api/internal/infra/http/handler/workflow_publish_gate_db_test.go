package handler

// The go-live gate against real Postgres (RFC-125 D6):
//   - low risk publishes at once, without step-up;
//   - elevated needs a recent re-authentication (403 STEP_UP_REQUIRED);
//   - high risk (here: chaining on) waits for a second publisher: the
//     publisher cannot approve it, a wrong digest or a replaced request is
//     409 VERSION_CHANGED, another publisher's approval makes it live with
//     the publisher as owner;
//   - a draft with blocking problems is refused with the problems.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestWorkflowPublishGate_DB(t *testing.T) {
	f := newWFDB(t)
	admin2 := shared.NewID().String()
	f.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Second Admin')`, admin2, admin2+"@wfd.test")
	f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, admin2, f.tenantA)
	t.Cleanup(func() { _, _ = f.raw.Exec(`DELETE FROM users WHERE id = $1`, admin2) })
	asAdmin2 := func(method, body string, params map[string]string) *http.Request {
		r := f.as(f.admin, method, body, params)
		return r.WithContext(context.WithValue(r.Context(), middleware.UserIDKey, admin2))
	}
	publish := func(wf, user string) (int, string) {
		r := f.as(f.admin, http.MethodPost, `{}`, map[string]string{"id": wf})
		if user == admin2 {
			r = asAdmin2(http.MethodPost, `{}`, map[string]string{"id": wf})
		}
		return f.call(f.h.Publish, r)
	}
	detail := func(wf string) WorkflowResponse {
		_, b := f.call(f.h.GetWorkflow, f.as(f.admin, http.MethodGet, "", map[string]string{"id": wf}))
		var d WorkflowResponse
		_ = json.Unmarshal([]byte(b), &d)
		return d
	}

	t.Run("low risk publishes without step-up", func(t *testing.T) {
		wf := f.create(tagFlow("low"))
		if s, b := publish(wf, f.admin); s != http.StatusOK || detail(wf).Mode != "live" {
			t.Fatalf("low-risk publish = %d %s", s, b)
		}
	})

	t.Run("elevated needs step-up", func(t *testing.T) {
		wf := f.create(`[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
			{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"update_status","action_config":{"status":"confirmed"}}}]`,
			`[{"source_node_key":"t","target_node_key":"a"}]`)
		s, b := publish(wf, f.admin)
		if s != http.StatusForbidden || !strings.Contains(b, "STEP_UP_REQUIRED") {
			t.Fatalf("elevated publish without step-up = %d %s, want 403 STEP_UP_REQUIRED", s, b)
		}
		if detail(wf).Mode != "simulate" {
			t.Fatal("a refused publish went live")
		}
		f.stepUp.set(f.admin, true)
		defer f.stepUp.set(f.admin, false)
		if s, b := publish(wf, f.admin); s != http.StatusOK {
			t.Fatalf("elevated publish after step-up = %d %s", s, b)
		}
		d := detail(wf)
		if d.Mode != "live" || d.PublishedVersion == nil || d.PublishedVersion.StepUpAt == nil || d.PublishedVersion.RiskClass != "elevated" {
			t.Fatalf("after elevated publish = %+v", d.PublishedVersion)
		}
	})

	t.Run("high risk needs a second publisher", func(t *testing.T) {
		chain := func(tag string) string {
			return `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created","trigger_config":{"allow_automation_triggers":true}}},
				{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"add_tags","action_config":{"tags":["` + tag + `"]}}}]`
		}
		edges := `[{"source_node_key":"t","target_node_key":"a"}]`
		wf := f.create(chain("h1"), edges)
		f.stepUp.set(f.admin, true)
		f.stepUp.set(admin2, true)
		defer f.stepUp.set(f.admin, false)

		s, b := publish(wf, f.admin)
		if s != http.StatusAccepted {
			t.Fatalf("high-risk publish = %d %s, want 202", s, b)
		}
		var pending PublishPendingResponse
		_ = json.Unmarshal([]byte(b), &pending)
		if pending.Version == nil || pending.Version.Status != "pending_approval" || pending.Version.RiskClass != "high" {
			t.Fatalf("pending = %+v", pending.Version)
		}
		if d := detail(wf); d.Mode != "simulate" || d.PendingVersion == nil || d.PendingVersion.PublishedByName != "wfd" {
			t.Fatalf("before approval = mode %s pending %+v", d.Mode, d.PendingVersion)
		}
		approve := func(r *http.Request) (int, string) { return f.call(f.h.ApproveVersion, r) }
		params := map[string]string{"id": wf, "versionId": pending.Version.ID}
		body := `{"digest":"` + pending.Version.Digest + `"}`
		if s, b := approve(f.as(f.admin, http.MethodPost, body, params)); s != http.StatusForbidden || !strings.Contains(b, "SELF_APPROVAL") {
			t.Fatalf("self-approval = %d %s, want 403 SELF_APPROVAL", s, b)
		}
		wrong := `{"digest":"` + strings.Repeat("0", 64) + `"}`
		if s, b := approve(asAdmin2(http.MethodPost, wrong, params)); s != http.StatusConflict || !strings.Contains(b, "VERSION_CHANGED") {
			t.Fatalf("wrong digest = %d %s, want 409 VERSION_CHANGED", s, b)
		}
		f.stepUp.set(admin2, false)
		if s, b := approve(asAdmin2(http.MethodPost, body, params)); s != http.StatusForbidden || !strings.Contains(b, "STEP_UP_REQUIRED") {
			t.Fatalf("approval without step-up = %d %s", s, b)
		}
		f.stepUp.set(admin2, true)

		// A new request replaces the pending one: approving the old one is refused.
		if s, b := f.call(f.h.UpdateWorkflowGraph, f.as(f.admin, http.MethodPut, `{"nodes":`+chain("h2")+`,"edges":`+edges+`}`, map[string]string{"id": wf})); s != http.StatusOK {
			t.Fatalf("edit = %d %s", s, b)
		}
		s, b = publish(wf, f.admin)
		var second PublishPendingResponse
		_ = json.Unmarshal([]byte(b), &second)
		if s != http.StatusAccepted || second.Version == nil {
			t.Fatalf("second request = %d %s", s, b)
		}
		if s, b := approve(asAdmin2(http.MethodPost, body, params)); s != http.StatusConflict {
			t.Fatalf("approving a replaced request = %d %s, want 409", s, b)
		}
		params2 := map[string]string{"id": wf, "versionId": second.Version.ID}
		if s, b := approve(asAdmin2(http.MethodPost, `{"digest":"`+second.Version.Digest+`"}`, params2)); s != http.StatusOK {
			t.Fatalf("second publisher approves = %d %s", s, b)
		}
		d := detail(wf)
		if d.Mode != "live" || d.PublishedVersion == nil || d.PublishedVersion.ID != second.Version.ID ||
			d.PublishedVersion.ApprovedBy == nil || *d.PublishedVersion.ApprovedBy != admin2 || d.PublishedVersion.ApprovedByName != "Second Admin" {
			t.Fatalf("after approval = mode %s published %+v", d.Mode, d.PublishedVersion)
		}
		if d.CreatedBy == nil || *d.CreatedBy != f.admin {
			t.Fatalf("owner = %v, want the publisher", d.CreatedBy)
		}
	})

	t.Run("blocking problems refuse the publish", func(t *testing.T) {
		wf := f.create(`[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
			{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"add_tags","action_config":{}}}]`,
			`[{"source_node_key":"t","target_node_key":"a"}]`)
		s, b := publish(wf, f.admin)
		if s != http.StatusBadRequest || !strings.Contains(b, "WORKFLOW_INVALID") || !strings.Contains(b, "CONFIG_MISSING") {
			t.Fatalf("publish with a missing setting = %d %s", s, b)
		}
	})
}

// A request waiting for approval is withdrawn by an edit that changes what
// the draft does, so the second person never approves a version while the
// editor shows them something else; moving a node keeps it.
func TestWorkflowPublishGate_DraftEditWithdrawsRequest_DB(t *testing.T) {
	f := newWFDB(t)
	admin2 := shared.NewID().String()
	f.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Second Admin')`, admin2, admin2+"@wfd.test")
	f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, admin2, f.tenantA)
	t.Cleanup(func() { _, _ = f.raw.Exec(`DELETE FROM users WHERE id = $1`, admin2) })
	f.stepUp.set(f.admin, true)
	f.stepUp.set(admin2, true)
	chain := func(tag string, x int) string {
		return `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created","trigger_config":{"allow_automation_triggers":true}}},
			{"node_key":"a","node_type":"action","name":"a","ui_position":{"x":` + strconv.Itoa(x) + `,"y":0},"config":{"action_type":"add_tags","action_config":{"tags":["` + tag + `"]}}}]`
	}
	edges := `[{"source_node_key":"t","target_node_key":"a"}]`
	request := func(wf string) PublishPendingResponse {
		s, b := f.call(f.h.Publish, f.as(f.admin, http.MethodPost, `{}`, map[string]string{"id": wf}))
		var p PublishPendingResponse
		_ = json.Unmarshal([]byte(b), &p)
		if s != http.StatusAccepted || p.Version == nil {
			t.Fatalf("high-risk publish = %d %s", s, b)
		}
		return p
	}
	approve := func(wf string, p PublishPendingResponse) int {
		r := f.as(f.admin, http.MethodPost, `{"digest":"`+p.Version.Digest+`"}`, map[string]string{"id": wf, "versionId": p.Version.ID})
		r = r.WithContext(context.WithValue(r.Context(), middleware.UserIDKey, admin2))
		s, _ := f.call(f.h.ApproveVersion, r)
		return s
	}
	edit := func(wf, nodes string) {
		if s, b := f.call(f.h.UpdateWorkflowGraph, f.as(f.admin, http.MethodPut, `{"nodes":`+nodes+`,"edges":`+edges+`}`, map[string]string{"id": wf})); s != http.StatusOK {
			t.Fatalf("edit = %d %s", s, b)
		}
	}

	wf := f.create(chain("v1", 0), edges)
	p := request(wf)
	edit(wf, chain("v2", 0))
	if s := approve(wf, p); s != http.StatusConflict {
		t.Fatalf("approving a request whose draft was edited = %d, want 409", s)
	}

	p = request(wf)
	edit(wf, chain("v2", 300)) // only the position changes
	if s := approve(wf, p); s != http.StatusOK {
		t.Fatalf("approving after a node was only moved = %d, want 200", s)
	}
}
