package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func authzCtx(isAdmin bool, perms ...string) context.Context {
	ctx := context.WithValue(context.Background(), middleware.IsAdminKey, isAdmin)
	return context.WithValue(ctx, middleware.PermissionsKey, perms)
}

func actionCfg(actionType string) *NodeConfigRequest {
	return &NodeConfigRequest{ActionType: actionType}
}

// A member with only WorkflowsWrite must NOT be able to build a finding-mutating
// or scan/pipeline action node — that is the privilege-escalation this gate
// closes.
func TestWorkflowActionAuthz_DeniesWithoutResourcePermission(t *testing.T) {
	ctx := authzCtx(false, string(permission.WorkflowsWrite))
	cases := []struct {
		action string
		want   permission.Permission
	}{
		{"update_status", permission.FindingsWrite},
		{"assign_user", permission.FindingsWrite},
		{"add_tags", permission.FindingsWrite},
		{"create_ticket", permission.FindingsWrite},
		{"trigger_ai_triage", permission.FindingsWrite},
		{"trigger_scan", permission.ScansWrite},
		{"trigger_pipeline", permission.ScanWorkflowsWrite},
	}
	for _, tc := range cases {
		perm, ok := authorizeActionConfigs(ctx, actionCfg(tc.action))
		if ok {
			t.Errorf("%s: expected denial, got authorized", tc.action)
		}
		if perm != tc.want {
			t.Errorf("%s: expected missing %q, got %q", tc.action, tc.want, perm)
		}
	}
}

// With the matching per-resource permission, the same nodes are allowed.
func TestWorkflowActionAuthz_AllowsWithResourcePermission(t *testing.T) {
	ctx := authzCtx(false,
		string(permission.WorkflowsWrite),
		string(permission.FindingsWrite),
		string(permission.ScansWrite),
		string(permission.ScanWorkflowsWrite),
	)
	if _, ok := authorizeActionConfigs(ctx,
		actionCfg("update_status"), actionCfg("trigger_scan"), actionCfg("trigger_pipeline")); !ok {
		t.Fatal("expected authorization with all resource permissions")
	}
}

// Owners/admins bypass (IsAdmin flag) even with no explicit permissions.
func TestWorkflowActionAuthz_AdminBypass(t *testing.T) {
	ctx := authzCtx(true)
	if _, ok := authorizeActionConfigs(ctx, actionCfg("trigger_scan")); !ok {
		t.Fatal("admin should bypass action permission checks")
	}
}

// Trigger and condition nodes (and a nil config) need nothing beyond the
// workflow permission.
func TestWorkflowActionAuthz_NonGatedNodesIgnored(t *testing.T) {
	ctx := authzCtx(false, string(permission.WorkflowsWrite))
	if _, ok := authorizeActionConfigs(ctx,
		nil,
		&NodeConfigRequest{TriggerType: "finding_created"},
		&NodeConfigRequest{ConditionExpr: "trigger.finding.severity == 'critical'"},
	); !ok {
		t.Fatal("trigger and condition nodes must not require extra permissions")
	}
}

// Outbound HTTP sends run data to an address of the editor's choosing: it
// needs integrations:manage. A notification needs integrations:read. An
// action type with no mapping (run_script) is refused to non-admins rather
// than allowed.
func TestWorkflowActionAuthz_OutboundNodesGated(t *testing.T) {
	ctx := authzCtx(false, string(permission.WorkflowsWrite), string(permission.FindingsWrite))
	cases := []struct {
		name string
		cfg  *NodeConfigRequest
		want permission.Permission
	}{
		{"http_request", actionCfg("http_request"), permission.IntegrationsManage},
		{"run_script", actionCfg("run_script"), permission.IntegrationsManage},
		{"slack notification", &NodeConfigRequest{NotificationType: "slack"}, permission.IntegrationsRead},
		{"email notification", &NodeConfigRequest{NotificationType: "email"}, permission.IntegrationsRead},
	}
	for _, tc := range cases {
		perm, ok := authorizeActionConfigs(ctx, tc.cfg)
		if ok || perm != tc.want {
			t.Errorf("%s: got (%q, %v), want denial for %q", tc.name, perm, ok, tc.want)
		}
	}
	ok := authzCtx(false, string(permission.IntegrationsManage), string(permission.IntegrationsRead))
	if _, allowed := authorizeActionConfigs(ok, actionCfg("http_request"), &NodeConfigRequest{NotificationType: "slack"}); !allowed {
		t.Fatal("integration holders may build outbound nodes")
	}
}

// The first missing permission short-circuits; a mixed graph is denied if ANY
// action node exceeds the caller's grants.
func TestWorkflowActionAuthz_MixedGraphDeniedOnFirstGap(t *testing.T) {
	ctx := authzCtx(false, string(permission.WorkflowsWrite), string(permission.FindingsWrite))
	// update_status OK (FindingsWrite), trigger_scan NOT OK (needs ScansWrite).
	perm, ok := authorizeActionConfigs(ctx, actionCfg("update_status"), actionCfg("trigger_scan"))
	if ok {
		t.Fatal("expected denial on the scan node")
	}
	if perm != permission.ScansWrite {
		t.Fatalf("expected missing %q, got %q", permission.ScansWrite, perm)
	}
}

// A stored http_request node keeps its headers only to keep running: no
// reader of the workflow sees their values. Other configs pass unchanged.
func TestWorkflowResponse_RedactsHTTPRequestHeaders(t *testing.T) {
	cfg := map[string]any{"url": "https://hooks.example.com", "headers": map[string]any{"Authorization": "Bearer s3cr3t"}}
	node, _ := automation.NewNode(shared.NewID(), "a", automation.NodeTypeAction, "a")
	_ = node.SetActionConfig(automation.ActionTypeHTTPRequest, cfg)
	resp := toNodeResponse(node)
	hdrs, _ := resp.Config.ActionConfig["headers"].(map[string]any)
	if hdrs["Authorization"] != redactedValue {
		t.Fatalf("header value in the response: %v", resp.Config.ActionConfig)
	}
	if cfg["headers"].(map[string]any)["Authorization"] != "Bearer s3cr3t" {
		t.Fatal("redaction changed the stored config")
	}
	if resp.Config.ActionConfig["url"] != "https://hooks.example.com" {
		t.Fatal("redaction dropped other fields")
	}
	other := map[string]any{"tags": []any{"x"}}
	if got := redactActionConfig(automation.ActionTypeAddTags, other); got["tags"] == nil {
		t.Fatal("other actions must pass unchanged")
	}
}
