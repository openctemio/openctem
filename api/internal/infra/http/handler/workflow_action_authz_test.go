package handler

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
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
		{"trigger_pipeline", permission.PipelinesWrite},
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
		string(permission.PipelinesWrite),
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

// Non-action nodes (nil config / trigger / condition) and actions that need no
// extra permission (disabled run_script, outbound http_request) are ignored.
func TestWorkflowActionAuthz_NonGatedNodesIgnored(t *testing.T) {
	ctx := authzCtx(false, string(permission.WorkflowsWrite))
	if _, ok := authorizeActionConfigs(ctx,
		nil,
		&NodeConfigRequest{TriggerType: "finding_created"},
		actionCfg("http_request"),
		actionCfg("run_script"),
	); !ok {
		t.Fatal("non-gated nodes must not require extra permissions")
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
