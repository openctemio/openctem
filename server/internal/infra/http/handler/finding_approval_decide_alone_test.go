package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Only a person's own session holding findings:approve may be the one
// person who decides a false positive or accepted risk under the
// organization's level: an API key or an MCP access token carrying the same
// permission never does (its request waits for a second person).
func TestRequesterMayDecideAlone(t *testing.T) {
	approve := []string{permission.FindingsApprove.String(), permission.FindingsWrite.String()}
	base := context.WithValue(context.Background(), middleware.FetchedPermissionsKey, approve)
	cases := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"session with findings:approve", base, true},
		{"session without findings:approve",
			context.WithValue(context.Background(), middleware.FetchedPermissionsKey, []string{permission.FindingsWrite.String()}), false},
		{"API key with findings:approve", context.WithValue(base, middleware.APIKeyIDKey, "key-1"), false},
		{"API key provider with findings:approve", context.WithValue(base, middleware.AuthProviderKey, middleware.AuthProviderAPIKey), false},
		{"MCP access token with findings:approve", context.WithValue(base, middleware.AuthProviderKey, middleware.AuthProviderMCPOAuth), false},
		{"administrator through an API key", context.WithValue(context.WithValue(base, middleware.IsAdminKey, true), middleware.APIKeyIDKey, "key-2"), false},
	}
	for _, c := range cases {
		if got := requesterMayDecideAlone(c.ctx); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// A settings change that lowers both levels names both in the approvers'
// notice; a change that lowers nothing gets the general line.
func TestApprovalSettingsChangeNotice(t *testing.T) {
	at := "2026-10-24T10:00:00Z"
	both := approvalSettingsChangeNotice(FindingApprovalSettingsResponse{},
		FindingApprovalSettingsResponse{PendingFPApproval: "off", PendingFPApprovalAt: &at, PendingAcceptApproval: "high_and_above", PendingAcceptApprovalAt: &at})
	if !strings.Contains(both, "false-positive approval level") || !strings.Contains(both, "risk acceptance approval level") {
		t.Fatalf("a lowering is hidden: %q", both)
	}
	if got := approvalSettingsChangeNotice(FindingApprovalSettingsResponse{}, FindingApprovalSettingsResponse{}); !strings.Contains(got, "changed how this organization approves") {
		t.Fatalf("general line: %q", got)
	}
}
