package admin

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestApprovalTargets(t *testing.T) {
	id := shared.NewID().String()
	cases := []struct {
		action ApprovalAction
		target string
		ok     bool
	}{
		{ApprovalGrantSuperAdmin, "email:a@example.com", true},
		{ApprovalGrantSuperAdmin, "admin:" + id, true},
		{ApprovalGrantSuperAdmin, "tenant:" + id, false},
		{ApprovalGrantSuperAdmin, "email:not an email", false},
		{ApprovalRevokeSuperAdmin, "admin:" + id, true},
		{ApprovalRevokeSuperAdmin, "email:a@example.com", false},
		{ApprovalConsoleMFAOff, "off", true},
		{ApprovalConsoleMFAOff, "on", false},
		{ApprovalPlatformIdPRemove, "remove", true},
		{ApprovalPlatformIdPRemove, "require_idp_off", true},
		{ApprovalPlatformIdPRemove, "rename", false},
		{ApprovalSignupOpen, "mode=self_service;accounts=open", true},
		{ApprovalSignupOpen, "mode=admin_only;accounts=domain", true},
		{ApprovalSignupOpen, "mode=self_service;accounts=all", false},
		{ApprovalAuditChainRebaseline, "tenant:" + id, true},
		{ApprovalAuditChainRebaseline, "tenant:" + id + "x", false},
		{ApprovalOrgPurge, "tenant:" + id, true},
		{ApprovalOrgPurge, "admin:" + id, false},
		{ApprovalOrgPurge, "tenant:" + id + "x", false},
		{"admin.other", "off", false},
	}
	for _, c := range cases {
		if got := c.action.IsValid() && c.action.ValidTarget(c.target); got != c.ok {
			t.Errorf("%s %q valid = %v, want %v", c.action, c.target, got, c.ok)
		}
	}
	if got, ok := TargetID("tenant:" + id); !ok || got.String() != id {
		t.Errorf("TargetID = %v, %v", got, ok)
	}
}

func TestApprovalStatus(t *testing.T) {
	now := time.Now()
	used := now
	cases := map[string]Approval{
		ApprovalPending:  {ExpiresAt: now.Add(time.Hour)},
		ApprovalApproved: {ExpiresAt: now.Add(time.Hour), Decision: DecisionApproved},
		ApprovalRejected: {ExpiresAt: now.Add(-time.Hour), Decision: DecisionRejected},
		ApprovalCanceled: {ExpiresAt: now.Add(time.Hour), Decision: DecisionCanceled},
		ApprovalExpired:  {ExpiresAt: now, Decision: DecisionApproved},
		ApprovalUsed:     {ExpiresAt: now.Add(-time.Hour), Decision: DecisionApproved, ConsumedAt: &used},
	}
	for want, a := range cases {
		if got := a.Status(now); got != want {
			t.Errorf("status = %q, want %q", got, want)
		}
	}
}
