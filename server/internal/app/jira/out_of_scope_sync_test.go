package jira

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// closedFinding is a finding resolved with reason, linked to ticketURL.
func closedFinding(reason vulnerability.ClosureReason, ticketURL string) *vulnerability.Finding {
	now := time.Now().UTC()
	return vulnerability.ReconstituteFinding(vulnerability.FindingData{
		ID: shared.NewID(), TenantID: shared.NewID(), AssetID: shared.NewID(),
		Source: vulnerability.FindingSourceDAST, ToolName: "tool", Severity: vulnerability.SeverityCritical,
		Message: "m", Status: vulnerability.FindingStatusResolved, ClosureReason: string(reason),
		ResolvedAt: &now, WorkItemURIs: []string{ticketURL},
		FirstDetectedAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now,
	})
}

// A finding closed because its asset was marked out of scope was not fixed:
// its Jira issue gets a comment saying so and is never moved to done. A
// fixed close still transitions. With outbound sync off, nothing is sent.
func TestSyncFindingStatusToTicket_OutOfScopeComments(t *testing.T) {
	ctx := context.Background()
	url := "https://x.atlassian.net/browse/SEC-1"

	c := &recordingClient{curStatus: "In Progress"}
	s := newSync(&stubFindingRepo{finding: closedFinding(vulnerability.ClosureReasonOutOfScope, url)}, c)
	if err := s.SyncFindingStatusToTicket(ctx, shared.NewID(), shared.NewID(), enabledMapping()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(c.transitions) != 0 {
		t.Fatalf("an out-of-scope close must not move the issue; got %v", c.transitions)
	}
	if len(c.comments) != 1 || !strings.Contains(c.comments[0], "out of scope") ||
		!strings.Contains(c.comments[0], "not fixed") {
		t.Fatalf("want one out-of-scope comment, got %v", c.comments)
	}

	off := &recordingClient{curStatus: "In Progress"}
	s = newSync(&stubFindingRepo{finding: closedFinding(vulnerability.ClosureReasonOutOfScope, url)}, off)
	if err := s.SyncFindingStatusToTicket(ctx, shared.NewID(), shared.NewID(), DefaultMappingConfig()); err != nil {
		t.Fatalf("sync off: %v", err)
	}
	if len(off.transitions) != 0 || len(off.comments) != 0 {
		t.Fatalf("outbound sync off must send nothing; got %v / %v", off.transitions, off.comments)
	}

	fixed := &recordingClient{curStatus: "In Progress"}
	s = newSync(&stubFindingRepo{finding: closedFinding(vulnerability.ClosureReasonFixed, url)}, fixed)
	if err := s.SyncFindingStatusToTicket(ctx, shared.NewID(), shared.NewID(), enabledMapping()); err != nil {
		t.Fatalf("sync fixed: %v", err)
	}
	if len(fixed.transitions) != 1 {
		t.Fatalf("a fixed close still transitions the issue; got %v", fixed.transitions)
	}
}
