package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/activity"
	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// recordingActivityRepo keeps every activity written to it.
type recordingActivityRepo struct {
	findingActActivityRepo
	acts []*vulnerability.FindingActivity
}

func (r *recordingActivityRepo) Create(_ context.Context, a *vulnerability.FindingActivity) error {
	r.acts = append(r.acts, a)
	return nil
}

func (r *recordingActivityRepo) CreateBatch(_ context.Context, as []*vulnerability.FindingActivity) error {
	r.acts = append(r.acts, as...)
	return nil
}

func (r *recordingActivityRepo) types() []string {
	var out []string
	for _, a := range r.acts {
		out = append(out, string(a.ActivityType()))
	}
	return out
}

func TestFindingComment_EditAndDelete_AreAppendOnlyAndAudited(t *testing.T) {
	svc, _, findingRepo := newVulnTestService()
	commentRepo := newMockCommentRepo()
	svc.SetCommentRepository(commentRepo)
	actRepo := &recordingActivityRepo{}
	svc.SetActivityService(activity.NewFindingActivityService(actRepo, findingRepo, logger.NewNop()))
	rec := &recordingAuthAuditRepo{}
	svc.SetAuditService(auditsvc.NewAuditService(rec, logger.NewNop()))

	tenantID := shared.NewID()
	findingID := seedCommentFinding(t, findingRepo, tenantID)
	author := shared.NewID().String()
	ctx := context.Background()

	c, err := svc.AddFindingComment(ctx, tenantID.String(), findingID.String(), author, "original text")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateFindingComment(ctx, tenantID.String(), c.ID().String(), author, "rewritten text"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteFindingComment(ctx, tenantID.String(), c.ID().String(), author); err != nil {
		t.Fatal(err)
	}

	got := actRepo.types()
	want := []string{"comment_added", "comment_updated", "comment_deleted"}
	if len(got) != len(want) {
		t.Fatalf("activities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("activities = %v, want %v", got, want)
		}
	}
	if v := actRepo.acts[0].Changes()["content"]; v != "original text" {
		t.Errorf("original entry was rewritten: %v", v)
	}
	if v := actRepo.acts[1].Changes()["previous_content"]; v != "original text" {
		t.Errorf("revision lost the previous text: %v", v)
	}
	if len(rec.logs) != 2 {
		t.Fatalf("audit events = %d, want 2 (edit, delete)", len(rec.logs))
	}
	if rec.logs[0].Action() != "finding.comment_edited" || rec.logs[1].Action() != "finding.comment_deleted" {
		t.Errorf("audit actions = %v, %v", rec.logs[0].Action(), rec.logs[1].Action())
	}
}

func TestFindingComment_UnknownActor_FailsClosed(t *testing.T) {
	svc, _, findingRepo := newVulnTestService()
	commentRepo := newMockCommentRepo()
	svc.SetCommentRepository(commentRepo)
	tenantID := shared.NewID()
	findingID := seedCommentFinding(t, findingRepo, tenantID)
	c, err := svc.AddFindingComment(context.Background(), tenantID.String(), findingID.String(), shared.NewID().String(), "text")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateFindingComment(context.Background(), tenantID.String(), c.ID().String(), "", "x"); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("edit with empty actor = %v, want forbidden", err)
	}
	if err := svc.DeleteFindingComment(context.Background(), tenantID.String(), c.ID().String(), ""); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("delete with empty actor = %v, want forbidden", err)
	}
	if len(commentRepo.comments) != 1 || commentRepo.comments[c.ID().String()].Content() != "text" {
		t.Error("comment changed despite the refusal")
	}
}

func TestFindingComment_DecisionComment_IsLocked(t *testing.T) {
	svc, _, findingRepo := newVulnTestService()
	commentRepo := newMockCommentRepo()
	svc.SetCommentRepository(commentRepo)
	approvals := newMockApprovalRepository()
	svc.SetApprovalRepository(approvals)

	tenantID := shared.NewID()
	findingID := seedCommentFinding(t, findingRepo, tenantID)
	requester := shared.NewID()
	other := shared.NewID()

	ap := vulnerability.NewApproval(tenantID, findingID, requester, "false_positive", "test-only route", nil)
	ap.CreatedAt = time.Now().UTC().Add(-time.Hour)
	approvals.approvals[ap.ID] = ap

	ctx := context.Background()
	mine, err := svc.AddFindingComment(ctx, tenantID.String(), findingID.String(), requester.String(), "why this is a false positive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateFindingComment(ctx, tenantID.String(), mine.ID().String(), requester.String(), "changed"); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("edit of a pending-request comment = %v, want forbidden", err)
	}
	if err := svc.DeleteFindingComment(ctx, tenantID.String(), mine.ID().String(), requester.String()); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("delete of a pending-request comment = %v, want forbidden", err)
	}

	// A comment by someone who is not part of the request stays editable.
	free, err := svc.AddFindingComment(ctx, tenantID.String(), findingID.String(), other.String(), "unrelated")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateFindingComment(ctx, tenantID.String(), free.ID().String(), other.String(), "edited"); err != nil {
		t.Errorf("edit by a non-participant: %v", err)
	}

	// An approved acceptance whose period ended (expired) was still a
	// decision: its comments stay locked.
	decided := time.Now().UTC().Add(time.Minute)
	ap.Status, ap.ApprovedAt = vulnerability.ApprovalStatusExpired, &decided
	if _, err := svc.UpdateFindingComment(ctx, tenantID.String(), mine.ID().String(), requester.String(), "rewritten"); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("edit of an expired acceptance's comment = %v, want forbidden", err)
	}
	// A decided request without a decision time fails closed.
	ap.Status, ap.ApprovedAt = vulnerability.ApprovalStatusApproved, nil
	if err := svc.DeleteFindingComment(ctx, tenantID.String(), mine.ID().String(), requester.String()); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("delete with no decision time = %v, want forbidden", err)
	}

	// A canceled request decided nothing: it locks nothing.
	ap.Status = vulnerability.ApprovalStatusCanceled
	if _, err := svc.UpdateFindingComment(ctx, tenantID.String(), mine.ID().String(), requester.String(), "now ok"); err != nil {
		t.Errorf("edit after cancel: %v", err)
	}
}
