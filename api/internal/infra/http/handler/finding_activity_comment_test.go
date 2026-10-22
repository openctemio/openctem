package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestHideDeletedCommentText(t *testing.T) {
	deleted := map[string]bool{"c1": true}
	for _, typ := range []string{"comment_added", "comment_updated"} {
		in := FindingActivityResponse{ActivityType: typ, Changes: map[string]any{
			"comment_id": "c1", "content": "secret words", "preview": "secret", "previous_content": "older", "visibility": "team",
		}}
		out := hideDeletedCommentText(in, deleted)
		for _, k := range []string{"content", "preview", "previous_content"} {
			if _, ok := out.Changes[k]; ok {
				t.Errorf("%s: %s still present for a deleted comment", typ, k)
			}
		}
		if out.Changes["deleted"] != true || out.Changes["comment_id"] != "c1" {
			t.Errorf("%s: placeholder markers missing: %v", typ, out.Changes)
		}
		if _, ok := in.Changes["content"]; !ok {
			t.Errorf("%s: the stored entry was modified", typ)
		}
	}
	live := FindingActivityResponse{ActivityType: "comment_added", Changes: map[string]any{"comment_id": "c2", "content": "kept"}}
	if got := hideDeletedCommentText(live, deleted); got.Changes["content"] != "kept" {
		t.Error("a live comment lost its text")
	}
}

func TestClientSafeActivity_CommentRevisionsKeepOnlyClientKeys(t *testing.T) {
	a := FindingActivityResponse{ActivityType: "comment_updated", Changes: map[string]any{
		"comment_id": "c1", "content": "new", "previous_content": "old", "visibility": "client",
	}}
	out := clientSafeActivity(a)
	if _, ok := out.Changes["previous_content"]; ok {
		t.Error("a campaign client must not read the previous text")
	}
	if out.Changes["content"] != "new" {
		t.Error("the client's current text is missing")
	}
}

type feedFindingRepo struct {
	vulnerability.FindingRepository
	f *vulnerability.Finding
}

func (r feedFindingRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	if r.f.TenantID() != tenantID || r.f.ID() != id {
		return nil, shared.ErrNotFound
	}
	return r.f, nil
}

type feedActivityRepo struct {
	vulnerability.FindingActivityRepository
	acts []*vulnerability.FindingActivity
}

func (r feedActivityRepo) ListByFinding(context.Context, shared.ID, shared.ID, vulnerability.FindingActivityFilter, pagination.Pagination) (pagination.Result[*vulnerability.FindingActivity], error) {
	return pagination.Result[*vulnerability.FindingActivity]{Data: r.acts, Total: int64(len(r.acts)), Page: 1, PerPage: 20}, nil
}

func (feedActivityRepo) DeletedCommentIDs(context.Context, shared.ID, shared.ID, []string) (map[string]bool, error) {
	return nil, errors.New("db down")
}

// When the deleted-comment lookup fails the feed is refused: serving it would
// show the text of a comment its author deleted.
func TestListActivities_DeletedLookupFailure_FailsClosed(t *testing.T) {
	tenant := shared.NewID()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSAST, "tool", vulnerability.SeverityLow, "x")
	if err != nil {
		t.Fatal(err)
	}
	act, err := vulnerability.NewFindingActivity(tenant, f.ID(), vulnerability.ActivityCommentAdded, nil, vulnerability.ActorTypeUser,
		map[string]any{"comment_id": "c1", "content": "deleted words"}, vulnerability.SourceAPI, nil)
	if err != nil {
		t.Fatal(err)
	}
	log := logger.NewNop()
	findings := feedFindingRepo{f: f}
	vuln := finding.NewVulnerabilityService(nil, findings, log)
	h := NewFindingActivityHandler(activity.NewFindingActivityService(feedActivityRepo{acts: []*vulnerability.FindingActivity{act}}, findings, log), vuln, log)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetPathValue("id", f.ID().String())
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	w := httptest.NewRecorder()
	h.ListActivities(w, req.WithContext(ctx))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "deleted words") {
		t.Fatalf("got %d %s, want 500 without the comment text", w.Code, w.Body.String())
	}
}
