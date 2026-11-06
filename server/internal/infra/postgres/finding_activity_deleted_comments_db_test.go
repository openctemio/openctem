package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestFindingActivity_DeletedCommentIDs_TenantAndFindingScoped(t *testing.T) {
	fx := newSevFixture(t)
	ctx := context.Background()
	mk := func() *vulnerability.Finding {
		f, err := fx.svc("", "").CreateFinding(ctx, finding.CreateFindingInput{
			TenantID: fx.tenant.String(), AssetID: fx.asset.String(), Source: "manual", ToolName: "manual-entry",
			Message: "deleted comments probe " + shared.NewID().String(), Severity: "low",
		})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f, other := mk(), mk()
	repo := NewFindingActivityRepository(&DB{DB: fx.db})

	ins := func(finding shared.ID, typ, comment string) {
		t.Helper()
		if _, err := fx.db.ExecContext(ctx, `INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, changes, source)
			VALUES (gen_random_uuid(), $1, $2, $3, 'user', jsonb_build_object('comment_id', $4::text), 'api')`,
			fx.tenant.String(), finding.String(), typ, comment); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	ins(f.ID(), "comment_added", "c1")
	ins(f.ID(), "comment_deleted", "c1")
	ins(f.ID(), "comment_added", "c2")
	ins(other.ID(), "comment_deleted", "c3")

	got, err := repo.DeletedCommentIDs(ctx, fx.tenant, f.ID(), []string{"c1", "c2", "c3"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["c1"] || got["c2"] || got["c3"] || len(got) != 1 {
		t.Errorf("deleted set = %v, want only c1 (c2 live, c3 is another finding's)", got)
	}
	// Another tenant sees nothing.
	got, err = repo.DeletedCommentIDs(ctx, shared.NewID(), f.ID(), []string{"c1"})
	if err != nil || len(got) != 0 {
		t.Errorf("other tenant: %v %v", got, err)
	}
}
