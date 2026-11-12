package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The status endpoint and the bulk status change apply the same claim and
// close rules as the dedicated routes: a fix claim needs findings:fix_apply, a
// note and the finding to be the person's (assignee, assigned group, asset
// owner); a resolve without a complete verification checklist is attested
// and needs a note. Refused moves write nothing.
func TestSameRules_FixAppliedAndResolveOnEveryRoute(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, db, "same-rules")
	owner, stranger := shared.NewID(), shared.NewID()
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
		for _, u := range []shared.ID{owner, stranger} {
			_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, u.String())
		}
		_ = db.Close()
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	for _, u := range []shared.ID{owner, stranger} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'sr')`, u.String(), u.String()+"@example.com")
	}
	asset := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'sr-host', 'host')`, asset.String(), tenant.String())
	exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, asset.String(), owner.String())

	pdb := &postgres.DB{DB: db}
	repo := postgres.NewFindingRepository(pdb)
	svc := finding.NewVulnerabilityService(nil, repo, logger.NewNop())
	actions := finding.NewFindingActionsService(repo, postgres.NewAccessControlRepository(pdb), postgres.NewGroupRepository(pdb),
		postgres.NewAssetRepository(pdb), nil, db, logger.NewNop())
	svc.SetFixApplierCheck(actions.FixAppliers)

	newFinding := func(status string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, 'sast', 'sr-tool', 'm', 'medium', $4, $5)`, id.String(), tenant.String(), asset.String(), "sr-"+id.String(), status)
		return id
	}
	statusOf := func(id shared.ID) string {
		var s string
		if err := db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	patch := func(id, actor shared.ID, status, note string, fixApply bool) error {
		_, err := svc.UpdateFindingStatus(ctx, id.String(), tenant.String(), finding.UpdateFindingStatusInput{
			Status: status, Resolution: note, ActorID: actor.String(), HasVerifyPermission: true, HasFixApplyPermission: fixApply,
		})
		return err
	}

	// Fix claim through PATCH.
	f := newFinding("in_progress")
	if err := patch(f, owner, "fix_applied", "upgraded to 4.2", false); !errors.Is(err, finding.ErrFixApplyRequiresPermission) {
		t.Errorf("without findings:fix_apply: err = %v", err)
	}
	if err := patch(f, owner, "fix_applied", " ", true); !errors.Is(err, finding.ErrNoteRequired) {
		t.Errorf("without a note: err = %v", err)
	}
	if err := patch(f, stranger, "fix_applied", "upgraded", true); !errors.Is(err, finding.ErrFixApplyNotYours) {
		t.Errorf("by someone it is not theirs: err = %v", err)
	}
	if st := statusOf(f); st != "in_progress" {
		t.Fatalf("refused claims moved the finding to %s", st)
	}
	if err := patch(f, owner, "fix_applied", "upgraded to 4.2", true); err != nil {
		t.Fatalf("the asset owner's claim with a note: %v", err)
	}

	// Resolve through PATCH without a checklist: attested, needs a note.
	r := newFinding("confirmed")
	if err := patch(r, owner, "resolved", "", false); !errors.Is(err, finding.ErrNoteRequired) {
		t.Errorf("attested resolve without a note: err = %v", err)
	}
	if err := patch(r, owner, "resolved", "removed the endpoint", false); err != nil {
		t.Fatalf("attested resolve with a note: %v", err)
	}

	// The bulk status change: a fix claim by a stranger moves none of the
	// owner's findings; a bulk resolve without a note is refused.
	b := newFinding("in_progress")
	res, err := svc.BulkUpdateFindingsStatus(ctx, tenant.String(), finding.BulkUpdateStatusInput{
		FindingIDs: []string{b.String()}, Status: "fix_applied", Resolution: "patched", ActorID: stranger.String(),
		HasVerifyPermission: true, HasFixApplyPermission: true,
	})
	if err != nil || res.Updated != 0 || statusOf(b) != "in_progress" {
		t.Errorf("stranger's bulk claim: res=%+v err=%v status=%s, want nothing moved", res, err, statusOf(b))
	}
	if _, err := svc.BulkUpdateFindingsStatus(ctx, tenant.String(), finding.BulkUpdateStatusInput{
		FindingIDs: []string{b.String()}, Status: "resolved", ActorID: owner.String(), HasVerifyPermission: true,
	}); !errors.Is(err, finding.ErrNoteRequired) {
		t.Errorf("bulk resolve without a note: err = %v", err)
	}
}
