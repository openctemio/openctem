package routes

import (
	"context"
	"net/http"
	"sync"
	"testing"

	activityapp "github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Every route that changes a finding's status runs the same side effects,
// once per finding it actually moved: a timeline entry naming the actor, the
// finding_status_changed workflow event, the assignee's notification and the
// outbound ticket sync. The fix claim, verify and reject actions used to
// write the status with a plain update and fired none of them; bulk status
// recorded activity and ticket syncs for findings its guarded write had left
// alone; bulk assign recorded and notified nothing.

type effectsRecorder struct {
	mu       sync.Mutex
	workflow []string // finding:old->new
}

func (r *effectsRecorder) wire(vuln *finding.VulnerabilityService) {
	vuln.SetWorkflowStatusDispatch(func(_ context.Context, _ shared.ID, f *vulnerability.Finding, oldStatus, newStatus string) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.workflow = append(r.workflow, f.ID().String()+":"+oldStatus+"->"+newStatus)
	})
	vuln.EnableTicketStatusSync()
}

func (r *effectsRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.workflow = nil
}

func newEffectsHarness(t *testing.T) (*gsHarness, *effectsRecorder) {
	t.Helper()
	h := newGroupScopeHarness(t)
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	findingRepo := postgres.NewFindingRepository(db)
	h.vuln.SetActivityService(activityapp.NewFindingActivityService(postgres.NewFindingActivityRepository(db), findingRepo, log))
	h.vuln.SetUserNotificationService(integration.NewNotificationService(postgres.NewNotificationRepository(db), nil, log))
	h.vuln.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	h.actions.SetStatusEffects(h.vuln)
	rec := &effectsRecorder{}
	rec.wire(h.vuln)
	return h, rec
}

func (h *gsHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// ticketPushes counts the queued outbound ticket status pushes of a finding
// (one per provider kind; a pending push coalesces).
func (h *gsHarness) ticketPushes(id shared.ID) int {
	return h.count(`SELECT COUNT(*) FROM durable_jobs WHERE tenant_id = $1 AND subject_id = $2 AND kind = 'jira_status_sync'`,
		h.tenant.String(), id.String())
}

func (h *gsHarness) clearTicketPushes() {
	h.exec(`DELETE FROM durable_jobs WHERE tenant_id = $1`, h.tenant.String())
}

func (h *gsHarness) statusActivities(id, actor shared.ID) int {
	return h.count(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND activity_type = 'status_changed' AND actor_id = $3`, h.tenant.String(), id.String(), actor.String())
}

func (h *gsHarness) statusNotices(id, to shared.ID) int {
	return h.count(`SELECT COUNT(*) FROM notifications WHERE tenant_id = $1 AND resource_id = $2
		AND audience = 'user' AND audience_id = $3 AND notification_type = 'finding_status_change'`,
		h.tenant.String(), id.String(), to.String())
}

func TestFindingActions_StatusSideEffects_DB(t *testing.T) {
	h, rec := newEffectsHarness(t)
	fa := h.findingA
	// memberA's finding, linked to a ticket; the owner is told of changes
	// made by someone else, so the owner is the assignee for the decisions.
	h.exec(`UPDATE findings SET status = 'in_progress', severity = 'medium', assigned_to = $2,
		work_item_uris = ARRAY['https://tickets.example.com/browse/SEC-1'] WHERE id = $1`, fa.String(), h.memberA.String())

	t.Run("fix applied", func(t *testing.T) {
		rec.reset()
		h.clearTicketPushes()
		// The fix claim reads the claimer's groups: an actions service with
		// the group store, as wired in production.
		db := &postgres.DB{DB: h.db}
		actions := finding.NewFindingActionsService(postgres.NewFindingRepository(db), postgres.NewAccessControlRepository(db),
			postgres.NewGroupRepository(db), postgres.NewAssetRepository(db), nil, h.db, logger.NewNop())
		actions.SetStatusEffects(h.vuln)
		res, err := actions.BulkFixApplied(context.Background(), h.tenant.String(), h.memberA.String(), finding.BulkFixAppliedInput{
			Filter: vulnerability.NewFindingFilter().WithTenantID(h.tenant).WithAssetID(h.assetA), Note: "patched",
		})
		if err != nil || res.Updated != 1 || h.statusOf(fa) != "fix_applied" {
			t.Fatalf("fix-applied: %v %+v (status %s)", err, res, h.statusOf(fa))
		}
		if n := h.statusActivities(fa, h.memberA); n != 1 {
			t.Fatalf("fix claim activities = %d, want 1", n)
		}
		if len(rec.workflow) != 1 || rec.workflow[0] != fa.String()+":in_progress->fix_applied" || h.ticketPushes(fa) != 1 {
			t.Fatalf("fix claim side effects: workflow %v ticket pushes %d", rec.workflow, h.ticketPushes(fa))
		}
	})

	// The owner is now the assignee: memberA's decisions notify them.
	h.exec(`UPDATE findings SET assigned_to = $2 WHERE id = $1`, fa.String(), h.owner.String())

	t.Run("reject fix", func(t *testing.T) {
		rec.reset()
		h.clearTicketPushes()
		code, body := h.doPerms(h.memberA, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/reject-fix",
			map[string]any{"finding_ids": []string{fa.String()}, "reason": "still reachable"})
		if code != http.StatusOK || h.statusOf(fa) != "in_progress" {
			t.Fatalf("reject-fix: %d %s (status %s)", code, body, h.statusOf(fa))
		}
		if n := h.statusActivities(fa, h.memberA); n != 2 {
			t.Fatalf("activities after reject = %d, want 2", n)
		}
		if len(rec.workflow) != 1 || rec.workflow[0] != fa.String()+":fix_applied->in_progress" || h.ticketPushes(fa) != 1 {
			t.Fatalf("reject side effects: workflow %v ticket pushes %d", rec.workflow, h.ticketPushes(fa))
		}
		if n := h.statusNotices(fa, h.owner); n != 1 {
			t.Fatalf("assignee notices after reject = %d, want 1", n)
		}
	})

	t.Run("verify", func(t *testing.T) {
		h.exec(`UPDATE findings SET status = 'fix_applied' WHERE id = $1`, fa.String())
		h.completeChecklistViaAPI(h.memberA, fa)
		before := h.statusActivities(fa, h.memberA)
		rec.reset()
		h.clearTicketPushes()
		code, body := h.doPerms(h.memberA, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/verify",
			map[string]any{"finding_ids": []string{fa.String()}, "note": "verified"})
		if code != http.StatusOK || h.statusOf(fa) != "resolved" {
			t.Fatalf("verify: %d %s (status %s)", code, body, h.statusOf(fa))
		}
		if n := h.statusActivities(fa, h.memberA); n != before+1 {
			t.Fatalf("verify activities = %d, want %d", n, before+1)
		}
		if len(rec.workflow) != 1 || rec.workflow[0] != fa.String()+":fix_applied->resolved" || h.ticketPushes(fa) != 1 {
			t.Fatalf("verify side effects: workflow %v ticket pushes %d", rec.workflow, h.ticketPushes(fa))
		}
		if n := h.statusNotices(fa, h.owner); n != 2 {
			t.Fatalf("assignee notices after verify = %d, want 2", n)
		}
		// A second verify finds nothing to move and fires nothing.
		rec.reset()
		h.clearTicketPushes()
		_, _ = h.doPerms(h.memberA, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/verify",
			map[string]any{"finding_ids": []string{fa.String()}, "note": "again"})
		if len(rec.workflow) != 0 || h.ticketPushes(fa) != 0 || h.statusActivities(fa, h.memberA) != before+1 {
			t.Fatalf("a repeated verify fired side effects: workflow %v ticket pushes %d", rec.workflow, h.ticketPushes(fa))
		}
	})
}

// racingRepo changes one finding's status right after the bulk call read it,
// as another person would between the read and the guarded write.
type racingRepo struct {
	*postgres.FindingRepository
	h      *gsHarness
	victim shared.ID
}

func (r *racingRepo) GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	out, err := r.FindingRepository.GetByIDs(ctx, tenantID, ids)
	if err == nil && !r.victim.IsZero() {
		r.h.exec(`UPDATE findings SET status = 'false_positive', resolved_at = NOW() WHERE id = $1`, r.victim.String())
		r.victim = shared.ID{}
	}
	return out, err
}

func TestBulkStatus_SideEffectsOnlyForMovedRows_DB(t *testing.T) {
	h, _ := newEffectsHarness(t)
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	a, b := h.findingA, h.findingB
	for _, id := range []shared.ID{a, b} {
		h.exec(`UPDATE findings SET status = 'confirmed', work_item_uris = ARRAY['https://tickets.example.com/browse/SEC-2'] WHERE id = $1`, id.String())
	}
	repo := &racingRepo{FindingRepository: postgres.NewFindingRepository(db), h: h, victim: b}
	svc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), repo, log)
	svc.SetActivityService(activityapp.NewFindingActivityService(postgres.NewFindingActivityRepository(db), repo, log))
	rec := &effectsRecorder{}
	rec.wire(svc)

	res, err := svc.BulkUpdateFindingsStatus(context.Background(), h.tenant.String(), finding.BulkUpdateStatusInput{
		FindingIDs: []string{a.String(), b.String()}, Status: "in_progress", ActorID: h.memberA.String(),
	})
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if res.Updated != 1 || res.Failed != 1 {
		t.Fatalf("bulk result: updated %d failed %d (%v)", res.Updated, res.Failed, res.Errors)
	}
	if h.statusOf(b) != "false_positive" {
		t.Fatalf("the guarded write moved the changed finding: %s", h.statusOf(b))
	}
	if n := h.statusActivities(a, h.memberA); n != 1 {
		t.Fatalf("activities for the moved finding = %d, want 1", n)
	}
	if n := h.statusActivities(b, h.memberA); n != 0 {
		t.Fatalf("activities for the finding left alone = %d, want 0", n)
	}
	if h.ticketPushes(a) != 1 || h.ticketPushes(b) != 0 || len(rec.workflow) != 1 {
		t.Fatalf("side effects: ticket pushes a=%d b=%d, workflow %v; want only %s", h.ticketPushes(a), h.ticketPushes(b), rec.workflow, a)
	}
}

func TestBulkAssign_RecordsAndNotifies_DB(t *testing.T) {
	h, _ := newEffectsHarness(t)
	ids := []string{h.findingA.String(), h.findingB.String()}
	if _, err := h.vuln.BulkAssignFindings(context.Background(), h.tenant.String(), finding.BulkAssignInput{
		FindingIDs: ids, UserID: h.memberA.String(), AssignerID: h.owner.String(),
	}); err != nil {
		t.Fatalf("bulk assign: %v", err)
	}
	if n := h.count(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = ANY($2::uuid[])
		AND activity_type = 'assigned' AND actor_id = $3`, h.tenant.String(), "{"+ids[0]+","+ids[1]+"}", h.owner.String()); n != 2 {
		t.Fatalf("assigned activities = %d, want 2", n)
	}
	if n := h.count(`SELECT COUNT(*) FROM notifications WHERE tenant_id = $1 AND audience = 'user' AND audience_id = $2
		AND notification_type = 'finding_assigned'`, h.tenant.String(), h.memberA.String()); n != 1 {
		t.Fatalf("assignee notifications = %d, want 1", n)
	}
}
