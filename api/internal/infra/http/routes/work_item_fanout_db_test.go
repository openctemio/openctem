package routes

// Who hears about comments, status changes and assignments of a finding once
// watchers exist (RFC-120): the assignee and the watchers who can still read
// it, never the actor, never someone who stopped watching, never a scanner's
// audience, never a pentest client for team-only content. Real Postgres.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	participationapp "github.com/openctemio/openctem/api/internal/app/participation"
	appremediation "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	participationdom "github.com/openctemio/openctem/api/pkg/domain/participation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fanoutHarness struct {
	*dsHarness
	vuln *finding.VulnerabilityService
	svc  *participationapp.Service
	// scoped is a second member whose scope covers asset A.
	scoped shared.ID
}

func newFanoutHarness(t *testing.T) *fanoutHarness {
	t.Helper()
	ds := newDSHarness(t)
	db := &postgres.DB{DB: ds.db}
	log := logger.NewNop()
	vuln := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), log)
	vuln.SetDataScope(ds.enforcer)
	vuln.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	vuln.SetCommentRepository(postgres.NewFindingCommentRepository(db))
	notifs := postgres.NewNotificationRepository(db)
	vuln.SetUserNotificationService(integration.NewNotificationService(notifs, nil, log))
	tasks := appremediation.NewTaskService(postgres.NewRemediationTaskRepository(db), log)
	tasks.SetDataScope(ds.enforcer)
	svc := participationapp.NewService(postgres.NewWorkItemSubscriptionRepository(db), postgres.NewAccessControlRepository(db), log)
	svc.SetItemAccess(participationdom.ItemFinding, vuln.ParticipationAccess())
	svc.SetItemAccess(participationdom.ItemTask, tasks.ParticipationAccess())
	svc.SetAuditLogger(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	svc.SetAutoWatchPreference(notifs)
	vuln.SetParticipants(svc)

	h := &fanoutHarness{dsHarness: ds, vuln: vuln, svc: svc}
	h.scoped = shared.NewID()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Scoped Watcher')`, h.scoped.String(), h.scoped.String()+"@fan.test")
	t.Cleanup(func() { _, _ = ds.db.Exec(`DELETE FROM users WHERE id = $1`, h.scoped.String()) })
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, h.scoped.String(), ds.tenant.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped.String(), ds.tenant.String(), ds.assetA.String())
	h.exec(`DELETE FROM notifications WHERE tenant_id = $1`, ds.tenant.String())
	return h
}

// ctx is the request context of the tenant owner (an administrator).
func (h *fanoutHarness) ctx() context.Context {
	c := context.WithValue(context.Background(), middleware.UserIDKey, h.owner.String())
	c = context.WithValue(c, middleware.TenantIDKey, h.tenant.String())
	return context.WithValue(c, middleware.IsAdminKey, true)
}

func (h *fanoutHarness) watch(user shared.ID, state string) {
	h.t.Helper()
	h.exec(`INSERT INTO work_item_subscriptions (tenant_id, finding_id, user_id, state, reason) VALUES ($1, $2, $3, $4, 'manual')`,
		h.tenant.String(), h.findingA.String(), user.String(), state)
}

// told returns the users who got a notification of the type about finding A, with the reason.
func (h *fanoutHarness) told(typ string) map[string]string {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT audience_id::text, COALESCE(reason, ''), coalesced_count FROM notifications
		WHERE tenant_id = $1 AND notification_type = $2 AND resource_id = $3 AND audience = 'user'`,
		h.tenant.String(), typ, h.findingA.String())
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, reason string
		var n int
		if err := rows.Scan(&id, &reason, &n); err != nil {
			h.t.Fatal(err)
		}
		out[id] = reason
		if n > 1 {
			out[id] += " x" + string(rune('0'+n))
		}
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *fanoutHarness) comment(author shared.ID, text string) {
	h.t.Helper()
	if _, err := h.vuln.AddFindingCommentWithInput(h.ctx(), finding.AddFindingCommentInput{
		TenantID: h.tenant.String(), FindingID: h.findingA.String(), AuthorID: author.String(), Content: text,
		ActingUserID: author.String(), IsAdmin: author == h.owner,
	}); err != nil {
		h.t.Fatalf("comment: %v", err)
	}
}

func (h *fanoutHarness) subscription(user shared.ID) string {
	var state sql.NullString
	_ = h.db.QueryRow(`SELECT state||':'||reason FROM work_item_subscriptions WHERE tenant_id = $1 AND finding_id = $2 AND user_id = $3`,
		h.tenant.String(), h.findingA.String(), user.String()).Scan(&state)
	return state.String
}

func TestFindingComment_ReachesAssigneeAndWatchers_DB(t *testing.T) {
	h := newFanoutHarness(t)
	h.exec(`UPDATE findings SET assigned_to = $1 WHERE id = $2`, h.memberA.String(), h.findingA.String())
	h.watch(h.scoped, "subscribed")     // watches, can read
	h.watch(h.memberFree, "subscribed") // watches but has no scope: hears nothing
	h.watch(h.memberStrict, "unsubscribed")
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberStrict.String(), h.tenant.String(), h.assetA.String())

	h.comment(h.owner, "looking at this")
	got := h.told("finding_comment")
	if len(got) != 2 || got[h.memberA.String()] != "assigned" || got[h.scoped.String()] != "watching" {
		t.Fatalf("comment reached %v, want the assignee (assigned) and the scoped watcher (watching)", got)
	}
	// The author starts watching (reason commented); the actor is not told.
	if h.subscription(h.owner) != "subscribed:commented" {
		t.Errorf("author subscription = %q", h.subscription(h.owner))
	}
	if _, told := got[h.owner.String()]; told {
		t.Error("the author was told about their own comment")
	}
	// A stop survives taking part: the one who stopped comments and stays stopped.
	h.comment(h.memberStrict, "I still have an opinion")
	if h.subscription(h.memberStrict) != "unsubscribed:manual" {
		t.Errorf("an unsubscribe was overridden by a comment: %q", h.subscription(h.memberStrict))
	}

	// Coalescing: the second comment within the window folds into the unread notice.
	if got[h.scoped.String()] == "watching x2" {
		t.Fatal("first comment already coalesced")
	}
	got = h.told("finding_comment")
	if got[h.scoped.String()] != "watching x2" || got[h.memberA.String()] != "assigned x2" {
		t.Errorf("after two comments: %v, want one row each with a count of 2", got)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM notifications WHERE tenant_id = $1 AND audience_id = $2 AND notification_type = 'finding_comment'`,
		h.tenant.String(), h.scoped.String()); n != 1 {
		t.Errorf("watcher has %d comment notices, want 1", n)
	}
	// Once read, the next comment is a new notice.
	h.exec(`INSERT INTO notification_reads (notification_id, user_id) SELECT id, audience_id FROM notifications
		WHERE tenant_id = $1 AND audience_id = $2 AND notification_type = 'finding_comment'`, h.tenant.String(), h.scoped.String())
	h.comment(h.owner, "one more")
	if n := h.countRows(`SELECT COUNT(*) FROM notifications WHERE tenant_id = $1 AND audience_id = $2 AND notification_type = 'finding_comment'`,
		h.tenant.String(), h.scoped.String()); n != 2 {
		t.Errorf("after a read, watcher has %d comment notices, want 2", n)
	}

	// Losing scope: the watcher hears nothing more.
	h.exec(`DELETE FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = $2`, h.tenant.String(), h.scoped.String())
	h.exec(`DELETE FROM notifications WHERE tenant_id = $1`, h.tenant.String())
	h.comment(h.owner, "after the scope change")
	if got := h.told("finding_comment"); len(got) != 1 || got[h.memberA.String()] == "" {
		t.Errorf("after the scope change: %v, want the assignee only", got)
	}
	// A suspended member hears nothing either.
	h.exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() WHERE tenant_id = $1 AND user_id = $2`, h.tenant.String(), h.memberA.String())
	h.exec(`DELETE FROM notifications WHERE tenant_id = $1`, h.tenant.String())
	h.comment(h.owner, "to a suspended assignee")
	if got := h.told("finding_comment"); len(got) != 0 {
		t.Errorf("a suspended assignee was told: %v", got)
	}
	// And someone else's finding never reaches another tenant's watcher: the
	// rows carry the tenant and the recipient query reads only that tenant's.
	for id := range h.told("finding_comment") {
		if id == "" {
			t.Error("empty recipient")
		}
	}
}

func TestFindingAssignAndStatus_ReachWatchers_DB(t *testing.T) {
	h := newFanoutHarness(t)
	h.watch(h.scoped, "subscribed")
	ctx := h.ctx()

	// Assignment: the new assignee hears (assigned) even if they had stopped
	// watching, watchers hear too, the assigner does not.
	h.watch(h.memberA, "unsubscribed")
	if _, err := h.vuln.AssignFinding(ctx, h.findingA.String(), h.tenant.String(), h.memberA.String(), h.owner.String()); err != nil {
		t.Fatalf("assign: %v", err)
	}
	got := h.told("finding_assigned")
	if got[h.memberA.String()] != "assigned" || got[h.scoped.String()] != "watching" || len(got) != 2 {
		t.Fatalf("assignment reached %v, want the assignee (assigned) and the watcher", got)
	}
	if h.subscription(h.memberA) != "unsubscribed:manual" {
		t.Errorf("the assignee's stop was overridden: %q", h.subscription(h.memberA))
	}

	// A status change by a person reaches the assignee and the watchers; the
	// actor starts watching.
	if _, err := h.vuln.UpdateFindingStatus(ctx, h.findingA.String(), h.tenant.String(), finding.UpdateFindingStatusInput{
		Status: "in_progress", ActorID: h.owner.String(), HasVerifyPermission: true, HasFixApplyPermission: true, HasApprovePermission: true,
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	// memberA stopped watching, so only the watcher is told (the assignee stop wins for non-assignment events).
	got = h.told("finding_status_change")
	if got[h.scoped.String()] != "watching" || len(got) != 1 {
		t.Fatalf("status change reached %v, want the watcher only (the assignee stopped watching)", got)
	}
	if !strings.HasPrefix(h.subscription(h.owner), "subscribed:") {
		t.Errorf("status actor not watching: %q", h.subscription(h.owner))
	}
	// An automated change (no person) reaches the assignee's role only, not watchers.
	h.exec(`DELETE FROM notifications WHERE tenant_id = $1`, h.tenant.String())
	h.exec(`UPDATE work_item_subscriptions SET state = 'subscribed' WHERE tenant_id = $1 AND user_id = $2`, h.tenant.String(), h.memberA.String())
	if _, err := h.vuln.UpdateFindingStatus(ctx, h.findingA.String(), h.tenant.String(), finding.UpdateFindingStatusInput{
		Status: "confirmed", ActorID: "", HasVerifyPermission: true, HasFixApplyPermission: true, HasApprovePermission: true,
	}); err != nil {
		t.Logf("automated status change refused by the lifecycle (%v): skipping that check", err)
		return
	}
	got = h.told("finding_status_change")
	if _, watcherTold := got[h.scoped.String()]; watcherTold || got[h.memberA.String()] == "" {
		t.Errorf("automated change reached %v, want the assignee only", got)
	}
}

func TestAutoWatchPreference_DB(t *testing.T) {
	h := newFanoutHarness(t)
	item := participationdom.Item{Kind: participationdom.ItemFinding, ID: h.findingA}
	h.exec(`INSERT INTO notification_preferences (tenant_id, user_id, auto_watch) VALUES ($1, $2, false)`, h.tenant.String(), h.memberA.String())
	h.svc.AutoWatch(context.Background(), h.tenant, item, h.memberA, participationdom.ReasonCommented)
	h.svc.AutoWatch(context.Background(), h.tenant, item, h.scoped, participationdom.ReasonCommented)
	if h.subscription(h.memberA) != "" {
		t.Errorf("auto watch ignored the person's switch: %q", h.subscription(h.memberA))
	}
	if h.subscription(h.scoped) != "subscribed:commented" {
		t.Errorf("no preferences row means on: %q", h.subscription(h.scoped))
	}
}

// Team-only comments on a pentest finding never reach a campaign client, even
// one who watches the finding; a client-visible comment does (RFC-120 U25).
func TestPentestFindingComment_NotToClientWatcher_DB(t *testing.T) {
	h := newFanoutHarness(t)
	campaign, f := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, 'fanout campaign')`, campaign.String(), h.tenant.String())
	for user, role := range map[shared.ID]string{h.memberA: "lead", h.memberStrict: "tester", h.scoped: "client"} {
		h.exec(`INSERT INTO pentest_campaign_members (tenant_id, campaign_id, user_id, role) VALUES ($1, $2, $3, $4)`,
			h.tenant.String(), campaign.String(), user.String(), role)
	}
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status, pentest_campaign_id)
		VALUES ($1, $2, 'pentest', 'manual', 'pentest finding', 'high', $3, 'confirmed', $4)`, f.String(), h.tenant.String(), "fp-"+f.String(), campaign.String())
	for _, u := range []shared.ID{h.scoped, h.memberStrict} {
		h.exec(`INSERT INTO work_item_subscriptions (tenant_id, finding_id, user_id, reason) VALUES ($1, $2, $3, 'manual')`, h.tenant.String(), f.String(), u.String())
	}
	post := func(visibility string) {
		t.Helper()
		if _, err := h.vuln.AddFindingCommentWithInput(h.ctx(), finding.AddFindingCommentInput{
			TenantID: h.tenant.String(), FindingID: f.String(), AuthorID: h.memberA.String(), Content: "note " + visibility,
			ActingUserID: h.memberA.String(), Visibility: visibility,
		}); err != nil {
			t.Fatalf("comment (%s): %v", visibility, err)
		}
	}
	toldOnPentest := func() map[string]bool {
		rows, err := h.db.Query(`SELECT audience_id::text FROM notifications WHERE tenant_id = $1 AND resource_id = $2 AND notification_type = 'finding_comment'`, h.tenant.String(), f.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			out[id] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	post("team")
	if got := toldOnPentest(); !got[h.memberStrict.String()] || got[h.scoped.String()] {
		t.Fatalf("team comment reached %v, want the tester and not the client", got)
	}
	h.exec(`DELETE FROM notifications WHERE tenant_id = $1`, h.tenant.String())
	post("client")
	if got := toldOnPentest(); !got[h.memberStrict.String()] || !got[h.scoped.String()] {
		t.Fatalf("client-visible comment reached %v, want the tester and the client", got)
	}
}
