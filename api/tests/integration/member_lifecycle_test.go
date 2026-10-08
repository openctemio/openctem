package integration

// Member lifecycle against a real database: disable, re-enable, offboard
// (mandatory reassignment, tombstone), re-join from zero, erase personal
// data. Design: docs/rfcs/RFC-050-asset-access-model.md.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type lifecycleFixture struct {
	db        *sql.DB
	svc       *tenant.TenantService
	repo      *postgres.TenantRepository
	scope     *postgres.DataScopeRepository
	tenantID  shared.ID
	otherTID  shared.ID
	ownerID   shared.ID
	memberID  shared.ID // the person whose lifecycle is exercised
	mshipID   shared.ID
	peerID    shared.ID // another active member: the reassignment target
	foreignID shared.ID // active member of the OTHER tenant only
	assetA    shared.ID // via group
	assetB    shared.ID // via direct grant
	groupID   shared.ID
	keyID     shared.ID
	scanID    shared.ID
	reportID  shared.ID
	workflow  shared.ID
	findingID shared.ID
	campaign  shared.ID
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	f := &lifecycleFixture{db: db}
	f.repo = postgres.NewTenantRepository(pdb)
	f.scope = postgres.NewDataScopeRepository(pdb)
	f.svc = tenant.NewTenantService(f.repo, logger.NewNop())
	f.svc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(pdb))

	f.tenantID = createTestTenant(t, db, "lifecycle")
	f.otherTID = createTestTenant(t, db, "lifecycle-other")
	stamp := time.Now().UnixNano()
	mk := func(label string) shared.ID {
		return createTestUser(t, db, fmt.Sprintf("lc-%s-%d@example.com", label, stamp), "LC "+label)
	}
	f.ownerID, f.memberID, f.peerID, f.foreignID = mk("owner"), mk("member"), mk("peer"), mk("foreign")
	users := []shared.ID{f.ownerID, f.memberID, f.peerID, f.foreignID}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tid := range []shared.ID{f.tenantID, f.otherTID} {
			for _, q := range []string{
				`DELETE FROM pentest_campaign_members WHERE tenant_id = $1`,
				`DELETE FROM pentest_campaigns WHERE tenant_id = $1`,
				`DELETE FROM api_keys WHERE tenant_id = $1`,
				`DELETE FROM scans WHERE tenant_id = $1`,
				`DELETE FROM report_schedules WHERE tenant_id = $1`,
				`DELETE FROM workflows WHERE tenant_id = $1`,
				`DELETE FROM asset_access_grants WHERE tenant_id = $1`,
				`DELETE FROM user_accessible_assets WHERE tenant_id = $1`,
				`DELETE FROM asset_owners WHERE asset_id IN (SELECT id FROM assets WHERE tenant_id = $1)`,
				`DELETE FROM groups WHERE tenant_id = $1`,
				`DELETE FROM audit_logs WHERE tenant_id = $1`,
				`DELETE FROM tenant_members WHERE tenant_id = $1`,
			} {
				_, _ = db.ExecContext(bg, q, tid.String())
			}
		}
		cleanupTestData(db, f.tenantID, f.otherTID)
		for _, u := range users {
			_, _ = db.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})

	createTestMembership(t, db, f.tenantID, f.ownerID, "owner")
	f.mshipID = createTestMembership(t, db, f.tenantID, f.memberID, "member")
	createTestMembership(t, db, f.tenantID, f.peerID, "member")
	createTestMembership(t, db, f.otherTID, f.foreignID, "member")

	f.assetA = createTestAsset(t, db, f.tenantID, fmt.Sprintf("lc-a-%d", stamp))
	f.assetB = createTestAsset(t, db, f.tenantID, fmt.Sprintf("lc-b-%d", stamp))
	f.groupID = shared.NewID()
	f.keyID = shared.NewID()
	f.scanID = shared.NewID()
	f.reportID = shared.NewID()
	f.workflow = shared.NewID()
	f.campaign = shared.NewID()
	tid, uid := f.tenantID.String(), f.memberID.String()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, 'LC team', $3, TRUE)`,
			[]any{f.groupID.String(), tid, fmt.Sprintf("lc-team-%d", stamp)}},
		{`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, []any{f.groupID.String(), uid}},
		{`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'primary')`, []any{f.assetA.String(), f.groupID.String()}},
		{`SELECT refresh_access_for_asset_assign($1, $2, 'primary')`, []any{f.groupID.String(), f.assetA.String()}},
		{`INSERT INTO asset_access_grants (tenant_id, asset_id, user_id) VALUES ($1, $2, $3)`, []any{tid, f.assetB.String(), uid}},
		{`SELECT refresh_access_for_grant_add($1, $2)`, []any{f.assetB.String(), uid}},
		{`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, []any{f.assetB.String(), uid}},
		{`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status) VALUES ($1, $2, $3, 'lc key', $4, 'oct_lc', 'active')`,
			[]any{f.keyID.String(), tid, uid, fmt.Sprintf("hash-%d", stamp)}},
		{`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, schedule_type, status, targets, created_by)
		  VALUES ($1, $2, 'LC nightly', 'single', 'nuclei', 'daily', 'active', ARRAY['lc.example.com'], $3)`, []any{f.scanID.String(), tid, uid}},
		{`INSERT INTO report_schedules (id, tenant_id, name, report_type, cron_expression, is_active, created_by, created_at, updated_at)
		  VALUES ($1, $2, 'LC weekly', 'executive_summary', '0 8 * * 1', TRUE, $3, NOW(), NOW())`, []any{f.reportID.String(), tid, uid}},
		{`INSERT INTO workflows (id, tenant_id, name, is_active, created_by) VALUES ($1, $2, 'LC flow', TRUE, $3)`, []any{f.workflow.String(), tid, uid}},
		{`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, 'LC campaign')`, []any{f.campaign.String(), tid}},
		{`INSERT INTO pentest_campaign_members (tenant_id, campaign_id, user_id, role) VALUES ($1, $2, $3, 'tester')`, []any{tid, f.campaign.String(), uid}},
	} {
		if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed %q: %v", strings.Fields(q.sql)[0:3], err)
		}
	}
	f.findingID = createTestFinding(t, db, f.tenantID, f.assetA, "lc finding")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET assigned_to = $1 WHERE id = $2 AND tenant_id = $3`,
		uid, f.findingID.String(), tid); err != nil {
		t.Fatalf("assign finding: %v", err)
	}
	return f
}

func (f *lifecycleFixture) ownerCtx() audit.AuditContext {
	return audit.AuditContext{TenantID: f.tenantID.String(), ActorID: f.ownerID.String(), ActorEmail: "owner@example.com"}
}

func (f *lifecycleFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func (f *lifecycleFixture) str(t *testing.T, query string, args ...any) string {
	t.Helper()
	var s sql.NullString
	if err := f.db.QueryRowContext(context.Background(), query, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return s.String
}

func (f *lifecycleFixture) visible(t *testing.T) int {
	return f.count(t, `SELECT COUNT(*) FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = $2`,
		f.tenantID.String(), f.memberID.String())
}

// Disable cuts access at once and freezes what the member holds; re-enable
// restores it from the frozen sources.
func TestMemberLifecycle_DisableFreezesAndReenableRestores(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID.String(), f.memberID.String()
	if got := f.visible(t); got != 2 {
		t.Fatalf("baseline visible assets = %d, want 2", got)
	}

	if err := f.svc.SuspendMember(ctx, f.mshipID.String(), f.ownerCtx()); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got := f.str(t, `SELECT status FROM tenant_members WHERE id = $1 AND tenant_id = $2`, f.mshipID.String(), tid); got != "suspended" {
		t.Errorf("membership status = %q, want suspended", got)
	}
	if got := f.visible(t); got != 0 {
		t.Errorf("visible assets after disable = %d, want 0", got)
	}
	ids, err := f.scope.AssetIDsInScope(ctx, f.tenantID, f.memberID, []shared.ID{f.assetA, f.assetB})
	if err != nil || len(ids) != 0 {
		t.Errorf("AssetIDsInScope after disable = %v (err %v), want none", ids, err)
	}
	if got := f.str(t, `SELECT status FROM api_keys WHERE id = $1 AND tenant_id = $2`, f.keyID.String(), tid); got != "suspended" {
		t.Errorf("api key status = %q, want suspended", got)
	}
	if got := f.str(t, `SELECT status FROM scans WHERE id = $1 AND tenant_id = $2`, f.scanID.String(), tid); got != "paused" {
		t.Errorf("owned scan status = %q, want paused", got)
	}
	if got := f.count(t, `SELECT COUNT(*) FROM report_schedules WHERE id = $1 AND tenant_id = $2 AND is_active`, f.reportID.String(), tid); got != 0 {
		t.Error("owned report schedule still active after disable")
	}
	if got := f.count(t, `SELECT COUNT(*) FROM workflows WHERE id = $1 AND tenant_id = $2 AND is_active`, f.workflow.String(), tid); got != 0 {
		t.Error("owned workflow still active after disable")
	}
	// Frozen, not stripped.
	if got := f.count(t, `SELECT COUNT(*) FROM group_members WHERE group_id = $1 AND user_id = $2`, f.groupID.String(), uid); got != 1 {
		t.Error("disable must keep group memberships (frozen)")
	}
	if got := f.count(t, `SELECT COUNT(*) FROM asset_access_grants WHERE tenant_id = $1 AND user_id = $2`, tid, uid); got != 1 {
		t.Error("disable must keep direct grants (frozen)")
	}
	// A refresh while disabled never brings the rows back.
	if _, err := f.db.ExecContext(ctx, `SELECT refresh_access_for_member_add($1, $2)`, f.groupID.String(), uid); err != nil {
		t.Fatalf("member_add refresh: %v", err)
	}
	if _, err := f.db.ExecContext(ctx, `SELECT refresh_access_for_grant_add($1, $2)`, f.assetB.String(), uid); err != nil {
		t.Fatalf("grant_add refresh: %v", err)
	}
	if got := f.visible(t); got != 0 {
		t.Errorf("incremental refresh re-admitted a disabled member: %d rows", got)
	}
	// A background job acting for the member gets no full-data bypass.
	if full, err := f.scope.HasFullDataRole(ctx, f.tenantID, f.memberID); err != nil || full {
		t.Errorf("HasFullDataRole for a disabled member = %v (err %v), want false", full, err)
	}

	if err := f.svc.ReactivateMember(ctx, f.mshipID.String(), f.ownerCtx()); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if got := f.visible(t); got != 2 {
		t.Errorf("visible assets after re-enable = %d, want 2", got)
	}
	if got := f.str(t, `SELECT status FROM api_keys WHERE id = $1 AND tenant_id = $2`, f.keyID.String(), tid); got != "active" {
		t.Errorf("api key status after re-enable = %q, want active", got)
	}
	if got := f.str(t, `SELECT status FROM scans WHERE id = $1 AND tenant_id = $2`, f.scanID.String(), tid); got != "paused" {
		t.Errorf("scan after re-enable = %q, want still paused (an administrator resumes it)", got)
	}
}

// A background job (scheduled scan, report) acting for a disabled or
// offboarded ADMINISTRATOR refuses: the production admin lookup answers
// ErrInactivePrincipal instead of the admin bypass.
func TestMemberLifecycle_InactiveAdminActsAsNobody(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	tid := f.tenantID.String()
	if _, err := f.db.ExecContext(ctx, `UPDATE tenant_members SET role = 'admin' WHERE id = $1 AND tenant_id = $2`,
		f.mshipID.String(), tid); err != nil {
		t.Fatalf("promote: %v", err)
	}
	enf := datascope.New(f.scope, func(context.Context) datascope.Caller { return datascope.Caller{} }, logger.NewNop())
	enf.SetAdminLookup(datascope.MembershipAdminLookup(f.repo))

	// Control: the active administrator is unrestricted.
	if _, unrestricted, err := enf.CanActOnAssets(ctx, f.tenantID, &f.memberID, []shared.ID{f.assetA}); err != nil || !unrestricted {
		t.Fatalf("active admin: unrestricted=%v err=%v, want unrestricted", unrestricted, err)
	}
	for _, status := range []string{"suspended", "offboarded"} {
		if _, err := f.db.ExecContext(ctx, `UPDATE tenant_members SET status = $3 WHERE id = $1 AND tenant_id = $2`,
			f.mshipID.String(), tid, status); err != nil {
			t.Fatalf("set %s: %v", status, err)
		}
		canAct, unrestricted, err := enf.CanActOnAssets(ctx, f.tenantID, &f.memberID, []shared.ID{f.assetA})
		if !errors.Is(err, datascope.ErrInactivePrincipal) || unrestricted || canAct != nil {
			t.Errorf("%s admin: a job acting for them must refuse, got err=%v unrestricted=%v", status, err, unrestricted)
		}
		if err := enf.AssertFindingForUser(ctx, f.tenantID, f.memberID, f.findingID); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s admin: report-style finding read must be refused, got %v", status, err)
		}
	}
}

// Offboarding demands a new owner for every category of owned work, refuses
// a target outside the tenant, then strips access and keeps a tombstone.
func TestMemberLifecycle_OffboardReassignsStripsAndTombstones(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID.String(), f.memberID.String()

	_, err := f.svc.OffboardMember(ctx, f.mshipID.String(), tenant.OffboardMemberInput{}, f.ownerCtx())
	re, ok := tenantdom.AsReassignmentError(err)
	if !ok {
		t.Fatalf("offboard without a plan: want a reassignment error, got %v", err)
	}
	if got := strings.Join(re.Missing, ","); got != "schedules,findings,assets" {
		t.Errorf("missing = %q, want schedules,findings,assets", got)
	}
	if got := f.str(t, `SELECT status FROM tenant_members WHERE id = $1 AND tenant_id = $2`, f.mshipID.String(), tid); got != "active" {
		t.Fatalf("a refused offboarding changed the membership to %q", got)
	}
	if !errors.Is(err, tenantdom.ErrReassignmentRequired) {
		t.Fatalf("offboard without a plan: want ErrReassignmentRequired, got %v", err)
	}

	for name, target := range map[string]shared.ID{"other tenant": f.foreignID, "self": f.memberID, "unknown": shared.NewID()} {
		_, err := f.svc.OffboardMember(ctx, f.mshipID.String(), tenant.OffboardMemberInput{
			SchedulesTo: target.String(), FindingsTo: target.String(), AssetsTo: target.String(),
		}, f.ownerCtx())
		if !errors.Is(err, tenantdom.ErrInvalidReassignTarget) {
			t.Errorf("target %s: want ErrInvalidReassignTarget, got %v", name, err)
		}
	}

	peer := f.peerID.String()
	res, err := f.svc.OffboardMember(ctx, f.mshipID.String(), tenant.OffboardMemberInput{
		SchedulesTo: peer, FindingsTo: peer, AssetsTo: peer,
	}, f.ownerCtx())
	if err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if res.ReassignedSchedules != 3 || res.ReassignedFindings != 1 || res.ReassignedAssets != 1 {
		t.Errorf("reassigned schedules/findings/assets = %d/%d/%d, want 3/1/1",
			res.ReassignedSchedules, res.ReassignedFindings, res.ReassignedAssets)
	}
	checks := []struct {
		name  string
		query string
		args  []any
		want  int
	}{
		{"membership row kept as tombstone", `SELECT COUNT(*) FROM tenant_members WHERE id = $1 AND tenant_id = $2 AND status = 'offboarded' AND offboarded_at IS NOT NULL AND offboarded_by = $3`, []any{f.mshipID.String(), tid, f.ownerID.String()}, 1},
		{"scan owned by peer", `SELECT COUNT(*) FROM scans WHERE id = $1 AND tenant_id = $2 AND created_by = $3`, []any{f.scanID.String(), tid, peer}, 1},
		{"report schedule owned by peer", `SELECT COUNT(*) FROM report_schedules WHERE id = $1 AND tenant_id = $2 AND created_by = $3`, []any{f.reportID.String(), tid, peer}, 1},
		{"workflow owned by peer", `SELECT COUNT(*) FROM workflows WHERE id = $1 AND tenant_id = $2 AND created_by = $3`, []any{f.workflow.String(), tid, peer}, 1},
		{"finding assigned to peer", `SELECT COUNT(*) FROM findings WHERE id = $1 AND tenant_id = $2 AND assigned_to = $3`, []any{f.findingID.String(), tid, peer}, 1},
		{"asset owned by peer", `SELECT COUNT(*) FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, []any{f.assetB.String(), peer}, 1},
		{"api key revoked", `SELECT COUNT(*) FROM api_keys WHERE id = $1 AND tenant_id = $2 AND status = 'revoked' AND revoked_by = $3`, []any{f.keyID.String(), tid, f.ownerID.String()}, 1},
		{"group membership removed", `SELECT COUNT(*) FROM group_members WHERE group_id = $1 AND user_id = $2`, []any{f.groupID.String(), uid}, 0},
		{"grants removed", `SELECT COUNT(*) FROM asset_access_grants WHERE tenant_id = $1 AND user_id = $2`, []any{tid, uid}, 0},
		{"campaign membership removed", `SELECT COUNT(*) FROM pentest_campaign_members WHERE tenant_id = $1 AND user_id = $2`, []any{tid, uid}, 0},
		{"roles removed", `SELECT COUNT(*) FROM user_roles WHERE tenant_id = $1 AND user_id = $2`, []any{tid, uid}, 0},
		{"scope rows removed", `SELECT COUNT(*) FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = $2`, []any{tid, uid}, 0},
	}
	for _, c := range checks {
		if got := f.count(t, c.query, c.args...); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}

	// The tombstone yields no token and no tenant in the switcher.
	byStatus, err := f.repo.GetUserMembershipsWithStatus(ctx, f.memberID)
	if err != nil {
		t.Fatalf("memberships with status: %v", err)
	}
	for _, m := range append(byStatus.Active, byStatus.Suspended...) {
		if m.TenantID == tid {
			t.Error("an offboarded membership is listed for token exchange")
		}
	}
	tenants, err := f.repo.ListTenantsByUser(ctx, f.memberID)
	if err != nil {
		t.Fatalf("list tenants: %v", err)
	}
	for _, tw := range tenants {
		if tw.Tenant.ID() == f.tenantID {
			t.Error("an offboarded membership is listed in the tenant switcher")
		}
	}
	// Pickers (the default member list) leave the tombstone out.
	list, err := f.repo.SearchMembersWithUserInfo(ctx, f.tenantID, tenantdom.MemberSearchFilters{Limit: 50})
	if err != nil {
		t.Fatalf("search members: %v", err)
	}
	for _, m := range list.Members {
		if m.UserID == f.memberID {
			t.Error("default member list includes an offboarded member")
		}
	}
	off, err := f.repo.SearchMembersWithUserInfo(ctx, f.tenantID, tenantdom.MemberSearchFilters{Limit: 50, Status: "offboarded"})
	if err != nil || off.Total != 1 {
		t.Errorf("status=offboarded total = %d (err %v), want 1", off.Total, err)
	}

	// A tombstone cannot be given a group or a grant meanwhile (it would
	// survive into a later re-join).
	acr := postgres.NewAccessControlRepository(&postgres.DB{DB: f.db})
	if in, err := acr.IsUserInTenant(ctx, f.tenantID, f.memberID); err != nil || in {
		t.Errorf("IsUserInTenant for an offboarded member = %v (err %v), want false", in, err)
	}
	if in, err := acr.IsUserInTenant(ctx, f.tenantID, f.peerID); err != nil || !in {
		t.Errorf("IsUserInTenant for an active member = %v (err %v), want true", in, err)
	}

	// Re-invite: the person re-joins from zero.
	if _, err := f.svc.AddMember(ctx, tid, tenant.AddMemberInput{UserID: f.memberID, Role: "member"}, f.ownerID, f.ownerCtx()); err != nil {
		t.Fatalf("re-add after offboarding: %v", err)
	}
	m, err := f.repo.GetMembership(ctx, f.memberID, f.tenantID)
	if err != nil || !m.IsActive() {
		t.Fatalf("re-added membership: active=%v err=%v", m != nil && m.IsActive(), err)
	}
	for _, c := range []struct {
		name  string
		query string
		want  int
	}{
		{"groups", `SELECT COUNT(*) FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE g.tenant_id = $1 AND gm.user_id = $2`, 0},
		{"grants", `SELECT COUNT(*) FROM asset_access_grants WHERE tenant_id = $1 AND user_id = $2`, 0},
		{"scope rows", `SELECT COUNT(*) FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = $2`, 0},
		{"usable keys", `SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND user_id = $2 AND status <> 'revoked'`, 0},
		{"campaigns", `SELECT COUNT(*) FROM pentest_campaign_members WHERE tenant_id = $1 AND user_id = $2`, 0},
		{"tombstones", `SELECT COUNT(*) FROM tenant_members WHERE tenant_id = $1 AND user_id = $2 AND status = 'offboarded'`, 0},
	} {
		if got := f.count(t, c.query, tid, uid); got != c.want {
			t.Errorf("after re-join, %s = %d, want %d", c.name, got, c.want)
		}
	}
	// Adding the same person again is a conflict, not a duplicate.
	if _, err := f.svc.AddMember(ctx, tid, tenant.AddMemberInput{UserID: f.memberID, Role: "member"}, f.ownerID, f.ownerCtx()); err == nil {
		t.Error("adding an active member twice must fail")
	}
}

// Erasing personal data: owner only, after offboarding, never while the
// person belongs to another organization; the row and its foreign keys stay.
func TestMemberLifecycle_EraseAnonymisesAndKeepsReferences(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID.String(), f.memberID.String()

	if err := f.svc.EraseMemberPersonalData(ctx, f.mshipID.String(), f.ownerCtx()); !errors.Is(err, tenantdom.ErrEraseNotAllowed) {
		t.Fatalf("erase before offboarding: want ErrEraseNotAllowed, got %v", err)
	}
	peer := f.peerID.String()
	if _, err := f.svc.OffboardMember(ctx, f.mshipID.String(), tenant.OffboardMemberInput{
		SchedulesTo: peer, UnassignFindings: true, AssetsTo: peer,
	}, f.ownerCtx()); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if got := f.str(t, `SELECT assigned_to::text FROM findings WHERE id = $1 AND tenant_id = $2`, f.findingID.String(), tid); got != "" {
		t.Errorf("unassign_findings left the finding assigned to %q", got)
	}

	peerCtx := audit.AuditContext{TenantID: tid, ActorID: peer}
	if err := f.svc.EraseMemberPersonalData(ctx, f.mshipID.String(), peerCtx); !errors.Is(err, tenant.ErrOwnerRequiredForErase) {
		t.Fatalf("erase by a non-owner: want ErrOwnerRequiredForErase, got %v", err)
	}

	// Still a member elsewhere: refused.
	other := createTestMembership(t, f.db, f.otherTID, f.memberID, "member")
	if err := f.svc.EraseMemberPersonalData(ctx, f.mshipID.String(), f.ownerCtx()); !errors.Is(err, tenantdom.ErrEraseNotAllowed) {
		t.Fatalf("erase while a member of another organization: want ErrEraseNotAllowed, got %v", err)
	}
	if _, err := f.db.ExecContext(ctx, `DELETE FROM tenant_members WHERE id = $1 AND tenant_id = $2`, other.String(), f.otherTID.String()); err != nil {
		t.Fatalf("drop other membership: %v", err)
	}

	// An IdP identity bound to the account.
	if _, err := f.db.ExecContext(ctx, `INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1, $2, $3)`, uid, "https://idp.erase.example", uid); err != nil {
		t.Fatalf("bind identity: %v", err)
	}
	// A row that points at the person: the finding they created.
	if _, err := f.db.ExecContext(ctx, `UPDATE findings SET created_by = $1 WHERE id = $2 AND tenant_id = $3`, uid, f.findingID.String(), tid); err != nil {
		t.Fatalf("set created_by: %v", err)
	}
	if err := f.svc.EraseMemberPersonalData(ctx, f.mshipID.String(), f.ownerCtx()); err != nil {
		t.Fatalf("erase: %v", err)
	}
	var name, email, status string
	var erased sql.NullTime
	if err := f.db.QueryRowContext(ctx, `SELECT name, email, status::text, erased_at FROM users WHERE id = $1`, uid).
		Scan(&name, &email, &status, &erased); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if !strings.HasPrefix(name, "Deleted user #") || !strings.HasSuffix(email, "@erased.invalid") || status != "inactive" || !erased.Valid {
		t.Errorf("erased user = (%q, %q, %q, erased=%v)", name, email, status, erased.Valid)
	}
	if got := f.count(t, `SELECT COUNT(*) FROM findings WHERE id = $1 AND tenant_id = $2 AND created_by = $3`, f.findingID.String(), tid, uid); got != 1 {
		t.Error("erase broke a foreign key to the user")
	}
	if got := f.count(t, `SELECT COUNT(*) FROM tenant_members WHERE id = $1 AND tenant_id = $2`, f.mshipID.String(), tid); got != 1 {
		t.Error("erase removed the membership tombstone")
	}
	var mfaLeft int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_mfa WHERE user_id = $1`, uid).Scan(&mfaLeft)
	if mfaLeft != 0 {
		t.Error("erase left a second factor")
	}
	if got := f.count(t, `SELECT COUNT(*) FROM user_identities WHERE user_id = $1`, uid); got != 0 {
		t.Error("erase left a federated identity: a later sign-in would find the anonymised account")
	}
}
