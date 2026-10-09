package postgres

// Member lifecycle storage: disable, re-enable, offboard, rejoin, erase.
// Design: docs/rfcs/RFC-050-asset-access-model.md.
//
// Tenant isolation: every statement is bound to the membership's tenant
// (tenant_members.tenant_id, and the tenant_id of each owned row), which the
// service loaded with the caller's own tenant. A reassignment target must be
// an ACTIVE member of that same tenant, checked inside the transaction.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// MemberLifecycleRepository implements tenant.LifecycleRepository.
type MemberLifecycleRepository struct {
	db *DB
}

// NewMemberLifecycleRepository creates a MemberLifecycleRepository.
func NewMemberLifecycleRepository(db *DB) *MemberLifecycleRepository {
	return &MemberLifecycleRepository{db: db}
}

var _ tenant.LifecycleRepository = (*MemberLifecycleRepository)(nil)

// queryer is the read surface shared by *sql.DB and *sql.Tx.
type lifecycleQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func closedFindingStatuses() []string {
	closed := vulnerability.ClosedFindingStatuses()
	out := make([]string, 0, len(closed))
	for _, s := range closed {
		out = append(out, s.String())
	}
	return out
}

// AccessReport lists what the member holds and owns in the tenant.
func (r *MemberLifecycleRepository) AccessReport(ctx context.Context, m *tenant.Membership) (*tenant.AccessReport, error) {
	return accessReport(ctx, r.db, m)
}

func accessReport(ctx context.Context, q lifecycleQueryer, m *tenant.Membership) (*tenant.AccessReport, error) {
	tid, uid := m.TenantID().String(), m.UserID().String()
	rep := &tenant.AccessReport{
		MembershipID: m.ID().String(),
		UserID:       uid,
		Status:       m.Status(),
	}
	lists := []struct {
		dst   *[]tenant.LifecycleRef
		query string
	}{
		{&rep.Roles, `
			SELECT DISTINCT ro.id::text, ro.name, '', ''
			FROM v_user_role_grants ur JOIN roles ro ON ro.id = ur.role_id
			WHERE ur.tenant_id = $1 AND ur.user_id = $2
			ORDER BY ro.name`},
		{&rep.Groups, `
			SELECT g.id::text, g.name, CASE WHEN g.is_active THEN 'active' ELSE 'inactive' END, gm.role
			FROM group_members gm JOIN groups g ON g.id = gm.group_id
			WHERE g.tenant_id = $1 AND gm.user_id = $2
			ORDER BY g.name`},
		{&rep.APIKeys, `
			SELECT id::text, name, status, key_prefix
			FROM api_keys
			WHERE tenant_id = $1 AND user_id = $2 AND status IN ('active', 'suspended')
			ORDER BY name`},
		{&rep.Campaigns, `
			SELECT c.id::text, c.name, c.status, pcm.role
			FROM pentest_campaign_members pcm JOIN pentest_campaigns c ON c.id = pcm.campaign_id
			WHERE pcm.tenant_id = $1 AND c.tenant_id = $1 AND pcm.user_id = $2
			ORDER BY c.name`},
		{&rep.OwnedScans, `
			SELECT id::text, name, status, schedule_type
			FROM scans
			WHERE tenant_id = $1 AND created_by = $2
			ORDER BY name`},
		{&rep.OwnedReportSchedules, `
			SELECT id::text, name, CASE WHEN COALESCE(is_active, FALSE) THEN 'active' ELSE 'paused' END, report_type
			FROM report_schedules
			WHERE tenant_id = $1 AND created_by = $2
			ORDER BY name`},
		{&rep.OwnedWorkflows, `
			SELECT id::text, name, CASE WHEN is_active THEN 'active' ELSE 'paused' END, ''
			FROM automations
			WHERE tenant_id = $1 AND created_by = $2
			ORDER BY name`},
	}
	for _, l := range lists {
		refs, err := scanLifecycleRefs(ctx, q, l.query, tid, uid)
		if err != nil {
			return nil, err
		}
		*l.dst = refs
	}

	if err := q.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM asset_access_grants WHERE tenant_id = $1 AND user_id = $2),
			(SELECT COUNT(*) FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = $2),
			(SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND assigned_to = $2 AND NOT (status = ANY($3))),
			(SELECT COUNT(*) FROM asset_owners ao JOIN assets a ON a.id = ao.asset_id
			  WHERE a.tenant_id = $1 AND ao.user_id = $2)`,
		tid, uid, pq.Array(closedFindingStatuses()),
	).Scan(&rep.DirectGrants, &rep.VisibleAssets, &rep.AssignedFindings, &rep.OwnedAssets); err != nil {
		return nil, fmt.Errorf("access report counts: %w", err)
	}
	return rep, nil
}

func scanLifecycleRefs(ctx context.Context, q lifecycleQueryer, query, tenantID, userID string) ([]tenant.LifecycleRef, error) {
	rows, err := q.QueryContext(ctx, query, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("access report: %w", err)
	}
	defer rows.Close()
	out := []tenant.LifecycleRef{}
	for rows.Next() {
		var ref tenant.LifecycleRef
		if err := rows.Scan(&ref.ID, &ref.Name, &ref.Status, &ref.Detail); err != nil {
			return nil, fmt.Errorf("access report row: %w", err)
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// Disable suspends the membership and everything that acts as the member.
func (r *MemberLifecycleRepository) Disable(ctx context.Context, m *tenant.Membership) (_ *tenant.DisableResult, err error) {
	tid, uid := m.TenantID().String(), m.UserID().String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin disable: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	res, err := tx.ExecContext(ctx, `
		UPDATE tenant_members
		SET status = 'suspended', suspended_at = $3, suspended_by = $4, suspended_reason = $5
		WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'`,
		tid, uid, nullTime(m.SuspendedAt()), nullIDPtr(m.SuspendedBy()), nullString(m.SuspendedReason()))
	if err != nil {
		return nil, fmt.Errorf("suspend membership: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, shared.ErrNotFound
	}

	out := &tenant.DisableResult{}
	keys, err := tx.ExecContext(ctx, `
		UPDATE api_keys SET status = 'suspended', updated_at = NOW()
		WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'`, tid, uid)
	if err != nil {
		return nil, fmt.Errorf("suspend api keys: %w", err)
	}
	if n, _ := keys.RowsAffected(); n > 0 {
		out.SuspendedKeys = int(n)
	}

	if out.PausedScans, err = execReturningRefs(ctx, tx, `
		UPDATE scans SET status = 'paused', updated_at = NOW()
		WHERE tenant_id = $1 AND created_by = $2 AND status = 'active' AND schedule_type <> 'manual'
		RETURNING id::text, name, 'paused', schedule_type`, tid, uid); err != nil {
		return nil, fmt.Errorf("pause scans: %w", err)
	}
	if out.PausedReports, err = execReturningRefs(ctx, tx, `
		UPDATE report_schedules SET is_active = FALSE, updated_at = NOW()
		WHERE tenant_id = $1 AND created_by = $2 AND COALESCE(is_active, FALSE)
		RETURNING id::text, name, 'paused', report_type`, tid, uid); err != nil {
		return nil, fmt.Errorf("pause report schedules: %w", err)
	}
	if out.PausedWorkflow, err = execReturningRefs(ctx, tx, `
		UPDATE automations SET is_active = FALSE, updated_at = NOW()
		WHERE tenant_id = $1 AND created_by = $2 AND is_active
		RETURNING id::text, name, 'paused', ''`, tid, uid); err != nil {
		return nil, fmt.Errorf("pause workflows: %w", err)
	}

	// The membership is no longer active, so the recompute leaves no row.
	if _, err = tx.ExecContext(ctx, `SELECT refresh_access_for_user($1, $2)`, tid, uid); err != nil {
		return nil, fmt.Errorf("drop scope: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit disable: %w", err)
	}
	return out, nil
}

func execReturningRefs(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]tenant.LifecycleRef, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []tenant.LifecycleRef{}
	for rows.Next() {
		var ref tenant.LifecycleRef
		if err := rows.Scan(&ref.ID, &ref.Name, &ref.Status, &ref.Detail); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// Reenable reactivates a disabled membership.
func (r *MemberLifecycleRepository) Reenable(ctx context.Context, m *tenant.Membership) (err error) {
	tid, uid := m.TenantID().String(), m.UserID().String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin re-enable: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	res, err := tx.ExecContext(ctx, `
		UPDATE tenant_members
		SET status = 'active', suspended_at = NULL, suspended_by = NULL, suspended_reason = NULL,
		    expires_at = $3, expiry_reason = $4
		WHERE tenant_id = $1 AND user_id = $2 AND status = 'suspended'`,
		tid, uid, nullTime(m.ExpiresAt()), nullString(m.ExpiryReason()))
	if err != nil {
		return fmt.Errorf("reactivate membership: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	// Only keys a disable suspended come back; a revoked or expired key stays
	// so. An expired key's own expires_at still refuses it at authentication.
	if _, err = tx.ExecContext(ctx, `
		UPDATE api_keys SET status = 'active', updated_at = NOW()
		WHERE tenant_id = $1 AND user_id = $2 AND status = 'suspended'`, tid, uid); err != nil {
		return fmt.Errorf("reactivate api keys: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `SELECT refresh_access_for_user($1, $2)`, tid, uid); err != nil {
		return fmt.Errorf("recompute scope: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit re-enable: %w", err)
	}
	return nil
}

// Offboard reassigns owned work, strips access and leaves a tombstone.
func (r *MemberLifecycleRepository) Offboard(ctx context.Context, m *tenant.Membership, actor *shared.ID, plan tenant.OffboardPlan) (_ *tenant.OffboardResult, err error) {
	tid, uid := m.TenantID().String(), m.UserID().String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin offboard: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if stepErr := lockMembershipForOffboard(ctx, tx, tid, uid); stepErr != nil {
		return nil, stepErr
	}
	if stepErr := checkReassignTargets(ctx, tx, m, plan); stepErr != nil {
		return nil, stepErr
	}
	report, err := accessReport(ctx, tx, m)
	if err != nil {
		return nil, err
	}
	if missing := plan.Missing(report); len(missing) > 0 {
		return nil, &tenant.ReassignmentError{Missing: missing}
	}

	out := &tenant.OffboardResult{Report: report}
	if stepErr := reassignOwnedWork(ctx, tx, tid, uid, plan, report, out); stepErr != nil {
		return nil, stepErr
	}
	var actorArg any
	if actor != nil && !actor.IsZero() {
		actorArg = actor.String()
	}
	if stepErr := stripAccess(ctx, tx, tid, uid, actorArg, out); stepErr != nil {
		return nil, stepErr
	}

	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `
		UPDATE tenant_members
		SET status = 'offboarded', offboarded_at = $3, offboarded_by = $4,
		    suspended_at = NULL, suspended_by = NULL
		WHERE tenant_id = $1 AND user_id = $2`, tid, uid, now, actorArg); err != nil {
		return nil, fmt.Errorf("tombstone membership: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `SELECT refresh_access_for_user($1, $2)`, tid, uid); err != nil {
		return nil, fmt.Errorf("drop scope: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit offboard: %w", err)
	}
	out.OffboardedAt = now
	return out, nil
}

// lockMembershipForOffboard locks the membership row so two offboardings (or
// an offboarding and a re-enable) cannot interleave, and refuses a tombstone.
func lockMembershipForOffboard(ctx context.Context, tx *sql.Tx, tid, uid string) error {
	var status string
	if err := tx.QueryRowContext(ctx, `
		SELECT status FROM tenant_members
		WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`, tid, uid).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("lock membership: %w", err)
	}
	if status == string(tenant.MemberStatusOffboarded) {
		return fmt.Errorf("%w: membership is already offboarded", shared.ErrValidation)
	}
	return nil
}

// checkReassignTargets requires every target to be another ACTIVE member of
// the membership's tenant (checked inside the transaction).
func checkReassignTargets(ctx context.Context, tx *sql.Tx, m *tenant.Membership, plan tenant.OffboardPlan) error {
	for _, target := range plan.Targets() {
		if target == m.UserID() {
			return tenant.ErrInvalidReassignTarget
		}
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT principal_is_active($1, $2)`,
			m.TenantID().String(), target.String()).Scan(&ok); err != nil {
			return fmt.Errorf("check reassignment target: %w", err)
		}
		if !ok {
			return tenant.ErrInvalidReassignTarget
		}
	}
	return nil
}

// reassignOwnedWork hands the member's schedules, open findings and owned
// assets to the plan's targets.
func reassignOwnedWork(ctx context.Context, tx *sql.Tx, tid, uid string, plan tenant.OffboardPlan, report *tenant.AccessReport, out *tenant.OffboardResult) error {
	if plan.SchedulesTo != nil {
		to := plan.SchedulesTo.String()
		for _, q := range []string{
			`UPDATE scans SET created_by = $3, updated_at = NOW() WHERE tenant_id = $1 AND created_by = $2`,
			`UPDATE report_schedules SET created_by = $3, updated_at = NOW() WHERE tenant_id = $1 AND created_by = $2`,
			`UPDATE automations SET created_by = $3, updated_at = NOW() WHERE tenant_id = $1 AND created_by = $2`,
		} {
			n, err := execCount(ctx, tx, q, tid, uid, to)
			if err != nil {
				return fmt.Errorf("reassign schedules: %w", err)
			}
			out.ReassignedSchedules += n
		}
	}

	if report.AssignedFindings > 0 {
		var findingsTo any // NULL puts the findings back in the queue
		if plan.FindingsTo != nil {
			findingsTo = plan.FindingsTo.String()
		}
		n, err := execCount(ctx, tx, `
			UPDATE findings SET assigned_to = $3, updated_at = NOW()
			WHERE tenant_id = $1 AND assigned_to = $2 AND NOT (status = ANY($4))`,
			tid, uid, findingsTo, pq.Array(closedFindingStatuses()))
		if err != nil {
			return fmt.Errorf("reassign findings: %w", err)
		}
		out.ReassignedFindings = n
	}

	if plan.AssetsTo != nil && report.OwnedAssets > 0 {
		to := plan.AssetsTo.String()
		// Where the new owner already owns the asset, the member's row goes;
		// elsewhere it moves to the new owner.
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM asset_owners ao
			USING assets a
			WHERE a.id = ao.asset_id AND a.tenant_id = $1 AND ao.user_id = $2
			  AND EXISTS (SELECT 1 FROM asset_owners o2 WHERE o2.asset_id = ao.asset_id AND o2.user_id = $3)`,
			tid, uid, to); err != nil {
			return fmt.Errorf("merge owned assets: %w", err)
		}
		n, err := execCount(ctx, tx, `
			UPDATE asset_owners ao SET user_id = $3, assigned_at = NOW()
			FROM assets a
			WHERE a.id = ao.asset_id AND a.tenant_id = $1 AND ao.user_id = $2`,
			tid, uid, to)
		if err != nil {
			return fmt.Errorf("reassign owned assets: %w", err)
		}
		out.ReassignedAssets = n
	}
	return nil
}

// stripAccess revokes the member's keys and removes every access source:
// group memberships, grants, engagement memberships, roles and invitations.
func stripAccess(ctx context.Context, tx *sql.Tx, tid, uid string, actorArg any, out *tenant.OffboardResult) error {
	counted := []struct {
		dst   *int
		what  string
		query string
		args  []any
	}{
		{&out.RevokedKeys, "revoke api keys", `
			UPDATE api_keys SET status = 'revoked', revoked_at = NOW(), revoked_by = $3, updated_at = NOW()
			WHERE tenant_id = $1 AND user_id = $2 AND status IN ('active', 'suspended')`, []any{tid, uid, actorArg}},
		{&out.RemovedGroups, "remove group memberships", `
			DELETE FROM group_members gm USING groups g
			WHERE g.id = gm.group_id AND g.tenant_id = $1 AND gm.user_id = $2`, []any{tid, uid}},
		{&out.RemovedGrants, "remove grants", `
			DELETE FROM asset_access_grants WHERE tenant_id = $1 AND user_id = $2`, []any{tid, uid}},
		{&out.RemovedCampaigns, "remove campaign memberships", `
			DELETE FROM pentest_campaign_members WHERE tenant_id = $1 AND user_id = $2`, []any{tid, uid}},
	}
	for _, c := range counted {
		n, err := execCount(ctx, tx, c.query, c.args...)
		if err != nil {
			return fmt.Errorf("%s: %w", c.what, err)
		}
		*c.dst = n
	}
	for _, s := range []struct{ what, query string }{
		{"remove roles", `DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2`},
		{"remove invitations", `
			DELETE FROM tenant_invitations
			WHERE tenant_id = $1 AND accepted_at IS NULL
			  AND LOWER(email) = (SELECT LOWER(email) FROM users WHERE id = $2)`},
	} {
		if _, err := tx.ExecContext(ctx, s.query, tid, uid); err != nil {
			return fmt.Errorf("%s: %w", s.what, err)
		}
	}
	return nil
}

func execCount(ctx context.Context, tx *sql.Tx, query string, args ...any) (int, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// Rejoin re-activates an offboarded tombstone with the membership's (new)
// role. Starts from zero: offboarding stripped every other source.
func (r *MemberLifecycleRepository) Rejoin(ctx context.Context, m *tenant.Membership) (err error) {
	tid, uid := m.TenantID().String(), m.UserID().String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rejoin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var invitedBy any
	if m.InvitedBy() != nil {
		invitedBy = m.InvitedBy().String()
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE tenant_members
		SET status = 'active', role = $3, invited_by = $4, joined_at = $5,
		    offboarded_at = NULL, offboarded_by = NULL, suspended_at = NULL, suspended_by = NULL,
		    suspended_reason = NULL, kind = $6, home_tenant_id = $7, home_domain = $8,
		    expires_at = $9, expiry_reason = $10
		WHERE tenant_id = $1 AND user_id = $2 AND status = 'offboarded'`,
		append([]any{tid, uid, m.Role().String(), invitedBy, m.JoinedAt()}, memberAccessArgs(m)...)...)
	if err != nil {
		return fmt.Errorf("rejoin membership: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	// The role trigger only acts when the role column changes; insert the
	// system role explicitly so a rejoin with the same role still has it.
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
		SELECT $2, $1, ro.id, NOW(), $4
		FROM roles ro
		WHERE ro.slug = $3 AND ro.is_system = TRUE AND ro.tenant_id IS NULL
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING`,
		tid, uid, m.Role().String(), invitedBy); err != nil {
		return fmt.Errorf("rejoin role: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `SELECT refresh_access_for_user($1, $2)`, tid, uid); err != nil {
		return fmt.Errorf("recompute scope: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit rejoin: %w", err)
	}
	return nil
}

// ErasedEmail is the placeholder address an erased account gets: unique
// (users.email is unique), not deliverable (.invalid, RFC 2606).
func ErasedEmail(userID shared.ID) string {
	sum := sha256.Sum256([]byte("erased:" + userID.String()))
	return "erased-" + hex.EncodeToString(sum[:8]) + "@erased.invalid"
}

// ErasePersonalData anonymises the account. The row and every foreign key
// to it stay; history then shows the label instead of the person.
func (r *MemberLifecycleRepository) ErasePersonalData(ctx context.Context, tenantID, userID shared.ID, label string) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin erase: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var allowed bool
	if err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM tenant_members
		               WHERE tenant_id = $1 AND user_id = $2 AND status = 'offboarded')
		   AND NOT EXISTS (SELECT 1 FROM tenant_members
		                   WHERE user_id = $2 AND status <> 'offboarded')
		   AND NOT EXISTS (SELECT 1 FROM admin_users WHERE user_id = $2)`,
		tenantID.String(), userID.String()).Scan(&allowed); err != nil {
		return fmt.Errorf("check erase: %w", err)
	}
	if !allowed {
		return tenant.ErrEraseNotAllowed
	}
	if _, err = tx.ExecContext(ctx, `
		UPDATE users
		SET name = $2, email = $3, avatar_url = NULL, phone = NULL, preferences = '{}'::jsonb,
		    password_hash = NULL, keycloak_id = NULL,
		    email_verification_token = NULL, email_verification_expires_at = NULL,
		    password_reset_token = NULL, password_reset_expires_at = NULL,
		    status = 'inactive', erased_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND erased_at IS NULL`,
		userID.String(), label, ErasedEmail(userID)); err != nil {
		return fmt.Errorf("anonymise user: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_mfa WHERE user_id = $1`, userID.String()); err != nil {
		return fmt.Errorf("remove second factor: %w", err)
	}
	// The IdP's ids for the person: personal data, and a later sign-in must
	// not find the anonymised account.
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_identities WHERE user_id = $1`, userID.String()); err != nil {
		return fmt.Errorf("remove federated identities: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `
		UPDATE sessions SET status = 'revoked', updated_at = NOW()
		WHERE user_id = $1 AND status = 'active'`, userID.String()); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL`, userID.String()); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit erase: %w", err)
	}
	return nil
}

// ActiveAdminIDs returns the active owners and administrators of the tenant.
func (r *MemberLifecycleRepository) ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT m.user_id
		FROM tenant_members m
		JOIN users u ON u.id = m.user_id AND u.status = 'active'
		JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.status = 'active' AND ver.role IN ('owner', 'admin')`,
		tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list active admins: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan admin: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
