package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// defaultAcceptanceIntervalSQL is vulnerability.DefaultAcceptanceDuration as
// a SQL interval: the end a status write gives an accepted finding that has
// none (an accepted risk always ends). A code constant, never input.
var defaultAcceptanceIntervalSQL = fmt.Sprintf("INTERVAL '%d hours'", int(vulnerability.DefaultAcceptanceDuration.Hours()))

// FindingAcceptanceExpiryRepository ends accepted risks whose acceptance end
// (findings.acceptance_expires_at) has passed. Each end is one transaction:
// the finding returns to confirmed with a new SLA clock, its approved
// acceptance requests are marked expired, and the timeline records both.
// Nothing is left half done, so a failed run is simply retried by the next.
type FindingAcceptanceExpiryRepository struct {
	db *DB
}

// NewFindingAcceptanceExpiryRepository creates the repository.
func NewFindingAcceptanceExpiryRepository(db *DB) *FindingAcceptanceExpiryRepository {
	return &FindingAcceptanceExpiryRepository{db: db}
}

// ListDue returns accepted findings whose acceptance has ended, oldest end
// first, across tenants (a background job; each row carries its tenant and
// every write is scoped by it).
func (r *FindingAcceptanceExpiryRepository) ListDue(ctx context.Context, limit int) ([]vulnerability.AcceptanceDue, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id, id, asset_id, COALESCE(priority_class, ''), severity,
		       sla_deadline, COALESCE(sla_status, ''), acceptance_expires_at
		FROM findings
		WHERE status = 'accepted' AND acceptance_expires_at IS NOT NULL AND acceptance_expires_at <= NOW()
		ORDER BY acceptance_expires_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list ended acceptances: %w", err)
	}
	defer rows.Close()
	var out []vulnerability.AcceptanceDue
	for rows.Next() {
		var (
			tenantStr, idStr string
			assetStr         sql.NullString
			deadline         sql.NullTime
			d                vulnerability.AcceptanceDue
		)
		if err := rows.Scan(&tenantStr, &idStr, &assetStr, &d.PriorityClass, &d.Severity,
			&deadline, &d.SLAStatus, &d.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan ended acceptance: %w", err)
		}
		if d.TenantID, err = shared.IDFromString(tenantStr); err != nil {
			continue
		}
		if d.FindingID, err = shared.IDFromString(idStr); err != nil {
			continue
		}
		if assetStr.Valid {
			d.AssetID, _ = shared.IDFromString(assetStr.String)
		}
		if deadline.Valid {
			t := deadline.Time
			d.SLADeadline = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Expire ends one accepted risk in one transaction, only while the finding is
// still accepted and its end has passed (a finding someone moved on, or whose
// acceptance was renewed, is left alone and false is returned):
//
//   - the finding returns to confirmed; resolution fields are cleared (the
//     acceptance end is cleared by trg_findings_clear_acceptance_expiry);
//   - a new SLA clock starts when newDeadline is set (the policy deadline from
//     the reopen); a nil deadline (no SLA for this finding) leaves the SLA as is;
//   - the finding's approved acceptance requests are marked expired;
//   - one acceptance_expired timeline entry, and one sla_restarted entry when
//     the clock restarted.
func (r *FindingAcceptanceExpiryRepository) Expire(ctx context.Context, due vulnerability.AcceptanceDue, newDeadline *time.Time, now time.Time) (bool, error) {
	return r.endAcceptance(ctx, due, newDeadline, now, acceptanceEnding{
		reason:  "acceptance_expired",
		message: "Risk acceptance ended: the finding is open again",
		dueOnly: true,
	})
}

// acceptanceEnding says why an acceptance ends: its end passed (dueOnly:
// only while the end has passed), or its finding changed (extra carries the
// signals, audit names the audit action written in the same transaction).
type acceptanceEnding struct {
	reason  string
	message string
	dueOnly bool
	extra   map[string]any
	audit   string
	// approvalID, when set, is the approved request the ending acts on: the
	// row is locked first and the ending stops when it is no longer approved
	// or the finding holds a newer approved request (a decision made after the
	// change was seen must not be undone by it).
	approvalID string
}

// endAcceptance reopens one accepted finding in one transaction (see Expire).
func (r *FindingAcceptanceExpiryRepository) endAcceptance(ctx context.Context, due vulnerability.AcceptanceDue, newDeadline *time.Time, now time.Time, why acceptanceEnding) (bool, error) {
	wrote := false
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if why.approvalID != "" {
			if ok, err := lockApprovedRequest(ctx, tx, due.TenantID, why.approvalID); err != nil || !ok {
				return err
			}
		}
		var expiresAt sql.NullTime
		err := tx.QueryRowContext(ctx, `
			SELECT acceptance_expires_at FROM findings
			WHERE tenant_id = $1 AND id = $2 AND status = 'accepted'
			  AND (NOT $4 OR (acceptance_expires_at IS NOT NULL AND acceptance_expires_at <= $3))
			FOR UPDATE`,
			due.TenantID.String(), due.FindingID.String(), now, why.dueOnly).Scan(&expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lock ended acceptance: %w", err)
		}
		if why.approvalID != "" {
			// The finding is locked now, so a request approved a moment ago
			// is visible.
			if newer, err := hasNewerApprovedRequest(ctx, tx, due.TenantID, why.approvalID); err != nil || newer {
				return err
			}
		}

		if newDeadline != nil {
			if err := markSLARestart(ctx, tx); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET
				status = 'confirmed', resolution = NULL, closure_reason = NULL, verification = NULL,
				resolved_at = NULL, resolved_by = NULL,
				sla_deadline = COALESCE($3, sla_deadline),
				sla_status = CASE WHEN $3::timestamptz IS NULL THEN sla_status ELSE 'on_track' END,
				updated_at = $4
			WHERE tenant_id = $1 AND id = $2 AND status = 'accepted'`,
			due.TenantID.String(), due.FindingID.String(), newDeadline, now); err != nil {
			return fmt.Errorf("reopen ended acceptance: %w", err)
		}

		approvalIDs, err := expireAcceptanceRequests(ctx, tx, due)
		if err != nil {
			return err
		}

		changes := map[string]any{
			"old_status":   string(vulnerability.FindingStatusAccepted),
			"new_status":   string(vulnerability.FindingStatusConfirmed),
			"reason":       why.reason,
			"approval_ids": approvalIDs,
		}
		if expiresAt.Valid {
			changes["expired_at"] = expiresAt.Time.UTC().Format(time.RFC3339)
		}
		for k, v := range why.extra {
			changes[k] = v
		}
		if err := insertSystemActivity(ctx, tx, due, vulnerability.ActivityAcceptanceExpired, changes, why.message, now); err != nil {
			return err
		}

		if newDeadline != nil {
			sla := map[string]any{
				"reason":              why.reason,
				"trigger":             why.reason,
				"sla_deadline":        newDeadline.UTC().Format(time.RFC3339),
				"restarted_at":        now.UTC().Format(time.RFC3339),
				"previous_sla_status": due.SLAStatus,
			}
			if due.SLADeadline != nil {
				sla["previous_sla_deadline"] = due.SLADeadline.UTC().Format(time.RFC3339)
			}
			if err := insertSystemActivity(ctx, tx, due, vulnerability.ActivitySLARestarted, sla,
				"A new SLA clock started at the reopen", now); err != nil {
				return err
			}
		}
		if why.audit != "" {
			if err := insertDecisionAudit(ctx, tx, due.TenantID, due.FindingID, why.audit, "high", why.message, changes); err != nil {
				return err
			}
		}
		wrote = true
		return nil
	})
	return wrote, err
}

// ExpireStaleRequests marks approved **accepted-risk** requests whose end
// has passed as expired when their finding is not an ended acceptance waiting
// for Expire (it moved on, or holds a newer acceptance). The finding's status
// is never touched; each expired request gets a timeline entry on its finding
// and an audit row in its tenant, in the same statement. A false-positive
// request never expires (it carries no end), and an old one that does carry
// an end is left alone. Returns how many requests it marked.
func (r *FindingAcceptanceExpiryRepository) ExpireStaleRequests(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `
		WITH ended AS (
			UPDATE finding_status_approvals a SET status = 'expired', version = a.version + 1
			WHERE a.status = 'approved' AND a.requested_status = 'accepted'
			  AND a.expires_at IS NOT NULL AND a.expires_at < NOW()
			  AND NOT EXISTS (
				SELECT 1 FROM findings f
				WHERE f.tenant_id = a.tenant_id AND f.id = a.finding_id AND f.status = 'accepted'
				  AND (f.acceptance_expires_at IS NULL OR f.acceptance_expires_at <= NOW()))
			RETURNING a.id, a.tenant_id, a.finding_id, a.expires_at
		), timeline AS (
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
			SELECT e.tenant_id, e.finding_id, 'approval_canceled', 'system', 'system: acceptance expiry',
			       jsonb_build_object('approval_id', e.id, 'approval_status', 'expired',
			                          'reason', 'acceptance_request_ended', 'expired_at', e.expires_at),
			       'auto', 'The accepted-risk request ended; the finding had already moved on'
			FROM ended e
		), audit AS (
			INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
			SELECT gen_random_uuid(), e.tenant_id, 'finding.updated', 'finding', e.finding_id::text, 'success', 'low',
			       'An accepted-risk request ended and was marked expired',
			       jsonb_build_object('approval_id', e.id, 'reason', 'acceptance_request_ended'), NOW()
			FROM ended e
		)
		SELECT COUNT(*) FROM ended`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("expire stale acceptance requests: %w", err)
	}
	return n, nil
}

// expireAcceptanceRequests marks the finding's approved acceptance requests
// expired and returns their ids.
func expireAcceptanceRequests(ctx context.Context, tx *sql.Tx, due vulnerability.AcceptanceDue) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		UPDATE finding_status_approvals SET status = 'expired', version = version + 1
		WHERE tenant_id = $1 AND finding_id = $2 AND status = 'approved' AND requested_status = 'accepted'
		RETURNING id::text`,
		due.TenantID.String(), due.FindingID.String())
	if err != nil {
		return nil, fmt.Errorf("expire acceptance requests: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan expired request: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("expire acceptance requests: %w", err)
	}
	return ids, nil
}

func insertSystemActivity(ctx context.Context, tx *sql.Tx, due vulnerability.AcceptanceDue,
	kind vulnerability.ActivityType, changes map[string]any, message string, now time.Time,
) error {
	raw, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("marshal %s activity: %w", kind, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message, created_at)
		VALUES ($1, $2, $3, $4, 'system', 'system: acceptance expiry', $5, 'auto', $6, $7)`,
		shared.NewID().String(), due.TenantID.String(), due.FindingID.String(), string(kind), raw, message, now); err != nil {
		return fmt.Errorf("record %s activity: %w", kind, err)
	}
	return nil
}
