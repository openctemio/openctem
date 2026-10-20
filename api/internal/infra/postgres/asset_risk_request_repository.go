package postgres

// Asset risk change requests (docs/architecture/asset-risk-governance.md).
// Every statement carries the tenant; a request applies only while the asset
// still has the values it was made from (the service checks that inside the
// sign-off transaction, with the request row locked).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SubjectTypeAssetRiskRequest is the approval_signoffs subject of an asset
// risk change request.
const SubjectTypeAssetRiskRequest = "asset_risk_request"

// AssetRiskRequestRepository stores asset risk change requests.
type AssetRiskRequestRepository struct {
	db *DB
}

// NewAssetRiskRequestRepository returns the repository.
func NewAssetRiskRequestRepository(db *DB) *AssetRiskRequestRepository {
	return &AssetRiskRequestRepository{db: db}
}

var _ asset.RiskChangeRequestRepository = (*AssetRiskRequestRepository)(nil)

const assetRiskRequestColumns = `r.id, r.tenant_id, r.asset_id,
	r.requested_exposure, r.requested_criticality, r.requested_crown_jewel,
	r.previous_exposure, r.previous_criticality, r.previous_crown_jewel,
	r.lowered_fields, r.reason, r.impact::text, r.requested_by, r.status, r.tier, r.required_approvals,
	r.decide_by, r.decided_by, r.decided_at, r.decision_note, r.created_at,
	(SELECT COUNT(*) FROM approval_signoffs so
	 WHERE so.tenant_id = r.tenant_id AND so.subject_type = '` + SubjectTypeAssetRiskRequest + `' AND so.subject_id = r.id)`

type assetRiskRequestScanner interface {
	Scan(dest ...any) error
}

func scanAssetRiskRequest(row assetRiskRequestScanner) (*asset.RiskChangeRequest, error) {
	var (
		id, tenant, assetID, reqExp, reqCrit, prevExp, prevCrit, status, tier, impact string
		requestedBy, decidedBy, note                                                  sql.NullString
		decidedAt                                                                     sql.NullTime
		lowered                                                                       pq.StringArray
		r                                                                             asset.RiskChangeRequest
	)
	if err := row.Scan(&id, &tenant, &assetID, &reqExp, &reqCrit, &r.Requested.CrownJewel,
		&prevExp, &prevCrit, &r.Previous.CrownJewel, &lowered, &r.Reason, &impact, &requestedBy, &status, &tier,
		&r.RequiredApprovals, &r.DecideBy, &decidedBy, &decidedAt, &note, &r.CreatedAt, &r.ApprovalsCollected); err != nil {
		return nil, err
	}
	r.ID, _ = shared.IDFromString(id)
	r.TenantID, _ = shared.IDFromString(tenant)
	r.AssetID, _ = shared.IDFromString(assetID)
	r.Requested.Exposure, r.Requested.Criticality = asset.Exposure(reqExp), asset.Criticality(reqCrit)
	r.Previous.Exposure, r.Previous.Criticality = asset.Exposure(prevExp), asset.Criticality(prevCrit)
	r.Lowered = []string(lowered)
	r.Impact = []byte(impact)
	r.Status = asset.RiskRequestStatus(status)
	r.Tier = tier
	r.RequestedBy = parseNullID(requestedBy)
	r.DecidedBy = parseNullID(decidedBy)
	if decidedAt.Valid {
		t := decidedAt.Time
		r.DecidedAt = &t
	}
	r.DecisionNote = note.String
	return &r, nil
}

// Create implements asset.RiskChangeRequestRepository.
func (r *AssetRiskRequestRepository) Create(ctx context.Context, req *asset.RiskChangeRequest) error {
	impact := req.Impact
	if len(impact) == 0 {
		impact = []byte("{}")
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		// A pending request nobody decided in time stops blocking a new one.
		if _, err := tx.ExecContext(ctx, `UPDATE asset_risk_requests SET status = 'expired'
			WHERE tenant_id = $1 AND asset_id = $2 AND status = 'pending' AND decide_by <= now()`,
			req.TenantID.String(), req.AssetID.String()); err != nil {
			return fmt.Errorf("expire stale asset risk requests: %w", err)
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO asset_risk_requests (id, tenant_id, asset_id,
				requested_exposure, requested_criticality, requested_crown_jewel,
				previous_exposure, previous_criticality, previous_crown_jewel,
				lowered_fields, reason, impact, requested_by, status, tier, required_approvals, decide_by, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, 'pending', $14, $15, $16, $17)`,
			req.ID.String(), req.TenantID.String(), req.AssetID.String(),
			string(req.Requested.Exposure), string(req.Requested.Criticality), req.Requested.CrownJewel,
			string(req.Previous.Exposure), string(req.Previous.Criticality), req.Previous.CrownJewel,
			pq.Array(req.Lowered), req.Reason, string(impact), nullID(req.RequestedBy), req.Tier,
			req.RequiredApprovals, req.DecideBy, req.CreatedAt)
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return asset.ErrRiskRequestPending
		}
		if err != nil {
			return fmt.Errorf("create asset risk request: %w", err)
		}
		return nil
	})
}

// Get implements asset.RiskChangeRequestRepository.
func (r *AssetRiskRequestRepository) Get(ctx context.Context, tenantID, id shared.ID) (*asset.RiskChangeRequest, error) {
	req, err := scanAssetRiskRequest(r.db.QueryRowContext(ctx, `SELECT `+assetRiskRequestColumns+`
		FROM asset_risk_requests r WHERE r.tenant_id = $1 AND r.id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: risk change request not found", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get asset risk request: %w", err)
	}
	return req, nil
}

// Pending implements asset.RiskChangeRequestRepository.
func (r *AssetRiskRequestRepository) Pending(ctx context.Context, tenantID, assetID shared.ID) (*asset.RiskChangeRequest, error) {
	req, err := scanAssetRiskRequest(r.db.QueryRowContext(ctx, `SELECT `+assetRiskRequestColumns+`
		FROM asset_risk_requests r
		WHERE r.tenant_id = $1 AND r.asset_id = $2 AND r.status = 'pending' AND r.decide_by > now()`,
		tenantID.String(), assetID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no pending request is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("get pending asset risk request: %w", err)
	}
	return req, nil
}

// Signoffs implements asset.RiskChangeRequestRepository.
func (r *AssetRiskRequestRepository) Signoffs(ctx context.Context, tenantID, id shared.ID) ([]approvalpolicy.Signoff, error) {
	return listSignoffs(ctx, r.db, tenantID, SubjectTypeAssetRiskRequest, id)
}

// SignOff implements asset.RiskChangeRequestRepository.
func (r *AssetRiskRequestRepository) SignOff(ctx context.Context, tenantID, id shared.ID, s asset.RiskSignoff,
	decide func(prior []approvalpolicy.Signoff) (bool, error),
	apply func(ctx context.Context) error,
) (bool, error) {
	applied := false
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var (
			status   string
			decideBy time.Time
		)
		err := tx.QueryRowContext(ctx, `SELECT status, decide_by FROM asset_risk_requests
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), id.String()).Scan(&status, &decideBy)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: risk change request not found", shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("lock asset risk request: %w", err)
		}
		if status != string(asset.RiskRequestPending) {
			return fmt.Errorf("%w: this request is %s", shared.ErrConflict, status)
		}
		if !time.Now().Before(decideBy) {
			return asset.ErrRiskRequestOverdue
		}
		prior, err := listSignoffs(ctx, tx, tenantID, SubjectTypeAssetRiskRequest, id)
		if err != nil {
			return err
		}
		complete, err := decide(prior)
		if err != nil {
			return err
		}
		if err := insertSignoff(ctx, tx, tenantID, SubjectTypeAssetRiskRequest, id, signoffRow{
			userID: s.UserID, securityPool: s.SecurityPool, poolFallback: s.PoolFallback, stepUp: s.StepUp,
		}); err != nil {
			return err
		}
		if !complete {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE asset_risk_requests
			SET status = 'approved', decided_by = $3, decided_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), s.UserID.String()); err != nil {
			return fmt.Errorf("approve asset risk request: %w", err)
		}
		if err := apply(ctx); err != nil {
			return err
		}
		applied = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return applied, nil
}

// Close implements asset.RiskChangeRequestRepository.
func (r *AssetRiskRequestRepository) Close(ctx context.Context, tenantID, id shared.ID, status asset.RiskRequestStatus,
	actor shared.ID, note string, requester *shared.ID,
) error {
	if status != asset.RiskRequestRejected && status != asset.RiskRequestCanceled {
		return fmt.Errorf("%w: a risk change request is closed as rejected or canceled", shared.ErrValidation)
	}
	q := `UPDATE asset_risk_requests SET status = $3, decided_by = $4, decided_at = now(), decision_note = NULLIF($5, '')
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`
	args := []any{tenantID.String(), id.String(), string(status), actor.String(), note}
	if requester != nil {
		q += ` AND requested_by = $6`
		args = append(args, requester.String())
	}
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("close asset risk request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: no pending risk change request to close", shared.ErrNotFound)
	}
	return nil
}
