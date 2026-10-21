package postgres

// Finding retest checks (docs/architecture/finding-retest-checks.md): one row
// per finding that has a custom retest check. Every query is tenant-scoped;
// the foreign keys are composite with tenant_id, so a check can never link a
// finding or a template of another tenant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/retestcheck"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FindingRetestCheckRepository stores retest checks.
type FindingRetestCheckRepository struct {
	db *DB
}

// NewFindingRetestCheckRepository creates the repository.
func NewFindingRetestCheckRepository(db *DB) *FindingRetestCheckRepository {
	return &FindingRetestCheckRepository{db: db}
}

var _ retestcheck.Repository = (*FindingRetestCheckRepository)(nil)

const findingRetestCheckColumns = `id, tenant_id, finding_id, template_id, kind, assertion, owns_template, tier, tier_reason,
	approved_digest, approved_by, approved_at, calibrated_digest, calibrated_at, author_id, created_by, updated_by,
	created_at, updated_at`

// GetByFinding returns the finding's check.
func (r *FindingRetestCheckRepository) GetByFinding(ctx context.Context, tenantID, findingID shared.ID) (*retestcheck.Check, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+findingRetestCheckColumns+`
		FROM finding_retest_checks WHERE tenant_id = $1 AND finding_id = $2`, tenantID.String(), findingID.String())
	c, err := scanRetestCheck(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: retest check", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get retest check: %w", err)
	}
	return c, nil
}

// Upsert creates the finding's check or replaces it (one per finding).
func (r *FindingRetestCheckRepository) Upsert(ctx context.Context, c *retestcheck.Check) error {
	var assertion any
	if c.Assertion != nil {
		b, err := json.Marshal(c.Assertion)
		if err != nil {
			return fmt.Errorf("encode assertion: %w", err)
		}
		assertion = string(b)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO finding_retest_checks (id, tenant_id, finding_id, template_id, kind, assertion, owns_template,
			tier, tier_reason, approved_digest, approved_by, approved_at, calibrated_digest, calibrated_at,
			author_id, created_by, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
			template_id = EXCLUDED.template_id, kind = EXCLUDED.kind, assertion = EXCLUDED.assertion,
			owns_template = EXCLUDED.owns_template, tier = EXCLUDED.tier, tier_reason = EXCLUDED.tier_reason,
			approved_digest = EXCLUDED.approved_digest, approved_by = EXCLUDED.approved_by,
			approved_at = EXCLUDED.approved_at, calibrated_digest = EXCLUDED.calibrated_digest,
			calibrated_at = EXCLUDED.calibrated_at, author_id = EXCLUDED.author_id,
			updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
		WHERE finding_retest_checks.tenant_id = EXCLUDED.tenant_id`,
		c.ID.String(), c.TenantID.String(), c.FindingID.String(), c.TemplateID.String(), string(c.Kind), assertion,
		c.OwnsTemplate, c.Tier, c.TierReason, nullString(c.ApprovedDigest), nullID(c.ApprovedBy), nullTime(c.ApprovedAt),
		nullString(c.CalibratedDigest), nullTime(c.CalibratedAt), nullID(c.AuthorID), nullID(c.CreatedBy),
		nullID(c.UpdatedBy), c.CreatedAt, c.UpdatedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			return fmt.Errorf("%w: finding or template", shared.ErrNotFound)
		}
		return fmt.Errorf("save retest check: %w", err)
	}
	return nil
}

// Delete removes the finding's check.
func (r *FindingRetestCheckRepository) Delete(ctx context.Context, tenantID, findingID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM finding_retest_checks WHERE tenant_id = $1 AND finding_id = $2`,
		tenantID.String(), findingID.String())
	if err != nil {
		return fmt.Errorf("delete retest check: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: retest check", shared.ErrNotFound)
	}
	return nil
}

// CountByTemplate counts the checks that use a template.
func (r *FindingRetestCheckRepository) CountByTemplate(ctx context.Context, tenantID, templateID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_retest_checks WHERE tenant_id = $1 AND template_id = $2`,
		tenantID.String(), templateID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count retest checks: %w", err)
	}
	return n, nil
}

// MarkCalibrated records the digest that matched the check's finding. It
// writes only while the check still uses a template with that content, so
// a match of an older version never calibrates a newer one.
func (r *FindingRetestCheckRepository) MarkCalibrated(ctx context.Context, tenantID, checkID shared.ID, digest string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE finding_retest_checks c SET calibrated_digest = $3, calibrated_at = $4
		FROM scanner_templates t
		WHERE c.tenant_id = $1 AND c.id = $2
		  AND t.tenant_id = c.tenant_id AND t.id = c.template_id AND 'sha256:' || t.content_hash = $3`,
		tenantID.String(), checkID.String(), digest, at)
	if err != nil {
		return fmt.Errorf("calibrate retest check: %w", err)
	}
	return nil
}

func scanRetestCheck(s retestScanner) (*retestcheck.Check, error) {
	var (
		id, tenantID, findingID, templateID, kind, tier, tierReason string
		assertion, approvedDigest, approvedBy, calibratedDigest     sql.NullString
		authorID, createdBy, updatedBy                              sql.NullString
		approvedAt, calibratedAt                                    sql.NullTime
		ownsTemplate                                                bool
		createdAt, updatedAt                                        time.Time
	)
	if err := s.Scan(&id, &tenantID, &findingID, &templateID, &kind, &assertion, &ownsTemplate, &tier, &tierReason,
		&approvedDigest, &approvedBy, &approvedAt, &calibratedDigest, &calibratedAt, &authorID, &createdBy, &updatedBy,
		&createdAt, &updatedAt); err != nil {
		return nil, err
	}
	c := &retestcheck.Check{
		Kind: retestcheck.Kind(kind), OwnsTemplate: ownsTemplate, Tier: tier, TierReason: tierReason,
		ApprovedDigest: approvedDigest.String, ApprovedBy: optionalID(approvedBy), ApprovedAt: nullTimeValue(approvedAt),
		CalibratedDigest: calibratedDigest.String, CalibratedAt: nullTimeValue(calibratedAt),
		AuthorID: optionalID(authorID), CreatedBy: optionalID(createdBy), UpdatedBy: optionalID(updatedBy),
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	var err error
	for _, p := range []struct {
		dst *shared.ID
		src string
	}{{&c.ID, id}, {&c.TenantID, tenantID}, {&c.FindingID, findingID}, {&c.TemplateID, templateID}} {
		if *p.dst, err = shared.IDFromString(p.src); err != nil {
			return nil, fmt.Errorf("retest check id: %w", err)
		}
	}
	if assertion.Valid && assertion.String != "" {
		var a retestcheck.HTTPAssertion
		if err := json.Unmarshal([]byte(assertion.String), &a); err != nil {
			return nil, fmt.Errorf("decode assertion: %w", err)
		}
		c.Assertion = &a
	}
	return c, nil
}
