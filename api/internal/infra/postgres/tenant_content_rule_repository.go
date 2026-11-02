package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TenantContentRuleRepository stores organization detection rules
// (migration tenant_content_rules). tenant_id is part of every predicate:
// a rule of another organization is not found.
type TenantContentRuleRepository struct {
	db *DB
}

// NewTenantContentRuleRepository creates a TenantContentRuleRepository.
func NewTenantContentRuleRepository(db *DB) *TenantContentRuleRepository {
	return &TenantContentRuleRepository{db: db}
}

var _ contentrule.Repository = (*TenantContentRuleRepository)(nil)

const tenantContentRuleColumns = `id, tenant_id, kind, enabled, version, sha256, body, created_by, updated_by, created_at, updated_at`

func scanTenantContentRule(row interface{ Scan(...any) error }) (*contentrule.StoredRule, error) {
	var (
		r                    contentrule.StoredRule
		id, tenantID, kind   string
		body                 []byte
		createdBy, updatedBy sql.NullString
	)
	if err := row.Scan(&id, &tenantID, &kind, &r.Enabled, &r.Version, &r.SHA256, &body, &createdBy, &updatedBy,
		&r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &r.Rule); err != nil {
		return nil, fmt.Errorf("decode detection rule: %w", err)
	}
	r.ID, _ = shared.IDFromString(id)
	r.TenantID, _ = shared.IDFromString(tenantID)
	r.Kind = contentrule.Kind(kind)
	if createdBy.Valid {
		v, _ := shared.IDFromString(createdBy.String)
		r.CreatedBy = &v
	}
	if updatedBy.Valid {
		v, _ := shared.IDFromString(updatedBy.String)
		r.UpdatedBy = &v
	}
	return &r, nil
}

func (r *TenantContentRuleRepository) query(ctx context.Context, q string, args ...any) ([]*contentrule.StoredRule, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list detection rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*contentrule.StoredRule
	for rows.Next() {
		s, err := scanTenantContentRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan detection rule: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// List returns the organization's rules by kind and id.
func (r *TenantContentRuleRepository) List(ctx context.Context, tenantID shared.ID) ([]*contentrule.StoredRule, error) {
	return r.query(ctx, `SELECT `+tenantContentRuleColumns+` FROM tenant_content_rules
		WHERE tenant_id = $1 ORDER BY kind, rule_id LIMIT $2`, tenantID.String(), contentrule.MaxOrganizationRules)
}

// EnabledRules returns the organization's enabled rules.
func (r *TenantContentRuleRepository) EnabledRules(ctx context.Context, tenantID shared.ID) ([]contentrule.EnabledRule, error) {
	list, err := r.query(ctx, `SELECT `+tenantContentRuleColumns+` FROM tenant_content_rules
		WHERE tenant_id = $1 AND enabled ORDER BY kind, rule_id LIMIT $2`, tenantID.String(), contentrule.MaxOrganizationRules)
	if err != nil {
		return nil, err
	}
	out := make([]contentrule.EnabledRule, 0, len(list))
	for _, s := range list {
		out = append(out, contentrule.EnabledRule{Kind: s.Kind, Rule: s.Rule, Version: s.Version, SHA256: s.SHA256})
	}
	return out, nil
}

// Get returns one rule of the organization.
func (r *TenantContentRuleRepository) Get(ctx context.Context, tenantID, id shared.ID) (*contentrule.StoredRule, error) {
	s, err := scanTenantContentRule(r.db.QueryRowContext(ctx, `SELECT `+tenantContentRuleColumns+` FROM tenant_content_rules
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contentrule.ErrRuleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get detection rule: %w", err)
	}
	return s, nil
}

// Create stores a rule. The count check and the insert are one statement,
// so concurrent creates cannot pass MaxOrganizationRules.
func (r *TenantContentRuleRepository) Create(ctx context.Context, s *contentrule.StoredRule) error {
	body, _, err := contentrule.Canonical(s.Rule)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_content_rules (id, tenant_id, kind, rule_id, name, enabled, version, sha256, body,
			created_by, updated_by, created_at, updated_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11, $11
		WHERE (SELECT count(*) FROM tenant_content_rules WHERE tenant_id = $2) < $12`,
		s.ID.String(), s.TenantID.String(), string(s.Kind), s.Rule.ID, s.Rule.Name, s.Enabled, s.Version, s.SHA256,
		string(body), nullableID(s.CreatedBy), s.CreatedAt, contentrule.MaxOrganizationRules)
	if err != nil {
		if isUniqueViolation(err) {
			return contentrule.ErrRuleIDTaken
		}
		return fmt.Errorf("create detection rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return contentrule.ErrTooManyRules
	}
	return nil
}

// Update stores a rule's body, enabled flag and version.
func (r *TenantContentRuleRepository) Update(ctx context.Context, s *contentrule.StoredRule) error {
	body, _, err := contentrule.Canonical(s.Rule)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenant_content_rules SET rule_id = $3, name = $4, enabled = $5, version = $6, sha256 = $7, body = $8,
			updated_by = $9, updated_at = $10
		WHERE tenant_id = $1 AND id = $2`,
		s.TenantID.String(), s.ID.String(), s.Rule.ID, s.Rule.Name, s.Enabled, s.Version, s.SHA256, string(body),
		nullableID(s.UpdatedBy), s.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return contentrule.ErrRuleIDTaken
		}
		return fmt.Errorf("update detection rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return contentrule.ErrRuleNotFound
	}
	return nil
}

// Delete removes one rule of the organization.
func (r *TenantContentRuleRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tenant_content_rules WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete detection rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return contentrule.ErrRuleNotFound
	}
	return nil
}
