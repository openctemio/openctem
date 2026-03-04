package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AssignmentRuleRepository implements app.AssignmentRuleRepository using PostgreSQL.
type AssignmentRuleRepository struct {
	db *DB
}

// NewAssignmentRuleRepository creates a new AssignmentRuleRepository.
func NewAssignmentRuleRepository(db *DB) *AssignmentRuleRepository {
	return &AssignmentRuleRepository{db: db}
}

// ListActiveByTenant returns all active assignment rules for a tenant, ordered by priority descending.
func (r *AssignmentRuleRepository) ListActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*app.AssignmentRule, error) {
	query := `
		SELECT id, tenant_id, name, description, priority, is_active,
			   conditions, target_group_id, options
		FROM assignment_rules
		WHERE tenant_id = $1 AND is_active = TRUE
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list active assignment rules: %w", err)
	}
	defer rows.Close()

	var rules []*app.AssignmentRule
	for rows.Next() {
		var (
			idStr, tenantIDStr, name string
			description              *string
			priority                 int
			isActive                 bool
			conditionsJSON           []byte
			targetGroupIDStr         string
			optionsJSON              []byte
		)

		if err := rows.Scan(
			&idStr, &tenantIDStr, &name, &description, &priority, &isActive,
			&conditionsJSON, &targetGroupIDStr, &optionsJSON,
		); err != nil {
			return nil, fmt.Errorf("failed to scan assignment rule: %w", err)
		}

		id, _ := shared.IDFromString(idStr)
		tid, _ := shared.IDFromString(tenantIDStr)
		targetGroupID, _ := shared.IDFromString(targetGroupIDStr)

		conditions, err := app.ParseConditions(conditionsJSON)
		if err != nil {
			// Log but skip malformed rules rather than failing the whole query
			continue
		}

		var options map[string]any
		if len(optionsJSON) > 0 {
			if err := json.Unmarshal(optionsJSON, &options); err != nil {
				options = make(map[string]any)
			}
		} else {
			options = make(map[string]any)
		}

		desc := ""
		if description != nil {
			desc = *description
		}

		rules = append(rules, &app.AssignmentRule{
			ID:            id,
			TenantID:      tid,
			Name:          name,
			Description:   desc,
			Priority:      priority,
			IsActive:      isActive,
			Conditions:    conditions,
			TargetGroupID: targetGroupID,
			Options:       options,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate assignment rules: %w", err)
	}

	return rules, nil
}
