package postgres

// Names of the people on scope entries and exclusions (research/53 §4.6).
// Only users with a current (active or suspended) membership of the tenant
// are named; anyone else, including a user of another organization and an
// offboarded member, is absent and shows as a former member. No e-mail.

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeActorRepository names tenant members.
type ScopeActorRepository struct {
	db *DB
}

// NewScopeActorRepository creates the repository.
func NewScopeActorRepository(db *DB) *ScopeActorRepository {
	return &ScopeActorRepository{db: db}
}

// maxActorNames bounds one lookup.
const maxActorNames = 500

// MemberNames maps the given user ids that are current members of the
// tenant to their display names (an empty name falls back to "Member").
func (r *ScopeActorRepository) MemberNames(ctx context.Context, tenantID shared.ID, userIDs []string) (map[string]string, error) {
	out := map[string]string{}
	ids := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		if _, err := shared.IDFromString(id); err == nil && len(ids) < maxActorNames {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id::text, u.name
		FROM tenant_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.tenant_id = $1 AND tm.user_id = ANY($2::uuid[]) AND tm.status <> 'offboarded'`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("name scope actors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		if name = strings.TrimSpace(name); name == "" {
			name = "Member"
		}
		out[id] = name
	}
	return out, rows.Err()
}
