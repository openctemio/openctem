package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatactor"
	"github.com/openctemio/api/pkg/pagination"
)

// ThreatActorRepository implements threatactor.Repository.
type ThreatActorRepository struct {
	db *DB
}

// NewThreatActorRepository creates a new threat actor repository.
func NewThreatActorRepository(db *DB) *ThreatActorRepository {
	return &ThreatActorRepository{db: db}
}

const taSelectCols = `id, tenant_id, name, aliases, description, actor_type,
	sophistication, motivation, country_of_origin,
	first_seen, last_seen, is_active, mitre_group_id, ttps,
	target_industries, target_regions, external_references,
	tags, created_at, updated_at`

func (r *ThreatActorRepository) scanActor(scan func(dest ...any) error) (*threatactor.ThreatActor, error) {
	var (
		id, tenantID, name     string
		aliases                pq.StringArray
		description, actorType string
		sophistication         sql.NullString
		motivation             sql.NullString
		country                sql.NullString
		firstSeen, lastSeen    sql.NullTime
		isActive               bool
		mitreGroupID           sql.NullString
		ttpsJSON               []byte
		targetIndustries       pq.StringArray
		targetRegions          pq.StringArray
		externalRefsJSON       []byte
		tags                   pq.StringArray
		createdAt, updatedAt   sql.NullTime
	)

	err := scan(
		&id, &tenantID, &name, &aliases, &description, &actorType,
		&sophistication, &motivation, &country,
		&firstSeen, &lastSeen, &isActive, &mitreGroupID, &ttpsJSON,
		&targetIndustries, &targetRegions, &externalRefsJSON,
		&tags, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, _ := shared.IDFromString(id)
	parsedTenantID, _ := shared.IDFromString(tenantID)

	var ttps []threatactor.TTP
	_ = json.Unmarshal(ttpsJSON, &ttps)

	var externalRefs []threatactor.ExternalReference
	_ = json.Unmarshal(externalRefsJSON, &externalRefs)

	var fs, ls *time.Time
	if firstSeen.Valid {
		fs = &firstSeen.Time
	}
	if lastSeen.Valid {
		ls = &lastSeen.Time
	}

	return threatactor.ReconstituteThreatActor(
		parsedID, parsedTenantID,
		name, []string(aliases), description,
		threatactor.ActorType(actorType),
		sophistication.String, motivation.String, country.String,
		fs, ls, isActive,
		mitreGroupID.String, ttps,
		[]string(targetIndustries), []string(targetRegions),
		externalRefs, []string(tags),
		createdAt.Time, updatedAt.Time,
	), nil
}

func (r *ThreatActorRepository) Create(ctx context.Context, actor *threatactor.ThreatActor) error {
	ttpsJSON, _ := json.Marshal(actor.TTPs())
	refsJSON, _ := json.Marshal(actor.ExternalReferences())

	query := `INSERT INTO threat_actors (
		id, tenant_id, name, aliases, description, actor_type,
		sophistication, motivation, country_of_origin,
		first_seen, last_seen, is_active, mitre_group_id, ttps,
		target_industries, target_regions, external_references,
		tags, created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`

	_, err := r.db.ExecContext(ctx, query,
		actor.ID().String(), actor.TenantID().String(),
		actor.Name(), pq.StringArray(actor.Aliases()), actor.Description(),
		string(actor.ActorType()),
		actor.Sophistication(), actor.Motivation(), actor.CountryOfOrigin(),
		actor.FirstSeen(), actor.LastSeen(), actor.IsActive(),
		actor.MitreGroupID(), ttpsJSON,
		pq.StringArray(actor.TargetIndustries()), pq.StringArray(actor.TargetRegions()),
		refsJSON, pq.StringArray(actor.Tags()),
		actor.CreatedAt(), actor.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create threat actor: %w", err)
	}
	return nil
}

func (r *ThreatActorRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*threatactor.ThreatActor, error) {
	query := "SELECT " + taSelectCols + " FROM threat_actors WHERE tenant_id = $1 AND id = $2"
	actor, err := r.scanActor(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: threat actor not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get threat actor: %w", err)
	}
	return actor, nil
}

func (r *ThreatActorRepository) Update(ctx context.Context, actor *threatactor.ThreatActor) error {
	ttpsJSON, _ := json.Marshal(actor.TTPs())
	refsJSON, _ := json.Marshal(actor.ExternalReferences())

	query := `UPDATE threat_actors SET
		name=$3, aliases=$4, description=$5, actor_type=$6,
		sophistication=$7, motivation=$8, country_of_origin=$9,
		first_seen=$10, last_seen=$11, is_active=$12, mitre_group_id=$13, ttps=$14,
		target_industries=$15, target_regions=$16, external_references=$17,
		tags=$18, updated_at=$19
		WHERE tenant_id=$1 AND id=$2`

	_, err := r.db.ExecContext(ctx, query,
		actor.TenantID().String(), actor.ID().String(),
		actor.Name(), pq.StringArray(actor.Aliases()), actor.Description(),
		string(actor.ActorType()),
		actor.Sophistication(), actor.Motivation(), actor.CountryOfOrigin(),
		actor.FirstSeen(), actor.LastSeen(), actor.IsActive(),
		actor.MitreGroupID(), ttpsJSON,
		pq.StringArray(actor.TargetIndustries()), pq.StringArray(actor.TargetRegions()),
		refsJSON, pq.StringArray(actor.Tags()),
		actor.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update threat actor: %w", err)
	}
	return nil
}

func (r *ThreatActorRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM threat_actors WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete threat actor: %w", err)
	}
	return nil
}

func (r *ThreatActorRepository) List(ctx context.Context, filter threatactor.Filter, page pagination.Pagination) (pagination.Result[*threatactor.ThreatActor], error) {
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, filter.TenantID.String())
		argIdx++
	}
	if filter.ActorType != nil {
		where += fmt.Sprintf(" AND actor_type = $%d", argIdx)
		args = append(args, string(*filter.ActorType))
		argIdx++
	}
	if filter.IsActive != nil {
		where += fmt.Sprintf(" AND is_active = $%d", argIdx)
		args = append(args, *filter.IsActive)
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+*filter.Search+"%")
		// argIdx not incremented — no further conditions
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_actors "+where, args...).Scan(&total); err != nil {
		return pagination.Result[*threatactor.ThreatActor]{}, fmt.Errorf("failed to count threat actors: %w", err)
	}

	query := "SELECT " + taSelectCols + " FROM threat_actors " + where +
		" ORDER BY created_at DESC" +
		fmt.Sprintf(" LIMIT %d OFFSET %d", page.PerPage, (page.Page-1)*page.PerPage)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*threatactor.ThreatActor]{}, fmt.Errorf("failed to list threat actors: %w", err)
	}
	defer rows.Close()

	items := make([]*threatactor.ThreatActor, 0)
	for rows.Next() {
		actor, err := r.scanActor(rows.Scan)
		if err != nil {
			return pagination.Result[*threatactor.ThreatActor]{}, fmt.Errorf("failed to scan: %w", err)
		}
		items = append(items, actor)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*threatactor.ThreatActor]{}, fmt.Errorf("failed to iterate threat actors: %w", err)
	}

	return pagination.NewResult(items, int64(total), page), nil
}

func (r *ThreatActorRepository) LinkCVE(ctx context.Context, cve *threatactor.ThreatActorCVE) error {
	// Stub — will implement when CVE linking is needed
	return nil
}

func (r *ThreatActorRepository) ListCVEsByActor(ctx context.Context, tenantID, actorID shared.ID) ([]*threatactor.ThreatActorCVE, error) {
	return nil, nil
}

func (r *ThreatActorRepository) ListActorsByCVE(ctx context.Context, tenantID shared.ID, cveID string) ([]*threatactor.ThreatActor, error) {
	return nil, nil
}
