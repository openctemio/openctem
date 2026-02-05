package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// AssetGroupRepository implements assetgroup.Repository using PostgreSQL.
type AssetGroupRepository struct {
	db *DB
}

// NewAssetGroupRepository creates a new asset group repository.
func NewAssetGroupRepository(db *DB) *AssetGroupRepository {
	return &AssetGroupRepository{db: db}
}

// assetGroupSelectQuery uses LEFT JOIN with pre-aggregated findings count
// to avoid N+1 correlated subquery execution when listing multiple groups.
// OPTIMIZED: Changed from correlated subquery to LEFT JOIN for better performance.
const assetGroupSelectQuery = `
	SELECT
		ag.id, ag.tenant_id, ag.name, ag.description, ag.environment, ag.criticality,
		ag.business_unit, ag.owner, ag.owner_email, ag.tags,
		ag.asset_count, ag.domain_count, ag.website_count, ag.service_count,
		ag.repository_count, ag.cloud_count, ag.credential_count,
		ag.risk_score,
		COALESCE(fc.finding_count, 0) as finding_count,
		ag.created_at, ag.updated_at
	FROM asset_groups ag
	LEFT JOIN (
		SELECT agm.asset_group_id, COUNT(f.id) as finding_count
		FROM asset_group_members agm
		INNER JOIN findings f ON f.asset_id = agm.asset_id
		GROUP BY agm.asset_group_id
	) fc ON fc.asset_group_id = ag.id
`

func (r *AssetGroupRepository) scanAssetGroup(row interface{ Scan(...any) error }) (*assetgroup.AssetGroup, error) {
	var (
		id              string
		tenantID        string
		name            string
		description     sql.NullString
		environment     string
		criticality     string
		businessUnit    sql.NullString
		owner           sql.NullString
		ownerEmail      sql.NullString
		tags            pq.StringArray
		assetCount      int
		domainCount     int
		websiteCount    int
		serviceCount    int
		repositoryCount int
		cloudCount      int
		credentialCount int
		riskScore       int
		findingCount    int
		createdAt       sql.NullTime
		updatedAt       sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &name, &description, &environment, &criticality,
		&businessUnit, &owner, &ownerEmail, &tags,
		&assetCount, &domainCount, &websiteCount, &serviceCount,
		&repositoryCount, &cloudCount, &credentialCount,
		&riskScore, &findingCount, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	gid, _ := shared.IDFromString(id)
	tid, _ := shared.IDFromString(tenantID)
	env, _ := assetgroup.ParseEnvironment(environment)
	crit, _ := assetgroup.ParseCriticality(criticality)

	return assetgroup.Reconstitute(
		gid, tid, name, description.String, env, crit,
		businessUnit.String, owner.String, ownerEmail.String,
		[]string(tags),
		assetCount, domainCount, websiteCount, serviceCount,
		repositoryCount, cloudCount, credentialCount,
		riskScore, findingCount,
		createdAt.Time, updatedAt.Time,
	), nil
}

// Create creates a new asset group.
func (r *AssetGroupRepository) Create(ctx context.Context, g *assetgroup.AssetGroup) error {
	query := `
		INSERT INTO asset_groups (
			id, tenant_id, name, description, environment, criticality,
			business_unit, owner, owner_email, tags,
			asset_count, domain_count, website_count, service_count,
			repository_count, cloud_count, credential_count,
			risk_score, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`

	_, err := r.db.ExecContext(ctx, query,
		g.ID().String(),
		g.TenantID().String(),
		g.Name(),
		nullString(g.Description()),
		g.Environment().String(),
		g.Criticality().String(),
		nullString(g.BusinessUnit()),
		nullString(g.Owner()),
		nullString(g.OwnerEmail()),
		pq.StringArray(g.Tags()),
		g.AssetCount(),
		g.DomainCount(),
		g.WebsiteCount(),
		g.ServiceCount(),
		g.RepositoryCount(),
		g.CloudCount(),
		g.CredentialCount(),
		g.RiskScore(),
		g.CreatedAt(),
		g.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.ErrAlreadyExists
		}
		return fmt.Errorf("create asset group: %w", err)
	}

	return nil
}

// GetByID retrieves an asset group by ID.
func (r *AssetGroupRepository) GetByID(ctx context.Context, id shared.ID) (*assetgroup.AssetGroup, error) {
	query := assetGroupSelectQuery + " WHERE ag.id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	g, err := r.scanAssetGroup(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("get asset group: %w", err)
	}

	return g, nil
}

// Update updates an asset group.
func (r *AssetGroupRepository) Update(ctx context.Context, g *assetgroup.AssetGroup) error {
	query := `
		UPDATE asset_groups SET
			name = $2,
			description = $3,
			environment = $4,
			criticality = $5,
			business_unit = $6,
			owner = $7,
			owner_email = $8,
			tags = $9,
			updated_at = $10
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		g.ID().String(),
		g.Name(),
		nullString(g.Description()),
		g.Environment().String(),
		g.Criticality().String(),
		nullString(g.BusinessUnit()),
		nullString(g.Owner()),
		nullString(g.OwnerEmail()),
		pq.StringArray(g.Tags()),
		g.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("update asset group: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes an asset group.
func (r *AssetGroupRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM asset_groups WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete asset group: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// List lists asset groups with filtering and pagination.
func (r *AssetGroupRepository) List(
	ctx context.Context,
	filter assetgroup.Filter,
	opts assetgroup.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*assetgroup.AssetGroup], error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("ag.tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(ag.name ILIKE $%d OR ag.description ILIKE $%d)", argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	if len(filter.Environments) > 0 {
		envs := make([]string, len(filter.Environments))
		for i, e := range filter.Environments {
			envs[i] = e.String()
		}
		conditions = append(conditions, fmt.Sprintf("ag.environment = ANY($%d)", argNum))
		args = append(args, pq.StringArray(envs))
		argNum++
	}

	if len(filter.Criticalities) > 0 {
		crits := make([]string, len(filter.Criticalities))
		for i, c := range filter.Criticalities {
			crits[i] = c.String()
		}
		conditions = append(conditions, fmt.Sprintf("ag.criticality = ANY($%d)", argNum))
		args = append(args, pq.StringArray(crits))
		argNum++
	}

	if filter.BusinessUnit != nil && *filter.BusinessUnit != "" {
		conditions = append(conditions, fmt.Sprintf("ag.business_unit ILIKE $%d", argNum))
		args = append(args, wrapLikePattern(*filter.BusinessUnit))
		argNum++
	}

	if filter.HasFindings != nil {
		if *filter.HasFindings {
			conditions = append(conditions, `EXISTS (
				SELECT 1 FROM findings f
				INNER JOIN asset_group_members agm ON f.asset_id = agm.asset_id
				WHERE agm.asset_group_id = ag.id
			)`)
		} else {
			conditions = append(conditions, `NOT EXISTS (
				SELECT 1 FROM findings f
				INNER JOIN asset_group_members agm ON f.asset_id = agm.asset_id
				WHERE agm.asset_group_id = ag.id
			)`)
		}
	}

	if filter.MinRiskScore != nil {
		conditions = append(conditions, fmt.Sprintf("ag.risk_score >= $%d", argNum))
		args = append(args, *filter.MinRiskScore)
		argNum++
	}

	if filter.MaxRiskScore != nil {
		conditions = append(conditions, fmt.Sprintf("ag.risk_score <= $%d", argNum))
		args = append(args, *filter.MaxRiskScore)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM asset_groups ag" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*assetgroup.AssetGroup]{}, fmt.Errorf("count asset groups: %w", err)
	}

	// Build order clause
	orderClause := " ORDER BY ag.created_at DESC"
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		sortSQL := opts.Sort.SQL()
		// finding_count is a computed column alias, don't prefix with ag.
		if strings.HasPrefix(sortSQL, "finding_count") {
			orderClause = " ORDER BY " + sortSQL
		} else {
			orderClause = " ORDER BY ag." + sortSQL
		}
	}

	// Query with pagination
	query := assetGroupSelectQuery + whereClause + orderClause +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*assetgroup.AssetGroup]{}, fmt.Errorf("list asset groups: %w", err)
	}
	defer rows.Close()

	var groups []*assetgroup.AssetGroup
	for rows.Next() {
		g, err := r.scanAssetGroup(rows)
		if err != nil {
			return pagination.Result[*assetgroup.AssetGroup]{}, fmt.Errorf("scan asset group: %w", err)
		}
		groups = append(groups, g)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*assetgroup.AssetGroup]{}, fmt.Errorf("iterate asset groups: %w", err)
	}

	return pagination.NewResult(groups, total, page), nil
}

// Count counts asset groups.
func (r *AssetGroupRepository) Count(ctx context.Context, filter assetgroup.Filter) (int64, error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("ag.tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	query := "SELECT COUNT(*) FROM asset_groups ag" + whereClause
	var count int64
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count asset groups: %w", err)
	}

	return count, nil
}

// ExistsByName checks if a group with the name exists.
func (r *AssetGroupRepository) ExistsByName(ctx context.Context, tenantID shared.ID, name string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM asset_groups WHERE tenant_id = $1 AND name = $2)"
	var exists bool
	if err := r.db.QueryRowContext(ctx, query, tenantID.String(), name).Scan(&exists); err != nil {
		return false, fmt.Errorf("exists by name: %w", err)
	}
	return exists, nil
}

// GetStats returns aggregated statistics.
func (r *AssetGroupRepository) GetStats(ctx context.Context, tenantID shared.ID) (*assetgroup.Stats, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(asset_count), 0) as total_assets,
			COALESCE(AVG(risk_score), 0) as avg_risk_score
		FROM asset_groups
		WHERE tenant_id = $1
	`

	var stats assetgroup.Stats
	var avgScore float64

	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.Total,
		&stats.TotalAssets,
		&avgScore,
	)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}
	stats.AverageRiskScore = avgScore

	// Get total findings by counting from findings table through asset_group_members
	findingsQuery := `
		SELECT COUNT(DISTINCT f.id)
		FROM findings f
		INNER JOIN asset_group_members agm ON f.asset_id = agm.asset_id
		INNER JOIN asset_groups ag ON agm.asset_group_id = ag.id
		WHERE ag.tenant_id = $1
	`
	if err := r.db.QueryRowContext(ctx, findingsQuery, tenantID.String()).Scan(&stats.TotalFindings); err != nil {
		stats.TotalFindings = 0
	}

	// Get by environment
	stats.ByEnvironment = make(map[assetgroup.Environment]int64)
	envQuery := `
		SELECT environment, COUNT(*)
		FROM asset_groups
		WHERE tenant_id = $1
		GROUP BY environment
	`
	rows, err := r.db.QueryContext(ctx, envQuery, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("get stats by environment: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var env string
		var count int64
		if err := rows.Scan(&env, &count); err != nil {
			continue
		}
		if e, ok := assetgroup.ParseEnvironment(env); ok {
			stats.ByEnvironment[e] = count
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate environments: %w", err)
	}

	// Get by criticality
	stats.ByCriticality = make(map[assetgroup.Criticality]int64)
	critQuery := `
		SELECT criticality, COUNT(*)
		FROM asset_groups
		WHERE tenant_id = $1
		GROUP BY criticality
	`
	rows2, err := r.db.QueryContext(ctx, critQuery, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("get stats by criticality: %w", err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var crit string
		var count int64
		if err := rows2.Scan(&crit, &count); err != nil {
			continue
		}
		if c, ok := assetgroup.ParseCriticality(crit); ok {
			stats.ByCriticality[c] = count
		}
	}

	if err := rows2.Err(); err != nil {
		return nil, fmt.Errorf("iterate criticalities: %w", err)
	}

	return &stats, nil
}

// AddAssets adds assets to a group.
func (r *AssetGroupRepository) AddAssets(ctx context.Context, groupID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	// Use ON CONFLICT to handle duplicates
	query := "INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"

	for _, assetID := range assetIDs {
		if _, err := r.db.ExecContext(ctx, query, groupID.String(), assetID.String()); err != nil {
			return fmt.Errorf("add asset to group: %w", err)
		}
	}

	return nil
}

// RemoveAssets removes assets from a group.
func (r *AssetGroupRepository) RemoveAssets(ctx context.Context, groupID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}

	query := "DELETE FROM asset_group_members WHERE asset_group_id = $1 AND asset_id = ANY($2)"
	if _, err := r.db.ExecContext(ctx, query, groupID.String(), pq.StringArray(ids)); err != nil {
		return fmt.Errorf("remove assets from group: %w", err)
	}

	return nil
}

// GetGroupAssets returns assets belonging to a group.
func (r *AssetGroupRepository) GetGroupAssets(ctx context.Context, groupID shared.ID, page pagination.Pagination) (pagination.Result[*assetgroup.GroupAsset], error) {
	countQuery := `
		SELECT COUNT(*) FROM asset_group_members agm
		JOIN assets a ON a.id = agm.asset_id
		WHERE agm.asset_group_id = $1
	`

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, groupID.String()).Scan(&total); err != nil {
		return pagination.Result[*assetgroup.GroupAsset]{}, fmt.Errorf("count group assets: %w", err)
	}

	query := `
		SELECT a.id, a.name, a.asset_type, a.status, a.risk_score,
			   COALESCE((SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id), 0) as finding_count,
			   a.last_seen
		FROM asset_group_members agm
		JOIN assets a ON a.id = agm.asset_id
		WHERE agm.asset_group_id = $1
		ORDER BY a.name
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String(), page.Limit(), page.Offset())
	if err != nil {
		return pagination.Result[*assetgroup.GroupAsset]{}, fmt.Errorf("get group assets: %w", err)
	}
	defer rows.Close()

	var assets []*assetgroup.GroupAsset
	for rows.Next() {
		var (
			id           string
			name         string
			assetType    string
			status       string
			riskScore    int
			findingCount int
			lastSeen     sql.NullTime
		)

		if err := rows.Scan(&id, &name, &assetType, &status, &riskScore, &findingCount, &lastSeen); err != nil {
			continue
		}

		aid, _ := shared.IDFromString(id)
		ls := ""
		if lastSeen.Valid {
			ls = lastSeen.Time.Format("2006-01-02T15:04:05Z")
		}

		assets = append(assets, &assetgroup.GroupAsset{
			ID:           aid,
			Name:         name,
			Type:         assetType,
			Status:       status,
			RiskScore:    riskScore,
			FindingCount: findingCount,
			LastSeen:     ls,
		})
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*assetgroup.GroupAsset]{}, fmt.Errorf("iterate group assets: %w", err)
	}

	return pagination.NewResult(assets, total, page), nil
}

// RecalculateCounts recalculates asset counts for a group.
// Note: finding_count is computed in real-time during SELECT queries.
func (r *AssetGroupRepository) RecalculateCounts(ctx context.Context, groupID shared.ID) error {
	query := `
		UPDATE asset_groups SET
			asset_count = (
				SELECT COUNT(*) FROM asset_group_members WHERE asset_group_id = $1
			),
			domain_count = (
				SELECT COUNT(*) FROM asset_group_members agm
				JOIN assets a ON a.id = agm.asset_id
				WHERE agm.asset_group_id = $1 AND a.asset_type = 'domain'
			),
			website_count = (
				SELECT COUNT(*) FROM asset_group_members agm
				JOIN assets a ON a.id = agm.asset_id
				WHERE agm.asset_group_id = $1 AND a.asset_type = 'website'
			),
			service_count = (
				SELECT COUNT(*) FROM asset_group_members agm
				JOIN assets a ON a.id = agm.asset_id
				WHERE agm.asset_group_id = $1 AND a.asset_type IN ('api', 'service')
			),
			repository_count = (
				SELECT COUNT(*) FROM asset_group_members agm
				JOIN assets a ON a.id = agm.asset_id
				WHERE agm.asset_group_id = $1 AND a.asset_type = 'repository'
			),
			cloud_count = (
				SELECT COUNT(*) FROM asset_group_members agm
				JOIN assets a ON a.id = agm.asset_id
				WHERE agm.asset_group_id = $1 AND a.asset_type IN ('cloud_account', 'compute', 'storage', 'serverless', 'container')
			),
			credential_count = (
				SELECT COUNT(*) FROM asset_group_members agm
				JOIN assets a ON a.id = agm.asset_id
				WHERE agm.asset_group_id = $1 AND a.asset_type = 'credential'
			),
			risk_score = COALESCE((
				SELECT AVG(a.risk_score)::integer FROM asset_group_members agm
				JOIN assets a ON a.id = agm.asset_id
				WHERE agm.asset_group_id = $1
			), 0),
			updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, groupID.String())
	if err != nil {
		return fmt.Errorf("recalculate counts: %w", err)
	}

	return nil
}

// GetGroupIDsByAssetID returns IDs of groups containing a specific asset.
func (r *AssetGroupRepository) GetGroupIDsByAssetID(ctx context.Context, assetID shared.ID) ([]shared.ID, error) {
	query := `SELECT asset_group_id FROM asset_group_members WHERE asset_id = $1`

	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("get groups by asset: %w", err)
	}
	defer rows.Close()

	var groupIDs []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			continue
		}
		if id, err := shared.IDFromString(idStr); err == nil {
			groupIDs = append(groupIDs, id)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate group IDs: %w", err)
	}

	return groupIDs, nil
}

// GetGroupFindings returns findings for assets belonging to a group.
func (r *AssetGroupRepository) GetGroupFindings(ctx context.Context, groupID shared.ID, page pagination.Pagination) (pagination.Result[*assetgroup.GroupFinding], error) {
	countQuery := `
		SELECT COUNT(*) FROM findings f
		INNER JOIN asset_group_members agm ON f.asset_id = agm.asset_id
		WHERE agm.asset_group_id = $1
	`

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, groupID.String()).Scan(&total); err != nil {
		return pagination.Result[*assetgroup.GroupFinding]{}, fmt.Errorf("count group findings: %w", err)
	}

	query := `
		SELECT f.id, f.message, f.severity, f.status, f.asset_id, a.name, a.asset_type, f.created_at
		FROM findings f
		INNER JOIN asset_group_members agm ON f.asset_id = agm.asset_id
		INNER JOIN assets a ON f.asset_id = a.id
		WHERE agm.asset_group_id = $1
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			f.created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String(), page.Limit(), page.Offset())
	if err != nil {
		return pagination.Result[*assetgroup.GroupFinding]{}, fmt.Errorf("get group findings: %w", err)
	}
	defer rows.Close()

	var findings []*assetgroup.GroupFinding
	for rows.Next() {
		var (
			id           string
			title        string
			severity     string
			status       string
			assetID      string
			assetName    string
			assetType    string
			discoveredAt sql.NullTime
		)

		if err := rows.Scan(&id, &title, &severity, &status, &assetID, &assetName, &assetType, &discoveredAt); err != nil {
			continue
		}

		fid, _ := shared.IDFromString(id)
		aid, _ := shared.IDFromString(assetID)
		da := ""
		if discoveredAt.Valid {
			da = discoveredAt.Time.Format("2006-01-02T15:04:05Z")
		}

		findings = append(findings, &assetgroup.GroupFinding{
			ID:           fid,
			Title:        title,
			Severity:     severity,
			Status:       status,
			AssetID:      aid,
			AssetName:    assetName,
			AssetType:    assetType,
			DiscoveredAt: da,
		})
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*assetgroup.GroupFinding]{}, fmt.Errorf("iterate group findings: %w", err)
	}

	return pagination.NewResult(findings, total, page), nil
}

// GetDistinctAssetTypes returns all unique asset types in a group.
func (r *AssetGroupRepository) GetDistinctAssetTypes(ctx context.Context, groupID shared.ID) ([]string, error) {
	query := `
		SELECT DISTINCT a.asset_type
		FROM asset_group_members agm
		INNER JOIN assets a ON a.id = agm.asset_id
		WHERE agm.asset_group_id = $1
		ORDER BY a.asset_type
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("get distinct asset types: %w", err)
	}
	defer rows.Close()

	var types []string
	for rows.Next() {
		var assetType string
		if err := rows.Scan(&assetType); err != nil {
			continue
		}
		types = append(types, assetType)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset types: %w", err)
	}

	return types, nil
}

// GetDistinctAssetTypesMultiple returns all unique asset types across multiple groups.
func (r *AssetGroupRepository) GetDistinctAssetTypesMultiple(ctx context.Context, groupIDs []shared.ID) ([]string, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}

	// Convert to strings
	ids := make([]string, len(groupIDs))
	for i, id := range groupIDs {
		ids[i] = id.String()
	}

	query := `
		SELECT DISTINCT a.asset_type
		FROM asset_group_members agm
		INNER JOIN assets a ON a.id = agm.asset_id
		WHERE agm.asset_group_id = ANY($1)
		ORDER BY a.asset_type
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("get distinct asset types multiple: %w", err)
	}
	defer rows.Close()

	var types []string
	for rows.Next() {
		var assetType string
		if err := rows.Scan(&assetType); err != nil {
			continue
		}
		types = append(types, assetType)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset types: %w", err)
	}

	return types, nil
}

// CountAssetsByType returns count of assets per type in a group.
func (r *AssetGroupRepository) CountAssetsByType(ctx context.Context, groupID shared.ID) (map[string]int64, error) {
	query := `
		SELECT a.asset_type, COUNT(*) as count
		FROM asset_group_members agm
		INNER JOIN assets a ON a.id = agm.asset_id
		WHERE agm.asset_group_id = $1
		GROUP BY a.asset_type
		ORDER BY a.asset_type
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("count assets by type: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var assetType string
		var count int64
		if err := rows.Scan(&assetType, &count); err != nil {
			continue
		}
		counts[assetType] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset counts: %w", err)
	}

	return counts, nil
}
