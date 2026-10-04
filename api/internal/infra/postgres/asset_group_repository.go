package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
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
		ag.business_unit, ag.business_unit_id, ag.owner, ag.owner_email, ag.tags,
		ag.asset_count, ag.domain_count, ag.website_count, ag.service_count,
		ag.repository_count, ag.cloud_count, ag.credential_count,
		ag.risk_score,
		COALESCE(fc.finding_count, 0) as finding_count,
		ag.created_at, ag.updated_at
	FROM asset_groups ag
	LEFT JOIN (
		SELECT agm.asset_group_id, COUNT(f.id) as finding_count
		FROM asset_group_members agm
		INNER JOIN asset_groups fg ON fg.id = agm.asset_group_id
		INNER JOIN findings f ON f.asset_id = agm.asset_id AND f.tenant_id = fg.tenant_id
		GROUP BY agm.asset_group_id
	) fc ON fc.asset_group_id = ag.id
`

// groupMembersFrom is the FROM clause for every read of a group's members:
// asset_group_members has no tenant_id, so each member is joined to an asset
// of the group's own tenant (alias a). A member row pointing at another
// tenant's asset is never returned or counted. $1 is the group id.
const groupMembersFrom = `asset_group_members agm
		JOIN asset_groups mg ON mg.id = agm.asset_group_id
		JOIN assets a ON a.id = agm.asset_id AND a.tenant_id = mg.tenant_id AND a.deleted_at IS NULL`

func (r *AssetGroupRepository) scanAssetGroup(row interface{ Scan(...any) error }) (*assetgroup.AssetGroup, error) {
	var (
		id              string
		tenantID        string
		name            string
		description     sql.NullString
		environment     string
		criticality     string
		businessUnit    sql.NullString
		businessUnitID  sql.NullString
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
		&businessUnit, &businessUnitID, &owner, &ownerEmail, &tags,
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

	g := assetgroup.Reconstitute(
		gid, tid, name, description.String, env, crit,
		businessUnit.String, owner.String, ownerEmail.String,
		[]string(tags),
		assetCount, domainCount, websiteCount, serviceCount,
		repositoryCount, cloudCount, credentialCount,
		riskScore, findingCount,
		createdAt.Time, updatedAt.Time,
	)
	if businessUnitID.Valid {
		if buID, err := shared.IDFromString(businessUnitID.String); err == nil {
			g.SetBusinessUnitID(&buID)
		}
	}
	return g, nil
}

// Create creates a new asset group.
func (r *AssetGroupRepository) Create(ctx context.Context, g *assetgroup.AssetGroup) error {
	// business_unit_id is resolved in-SQL from the free-text business_unit so
	// the reconciled FK stays in sync with the string without a separate
	// service round-trip. It resolves to NULL when the label matches no BU.
	query := `
		INSERT INTO asset_groups (
			id, tenant_id, name, description, environment, criticality,
			business_unit, business_unit_id, owner, owner_email, tags,
			asset_count, domain_count, website_count, service_count,
			repository_count, cloud_count, credential_count,
			risk_score, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7::text,
			(SELECT bu.id FROM business_units bu
			 WHERE bu.tenant_id = $2::uuid AND $7::text <> '' AND lower(bu.name) = lower($7::text)
			 LIMIT 1),
			$8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
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

// GetByTenantAndID retrieves an asset group by tenant and ID (tenant-scoped).
func (r *AssetGroupRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*assetgroup.AssetGroup, error) {
	query := assetGroupSelectQuery + " WHERE ag.tenant_id = $1 AND ag.id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())

	g, err := r.scanAssetGroup(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("get asset group: %w", err)
	}

	return g, nil
}

// Update updates an asset group within the given tenant scope.
// Security: WHERE tenant_id = ? prevents IDOR — caller cannot mutate
// another tenant's group even with a known UUID.
func (r *AssetGroupRepository) Update(ctx context.Context, tenantID shared.ID, g *assetgroup.AssetGroup) error {
	query := `
		UPDATE asset_groups SET
			name = $3,
			description = $4,
			environment = $5,
			criticality = $6,
			business_unit = $7::text,
			business_unit_id = (
				SELECT bu.id FROM business_units bu
				WHERE bu.tenant_id = $2::uuid AND $7::text <> '' AND lower(bu.name) = lower($7::text)
				LIMIT 1
			),
			owner = $8,
			owner_email = $9,
			tags = $10,
			updated_at = $11
		WHERE id = $1 AND tenant_id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		g.ID().String(),
		tenantID.String(),
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

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes an asset group within the given tenant scope.
// Security: WHERE tenant_id = ? prevents IDOR — see Update for rationale.
func (r *AssetGroupRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := "DELETE FROM asset_groups WHERE id = $1 AND tenant_id = $2"
	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("delete asset group: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
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

	if filter.BusinessUnitID != nil && *filter.BusinessUnitID != "" {
		conditions = append(conditions, fmt.Sprintf("ag.business_unit_id = $%d", argNum))
		args = append(args, *filter.BusinessUnitID)
		argNum++
	}

	if filter.HasFindings != nil {
		if *filter.HasFindings {
			conditions = append(conditions, `EXISTS (
				SELECT 1 FROM findings f
				INNER JOIN asset_group_members agm ON f.asset_id = agm.asset_id
				WHERE agm.asset_group_id = ag.id AND f.tenant_id = ag.tenant_id
			)`)
		} else {
			conditions = append(conditions, `NOT EXISTS (
				SELECT 1 FROM findings f
				INNER JOIN asset_group_members agm ON f.asset_id = agm.asset_id
				WHERE agm.asset_group_id = ag.id AND f.tenant_id = ag.tenant_id
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

	if filter.TenantID != nil {
		args = append(args, *filter.TenantID)
		conditions = append(conditions, fmt.Sprintf("ag.tenant_id = $%d", len(args)))
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
		WHERE ag.tenant_id = $1 AND f.tenant_id = $1
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

// AddAssets adds assets to a group. Only assets of the group's own tenant
// are inserted: the ids are matched against assets in the group's tenant in
// the same statement, so an id of another tenant's asset (or an unknown id)
// is never written, whatever the caller checked before. It returns how many
// of the given ids are assets of that tenant (already a member or not).
func (r *AssetGroupRepository) AddAssets(ctx context.Context, groupID shared.ID, assetIDs []shared.ID) (int, error) {
	if len(assetIDs) == 0 {
		return 0, nil
	}
	var matched int
	err := r.db.QueryRowContext(ctx, `
		WITH own AS (
			SELECT ag.id AS group_id, a.id AS asset_id
			FROM asset_groups ag
			JOIN assets a ON a.tenant_id = ag.tenant_id AND a.deleted_at IS NULL
			WHERE ag.id = $1 AND a.id = ANY($2::uuid[])
		), ins AS (
			INSERT INTO asset_group_members (asset_group_id, asset_id)
			SELECT group_id, asset_id FROM own
			ON CONFLICT DO NOTHING
		)
		SELECT COUNT(*) FROM own`, groupID.String(), pq.Array(memberIDStrings(assetIDs))).Scan(&matched)
	if err != nil {
		return 0, fmt.Errorf("add assets to group: %w", err)
	}
	return matched, nil
}

// FilterTenantAssetIDs returns the subset of assetIDs that are assets of
// tenantID. Callers compare it with their input to refuse unknown and
// foreign ids alike.
func (r *AssetGroupRepository) FilterTenantAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]shared.ID, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL`,
		tenantID.String(), pq.Array(memberIDStrings(assetIDs)))
	if err != nil {
		return nil, fmt.Errorf("filter tenant assets: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0, len(assetIDs))
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan tenant asset: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func memberIDStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// RemoveAssets removes assets from a group.
func (r *AssetGroupRepository) RemoveAssets(ctx context.Context, groupID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	query := "DELETE FROM asset_group_members WHERE asset_group_id = $1 AND asset_id = ANY($2)"
	if _, err := r.db.ExecContext(ctx, query, groupID.String(), pq.StringArray(memberIDStrings(assetIDs))); err != nil {
		return fmt.Errorf("remove assets from group: %w", err)
	}

	return nil
}

// GetGroupAssets returns assets belonging to a group.
func (r *AssetGroupRepository) GetGroupAssets(ctx context.Context, groupID shared.ID, page pagination.Pagination, scope *shared.DataScope) (pagination.Result[*assetgroup.GroupAsset], error) {
	scopeCond, args := dataScopeCond("a.id", scope, []any{groupID.String()})

	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	countQuery := `
		SELECT COUNT(*) FROM ` + groupMembersFrom + `
		WHERE agm.asset_group_id = $1 AND ` + scopeCond

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*assetgroup.GroupAsset]{}, fmt.Errorf("count group assets: %w", err)
	}

	n := len(args)
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	query := `
		SELECT a.id, a.name, a.asset_type, a.status, a.risk_score,
			   COALESCE(fc.finding_count, 0) as finding_count,
			   a.last_seen
		FROM ` + groupMembersFrom + `
		LEFT JOIN (SELECT asset_id, COUNT(*) as finding_count FROM findings GROUP BY asset_id) fc ON fc.asset_id = a.id
		WHERE agm.asset_group_id = $1 AND ` + scopeCond + `
		ORDER BY a.name
		LIMIT $` + strconv.Itoa(n+1) + ` OFFSET $` + strconv.Itoa(n+2)

	rows, err := r.db.QueryContext(ctx, query, append(args, page.Limit(), page.Offset())...)
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

// scanMemberMatchProps selects the asset properties exclusion matching reads for
// a scan member (scope.AssetExclusionValues): its addresses and, for
// repositories, its URLs. Only these leave the database.
const scanMemberMatchProps = `jsonb_strip_nulls(jsonb_build_object(
		'ip_addresses', a.properties->'ip_addresses',
		'ip', a.properties->'ip',
		'full_name', a.properties->'full_name',
		'web_url', a.properties->'web_url',
		'clone_url', a.properties->'clone_url'))`

// ListScanMembers returns one keyset page of a group's members for scan
// dispatch. The group must belong to q.TenantID and so must every member
// returned. Archived assets are never returned; the first page counts them.
func (r *AssetGroupRepository) ListScanMembers(ctx context.Context, q assetgroup.ScanMemberQuery) (*assetgroup.ScanMemberPage, error) {
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	page := &assetgroup.ScanMemberPage{}
	first := q.AfterName == "" && q.AfterID.IsZero()

	if first {
		if err := r.db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM asset_group_members agm
			JOIN asset_groups ag ON ag.id = agm.asset_group_id
			JOIN assets a ON a.id = agm.asset_id AND a.tenant_id = ag.tenant_id
			WHERE agm.asset_group_id = $1 AND ag.tenant_id = $2 AND a.status = 'archived'`,
			q.GroupID.String(), q.TenantID.String()).Scan(&page.ArchivedCount); err != nil {
			return nil, fmt.Errorf("count archived group members: %w", err)
		}
	}

	args := []any{q.GroupID.String(), q.TenantID.String(), limit}
	cursor := ""
	if !first {
		cursor = ` AND (a.name, a.id) > ($4, $5)`
		args = append(args, q.AfterName, q.AfterID.String())
	}
	//nolint:gosec // G202: cursor and scanMemberMatchProps are fixed SQL with numbered placeholders
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(a.sub_type, ''), a.status, `+scanMemberMatchProps+`
		FROM asset_group_members agm
		JOIN asset_groups ag ON ag.id = agm.asset_group_id
		JOIN assets a ON a.id = agm.asset_id AND a.tenant_id = ag.tenant_id
		WHERE agm.asset_group_id = $1 AND ag.tenant_id = $2 AND a.status <> 'archived'`+cursor+`
		ORDER BY a.name, a.id
		LIMIT $3`, args...)
	if err != nil {
		return nil, fmt.Errorf("list group scan members: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id, name, assetType, subType, status string
			props                                []byte
		)
		if err := rows.Scan(&id, &name, &assetType, &subType, &status, &props); err != nil {
			return nil, fmt.Errorf("scan group scan member: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("group scan member id: %w", err)
		}
		m := &assetgroup.ScanMember{ID: aid, Name: name, Type: assetType, SubType: subType, Status: status}
		if len(props) > 0 {
			if err := json.Unmarshal(props, &m.Properties); err != nil {
				return nil, fmt.Errorf("group scan member %s properties: %w", id, err)
			}
		}
		page.Members = append(page.Members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate group scan members: %w", err)
	}
	return page, nil
}

// RecalculateCounts recalculates asset counts for a group.
// Note: finding_count is computed in real-time during SELECT queries.
func (r *AssetGroupRepository) RecalculateCounts(ctx context.Context, groupID shared.ID) error {
	// The per-kind counters key on assets.asset_class (derived from the
	// stored (type, sub_type) by trg_assets_registry_class), never on alias
	// type names, which are not stored (RFC-042 §6.3.8): website_count and
	// credential_count were always 0.
	//   domain_count      class domain (domains and subdomains)
	//   website_count     class application, except mobile apps
	//   service_count     class service and web_endpoint, plus APIs
	//   repository_count  class code_repo
	//   cloud_count       classes cloud_account, function, container, cluster,
	//                     artifact_registry, plus storage and cloud compute
	//   credential_count  0: credentials have no asset type yet (secrets are
	//                     RFC-042 §6.3.8 O4); kept so the column stays honest
	//nolint:gosec // G202: groupMembersFrom is a fixed SQL fragment
	query := `
		UPDATE asset_groups SET
			asset_count = (
				SELECT COUNT(*) FROM ` + groupMembersFrom + ` WHERE agm.asset_group_id = $1
			),
			domain_count = (
				SELECT COUNT(*) FROM ` + groupMembersFrom + `
				WHERE agm.asset_group_id = $1 AND a.asset_class = 'domain'
			),
			website_count = (
				SELECT COUNT(*) FROM ` + groupMembersFrom + `
				WHERE agm.asset_group_id = $1 AND a.asset_class = 'application'
				  AND COALESCE(a.sub_type, '') NOT IN ('api', 'mobile_app')
			),
			service_count = (
				SELECT COUNT(*) FROM ` + groupMembersFrom + `
				WHERE agm.asset_group_id = $1
				  AND (a.asset_class IN ('service', 'web_endpoint')
				       OR (a.asset_class = 'application' AND a.sub_type = 'api'))
			),
			repository_count = (
				SELECT COUNT(*) FROM ` + groupMembersFrom + `
				WHERE agm.asset_group_id = $1 AND a.asset_class = 'code_repo'
			),
			cloud_count = (
				SELECT COUNT(*) FROM ` + groupMembersFrom + `
				WHERE agm.asset_group_id = $1
				  AND (a.asset_class IN ('cloud_account', 'function', 'container', 'cluster', 'artifact_registry')
				       OR a.asset_type = 'storage'
				       OR (a.asset_class = 'host' AND a.sub_type = 'compute'))
			),
			credential_count = 0,
			risk_score = COALESCE((
				SELECT AVG(a.risk_score)::integer FROM ` + groupMembersFrom + `
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
	// Only groups of the asset's own tenant.
	query := `SELECT agm.asset_group_id FROM ` + groupMembersFrom + ` WHERE agm.asset_id = $1`

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
func (r *AssetGroupRepository) GetGroupFindings(ctx context.Context, groupID shared.ID, page pagination.Pagination, scope *shared.DataScope) (pagination.Result[*assetgroup.GroupFinding], error) {
	scopeCond, args := dataScopeCond("f.asset_id", scope, []any{groupID.String()})

	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	countQuery := `
		SELECT COUNT(*) FROM ` + groupMembersFrom + `
		INNER JOIN findings f ON f.asset_id = a.id AND f.tenant_id = a.tenant_id
		WHERE agm.asset_group_id = $1 AND ` + scopeCond

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*assetgroup.GroupFinding]{}, fmt.Errorf("count group findings: %w", err)
	}

	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	query := `
		SELECT f.id, f.message, f.severity, f.status, f.asset_id, a.name, a.asset_type, f.created_at
		FROM ` + groupMembersFrom + `
		INNER JOIN findings f ON f.asset_id = a.id AND f.tenant_id = a.tenant_id
		WHERE agm.asset_group_id = $1 AND ` + scopeCond + `
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			f.created_at DESC
		LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)

	rows, err := r.db.QueryContext(ctx, query, append(args, page.Limit(), page.Offset())...)
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
		FROM ` + groupMembersFrom + `
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
		FROM ` + groupMembersFrom + `
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

// CountAssetsByType returns the count of assets per stored (type, sub_type)
// pair in a group. Scanner compatibility depends on the sub-type too
// (RFC-042 §6.3.8): an API and a mobile app are both `application`.
func (r *AssetGroupRepository) CountAssetsByType(ctx context.Context, groupID shared.ID) (map[asset.TypeRef]int64, error) {
	query := `
		SELECT a.asset_type, COALESCE(a.sub_type, ''), COUNT(*) as count
		FROM ` + groupMembersFrom + `
		WHERE agm.asset_group_id = $1
		GROUP BY a.asset_type, COALESCE(a.sub_type, '')
		ORDER BY a.asset_type
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("count assets by type: %w", err)
	}
	defer rows.Close()

	counts := make(map[asset.TypeRef]int64)
	for rows.Next() {
		var assetType, subType string
		var count int64
		if err := rows.Scan(&assetType, &subType, &count); err != nil {
			return nil, fmt.Errorf("scan asset type count: %w", err)
		}
		counts[asset.TypeRef{Type: asset.AssetType(assetType), SubType: subType}] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset counts: %w", err)
	}

	return counts, nil
}
