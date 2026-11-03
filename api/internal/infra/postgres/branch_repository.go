package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// branchSortColumns is the allowlist of user-selectable ORDER BY columns for
// branch listing. Keys are the values accepted from the `sort` query param;
// values are the literal, trusted column names. Anything not in this map falls
// back to the default sort — this prevents ORDER BY SQL injection.
var branchSortColumns = map[string]string{
	"name":            "name",
	"branch_type":     "branch_type",
	"is_default":      "is_default",
	"is_protected":    "is_protected",
	"last_commit_at":  "last_commit_at",
	"last_scanned_at": "last_scanned_at",
	"scan_status":     "scan_status",
	"findings_total":  "findings_total",
	"created_at":      "created_at",
	"updated_at":      "updated_at",
}

// BranchRepository implements branch.Repository using PostgreSQL.
type BranchRepository struct {
	db *DB
}

// NewBranchRepository creates a new BranchRepository.
func NewBranchRepository(db *DB) *BranchRepository {
	return &BranchRepository{db: db}
}

// Create persists a new branch.
func (r *BranchRepository) Create(ctx context.Context, b *branch.Branch) error {
	query := `
		INSERT INTO repository_branches (
			id, repository_id, name, branch_type, is_default, is_protected,
			last_commit_sha, last_commit_message, last_commit_author, last_commit_author_avatar, last_commit_at,
			scan_on_push, scan_on_pr, last_scan_id, last_scanned_at, scan_status, quality_gate_status,
			findings_total, findings_critical, findings_high, findings_medium, findings_low,
			keep_when_inactive, retention_days, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
	`

	_, err := r.db.ExecContext(ctx, query,
		b.ID().String(),
		b.RepositoryID().String(),
		b.Name(),
		b.Type().String(),
		b.IsDefault(),
		b.IsProtected(),
		nullString(b.LastCommitSHA()),
		nullString(b.LastCommitMessage()),
		nullString(b.LastCommitAuthor()),
		nullString(b.LastCommitAuthorAvatar()),
		nullTime(b.LastCommitAt()),
		b.ScanOnPush(),
		b.ScanOnPR(),
		nullIDPtr(b.LastScanID()),
		nullTime(b.LastScannedAt()),
		b.ScanStatus().String(),
		b.QualityGateStatus().String(),
		b.FindingsTotal(),
		b.FindingsCritical(),
		b.FindingsHigh(),
		b.FindingsMedium(),
		b.FindingsLow(),
		b.KeepWhenInactive(),
		nullIntPtr(b.RetentionDays()),
		b.CreatedAt(),
		b.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return branch.AlreadyExistsError(b.Name())
		}
		return fmt.Errorf("failed to create branch: %w", err)
	}

	return nil
}

// GetByID retrieves a branch by ID.
func (r *BranchRepository) GetByID(ctx context.Context, id shared.ID) (*branch.Branch, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanBranch(row)
}

// GetByName retrieves a branch by repository ID and name.
func (r *BranchRepository) GetByName(ctx context.Context, repositoryID shared.ID, name string) (*branch.Branch, error) {
	query := r.selectQuery() + " WHERE repository_id = $1 AND name = $2"
	row := r.db.QueryRowContext(ctx, query, repositoryID.String(), name)
	return r.scanBranch(row)
}

// Update updates an existing branch.
func (r *BranchRepository) Update(ctx context.Context, b *branch.Branch) error {
	query := `
		UPDATE repository_branches SET
			name = $2, branch_type = $3, is_default = $4, is_protected = $5,
			last_commit_sha = $6, last_commit_message = $7, last_commit_author = $8,
			last_commit_author_avatar = $9, last_commit_at = $10,
			scan_on_push = $11, scan_on_pr = $12, last_scan_id = $13, last_scanned_at = $14,
			scan_status = $15, quality_gate_status = $16,
			findings_total = $17, findings_critical = $18, findings_high = $19,
			findings_medium = $20, findings_low = $21,
			keep_when_inactive = $22, retention_days = $23, updated_at = $24
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		b.ID().String(),
		b.Name(),
		b.Type().String(),
		b.IsDefault(),
		b.IsProtected(),
		nullString(b.LastCommitSHA()),
		nullString(b.LastCommitMessage()),
		nullString(b.LastCommitAuthor()),
		nullString(b.LastCommitAuthorAvatar()),
		nullTime(b.LastCommitAt()),
		b.ScanOnPush(),
		b.ScanOnPR(),
		nullIDPtr(b.LastScanID()),
		nullTime(b.LastScannedAt()),
		b.ScanStatus().String(),
		b.QualityGateStatus().String(),
		b.FindingsTotal(),
		b.FindingsCritical(),
		b.FindingsHigh(),
		b.FindingsMedium(),
		b.FindingsLow(),
		b.KeepWhenInactive(),
		nullIntPtr(b.RetentionDays()),
		b.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to update branch: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return branch.NotFoundError(b.Name())
	}

	return nil
}

// Delete removes a branch.
func (r *BranchRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM repository_branches WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete branch: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return branch.ErrNotFound
	}

	return nil
}

// List returns branches matching the filter.
func (r *BranchRepository) List(ctx context.Context, filter branch.Filter, opts branch.ListOptions, page pagination.Pagination) (pagination.Result[*branch.Branch], error) {
	baseQuery := r.selectQuery()
	countQuery := `SELECT COUNT(*) FROM repository_branches`

	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Apply sorting. SECURITY: opts.SortBy originates from the user-supplied
	// `sort` query param and is interpolated into ORDER BY, so it MUST be
	// validated against a fixed column allowlist (no raw interpolation) to
	// prevent ORDER BY SQL injection.
	orderColumn, ok := branchSortColumns[opts.SortBy]
	if !ok {
		orderColumn = "" // fall back to the default sort
	}
	orderBy := defaultSortOrder
	if orderColumn != "" {
		direction := sortOrderASC
		if opts.SortOrder == sortOrderDescLower {
			direction = sortOrderDESC
		}
		orderBy = fmt.Sprintf("%s %s", orderColumn, direction)
	}
	baseQuery += " ORDER BY " + orderBy
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*branch.Branch]{}, fmt.Errorf("failed to count branches: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*branch.Branch]{}, fmt.Errorf("failed to query branches: %w", err)
	}
	defer rows.Close()

	var branches []*branch.Branch
	for rows.Next() {
		b, err := r.scanBranchFromRows(rows)
		if err != nil {
			return pagination.Result[*branch.Branch]{}, err
		}
		branches = append(branches, b)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*branch.Branch]{}, fmt.Errorf("failed to iterate branches: %w", err)
	}

	return pagination.NewResult(branches, total, page), nil
}

// ListByRepository returns all branches for a repository.
func (r *BranchRepository) ListByRepository(ctx context.Context, repositoryID shared.ID) ([]*branch.Branch, error) {
	query := r.selectQuery() + " WHERE repository_id = $1 ORDER BY is_default DESC, name ASC"

	rows, err := r.db.QueryContext(ctx, query, repositoryID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query branches: %w", err)
	}
	defer rows.Close()

	var branches []*branch.Branch
	for rows.Next() {
		b, err := r.scanBranchFromRows(rows)
		if err != nil {
			return nil, err
		}
		branches = append(branches, b)
	}

	return branches, nil
}

// GetDefaultBranch returns the default branch for a repository.
func (r *BranchRepository) GetDefaultBranch(ctx context.Context, repositoryID shared.ID) (*branch.Branch, error) {
	query := r.selectQuery() + " WHERE repository_id = $1 AND is_default = true"
	row := r.db.QueryRowContext(ctx, query, repositoryID.String())
	return r.scanBranch(row)
}

// SetDefaultBranch sets a branch as the default for a repository.
func (r *BranchRepository) SetDefaultBranch(ctx context.Context, repositoryID shared.ID, branchID shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Unset current default
	_, err = tx.ExecContext(ctx,
		`UPDATE repository_branches SET is_default = false WHERE repository_id = $1 AND is_default = true`,
		repositoryID.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to unset default branch: %w", err)
	}

	// Set new default
	result, err := tx.ExecContext(ctx,
		`UPDATE repository_branches SET is_default = true, updated_at = NOW() WHERE id = $1 AND repository_id = $2`,
		branchID.String(), repositoryID.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to set default branch: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return branch.ErrNotFound
	}

	return tx.Commit()
}

// Count returns the number of branches matching the filter.
func (r *BranchRepository) Count(ctx context.Context, filter branch.Filter) (int64, error) {
	query := `SELECT COUNT(*) FROM repository_branches`

	whereClause, args := r.buildWhereClause(filter)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count branches: %w", err)
	}

	return count, nil
}

// ExistsByName checks if a branch exists by repository ID and name.
func (r *BranchRepository) ExistsByName(ctx context.Context, repositoryID shared.ID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM repository_branches WHERE repository_id = $1 AND name = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, repositoryID.String(), name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check branch existence: %w", err)
	}

	return exists, nil
}

// Helper methods

func (r *BranchRepository) selectQuery() string {
	return `
		SELECT id, repository_id, name, branch_type, is_default, is_protected,
			last_commit_sha, last_commit_message, last_commit_author, last_commit_author_avatar, last_commit_at,
			scan_on_push, scan_on_pr, last_scan_id, last_scanned_at, scan_status, quality_gate_status,
			findings_total, findings_critical, findings_high, findings_medium, findings_low,
			keep_when_inactive, retention_days, created_at, updated_at
		FROM repository_branches
	`
}

func (r *BranchRepository) scanBranch(row *sql.Row) (*branch.Branch, error) {
	b, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, branch.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan branch: %w", err)
	}
	return b, nil
}

func (r *BranchRepository) scanBranchFromRows(rows *sql.Rows) (*branch.Branch, error) {
	return r.doScan(rows.Scan)
}

func (r *BranchRepository) doScan(scan func(dest ...any) error) (*branch.Branch, error) {
	var (
		idStr                  string
		repositoryIDStr        string
		name                   string
		branchType             string
		isDefault              bool
		isProtected            bool
		lastCommitSHA          sql.NullString
		lastCommitMessage      sql.NullString
		lastCommitAuthor       sql.NullString
		lastCommitAuthorAvatar sql.NullString
		lastCommitAt           sql.NullTime
		scanOnPush             bool
		scanOnPR               bool
		lastScanID             sql.NullString
		lastScannedAt          sql.NullTime
		scanStatus             string
		qualityGateStatus      string
		findingsTotal          int
		findingsCritical       int
		findingsHigh           int
		findingsMedium         int
		findingsLow            int
		keepWhenInactive       bool
		retentionDays          sql.NullInt32
		createdAt              time.Time
		updatedAt              time.Time
	)

	err := scan(
		&idStr, &repositoryIDStr, &name, &branchType, &isDefault, &isProtected,
		&lastCommitSHA, &lastCommitMessage, &lastCommitAuthor, &lastCommitAuthorAvatar, &lastCommitAt,
		&scanOnPush, &scanOnPR, &lastScanID, &lastScannedAt, &scanStatus, &qualityGateStatus,
		&findingsTotal, &findingsCritical, &findingsHigh, &findingsMedium, &findingsLow,
		&keepWhenInactive, &retentionDays, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	parsedRepositoryID, err := shared.IDFromString(repositoryIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository_id: %w", err)
	}

	var parsedLastScanID *shared.ID
	if lastScanID.Valid {
		id, err := shared.IDFromString(lastScanID.String)
		if err == nil {
			parsedLastScanID = &id
		}
	}

	var lastCommit *time.Time
	if lastCommitAt.Valid {
		lastCommit = &lastCommitAt.Time
	}

	var lastScanned *time.Time
	if lastScannedAt.Valid {
		lastScanned = &lastScannedAt.Time
	}

	var retention *int
	if retentionDays.Valid {
		r := int(retentionDays.Int32)
		retention = &r
	}

	return branch.Reconstitute(
		parsedID,
		parsedRepositoryID,
		name,
		branch.ParseType(branchType),
		isDefault,
		isProtected,
		nullStringValue(lastCommitSHA),
		nullStringValue(lastCommitMessage),
		nullStringValue(lastCommitAuthor),
		nullStringValue(lastCommitAuthorAvatar),
		lastCommit,
		scanOnPush,
		scanOnPR,
		parsedLastScanID,
		lastScanned,
		branch.ParseScanStatus(scanStatus),
		branch.ParseQualityGateStatus(qualityGateStatus),
		findingsTotal,
		findingsCritical,
		findingsHigh,
		findingsMedium,
		findingsLow,
		keepWhenInactive,
		retention,
		createdAt,
		updatedAt,
	), nil
}

func (r *BranchRepository) buildWhereClause(filter branch.Filter) (string, []any) {
	var conditions []string
	var args []any

	if filter.RepositoryID != nil {
		args = append(args, filter.RepositoryID.String())
		conditions = append(conditions, fmt.Sprintf("repository_id = $%d", len(args)))
	}

	if filter.Name != "" {
		args = append(args, wrapLikePattern(filter.Name))
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", len(args)))
	}

	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			args = append(args, t.String())
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		conditions = append(conditions, fmt.Sprintf("branch_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.IsDefault != nil {
		args = append(args, *filter.IsDefault)
		conditions = append(conditions, fmt.Sprintf("is_default = $%d", len(args)))
	}

	if filter.ScanStatus != nil {
		args = append(args, filter.ScanStatus.String())
		conditions = append(conditions, fmt.Sprintf("scan_status = $%d", len(args)))
	}

	return strings.Join(conditions, " AND "), args
}

// Helper functions

func nullIntPtr(v *int) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

// branchPresenceCTE is the open findings present on the branches named $2
// and $3 of repository $1 in tenant $4: an open occurrence on the branch, or,
// for a finding with no occurrence at all (rows from before occurrences),
// findings.branch_id. It is the rule the branch counters use (migration
// branch_counts_from_occurrences), so the compare, the counters and the
// findings list filtered on a branch agree.
func branchPresenceCTE() string {
	return `
		WITH br AS (
			SELECT rb.id, rb.name
			FROM repository_branches rb
			JOIN assets a ON a.id = rb.repository_id
			WHERE rb.repository_id = $1 AND a.tenant_id = $4 AND rb.name IN ($2, $3)
		),
		on_branch AS (
			SELECT br.name AS branch, f.id, f.title, f.severity, f.file_path, f.source
			FROM br
			JOIN finding_branch_occurrences o ON o.branch_id = br.id AND o.tenant_id = $4 AND o.status = 'open'
			JOIN findings f ON f.id = o.finding_id AND f.tenant_id = $4
			WHERE ` + vulnerability.OpenStatusSQL("f.status") + `
			UNION ALL
			SELECT br.name, f.id, f.title, f.severity, f.file_path, f.source
			FROM br
			JOIN findings f ON f.branch_id = br.id AND f.tenant_id = $4
			WHERE ` + vulnerability.OpenStatusSQL("f.status") + `
			  AND NOT EXISTS (SELECT 1 FROM finding_branch_occurrences x WHERE x.finding_id = f.id)
		),
		base AS (SELECT * FROM on_branch WHERE branch = $2),
		cmp AS (SELECT * FROM on_branch WHERE branch = $3)`
}

// CompareBranches compares the open findings present on two branches of a
// repository: new (on compare, not on base), resolved (on base, not on
// compare) and common, with the new ones by severity and the 50 most severe.
func (r *BranchRepository) CompareBranches(ctx context.Context, tenantID, repositoryID shared.ID, baseBranch, compareBranch string) (*branch.BranchComparison, error) {
	query := branchPresenceCTE() + `
		SELECT
			(SELECT COUNT(*) FROM cmp WHERE cmp.id NOT IN (SELECT id FROM base)),
			(SELECT COUNT(*) FROM base WHERE base.id NOT IN (SELECT id FROM cmp)),
			(SELECT COUNT(*) FROM cmp WHERE cmp.id IN (SELECT id FROM base)),
			(SELECT COALESCE(jsonb_object_agg(s.severity, s.n), '{}'::jsonb)::text FROM (
				SELECT cmp.severity, COUNT(*) AS n FROM cmp
				WHERE cmp.id NOT IN (SELECT id FROM base) GROUP BY cmp.severity) s)
	`

	result := &branch.BranchComparison{
		BaseBranch:    baseBranch,
		CompareBranch: compareBranch,
		NewBySeverity: make(map[string]int),
	}
	args := []any{repositoryID.String(), baseBranch, compareBranch, tenantID.String()}

	var bySeverity string
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&result.NewFindings,
		&result.ResolvedFindings,
		&result.CommonFindings,
		&bySeverity,
	); err != nil {
		return nil, fmt.Errorf("compare branches: %w", err)
	}
	if err := json.Unmarshal([]byte(bySeverity), &result.NewBySeverity); err != nil {
		return nil, fmt.Errorf("compare branches: new by severity: %w", err)
	}

	detailQuery := branchPresenceCTE() + `
		SELECT cmp.id, cmp.title, cmp.severity, COALESCE(cmp.file_path, ''), cmp.source
		FROM cmp
		WHERE cmp.id NOT IN (SELECT id FROM base)
		ORDER BY CASE cmp.severity
			WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4
		END, cmp.id
		LIMIT 50
	`
	rows, err := r.db.QueryContext(ctx, detailQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("compare branches: new findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result.NewItems = make([]branch.ComparisonFinding, 0)
	for rows.Next() {
		var f branch.ComparisonFinding
		if err := rows.Scan(&f.ID, &f.Title, &f.Severity, &f.FilePath, &f.Source); err != nil {
			return nil, fmt.Errorf("compare branches: scan new finding: %w", err)
		}
		result.NewItems = append(result.NewItems, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("compare branches: new findings: %w", err)
	}
	return result, nil
}
