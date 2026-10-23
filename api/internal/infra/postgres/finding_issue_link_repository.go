package postgres

// Same-issue links between findings (pkg/domain/issuelink decides).
// https://github.com/openctemio/openctem/blob/develop/api/docs/architecture/deduplication.md
//
// A link never changes either finding: no status, severity, SLA, ticket or
// task moves. Candidates come only from server-computed keys
// (finding_link_keys), one indexed lookup per batch. Derivation for a tenant
// runs under a transaction-scoped advisory lock, so two ingests of one tenant
// never build two groups from the same pair.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/issuelink"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingIssueLinkRepository stores link keys and same-issue links.
type FindingIssueLinkRepository struct {
	db *DB
}

var _ ingest.IssueLinkStore = (*FindingIssueLinkRepository)(nil)

// NewFindingIssueLinkRepository creates the repository.
func NewFindingIssueLinkRepository(db *DB) *FindingIssueLinkRepository {
	return &FindingIssueLinkRepository{db: db}
}

// IssueLinkDerivation is what one derivation did.
type IssueLinkDerivation struct {
	Findings int `json:"findings"`
	Keys     int `json:"keys"`
	Linked   int `json:"linked"`
	Released int `json:"released"`
	Crowded  int `json:"crowded"`
}

// linkableFindingSQL selects the findings that can have link keys: version-2 SAST
// and secret findings that are live (not a tombstone, not branch-only).
const linkableFindingSQL = `f.status <> 'duplicate' AND NOT f.branch_only
	AND f.identity_key IS NOT NULL AND f.identity_key->>'kind' IN ('sast', 'secret')`

// The linkable findings of a tenant: all of them, or those under the
// fingerprints or ids in $2.
const (
	linkableSelect = `
		SELECT f.id, COALESCE(f.asset_id::text, ''), f.identity_key, COALESCE(f.file_path, ''),
		       COALESCE(f.start_line, 0), COALESCE(f.end_line, 0), COALESCE(f.cwe_ids, '{}'), COALESCE(f.rule_id, ''), f.created_at
		FROM findings f
		WHERE f.tenant_id = $1 AND ` + linkableFindingSQL
	linkableAll           = linkableSelect
	linkableByFingerprint = linkableSelect + ` AND f.fingerprint = ANY($2)`
	linkableByID          = linkableSelect + ` AND f.id = ANY($2::uuid[])`
)

// DeriveByFingerprints recomputes the keys and links of the tenant's findings
// stored under the fingerprints (an ingest batch).
func (r *FindingIssueLinkRepository) DeriveByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) (IssueLinkDerivation, error) {
	if len(fingerprints) == 0 {
		return IssueLinkDerivation{}, nil
	}
	return r.derive(ctx, tenantID, linkableByFingerprint, pq.Array(fingerprints))
}

// DeriveIssueLinks is DeriveByFingerprints for ingest.
func (r *FindingIssueLinkRepository) DeriveIssueLinks(ctx context.Context, tenantID shared.ID, fingerprints []string) error {
	_, err := r.DeriveByFingerprints(ctx, tenantID, fingerprints)
	return err
}

// DeriveByIDs recomputes the keys and links of the tenant's findings (the
// backfill job).
func (r *FindingIssueLinkRepository) DeriveByIDs(ctx context.Context, tenantID shared.ID, ids []string) (IssueLinkDerivation, error) {
	if len(ids) == 0 {
		return IssueLinkDerivation{}, nil
	}
	return r.derive(ctx, tenantID, linkableByID, pq.Array(ids))
}

// ListLinkableIDs pages through the tenant's linkable findings by id (the
// backfill job).
func (r *FindingIssueLinkRepository) ListLinkableIDs(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]string, error) {
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := r.db.QueryContext(ctx, `SELECT f.id FROM findings f
		WHERE f.tenant_id = $1 AND f.id > $2 AND `+linkableFindingSQL+`
		ORDER BY f.id LIMIT $3`, tenantID.String(), afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list linkable findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan linkable finding: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// TenantsWithLinkableFindings lists the tenants the backfill job visits.
func (r *FindingIssueLinkRepository) TenantsWithLinkableFindings(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT f.tenant_id FROM findings f WHERE `+linkableFindingSQL)
	if err != nil {
		return nil, fmt.Errorf("list tenants with linkable findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("tenant id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r *FindingIssueLinkRepository) derive(ctx context.Context, tenantID shared.ID, query string, arg any) (IssueLinkDerivation, error) {
	var res IssueLinkDerivation
	tenant := tenantID.String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin issue links: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('issue_links:' || $1, 0))`, tenant); err != nil {
		return res, fmt.Errorf("lock issue links: %w", err)
	}

	batch, err := loadLinkable(ctx, tx, query, tenant, arg)
	if err != nil {
		return res, err
	}
	res.Findings = len(batch)
	if len(batch) == 0 {
		return res, tx.Commit()
	}
	ids := make([]string, 0, len(batch))
	var kKeys, kFindings, kKinds []string
	var kStart, kEnd []sql.NullInt64
	for _, f := range batch {
		ids = append(ids, f.ID)
		for _, k := range issuelink.Keys(f) {
			kKeys = append(kKeys, k.Key)
			kFindings = append(kFindings, f.ID)
			kKinds = append(kKinds, k.Kind)
			if k.Kind == issuelink.KindSASTCWE {
				kStart = append(kStart, sql.NullInt64{Int64: int64(k.StartLine), Valid: true})
				kEnd = append(kEnd, sql.NullInt64{Int64: int64(k.EndLine), Valid: true})
			} else {
				kStart = append(kStart, sql.NullInt64{})
				kEnd = append(kEnd, sql.NullInt64{})
			}
		}
	}
	res.Keys = len(kKeys)
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_link_keys WHERE tenant_id = $1 AND finding_id = ANY($2::uuid[])`,
		tenant, pq.Array(ids)); err != nil {
		return res, fmt.Errorf("clear link keys: %w", err)
	}
	if len(kKeys) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_link_keys (tenant_id, finding_id, kind, key, start_line, end_line)
			SELECT $1, u.finding_id, u.kind, u.key, u.start_line, u.end_line
			FROM unnest($2::uuid[], $3::text[], $4::text[], $5::int[], $6::int[]) AS u(finding_id, kind, key, start_line, end_line)
			ON CONFLICT DO NOTHING`,
			tenant, pq.Array(kFindings), pq.Array(kKinds), pq.Array(kKeys), nullIntArray(kStart), nullIntArray(kEnd)); err != nil {
			return res, fmt.Errorf("store link keys: %w", err)
		}
	}

	in := issuelink.Input{Batch: batch, Holders: map[string][]issuelink.Holder{}, KeyKinds: map[string]string{}, Created: map[string]time.Time{}}
	for _, f := range batch {
		in.Created[f.ID] = f.CreatedAt
	}
	crowded, err := loadHolders(ctx, tx, tenant, kKeys, &in)
	if err != nil {
		return res, err
	}
	res.Crowded = crowded
	involved := make([]string, 0, len(in.Created))
	for id := range in.Created {
		involved = append(involved, id)
	}
	if in.Existing, err = loadLinksTouching(ctx, tx, tenant, involved); err != nil {
		return res, err
	}
	plan := issuelink.PlanLinks(in)
	plan.Crowded += crowded

	for _, l := range plan.Release {
		n, err := execRows(ctx, tx, `UPDATE finding_issue_links SET state = 'released', ended_at = NOW(), updated_at = NOW()
			WHERE tenant_id = $1 AND primary_id = $2 AND member_id = $3 AND state = 'active'`, tenant, l.PrimaryID, l.MemberID)
		if err != nil {
			return res, fmt.Errorf("release issue link: %w", err)
		}
		res.Released += int(n)
	}
	for _, l := range plan.Make {
		made, err := makeIssueLink(ctx, tx, tenant, l)
		if err != nil {
			return res, err
		}
		if made {
			res.Linked++
		}
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit issue links: %w", err)
	}
	return res, nil
}

func execRows(ctx context.Context, tx *sql.Tx, q string, args ...any) (int64, error) {
	r, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func nullIntArray(in []sql.NullInt64) any {
	return pq.GenericArray{A: in}
}

// loadLinkable reads the batch's linkable findings and maps them onto the
// planner's inputs: the SAST path from the identity tuple (already
// normalized), the secret's keyed hash only from a key built on the raw
// value (field "secret"), never from a mask key.
func loadLinkable(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]issuelink.Finding, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("load linkable findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []issuelink.Finding
	for rows.Next() {
		var f issuelink.Finding
		var raw []byte
		var filePath string
		var cwes pq.StringArray
		if err := rows.Scan(&f.ID, &f.AssetID, &raw, &filePath, &f.StartLine, &f.EndLine, &cwes, &f.Rule, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan linkable finding: %w", err)
		}
		k, err := vulnerability.ParseIdentityKey(raw)
		if err != nil {
			continue
		}
		f.Kind = k.Kind
		switch k.Kind {
		case vulnerability.IdentityKindSAST:
			f.Path = k.Field("path")
			if f.Path == "" {
				f.Path = vulnerability.NormalizeRepoPath(filePath)
			}
			f.CWEs = cwes
		case vulnerability.IdentityKindSecret:
			f.SecretHMAC = k.Field("secret")
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// loadHolders fills in.Holders with every live finding holding one of keys,
// skipping keys held by more than issuelink.MaxHolders findings (counted, not
// read). It returns the number of such keys.
func loadHolders(ctx context.Context, tx *sql.Tx, tenant string, keys []string, in *issuelink.Input) (int, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	var crowded int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM (
			SELECT k.key FROM finding_link_keys k
			WHERE k.tenant_id = $1 AND k.key = ANY($2)
			GROUP BY k.key HAVING count(*) > $3) c`,
		tenant, pq.Array(keys), issuelink.MaxHolders).Scan(&crowded); err != nil {
		return 0, fmt.Errorf("count crowded link keys: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		WITH ok AS (
			SELECT k.key FROM finding_link_keys k
			WHERE k.tenant_id = $1 AND k.key = ANY($2)
			GROUP BY k.key HAVING count(*) <= $3)
		SELECT k.key, k.kind, k.finding_id, COALESCE(f.rule_id, ''), COALESCE(k.start_line, 0), COALESCE(k.end_line, 0), f.created_at
		FROM finding_link_keys k
		JOIN ok ON ok.key = k.key
		JOIN findings f ON f.id = k.finding_id AND f.tenant_id = k.tenant_id
		WHERE k.tenant_id = $1 AND f.status <> 'duplicate' AND NOT f.branch_only`,
		tenant, pq.Array(keys), issuelink.MaxHolders)
	if err != nil {
		return 0, fmt.Errorf("load link key holders: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key, kind string
		var h issuelink.Holder
		if err := rows.Scan(&key, &kind, &h.FindingID, &h.Rule, &h.StartLine, &h.EndLine, &h.CreatedAt); err != nil {
			return 0, fmt.Errorf("scan link key holder: %w", err)
		}
		in.Holders[key] = append(in.Holders[key], h)
		in.KeyKinds[key] = kind
		in.Created[h.FindingID] = h.CreatedAt
	}
	return crowded, rows.Err()
}

// loadLinksTouching returns every link (any state) of the findings, plus the
// active links of the groups they belong to, so the planner sees whole groups.
func loadLinksTouching(ctx context.Context, tx *sql.Tx, tenant string, ids []string) ([]issuelink.Link, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `
		WITH touched AS (
			SELECT primary_id FROM finding_issue_links
			WHERE tenant_id = $1 AND state = 'active' AND (primary_id = ANY($2::uuid[]) OR member_id = ANY($2::uuid[])))
		SELECT primary_id, member_id, rule, state FROM finding_issue_links
		WHERE tenant_id = $1 AND (primary_id = ANY($2::uuid[]) OR member_id = ANY($2::uuid[])
			OR (state = 'active' AND primary_id IN (SELECT primary_id FROM touched)))`,
		tenant, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("load issue links: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []issuelink.Link
	seen := map[string]bool{}
	for rows.Next() {
		var l issuelink.Link
		if err := rows.Scan(&l.PrimaryID, &l.MemberID, &l.Rule, &l.State); err != nil {
			return nil, fmt.Errorf("scan issue link: %w", err)
		}
		k := l.PrimaryID + "|" + l.MemberID
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	return out, rows.Err()
}

// makeIssueLink inserts an active link, or re-activates a pair the system
// released. A pair a person unlinked stays unlinked; a member that is already
// in another group (a concurrent writer) is left alone. The member's timeline
// records the link.
func makeIssueLink(ctx context.Context, tx *sql.Tx, tenant string, l issuelink.Link) (bool, error) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT issue_link`); err != nil {
		return false, fmt.Errorf("savepoint issue link: %w", err)
	}
	n, err := execRows(ctx, tx, `
		INSERT INTO finding_issue_links (tenant_id, primary_id, member_id, rule, basis, state)
		SELECT $1, $2, $3, $4, $5, 'active'
		WHERE NOT EXISTS (SELECT 1 FROM finding_issue_links x
			WHERE x.tenant_id = $1 AND x.state = 'active' AND (x.member_id = $3 OR x.member_id = $2 OR x.primary_id = $3))
		ON CONFLICT (tenant_id, primary_id, member_id) DO UPDATE
			SET state = 'active', rule = EXCLUDED.rule, basis = EXCLUDED.basis, ended_at = NULL, ended_by = NULL, updated_at = NOW()
			WHERE finding_issue_links.state = 'released'`,
		tenant, l.PrimaryID, l.MemberID, l.Rule, pq.Array(issuelink.Basis(l.Rule)))
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			if _, rerr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT issue_link`); rerr != nil {
				return false, fmt.Errorf("rollback issue link: %w", rerr)
			}
			return false, nil
		}
		return false, fmt.Errorf("make issue link: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT issue_link`); err != nil {
		return false, fmt.Errorf("release savepoint issue link: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	// The member's timeline names the primary only when both are on one
	// asset. Anyone who can read the member reads its timeline, and a
	// cross-asset link (one secret in two repositories) must not tell a
	// viewer of one repository that the other holds the same secret, nor
	// that finding's id: the group view lists it only to viewers of both.
	changes, _ := json.Marshal(map[string]any{"primary_id": l.PrimaryID, "rule": l.Rule, "basis": issuelink.Basis(l.Rule)})
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
		SELECT $1, m.id, 'issue_linked', 'system', $3, 'issue_link', $4
		FROM findings m JOIN findings p ON p.tenant_id = m.tenant_id AND p.id = $5::uuid
		WHERE m.tenant_id = $1 AND m.id = $2::uuid AND m.asset_id IS NOT DISTINCT FROM p.asset_id`,
		tenant, l.MemberID, changes, "Linked as the same issue as finding "+l.PrimaryID, l.PrimaryID); err != nil {
		return false, fmt.Errorf("record issue link activity: %w", err)
	}
	return true, nil
}

// IssueGroup returns the active group findingID belongs to (primary first),
// or nil when it is in none. The caller filters by data scope.
func (r *FindingIssueLinkRepository) IssueGroup(ctx context.Context, tenantID, findingID shared.ID) ([]issuelink.GroupMember, error) {
	tenant := tenantID.String()
	var primary string
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(
			(SELECT primary_id::text FROM finding_issue_links WHERE tenant_id = $1 AND member_id = $2 AND state = 'active'),
			(SELECT $2::text FROM finding_issue_links WHERE tenant_id = $1 AND primary_id = $2 AND state = 'active' LIMIT 1),
			'')`, tenant, findingID.String()).Scan(&primary)
	if err != nil {
		return nil, fmt.Errorf("read issue group: %w", err)
	}
	if primary == "" {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, COALESCE(f.asset_id::text, ''), COALESCE(a.name, ''), COALESCE(f.title, ''), COALESCE(f.tool_name, ''),
		       COALESCE(f.rule_id, ''), f.status, f.severity, COALESCE(f.file_path, ''), COALESCE(f.start_line, 0), f.created_at,
		       f.id = $2::uuid, COALESCE(l.rule, ''), COALESCE(l.basis, '{}'), l.created_at, f.assigned_to
		FROM findings f
		LEFT JOIN finding_issue_links l ON l.tenant_id = f.tenant_id AND l.member_id = f.id AND l.primary_id = $2::uuid AND l.state = 'active'
		LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1 AND (f.id = $2::uuid OR l.id IS NOT NULL)
		ORDER BY (f.id = $2::uuid) DESC, f.created_at, f.id
		LIMIT $3`, tenant, primary, issuelink.MaxMembers+1)
	if err != nil {
		return nil, fmt.Errorf("read issue group members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []issuelink.GroupMember
	for rows.Next() {
		var m issuelink.GroupMember
		var basis pq.StringArray
		var linked sql.NullTime
		var assigned sql.NullString
		if err := rows.Scan(&m.FindingID, &m.AssetID, &m.AssetName, &m.Title, &m.ToolName, &m.RuleID, &m.Status, &m.Severity,
			&m.FilePath, &m.StartLine, &m.CreatedAt, &m.IsPrimary, &m.Rule, &basis, &linked, &assigned); err != nil {
			return nil, fmt.Errorf("scan issue group member: %w", err)
		}
		m.Basis = basis
		if assigned.Valid {
			m.AssignedTo = assigned.String
		}
		if linked.Valid {
			t := linked.Time
			m.LinkedAt = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ErrIssueLinkNotFound: no active link joins the two findings.
var ErrIssueLinkNotFound = fmt.Errorf("%w: issue link not found", shared.ErrNotFound)

// Unlink takes otherID out of findingID's group (or findingID out of it, when
// otherID is the group's primary): the link ends as unlinked, by the actor,
// and is never made again automatically. Both timelines record it. Returns
// the pair that ended.
func (r *FindingIssueLinkRepository) Unlink(ctx context.Context, tenantID, findingID, otherID shared.ID, actorID string) (primaryID, memberID string, err error) {
	tenant := tenantID.String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("begin unlink: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('issue_links:' || $1, 0))`, tenant); err != nil {
		return "", "", fmt.Errorf("lock issue links: %w", err)
	}
	var id string
	err = tx.QueryRowContext(ctx, `
		WITH g AS (
			SELECT COALESCE(
				(SELECT primary_id FROM finding_issue_links WHERE tenant_id = $1 AND member_id = $2 AND state = 'active'),
				$2::uuid) AS primary_id)
		SELECT l.id, l.primary_id, l.member_id FROM finding_issue_links l, g
		WHERE l.tenant_id = $1 AND l.state = 'active' AND l.primary_id = g.primary_id
		  AND ((l.member_id = $3 AND $3 <> g.primary_id) OR (g.primary_id = $3 AND l.member_id = $2))
		FOR UPDATE OF l`, tenant, findingID.String(), otherID.String()).Scan(&id, &primaryID, &memberID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrIssueLinkNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("find issue link: %w", err)
	}
	var actor any
	if actorID != "" {
		actor = actorID
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding_issue_links SET state = 'unlinked', ended_at = NOW(), ended_by = $3, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`, tenant, id, actor); err != nil {
		return "", "", fmt.Errorf("unlink: %w", err)
	}
	// Each timeline names the other finding only when both are on one asset
	// (see makeIssueLink): a later viewer of one asset may not see the other.
	var sameAsset bool
	if err := tx.QueryRowContext(ctx, `
		SELECT p.asset_id IS NOT DISTINCT FROM m.asset_id FROM findings p, findings m
		WHERE p.tenant_id = $1 AND p.id = $2 AND m.tenant_id = $1 AND m.id = $3`,
		tenant, primaryID, memberID).Scan(&sameAsset); err != nil {
		return "", "", fmt.Errorf("read unlinked findings: %w", err)
	}
	pc, mc := []byte(`{}`), []byte(`{}`)
	pMsg, mMsg := "Unlinked a finding on another asset from this issue", "Unlinked from the issue of a finding on another asset"
	if sameAsset {
		pc, _ = json.Marshal(map[string]string{"member_id": memberID})
		mc, _ = json.Marshal(map[string]string{"primary_id": primaryID})
		pMsg, mMsg = "Unlinked finding "+memberID+" from this issue", "Unlinked from the issue of finding "+primaryID
	}
	actorType := actorTypeUser
	if actor == nil {
		actorType = "system"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_id, changes, source, message)
		VALUES ($1, $2, 'issue_unlinked', $6, $7, $3, 'issue_link', $8),
		       ($1, $5, 'issue_unlinked', $6, $7, $4, 'issue_link', $9)`,
		tenant, primaryID, pc, mc, memberID, actorType, actor, pMsg, mMsg); err != nil {
		return "", "", fmt.Errorf("record unlink activity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", "", fmt.Errorf("commit unlink: %w", err)
	}
	return primaryID, memberID, nil
}

// IssueLinkBackfill is the outcome of the link backfill for one tenant.
type IssueLinkBackfill struct {
	TenantID string `json:"tenant_id"`
	Applied  bool   `json:"applied"`
	IssueLinkDerivation
}

// BackfillLinks derives the keys and links of a tenant's stored findings.
// Applied, it runs DeriveByIDs over the findings in id order: a pair is
// decided when the later of its two findings is derived, by which time the
// earlier one's keys are stored. A dry run (read-only) plans the whole tenant
// in memory and writes nothing.
func (r *FindingIssueLinkRepository) BackfillLinks(ctx context.Context, tenantID shared.ID, apply bool, batch int) (*IssueLinkBackfill, error) {
	if batch <= 0 {
		batch = 500
	}
	rep := &IssueLinkBackfill{TenantID: tenantID.String(), Applied: apply}
	if apply {
		after := ""
		for {
			ids, err := r.ListLinkableIDs(ctx, tenantID, after, batch)
			if err != nil {
				return nil, err
			}
			if len(ids) == 0 {
				return rep, nil
			}
			d, err := r.DeriveByIDs(ctx, tenantID, ids)
			if err != nil {
				return nil, err
			}
			rep.Findings += d.Findings
			rep.Keys += d.Keys
			rep.Linked += d.Linked
			rep.Released += d.Released
			rep.Crowded += d.Crowded
			after = ids[len(ids)-1]
		}
	}
	return r.planTenant(ctx, tenantID, rep)
}

func (r *FindingIssueLinkRepository) planTenant(ctx context.Context, tenantID shared.ID, rep *IssueLinkBackfill) (*IssueLinkBackfill, error) {
	tenant := tenantID.String()
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin link plan: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	all, err := loadLinkable(ctx, tx, linkableAll, tenant)
	if err != nil {
		return nil, err
	}
	in := issuelink.Input{Batch: all, Holders: map[string][]issuelink.Holder{}, KeyKinds: map[string]string{}, Created: map[string]time.Time{}}
	ids := make([]string, 0, len(all))
	for _, f := range all {
		ids = append(ids, f.ID)
		in.Created[f.ID] = f.CreatedAt
		for _, k := range issuelink.Keys(f) {
			rep.Keys++
			in.Holders[k.Key] = append(in.Holders[k.Key], issuelink.Holder{FindingID: f.ID, Rule: f.Rule, StartLine: k.StartLine, EndLine: k.EndLine, CreatedAt: f.CreatedAt})
			in.KeyKinds[k.Key] = k.Kind
		}
	}
	rep.Findings = len(all)
	if in.Existing, err = loadLinksTouching(ctx, tx, tenant, ids); err != nil {
		return nil, err
	}
	plan := issuelink.PlanLinks(in)
	rep.Linked, rep.Released, rep.Crowded = len(plan.Make), len(plan.Release), plan.Crowded
	return rep, nil
}

// LinkAliasCollisions links, as the same issue, each finding still stored
// under an advisory key (Former) to the live finding of the same asset that
// holds the CVE key the feed gives it (Canonical). The earlier-created one
// is the primary. Never a merge: each keeps its status and triage; a pair a
// person unlinked stays unlinked.
func (r *FindingIssueLinkRepository) LinkAliasCollisions(ctx context.Context, tenantID shared.ID, pairs []ingest.AliasCollision) (int, error) {
	if len(pairs) == 0 {
		return 0, nil
	}
	tenant := tenantID.String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin alias links: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('issue_links:' || $1, 0))`, tenant); err != nil {
		return 0, fmt.Errorf("lock issue links: %w", err)
	}
	made := 0
	for _, p := range pairs {
		if p.Former == "" || p.Canonical == "" || p.Former == p.Canonical {
			continue
		}
		var a, b string
		var aCreated, bCreated time.Time
		err := tx.QueryRowContext(ctx, `
			SELECT o.id, o.created_at, c.id, c.created_at
			FROM findings o JOIN findings c ON c.tenant_id = o.tenant_id AND c.asset_id = o.asset_id AND c.id <> o.id
			WHERE o.tenant_id = $1 AND o.fingerprint = $2 AND c.fingerprint = $3
			  AND o.status <> 'duplicate' AND c.status <> 'duplicate'`, tenant, p.Former, p.Canonical).Scan(&a, &aCreated, &b, &bCreated)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return made, fmt.Errorf("find alias collision: %w", err)
		}
		primary, member := a, b
		if bCreated.Before(aCreated) || (bCreated.Equal(aCreated) && b < a) {
			primary, member = b, a
		}
		ok, err := makeIssueLink(ctx, tx, tenant, issuelink.Link{PrimaryID: primary, MemberID: member, Rule: issuelink.RuleVulnAlias})
		if err != nil {
			return made, err
		}
		if ok {
			made++
		}
	}
	if err := tx.Commit(); err != nil {
		return made, fmt.Errorf("commit alias links: %w", err)
	}
	return made, nil
}
