package postgres

// Storage of the one-time provider-address move
// (docs/architecture/provider-address-move.md). Every statement is bound to the
// organization of the run: the tenant id comes from the run, never from a
// row it read.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/server/pkg/domain/provideraddr"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const (
	// providerMoveLockTimeout bounds every lock wait of a batch, so ingest
	// never waits on the move for longer.
	providerMoveLockTimeout = 2 * time.Second
	// providerMoveStatementTimeout bounds every statement of a batch.
	providerMoveStatementTimeout = 30 * time.Second
	// providerMoveLockClass is the first key of the organization's advisory lock.
	providerMoveLockClass int32 = 531
)

// ProviderAddressMoveRepository stores the move's runs and journal and runs
// its batches.
type ProviderAddressMoveRepository struct {
	db *DB
}

// NewProviderAddressMoveRepository creates the repository.
func NewProviderAddressMoveRepository(db *DB) *ProviderAddressMoveRepository {
	return &ProviderAddressMoveRepository{db: db}
}

// providerMoveLockKey is the organization's advisory lock key.
func providerMoveLockKey(tenantID shared.ID) int32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenantID.String()))
	return int32(h.Sum32()) //nolint:gosec // G115: a hash, wrapping is intended
}

// providerHistoryRefs are references to an asset that record what happened
// to it (history, derived facts, queues) and do not hold an address: an
// address with only these is plain. Every other reference of the asset merge
// list holds it (kept): a new table there is safe by default.
var providerHistoryRefs = map[string]bool{
	"asset_change_events.asset_id":          true,
	"asset_attribute_sources.asset_id":      true,
	"asset_attribute_set_elements.asset_id": true,
	"asset_attribute_freshness.asset_id":    true,
	"asset_enrichment_requests.asset_id":    true,
	"asset_risk_queue.asset_id":             true,
	"finding_priority_queue.asset_id":       true,
	"asset_identifiers.asset_id":            true,
	"easm_evidence.asset_id":                true,
	"asset_coverage.asset_id":               true,
	"asset_liveness.asset_id":               true,
	"scan_step_outputs.asset_id":            true,
	"scan_run_targets.asset_id":             true,
	"scan_run_targets.parent_asset_id":      true,
	"scan_runs.asset_id":                    true,
	"asset_group_member_history.asset_id":   true,
	"exposure_events.asset_id":              true,
	"user_accessible_assets.asset_id":       true,
}

// ProviderKeepRefs are the asset references that keep a provider address
// (table.column), for tests and the runbook.
func ProviderKeepRefs() []string {
	out := make([]string, 0, len(assetMergeRefs))
	for _, r := range providerKeepRefs() {
		out = append(out, r.table+"."+r.column)
	}
	return out
}

func providerKeepRefs() []mergeRef {
	out := make([]mergeRef, 0, len(assetMergeRefs))
	for _, r := range assetMergeRefs {
		if !providerHistoryRefs[r.table+"."+r.column] {
			out = append(out, r)
		}
	}
	return out
}

// ProviderKeepRefsQuery is the statement that finds kept addresses ($1 the
// organization, $2 the batch's ids), for measurements.
func ProviderKeepRefsQuery() string { return providerKeepRefsSQL }

// providerKeepRefsSQL selects the ids among $2 that a keeping reference
// names, plus those with a child asset.
var providerKeepRefsSQL = func() string {
	parts := make([]string, 0, len(assetMergeRefs)+1)
	for _, r := range providerKeepRefs() {
		scope := ""
		if r.tenantCol != "" {
			scope = r.tenantCol + " = $1 AND "
		}
		parts = append(parts, fmt.Sprintf(`SELECT %[2]s FROM %[1]s WHERE %[3]s%[2]s = ANY($2::uuid[])`, r.table, r.column, scope))
	}
	parts = append(parts, `SELECT parent_id FROM assets WHERE tenant_id = $1 AND parent_id = ANY($2::uuid[]) AND deleted_at IS NULL`)
	return `SELECT DISTINCT x::text FROM (` + strings.Join(parts, " UNION ALL ") + `) refs(x) WHERE x IS NOT NULL`
}()

// StartRun opens an apply or restore run, or resumes the organization's
// unfinished one when it has the same mode, job version and dataset version.
// An unfinished run with another key is closed as superseded. initial is
// stored on a new run only.
func (r *ProviderAddressMoveRepository) StartRun(ctx context.Context, tenantID shared.ID, mode provideraddr.Mode,
	datasetVersion, actor string, initial provideraddr.Counts) (*provideraddr.Run, error) {
	run, err := r.startRun(ctx, tenantID, mode, datasetVersion, actor, initial)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		// Another runner opened the run at the same moment: resume it.
		return r.startRun(ctx, tenantID, mode, datasetVersion, actor, initial)
	}
	return run, err
}

func (r *ProviderAddressMoveRepository) startRun(ctx context.Context, tenantID shared.ID, mode provideraddr.Mode,
	datasetVersion, actor string, initial provideraddr.Counts) (*provideraddr.Run, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("provider addresses: a tenant is required")
	}
	if mode != provideraddr.ModeApply && mode != provideraddr.ModeRestore {
		return nil, fmt.Errorf("provider addresses: StartRun takes apply or restore, not %q", mode)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin start run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	run := &provideraddr.Run{TenantID: tenantID}
	var cursor sql.NullString
	var counts []byte
	var m string
	err = tx.QueryRowContext(ctx, `SELECT id::text, mode, job_version, dataset_version, counts, cursor_id::text, started_at
		FROM provider_address_moves WHERE tenant_id = $1 AND state = 'running' AND mode IN ('apply', 'restore') FOR UPDATE`,
		tenantID.String()).Scan(&run.ID, &m, &run.JobVersion, &run.DatasetVersion, &counts, &cursor, &run.StartedAt)
	switch {
	case err == nil:
		if provideraddr.Mode(m) == mode && run.JobVersion == provideraddr.JobVersion && run.DatasetVersion == datasetVersion {
			run.Mode, run.Resumed, run.Cursor = mode, true, cursor.String
			if err := json.Unmarshal(counts, &run.Counts); err != nil {
				return nil, fmt.Errorf("read run counts: %w", err)
			}
			return run, tx.Commit()
		}
		if _, err := tx.ExecContext(ctx, `UPDATE provider_address_moves SET state = 'superseded', finished_at = now(), updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), run.ID); err != nil {
			return nil, fmt.Errorf("supersede run: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
	default:
		return nil, fmt.Errorf("read running run: %w", err)
	}
	if initial == nil {
		initial = provideraddr.Counts{}
	}
	b, err := json.Marshal(initial)
	if err != nil {
		return nil, err
	}
	run = &provideraddr.Run{TenantID: tenantID, Mode: mode, JobVersion: provideraddr.JobVersion, DatasetVersion: datasetVersion, Counts: initial}
	if err := tx.QueryRowContext(ctx, `INSERT INTO provider_address_moves (tenant_id, job_version, dataset_version, mode, state, counts, actor)
		VALUES ($1, $2, $3, $4, 'running', $5, $6) RETURNING id::text, started_at`,
		tenantID.String(), provideraddr.JobVersion, datasetVersion, string(mode), b, actor).Scan(&run.ID, &run.StartedAt); err != nil {
		return nil, err
	}
	return run, tx.Commit()
}

// FinishRun closes a run (done or failed). The counts are the ones its
// committed batches stored (whichever runner ran them); finalize, when set,
// adds the closing counts. It returns the final counts.
func (r *ProviderAddressMoveRepository) FinishRun(ctx context.Context, tenantID shared.ID, runID, state string,
	finalize func(provideraddr.Counts), runErr string) (provideraddr.Counts, error) {
	if len(runErr) > 1000 {
		runErr = runErr[:1000]
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin finish run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, counts, err := readRun(ctx, tx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	if finalize != nil {
		finalize(counts)
	}
	b, err := json.Marshal(counts)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provider_address_moves SET state = $3, counts = $4, error = $5, finished_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND state = 'running'`, tenantID.String(), runID, state, b, runErr); err != nil {
		return nil, fmt.Errorf("finish run: %w", err)
	}
	return counts, tx.Commit()
}

// SaveDryRun records a finished dry run with its counts: the only row a dry
// run writes.
func (r *ProviderAddressMoveRepository) SaveDryRun(ctx context.Context, tenantID shared.ID, datasetVersion, actor string,
	counts provideraddr.Counts, startedAt time.Time) (string, error) {
	b, err := json.Marshal(counts)
	if err != nil {
		return "", err
	}
	var id string
	if err := r.db.QueryRowContext(ctx, `INSERT INTO provider_address_moves (tenant_id, job_version, dataset_version, mode, state, counts, actor,
			started_at, finished_at) VALUES ($1, $2, $3, 'dry_run', 'done', $4, $5, $6, now()) RETURNING id::text`,
		tenantID.String(), provideraddr.JobVersion, datasetVersion, b, actor, startedAt).Scan(&id); err != nil {
		return "", fmt.Errorf("save dry run: %w", err)
	}
	return id, nil
}

// LoadScopeEntries reads the organization's address entries that are in
// effect or waiting for approval.
func (r *ProviderAddressMoveRepository) LoadScopeEntries(ctx context.Context, tenantID shared.ID) ([]provideraddr.ScopeEntry, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT target_type, pattern, origin FROM scope_targets
		WHERE tenant_id = $1 AND target_type IN ('ip_address', 'cidr', 'ip_range') AND status IN ('active', 'pending')`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("load scope entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []provideraddr.ScopeEntry
	for rows.Next() {
		var e provideraddr.ScopeEntry
		if err := rows.Scan(&e.Type, &e.Pattern, &e.Origin); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// InventoryCount is the organization's inventory total: assets not deleted,
// not archived, and not in the review queue or rejected.
func (r *ProviderAddressMoveRepository) InventoryCount(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.status <> 'archived'
		AND NOT EXISTS (SELECT 1 FROM asset_attributions iv WHERE iv.tenant_id = $1 AND iv.asset_id = a.id AND iv.state IN ('needs_review', 'candidate', 'rejected'))`,
		tenantID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("inventory count: %w", err)
	}
	return n, nil
}

// beginBatch opens a batch transaction: repeatable read (the finding check
// compares two reads of one snapshot), read-only for a dry run, bounded lock
// waits and statements, and the organization's advisory lock (exclusive for
// a change, shared for a dry run). ErrBusy when another runner holds it.
func (r *ProviderAddressMoveRepository) beginBatch(ctx context.Context, tenantID shared.ID, write bool) (*sql.Tx, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: !write})
	if err != nil {
		return nil, fmt.Errorf("begin batch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL lock_timeout = %d", providerMoveLockTimeout.Milliseconds())); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set lock timeout: %w", err)
	}
	if err := setLocalStatementTimeout(ctx, tx, providerMoveStatementTimeout); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	lock := `SELECT pg_try_advisory_xact_lock_shared($1, $2)`
	if write {
		lock = `SELECT pg_try_advisory_xact_lock($1, $2)`
	}
	var got bool
	if err := tx.QueryRowContext(ctx, lock, providerMoveLockClass, providerMoveLockKey(tenantID)).Scan(&got); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("take organization lock: %w", err)
	}
	if !got {
		_ = tx.Rollback()
		return nil, provideraddr.ErrBusy
	}
	return tx, nil
}

// readRun reads and locks an apply or restore run's cursor and counts.
func readRun(ctx context.Context, tx *sql.Tx, tenantID shared.ID, runID string) (string, provideraddr.Counts, error) {
	var cursor sql.NullString
	var b []byte
	var state string
	err := tx.QueryRowContext(ctx, `SELECT state, cursor_id::text, counts FROM provider_address_moves
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), runID).Scan(&state, &cursor, &b)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, provideraddr.ErrNotRunning
	}
	if err != nil {
		return "", nil, fmt.Errorf("read run: %w", err)
	}
	if state != provideraddr.StateRunning {
		return "", nil, provideraddr.ErrNotRunning
	}
	counts := provideraddr.Counts{}
	if err := json.Unmarshal(b, &counts); err != nil {
		return "", nil, fmt.Errorf("read run counts: %w", err)
	}
	return cursor.String, counts, nil
}

func saveRun(ctx context.Context, tx *sql.Tx, tenantID shared.ID, runID, cursor string, counts provideraddr.Counts) error {
	b, err := json.Marshal(counts)
	if err != nil {
		return err
	}
	var cur any
	if cursor != "" {
		cur = cursor
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provider_address_moves SET cursor_id = $3, counts = $4, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), runID, cur, b); err != nil {
		return fmt.Errorf("save run position: %w", err)
	}
	return nil
}

// transientMove marks lock waits, statement time limits and serialization
// conflicts as retryable.
func transientMove(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "55P03", "40001", "40P01", "57014":
			return fmt.Errorf("%w (sqlstate %s)", provideraddr.ErrTransient, pqErr.Code)
		}
	}
	return err
}

// ProcessBatch plans the next batch of address assets and, for an apply,
// carries the plan out and moves the run's cursor in the same transaction:
// an interrupted run resumes after the last committed batch.
func (r *ProviderAddressMoveRepository) ProcessBatch(ctx context.Context, req provideraddr.BatchRequest) (provideraddr.BatchResult, error) {
	res, err := r.processBatch(ctx, req)
	return res, transientMove(err)
}

func (r *ProviderAddressMoveRepository) processBatch(ctx context.Context, req provideraddr.BatchRequest) (provideraddr.BatchResult, error) {
	var res provideraddr.BatchResult
	if req.TenantID.IsZero() || req.Classifier == nil || req.Entries == nil || req.Sim == nil || req.Limit <= 0 {
		return res, fmt.Errorf("provider addresses: incomplete batch request")
	}
	tx, err := r.beginBatch(ctx, req.TenantID, req.Apply)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()
	tenant := req.TenantID.String()
	after := req.After
	var runCounts provideraddr.Counts
	if req.Apply {
		if after, runCounts, err = readRun(ctx, tx, req.TenantID, req.RunID); err != nil {
			return res, err
		}
	}

	in, scanned, last, done, err := r.loadBatch(ctx, tx, req, after)
	if err != nil {
		return res, err
	}
	res.Scanned, res.Done = scanned, done
	res.Cursor = last
	if res.Cursor == "" {
		res.Cursor = after
	}
	plan := provideraddr.PlanBatch(in, req.Sim, req.Now)
	res.Counts = plan.Counts
	if !req.Apply {
		return res, tx.Commit()
	}

	touched := findingCheckAssets(in)
	before, err := findingStatusDigest(ctx, tx, tenant, touched)
	if err != nil {
		return res, err
	}
	if err := applyPlan(ctx, tx, req.TenantID, req.RunID, plan.Items); err != nil {
		return res, err
	}
	after2, err := findingStatusDigest(ctx, tx, tenant, touched)
	if err != nil {
		return res, err
	}
	if before != after2 {
		return res, provideraddr.ErrFindingStatusChanged
	}
	runCounts.Merge(plan.Counts)
	if err := saveRun(ctx, tx, req.TenantID, req.RunID, res.Cursor, runCounts); err != nil {
		return res, err
	}
	return res, tx.Commit()
}

// findingCheckAssets are the assets whose findings a batch could reach: the
// addresses and every asset their edges reach.
func findingCheckAssets(in provideraddr.BatchInput) []string {
	seen := map[string]bool{}
	for _, a := range in.Addresses {
		seen[a.ID] = true
	}
	for id := range in.Assets {
		seen[id] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// findingStatusDigest summarizes the status of the findings on assets.
func findingStatusDigest(ctx context.Context, tx *sql.Tx, tenant string, assets []string) (string, error) {
	if len(assets) == 0 {
		return "", nil
	}
	var n int64
	var sum string
	err := tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(hashtextextended(id::text || ':' || status, 0)), 0)::text
		FROM findings WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`, tenant, pq.Array(assets)).Scan(&n, &sum)
	if err != nil {
		return "", fmt.Errorf("finding status check: %w", err)
	}
	return fmt.Sprintf("%d/%s", n, sum), nil
}

// loadBatch reads the next address assets after a cursor and, for those
// inside a shared range, everything the move reads.
func (r *ProviderAddressMoveRepository) loadBatch(ctx context.Context, tx *sql.Tx, req provideraddr.BatchRequest, after string) (
	in provideraddr.BatchInput, scanned int, last string, done bool, err error) {
	in = provideraddr.BatchInput{Classes: map[string]edgeaddr.Result{}, Assets: map[string]provideraddr.Asset{},
		NamesByHost: map[string]string{}, Referenced: map[string]bool{}, ActiveRun: map[string]bool{}, Revived: map[string]bool{},
		EntryCovered: map[string]bool{}, History: map[provideraddr.HistoryKey]bool{}, Links: map[provideraddr.LinkKey]bool{},
		Findings: map[string]map[string]int{}}
	tenant := req.TenantID.String()
	var cur any
	if after != "" {
		cur = after
	}
	full := false
	err = eachRow(ctx, tx, `SELECT a.id::text, a.name, a.status, a.manual_status_override, COALESCE(cardinality(a.tags), 0) > 0,
			at.state, at.confidence, at.reason, at.decided_by::text, at.decided_at, at.follows_host_id::text
		FROM assets a
		LEFT JOIN asset_attributions at ON at.tenant_id = a.tenant_id AND at.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.asset_type = 'ip_address' AND a.deleted_at IS NULL AND ($2::uuid IS NULL OR a.id > $2::uuid)
		ORDER BY a.id LIMIT $3`, func(rows *sql.Rows) error {
		if full {
			return nil // the batch holds MaxShared shared addresses: the rest is the next batch's
		}
		a, err := scanBatchAddress(rows)
		if err != nil {
			return err
		}
		scanned++
		last = a.ID
		if cls, isShared := req.Classifier.SharedFrontEnd(a.Name); isShared {
			in.Addresses = append(in.Addresses, a)
			in.Classes[a.ID] = cls
			if req.Entries.Covers(a.Name) {
				in.EntryCovered[a.ID] = true
			}
			full = req.MaxShared > 0 && len(in.Addresses) >= req.MaxShared
		}
		return nil
	}, tenant, cur, req.Limit)
	if err != nil {
		return in, 0, "", false, fmt.Errorf("read address batch: %w", err)
	}
	// A batch cut short at MaxShared is never the organization's last.
	done = !full && scanned < req.Limit
	if len(in.Addresses) == 0 {
		return in, scanned, last, done, nil
	}
	ids := make([]string, len(in.Addresses))
	for i, a := range in.Addresses {
		ids[i] = a.ID
	}
	if err := loadDetails(ctx, tx, tenant, ids, &in); err != nil {
		return in, 0, "", false, err
	}
	return in, scanned, last, done, nil
}

// scanBatchAddress reads one row of the batch select.
func scanBatchAddress(rows *sql.Rows) (provideraddr.Address, error) {
	var a provideraddr.Address
	var state, reason, decidedBy, follows sql.NullString
	var conf sql.NullInt64
	var decidedAt sql.NullTime
	if err := rows.Scan(&a.ID, &a.Name, &a.Status, &a.ManualStatus, &a.Tagged, &state, &conf, &reason, &decidedBy, &decidedAt, &follows); err != nil {
		return a, err
	}
	if !state.Valid {
		return a, nil
	}
	at := &provideraddr.Attribution{State: state.String, Confidence: int(conf.Int64), Reason: reason.String}
	if decidedBy.Valid {
		at.DecidedBy = &decidedBy.String
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		at.DecidedAt = &t
	}
	if follows.Valid {
		at.FollowsHostID = &follows.String
	}
	a.Attribution = at
	return a, nil
}

// eachRow runs q and calls scan on every row; it closes the rows and reports
// their error.
func eachRow(ctx context.Context, tx *sql.Tx, q string, scan func(*sql.Rows) error, args ...any) error {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func normalizeIP(name string) (string, error) {
	return asset.NormalizeSetElement(asset.SetAttrIPAddresses, name)
}

// hostOfService is the host name a service names, "" when it names an
// address or nothing.
func hostOfService(name string) string {
	h := asset.HostOf(name)
	if h == "" || strings.Contains(h, "/") {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	return h
}

// loadDetails reads everything the plan of the batch's shared addresses
// needs: their edges, the assets at the other ends, the names of the
// services' hosts, existing name links, findings counts, the names'
// history, and the keep, active-run and revived flags.
func loadDetails(ctx context.Context, tx *sql.Tx, tenant string, ids []string, in *provideraddr.BatchInput) error {
	idArr := pq.Array(ids)
	edges, err := queryEdges(ctx, tx, `SELECT `+edgeColumns+` FROM asset_relationships
		WHERE tenant_id = $1 AND (source_asset_id = ANY($2::uuid[]) OR target_asset_id = ANY($2::uuid[]))`, tenant, idArr)
	if err != nil {
		return err
	}
	in.Edges = edges
	isAddr := map[string]bool{}
	for _, id := range ids {
		isAddr[id] = true
	}
	others := map[string]bool{}
	for _, e := range edges {
		for _, id := range []string{e.SourceID, e.TargetID} {
			if !isAddr[id] {
				others[id] = true
			}
		}
	}
	if len(others) > 0 {
		if err := loadOtherAssets(ctx, tx, tenant, keys(others), in); err != nil {
			return err
		}
	}
	if err := loadNamesAndLinks(ctx, tx, tenant, in); err != nil {
		return err
	}
	if err := loadNameHistory(ctx, tx, tenant, isAddr, in); err != nil {
		return err
	}
	return loadFlags(ctx, tx, tenant, idArr, in)
}

// loadNamesAndLinks reads the name assets of the services' hosts, the edges
// that already link a name to those services and certificates, and the
// findings on them.
func loadNamesAndLinks(ctx context.Context, tx *sql.Tx, tenant string, in *provideraddr.BatchInput) error {
	hosts := map[string]bool{}
	var linkTargets []string
	for id, a := range in.Assets {
		switch asset.AssetType(a.Type) {
		case asset.AssetTypeCertificate:
			linkTargets = append(linkTargets, id)
		case asset.AssetTypeDomain, asset.AssetTypeSubdomain, asset.AssetTypeIPAddress:
		default:
			linkTargets = append(linkTargets, id)
			if h := hostOfService(a.Name); h != "" {
				hosts[h] = true
			}
		}
	}
	if len(hosts) > 0 {
		if err := eachRow(ctx, tx, `SELECT id::text, name FROM assets WHERE tenant_id = $1 AND asset_type IN ('domain', 'subdomain')
			AND name = ANY($2::text[]) AND deleted_at IS NULL`, func(rows *sql.Rows) error {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				return err
			}
			in.NamesByHost[strings.ToLower(name)] = id
			in.Assets[id] = provideraddr.Asset{ID: id, Name: name, Type: string(asset.AssetTypeSubdomain)}
			return nil
		}, tenant, pq.Array(keys(hosts))); err != nil {
			return fmt.Errorf("read names of services: %w", err)
		}
	}
	if len(linkTargets) == 0 {
		return nil
	}
	sort.Strings(linkTargets)
	if err := eachRow(ctx, tx, `SELECT source_asset_id::text, target_asset_id::text, relationship_type FROM asset_relationships
		WHERE tenant_id = $1 AND target_asset_id = ANY($2::uuid[]) AND relationship_type IN ('exposes', 'serves_certificate')`,
		func(rows *sql.Rows) error {
			var k provideraddr.LinkKey
			if err := rows.Scan(&k.Source, &k.Target, &k.Type); err != nil {
				return err
			}
			in.Links[k] = true
			return nil
		}, tenant, pq.Array(linkTargets)); err != nil {
		return fmt.Errorf("read existing name links: %w", err)
	}
	if err := eachRow(ctx, tx, `SELECT asset_id::text, COALESCE(severity, ''), count(*) FROM findings
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) GROUP BY 1, 2`, func(rows *sql.Rows) error {
		var id, sev string
		var n int
		if err := rows.Scan(&id, &sev, &n); err != nil {
			return err
		}
		if in.Findings[id] == nil {
			in.Findings[id] = map[string]int{}
		}
		in.Findings[id][sev] += n
		return nil
	}, tenant, pq.Array(linkTargets)); err != nil {
		return fmt.Errorf("count findings of services: %w", err)
	}
	return nil
}

// loadNameHistory reads which names already hold these addresses in their
// history (any source).
func loadNameHistory(ctx context.Context, tx *sql.Tx, tenant string, isAddr map[string]bool, in *provideraddr.BatchInput) error {
	var nameIDs, elements []string
	for _, e := range in.Edges {
		if e.Type == "resolves_to" && isAddr[e.TargetID] {
			nameIDs = append(nameIDs, e.SourceID)
		}
	}
	for _, a := range in.Addresses {
		if el, err := normalizeIP(a.Name); err == nil {
			elements = append(elements, el)
		}
	}
	if len(nameIDs) == 0 || len(elements) == 0 {
		return nil
	}
	if err := eachRow(ctx, tx, `SELECT DISTINCT asset_id::text, element FROM asset_attribute_set_elements
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND attribute = 'ip_addresses' AND element = ANY($3::text[])`,
		func(rows *sql.Rows) error {
			var k provideraddr.HistoryKey
			if err := rows.Scan(&k.NameID, &k.Element); err != nil {
				return err
			}
			in.History[k] = true
			return nil
		}, tenant, pq.Array(nameIDs), pq.Array(elements)); err != nil {
		return fmt.Errorf("read name history: %w", err)
	}
	return nil
}

// loadFlags reads the keeping references, the active scan runs and the
// earlier revivals of the batch's addresses.
func loadFlags(ctx context.Context, tx *sql.Tx, tenant string, idArr any, in *provideraddr.BatchInput) error {
	if err := idSet(ctx, tx, providerKeepRefsSQL, in.Referenced, tenant, idArr); err != nil {
		return fmt.Errorf("read references: %w", err)
	}
	if err := idSet(ctx, tx, `SELECT DISTINCT t.asset_id::text FROM scan_run_targets t
			JOIN scan_runs sr ON sr.tenant_id = t.tenant_id AND sr.id = t.run_id
			WHERE t.tenant_id = $1 AND t.asset_id = ANY($2::uuid[]) AND sr.status IN ('pending', 'running')
		UNION SELECT asset_id::text FROM scan_runs WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND status IN ('pending', 'running')`,
		in.ActiveRun, tenant, idArr); err != nil {
		return fmt.Errorf("read active runs: %w", err)
	}
	if err := idSet(ctx, tx, `SELECT DISTINCT asset_id::text FROM provider_address_move_items
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND outcome = 'revived'`, in.Revived, tenant, idArr); err != nil {
		return fmt.Errorf("read revived addresses: %w", err)
	}
	return nil
}

func idSet(ctx context.Context, tx *sql.Tx, q string, into map[string]bool, args ...any) error {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id sql.NullString
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if id.Valid {
			into[id.String] = true
		}
	}
	return rows.Err()
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func loadOtherAssets(ctx context.Context, tx *sql.Tx, tenant string, ids []string, in *provideraddr.BatchInput) error {
	rows, err := tx.QueryContext(ctx, `SELECT id::text, name, asset_type,
			CASE WHEN asset_type = 'certificate' THEN properties ELSE NULL END
		FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenant, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("read linked assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a provideraddr.Asset
		var props []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &props); err != nil {
			return err
		}
		if a.Type == string(asset.AssetTypeCertificate) {
			a.Covers = certificateNames(props)
		}
		in.Assets[a.ID] = a
	}
	return rows.Err()
}

// certificateNames reads the names a certificate is for from its properties
// (subject CN and SANs, at the top level or under "certificate").
func certificateNames(props []byte) []string {
	if len(props) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(props, &m); err != nil {
		return nil
	}
	var out []string
	read := func(src map[string]any) {
		for _, k := range []string{"subject_cn", "common_name", "sans", "san", "dns_names"} {
			switch v := src[k].(type) {
			case string:
				out = append(out, v)
			case []any:
				for _, x := range v {
					if s, ok := x.(string); ok {
						out = append(out, s)
					}
				}
			}
		}
	}
	read(m)
	if c, ok := m["certificate"].(map[string]any); ok {
		read(c)
	}
	return out
}

const edgeColumns = `id::text, source_asset_id::text, target_asset_id::text, relationship_type, description, confidence,
	discovery_method, impact_weight, COALESCE(tags, '{}'), last_verified, created_at, updated_at, is_control_plane`

func queryEdges(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]provideraddr.Edge, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("read edges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []provideraddr.Edge
	for rows.Next() {
		var e provideraddr.Edge
		var desc sql.NullString
		var lv sql.NullTime
		var tags pq.StringArray
		if err := rows.Scan(&e.ID, &e.SourceID, &e.TargetID, &e.Type, &desc, &e.Confidence, &e.DiscoveryMethod,
			&e.ImpactWeight, &tags, &lv, &e.CreatedAt, &e.UpdatedAt, &e.IsControlPlane); err != nil {
			return nil, err
		}
		if desc.Valid {
			e.Description = &desc.String
		}
		if lv.Valid {
			t := lv.Time
			e.LastVerified = &t
		}
		e.Tags = []string(tags)
		out = append(out, e)
	}
	return out, rows.Err()
}

// applyPlan carries a batch's plan out and journals what actually happened.
func applyPlan(ctx context.Context, tx *sql.Tx, tenantID shared.ID, runID string, items []provideraddr.Item) error {
	if len(items) == 0 {
		return nil
	}
	tenant := tenantID.String()
	if err := foldHistory(ctx, tx, tenant, items); err != nil {
		return err
	}
	inserted, err := addNameEdges(ctx, tx, tenant, items)
	if err != nil {
		return err
	}
	var delIDs, archive, attrIDs []string
	for i := range items {
		for _, e := range items[i].Edges {
			delIDs = append(delIDs, e.ID)
		}
		if items[i].NewStatus != "" {
			archive = append(archive, items[i].AssetID)
		}
		if items[i].NewAttribution != nil {
			attrIDs = append(attrIDs, items[i].AssetID)
		}
	}
	// Only the edges actually deleted stay in the journal.
	deleted := map[string]bool{}
	if len(delIDs) > 0 {
		if err := idSet(ctx, tx, `DELETE FROM asset_relationships WHERE tenant_id = $1 AND id = ANY($2::uuid[]) RETURNING id::text`,
			deleted, tenant, pq.Array(delIDs)); err != nil {
			return fmt.Errorf("delete address edges: %w", err)
		}
	}
	archived := map[string]bool{}
	if len(archive) > 0 {
		if err := idSet(ctx, tx, `UPDATE assets SET status = 'archived', updated_at = now()
			WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND status <> 'archived' RETURNING id::text`,
			archived, tenant, pq.Array(archive)); err != nil {
			return fmt.Errorf("archive addresses: %w", err)
		}
	}
	// A person's decision is never overwritten.
	attributed := map[string]bool{}
	if len(attrIDs) > 0 {
		if err := idSet(ctx, tx, `
			INSERT INTO asset_attributions AS at (asset_id, tenant_id, state, confidence, reason)
			SELECT x, $1::uuid, 'dependency', 100, $3 FROM unnest($2::uuid[]) AS x
			 WHERE EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = $1::uuid AND a.id = x)
			ON CONFLICT (asset_id) DO UPDATE SET state = 'dependency', confidence = 100, reason = EXCLUDED.reason, updated_at = now()
			 WHERE at.tenant_id = EXCLUDED.tenant_id AND at.decided_by IS NULL AND at.decided_at IS NULL
			RETURNING asset_id::text`, attributed, tenant, pq.Array(attrIDs), provideraddr.Reason); err != nil {
			return fmt.Errorf("record provider attribution: %w", err)
		}
	}
	return journalItems(ctx, tx, tenant, runID, items, applied{inserted: inserted, deleted: deleted, archived: archived, attributed: attributed})
}

// foldHistory writes the folded history rows. Its own upsert keeps the
// earliest first_seen and the latest last_seen, and the row stays history
// only (removed_at = last_seen): it never moves last_seen backwards and
// touches no other source's row.
func foldHistory(ctx context.Context, tx *sql.Tx, tenant string, items []provideraddr.Item) error {
	var fNames, fElems []string
	var fFirst, fLast []time.Time
	for i := range items {
		for _, k := range items[i].FoldedKeys {
			fNames, fElems = append(fNames, k.NameID), append(fElems, k.Element)
			fFirst, fLast = append(fFirst, k.FirstSeen.UTC()), append(fLast, k.LastSeen.UTC())
		}
	}
	if len(fNames) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_attribute_set_elements AS s
		       (tenant_id, asset_id, attribute, source_kind, source_name, element, first_seen, last_seen, removed_at, updated_at)
		SELECT $1::uuid, w.asset_id, 'ip_addresses', 'scan', 'migrated_resolves_to', w.element, min(w.first_seen), max(w.last_seen), max(w.last_seen), now()
		  FROM unnest($2::uuid[], $3::text[], $4::timestamptz[], $5::timestamptz[]) AS w(asset_id, element, first_seen, last_seen)
		  WHERE EXISTS (SELECT 1 FROM assets n WHERE n.tenant_id = $1::uuid AND n.id = w.asset_id)
		  GROUP BY w.asset_id, w.element
		ON CONFLICT ON CONSTRAINT pk_asset_attribute_set_elements DO UPDATE SET
		       first_seen = LEAST(s.first_seen, EXCLUDED.first_seen),
		       last_seen = GREATEST(s.last_seen, EXCLUDED.last_seen),
		       removed_at = GREATEST(s.last_seen, EXCLUDED.last_seen),
		       updated_at = now()
		 WHERE s.first_seen > EXCLUDED.first_seen OR s.last_seen < EXCLUDED.last_seen
		    OR s.removed_at IS DISTINCT FROM GREATEST(s.last_seen, EXCLUDED.last_seen)`,
		tenant, pq.Array(fNames), pq.Array(fElems), pq.Array(fFirst), pq.Array(fLast)); err != nil {
		return fmt.Errorf("fold address history: %w", err)
	}
	return nil
}

// addNameEdges inserts the edges the relink adds and returns the ids
// actually inserted: only those are journaled as added, so a restore removes
// exactly those.
func addNameEdges(ctx context.Context, tx *sql.Tx, tenant string, items []provideraddr.Item) (map[string]bool, error) {
	var added []provideraddr.Edge
	for i := range items {
		added = append(added, items[i].AddedEdges...)
	}
	inserted := map[string]bool{}
	if len(added) == 0 {
		return inserted, nil
	}
	if err := idSet(ctx, tx, `
		INSERT INTO asset_relationships (id, tenant_id, source_asset_id, target_asset_id, relationship_type, description,
		       confidence, discovery_method, impact_weight, tags, last_verified, created_at, updated_at)
		SELECT e.id, $1::uuid, e.source_asset_id, e.target_asset_id, e.relationship_type, e.description,
		       e.confidence, e.discovery_method, e.impact_weight, COALESCE(e.tags, '{}'), e.last_verified, e.created_at, e.created_at
		  FROM jsonb_to_recordset($2::jsonb) AS e(id uuid, source_asset_id uuid, target_asset_id uuid, relationship_type text,
		       description text, confidence text, discovery_method text, impact_weight int, tags text[], last_verified timestamptz, created_at timestamptz)
		 WHERE EXISTS (SELECT 1 FROM assets s WHERE s.tenant_id = $1::uuid AND s.id = e.source_asset_id)
		   AND EXISTS (SELECT 1 FROM assets t WHERE t.tenant_id = $1::uuid AND t.id = e.target_asset_id)
		ON CONFLICT DO NOTHING
		RETURNING id::text`, inserted, tenant, provideraddr.MarshalJSONArray(added)); err != nil {
		return nil, fmt.Errorf("add name edges: %w", err)
	}
	return inserted, nil
}

// applied is what the writes of a batch actually changed.
type applied struct {
	inserted, deleted, archived, attributed map[string]bool
}

// journalItems writes the status history of the archived addresses and the
// journal items, each with only the changes that actually happened.
func journalItems(ctx context.Context, tx *sql.Tx, tenant, runID string, items []provideraddr.Item, done applied) error {
	var hAssets, hOld []string
	n := len(items)
	jIDs, jAssets, jAddrs, jProviders := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	jBuckets, jActions, jPrior, jOutcomes := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	jEdges, jAdded, jFolded := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	jPriorAttr, jNewAttr := make([]any, 0, n), make([]any, 0, n)
	for i := range items {
		it := items[i]
		var newAttr any
		if it.NewAttribution != nil && done.attributed[it.AssetID] {
			newAttr = jsonText(it.NewAttribution)
		}
		var priorAttr any
		if it.PriorAttribution != nil {
			priorAttr = jsonText(it.PriorAttribution)
		}
		if done.archived[it.AssetID] {
			hAssets, hOld = append(hAssets, it.AssetID), append(hOld, it.PriorStatus)
		}
		jIDs = append(jIDs, shared.NewID().String())
		jAssets, jAddrs, jProviders = append(jAssets, it.AssetID), append(jAddrs, it.Address), append(jProviders, it.Provider)
		jBuckets, jActions, jPrior = append(jBuckets, string(it.Bucket)), append(jActions, string(it.Action)), append(jPrior, it.PriorStatus)
		jPriorAttr, jNewAttr = append(jPriorAttr, priorAttr), append(jNewAttr, newAttr)
		jEdges = append(jEdges, string(provideraddr.MarshalJSONArray(onlyEdges(it.Edges, done.deleted))))
		jAdded = append(jAdded, string(provideraddr.MarshalJSONArray(onlyEdges(it.AddedEdges, done.inserted))))
		jFolded = append(jFolded, string(provideraddr.MarshalJSONArray(it.FoldedKeys)))
		jOutcomes = append(jOutcomes, it.Outcome)
	}
	if len(hAssets) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_state_history (tenant_id, asset_id, change_type, field, old_value, new_value, reason, source, metadata)
			SELECT $1::uuid, x.asset_id, 'status_changed', 'status', x.old, 'archived', 'provider_address', 'system',
			       jsonb_build_object('job', 'provider-addresses', 'move_id', $4::text)
			  FROM unnest($2::uuid[], $3::text[]) AS x(asset_id, old)`, tenant, pq.Array(hAssets), pq.Array(hOld), runID); err != nil {
			return fmt.Errorf("record status history: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO provider_address_move_items (id, tenant_id, move_id, asset_id, address, provider, bucket, action, prior_status,
		       prior_attribution, new_attribution, edges, added_edges, folded_keys, outcome)
		SELECT x.id, $1::uuid, $2::uuid, x.asset_id, x.address::inet, x.provider, x.bucket, x.action, x.prior,
		       x.prior_attr::jsonb, x.new_attr::jsonb, x.edges::jsonb, x.added::jsonb, x.folded::jsonb, x.outcome
		  FROM unnest($3::uuid[], $4::uuid[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[],
		              $12::text[], $13::text[], $14::text[], $15::text[])
		       AS x(id, asset_id, address, provider, bucket, action, prior, prior_attr, new_attr, edges, added, folded, outcome)`,
		tenant, runID, pq.Array(jIDs), pq.Array(jAssets), pq.Array(jAddrs), pq.Array(jProviders), pq.Array(jBuckets),
		pq.Array(jActions), pq.Array(jPrior), pq.GenericArray{A: jPriorAttr}, pq.GenericArray{A: jNewAttr},
		pq.Array(jEdges), pq.Array(jAdded), pq.Array(jFolded), pq.Array(jOutcomes)); err != nil {
		return fmt.Errorf("journal provider addresses: %w", err)
	}
	return nil
}

func onlyEdges(edges []provideraddr.Edge, keep map[string]bool) []provideraddr.Edge {
	var out []provideraddr.Edge
	for _, e := range edges {
		if keep[e.ID] {
			out = append(out, e)
		}
	}
	return out
}

// jsonText encodes an attribution for a jsonb column.
func jsonText(v *provideraddr.Attribution) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

// ListAppliedItems lists the organization's applied journal items after a
// cursor, for the pass that re-checks them against the current dataset.
func (r *ProviderAddressMoveRepository) ListAppliedItems(ctx context.Context, tenantID shared.ID, after string, limit int) ([]provideraddr.AppliedItem, error) {
	var cur any
	if after != "" {
		cur = after
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id::text, asset_id::text, host(address) FROM provider_address_move_items
		WHERE tenant_id = $1 AND outcome = 'applied' AND ($2::uuid IS NULL OR id > $2::uuid) ORDER BY id LIMIT $3`,
		tenantID.String(), cur, limit)
	if err != nil {
		return nil, fmt.Errorf("list applied items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []provideraddr.AppliedItem
	for rows.Next() {
		var it provideraddr.AppliedItem
		if err := rows.Scan(&it.ID, &it.AssetID, &it.Address); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

type journalItem struct {
	id, assetID, action, prior string
	priorAttr, newAttr         *provideraddr.Attribution
	edges, added               []provideraddr.Edge
	folded                     []provideraddr.FoldKey
}

// RestoreBatch restores applied journal items: the address's status and
// attribution as they were, the deleted edges back, the added edges and the
// folded history rows removed. An item whose address changed since (a
// person or a later scan moved its status or attribution) is left as is with
// outcome changed. With outcome reclassified (the range was withdrawn from
// the dataset) a confirmed attribution comes back as discovered: the move
// never confirms an address.
func (r *ProviderAddressMoveRepository) RestoreBatch(ctx context.Context, req provideraddr.RestoreRequest) (provideraddr.RestoreResult, error) {
	res, err := r.restoreBatch(ctx, req)
	return res, transientMove(err)
}

func (r *ProviderAddressMoveRepository) restoreBatch(ctx context.Context, req provideraddr.RestoreRequest) (provideraddr.RestoreResult, error) {
	var res provideraddr.RestoreResult
	if req.TenantID.IsZero() || req.Limit <= 0 ||
		(req.Outcome != provideraddr.OutcomeRestored && req.Outcome != provideraddr.OutcomeReclassified) {
		return res, fmt.Errorf("provider addresses: incomplete restore request")
	}
	tx, err := r.beginBatch(ctx, req.TenantID, true)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()
	tenant := req.TenantID.String()
	var after string
	var runCounts provideraddr.Counts
	if req.RunID != "" && len(req.ItemIDs) == 0 {
		if after, runCounts, err = readRun(ctx, tx, req.TenantID, req.RunID); err != nil {
			return res, err
		}
	}
	var cur any
	if after != "" {
		cur = after
	}
	q := `SELECT id::text, asset_id::text, action, prior_status, prior_attribution, new_attribution, edges, added_edges, folded_keys
		FROM provider_address_move_items WHERE tenant_id = $1 AND outcome = 'applied' AND ($2::uuid IS NULL OR id > $2::uuid)`
	args := []any{tenant, cur}
	if len(req.ItemIDs) > 0 {
		q += ` AND id = ANY($4::uuid[])`
	}
	q += ` ORDER BY id LIMIT $3 FOR UPDATE`
	args = append(args, req.Limit)
	if len(req.ItemIDs) > 0 {
		args = append(args, pq.Array(req.ItemIDs))
	}
	var items []journalItem
	if err := eachRow(ctx, tx, q, func(rows *sql.Rows) error {
		it, err := scanJournalItem(rows)
		if err != nil {
			return err
		}
		items = append(items, it)
		return nil
	}, args...); err != nil {
		return res, fmt.Errorf("read journal items: %w", err)
	}
	res.Done = len(items) < req.Limit
	for _, it := range items {
		res.Cursor = it.id
		ok, err := restoreItem(ctx, tx, tenant, it, req.Outcome)
		if err != nil {
			return res, err
		}
		outcome := req.Outcome
		if !ok {
			outcome = provideraddr.OutcomeChanged
			res.Changed++
		} else {
			res.Restored++
		}
		if _, err := tx.ExecContext(ctx, `UPDATE provider_address_move_items SET outcome = $3, restored_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenant, it.id, outcome); err != nil {
			return res, fmt.Errorf("mark journal item: %w", err)
		}
	}
	if req.RunID != "" && len(req.ItemIDs) == 0 {
		runCounts.Add(provideraddr.CountRestored, res.Restored)
		runCounts.Add(provideraddr.CountChanged, res.Changed)
		if err := saveRun(ctx, tx, req.TenantID, req.RunID, res.Cursor, runCounts); err != nil {
			return res, err
		}
	}
	return res, tx.Commit()
}

// scanJournalItem reads one journal item. A journal column that does not
// decode fails the batch: a restore never runs on half a record.
func scanJournalItem(rows *sql.Rows) (journalItem, error) {
	var it journalItem
	var pa, na, e, a, f []byte
	if err := rows.Scan(&it.id, &it.assetID, &it.action, &it.prior, &pa, &na, &e, &a, &f); err != nil {
		return it, err
	}
	if len(pa) > 0 {
		it.priorAttr = &provideraddr.Attribution{}
		if err := json.Unmarshal(pa, it.priorAttr); err != nil {
			return it, fmt.Errorf("journal item %s prior attribution: %w", it.id, err)
		}
	}
	if len(na) > 0 {
		it.newAttr = &provideraddr.Attribution{}
		if err := json.Unmarshal(na, it.newAttr); err != nil {
			return it, fmt.Errorf("journal item %s new attribution: %w", it.id, err)
		}
	}
	for _, col := range []struct {
		raw []byte
		dst any
	}{{e, &it.edges}, {a, &it.added}, {f, &it.folded}} {
		if err := json.Unmarshal(col.raw, col.dst); err != nil {
			return it, fmt.Errorf("journal item %s: %w", it.id, err)
		}
	}
	return it, nil
}

// restoreItem restores one item; false when the address changed since.
func restoreItem(ctx context.Context, tx *sql.Tx, tenant string, it journalItem, outcome string) (bool, error) {
	var status string
	var state, reason sql.NullString
	var decidedBy sql.NullString
	var decidedAt sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT a.status, at.state, at.reason, at.decided_by::text, at.decided_at
		FROM assets a LEFT JOIN asset_attributions at ON at.tenant_id = a.tenant_id AND at.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL FOR UPDATE OF a`, tenant, it.assetID).Scan(&status, &state, &reason, &decidedBy, &decidedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read address for restore: %w", err)
	}
	archivedByMove := it.action == string(provideraddr.ActionArchive) && it.prior != string(asset.StatusArchived)
	if archivedByMove && status != string(asset.StatusArchived) {
		return false, nil
	}
	if it.newAttr != nil && (!state.Valid || state.String != it.newAttr.State || reason.String != it.newAttr.Reason || decidedBy.Valid || decidedAt.Valid) {
		return false, nil
	}
	if archivedByMove {
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET status = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2 AND status = 'archived'`,
			tenant, it.assetID, it.prior); err != nil {
			return false, fmt.Errorf("restore status: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_state_history (tenant_id, asset_id, change_type, field, old_value, new_value, reason, source, metadata)
			VALUES ($1, $2, 'status_changed', 'status', 'archived', $3, $4, 'system', jsonb_build_object('job', 'provider-addresses', 'item_id', $5::text))`,
			tenant, it.assetID, it.prior, "provider_address_"+outcome, it.id); err != nil {
			return false, fmt.Errorf("record restore history: %w", err)
		}
	}
	if it.newAttr != nil {
		if it.priorAttr == nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM asset_attributions WHERE tenant_id = $1 AND asset_id = $2`, tenant, it.assetID); err != nil {
				return false, fmt.Errorf("restore attribution: %w", err)
			}
		} else {
			st := it.priorAttr.State
			if outcome == provideraddr.OutcomeReclassified && st == string(attribution.StateConfirmed) {
				st = string(attribution.StateDiscovered)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE asset_attributions SET state = $3, confidence = $4, reason = $5, updated_at = now()
				WHERE tenant_id = $1 AND asset_id = $2 AND decided_by IS NULL AND decided_at IS NULL`,
				tenant, it.assetID, st, it.priorAttr.Confidence, it.priorAttr.Reason); err != nil {
				return false, fmt.Errorf("restore attribution: %w", err)
			}
		}
	}
	if len(it.edges) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_relationships (id, tenant_id, source_asset_id, target_asset_id, relationship_type, description, confidence,
			       discovery_method, impact_weight, tags, last_verified, created_at, updated_at, is_control_plane)
			SELECT e.id, $1::uuid, e.source_asset_id, e.target_asset_id, e.relationship_type, e.description, e.confidence,
			       e.discovery_method, e.impact_weight, COALESCE(e.tags, '{}'), e.last_verified, e.created_at, e.updated_at, COALESCE(e.is_control_plane, false)
			  FROM jsonb_to_recordset($2::jsonb) AS e(id uuid, source_asset_id uuid, target_asset_id uuid, relationship_type text, description text,
			       confidence text, discovery_method text, impact_weight int, tags text[], last_verified timestamptz, created_at timestamptz,
			       updated_at timestamptz, is_control_plane boolean)
			 WHERE EXISTS (SELECT 1 FROM assets s WHERE s.tenant_id = $1::uuid AND s.id = e.source_asset_id)
			   AND EXISTS (SELECT 1 FROM assets t WHERE t.tenant_id = $1::uuid AND t.id = e.target_asset_id)
			ON CONFLICT DO NOTHING`, tenant, provideraddr.MarshalJSONArray(it.edges)); err != nil {
			return false, fmt.Errorf("restore edges: %w", err)
		}
	}
	if len(it.added) > 0 {
		ids := make([]string, len(it.added))
		for i, e := range it.added {
			ids[i] = e.ID
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM asset_relationships WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenant, pq.Array(ids)); err != nil {
			return false, fmt.Errorf("remove added edges: %w", err)
		}
	}
	if len(it.folded) > 0 {
		names := make([]string, len(it.folded))
		elems := make([]string, len(it.folded))
		for i, k := range it.folded {
			names[i], elems[i] = k.NameID, k.Element
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM asset_attribute_set_elements s USING unnest($2::uuid[], $3::text[]) AS k(asset_id, element)
			WHERE s.tenant_id = $1 AND s.asset_id = k.asset_id AND s.attribute = 'ip_addresses' AND s.source_kind = 'scan'
			  AND s.source_name = 'migrated_resolves_to' AND s.element = k.element`, tenant, pq.Array(names), pq.Array(elems)); err != nil {
			return false, fmt.Errorf("remove folded history: %w", err)
		}
	}
	return true, nil
}

// ReviveProviderAddress makes an address the move archived active again when
// a scan reports a result on the address itself (it stays a dependency of
// the organization's names). An address archived by a person, or archived
// before the move, has no applied archive item and stays archived. True when
// it was revived.
func (r *ProviderAddressMoveRepository) ReviveProviderAddress(ctx context.Context, tenantID, assetID shared.ID) (bool, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		WITH it AS (
			SELECT id FROM provider_address_move_items
			 WHERE tenant_id = $1 AND asset_id = $2 AND outcome = 'applied' AND action = 'archive' AND prior_status <> 'archived'
		), up AS (
			UPDATE assets SET status = 'active', updated_at = now()
			 WHERE tenant_id = $1 AND id = $2 AND status = 'archived' AND NOT manual_status_override AND EXISTS (SELECT 1 FROM it)
			RETURNING id
		), mark AS (
			UPDATE provider_address_move_items SET outcome = 'revived', revived_at = now()
			 WHERE tenant_id = $1 AND id IN (SELECT id FROM it) AND EXISTS (SELECT 1 FROM up)
			RETURNING 1
		), hist AS (
			INSERT INTO asset_state_history (tenant_id, asset_id, change_type, field, old_value, new_value, reason, source, metadata)
			SELECT $1, id, 'status_changed', 'status', 'archived', 'active', 'provider_address_revived', 'scan',
			       jsonb_build_object('job', 'provider-addresses') FROM up
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM up) + 0 * (SELECT count(*) FROM mark) + 0 * (SELECT count(*) FROM hist)`,
		tenantID.String(), assetID.String()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("revive provider address: %w", err)
	}
	return n > 0, nil
}

// NoticeSent reports whether the organization already had the move notice.
func (r *ProviderAddressMoveRepository) NoticeSent(ctx context.Context, tenantID shared.ID) (bool, error) {
	var sent bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM provider_address_moves WHERE tenant_id = $1 AND notice IS NOT NULL)`,
		tenantID.String()).Scan(&sent)
	if err != nil {
		return false, fmt.Errorf("read notice state: %w", err)
	}
	return sent, nil
}

// NoticeCounts are the notice's numbers: addresses the move changed and
// names that received folded history, and the providers involved.
func (r *ProviderAddressMoveRepository) NoticeCounts(ctx context.Context, tenantID shared.ID) (addresses, names int, providers []string, err error) {
	tenant := tenantID.String()
	if err = r.db.QueryRowContext(ctx, `SELECT count(DISTINCT asset_id) FROM provider_address_move_items
		WHERE tenant_id = $1 AND outcome = 'applied'`, tenant).Scan(&addresses); err != nil {
		return 0, 0, nil, fmt.Errorf("count moved addresses: %w", err)
	}
	if err = r.db.QueryRowContext(ctx, `SELECT count(DISTINCT asset_id) FROM asset_attribute_set_elements
		WHERE tenant_id = $1 AND attribute = 'ip_addresses' AND source_kind = 'scan' AND source_name = 'migrated_resolves_to'`, tenant).Scan(&names); err != nil {
		return 0, 0, nil, fmt.Errorf("count names: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT provider FROM provider_address_move_items
		WHERE tenant_id = $1 AND outcome = 'applied' AND provider <> '' ORDER BY provider`, tenant)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("list providers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p string
		if scanErr := rows.Scan(&p); scanErr != nil {
			return 0, 0, nil, scanErr
		}
		providers = append(providers, p)
	}
	return addresses, names, providers, rows.Err()
}

// SendNotice records the one-time notice on the run and posts it to the
// organization's notification feed, once per organization.
func (r *ProviderAddressMoveRepository) SendNotice(ctx context.Context, tenantID shared.ID, runID string, n provideraddr.Notice) (bool, error) {
	b, err := json.Marshal(n)
	if err != nil {
		return false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin notice: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var got bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1, $2)`, providerMoveLockClass, providerMoveLockKey(tenantID)).Scan(&got); err != nil {
		return false, fmt.Errorf("take organization lock: %w", err)
	}
	if !got {
		return false, provideraddr.ErrBusy
	}
	res, err := tx.ExecContext(ctx, `UPDATE provider_address_moves SET notice = $3, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND NOT EXISTS (SELECT 1 FROM provider_address_moves o WHERE o.tenant_id = $1 AND o.notice IS NOT NULL)`,
		tenantID.String(), runID, b)
	if err != nil {
		return false, fmt.Errorf("record notice: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notifications (tenant_id, audience, notification_type, title, body, severity, url)
		VALUES ($1, 'all', 'system_alert', $2, $3, 'info', '/assets')`, tenantID.String(), n.TitleEn, n.En); err != nil {
		return false, fmt.Errorf("post notice: %w", err)
	}
	return true, tx.Commit()
}

// ListTenants lists every organization id, for a dry run over all of them.
func (r *ProviderAddressMoveRepository) ListTenants(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
