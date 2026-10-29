package postgres

// Asset coverage ledger (docs/rfcs/RFC-093-asset-coverage.md).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetCoverageRepository reads and writes the coverage ledger. Every query
// is scoped to one tenant.
type AssetCoverageRepository struct {
	db *DB
}

// NewAssetCoverageRepository creates the repository.
func NewAssetCoverageRepository(db *DB) *AssetCoverageRepository {
	return &AssetCoverageRepository{db: db}
}

const coverageRowColumns = `capability, vantage, state, reason, priority, next_due_at, queued_at,
	last_attempt_at, last_success_at, last_outcome, last_error, last_tool, last_run_id,
	fail_streak, change_token, created_at, updated_at`

func scanCoverageRow(sc interface{ Scan(...any) error }, tenantID, assetID shared.ID) (coverage.Row, error) {
	var (
		row                                    coverage.Row
		state                                  string
		nextDue, queued, lastAttempt, lastSucc sql.NullTime
		runID                                  sql.NullString
	)
	err := sc.Scan(&row.Capability, &row.Vantage, &state, &row.Reason, &row.Priority, &nextDue, &queued,
		&lastAttempt, &lastSucc, &row.LastOutcome, &row.LastError, &row.LastTool, &runID,
		&row.FailStreak, &row.ChangeToken, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return row, err
	}
	row.TenantID, row.AssetID, row.State = tenantID, assetID, coverage.State(state)
	row.NextDueAt, row.QueuedAt = coverageTime(nextDue), coverageTime(queued)
	row.LastAttemptAt, row.LastSuccessAt = coverageTime(lastAttempt), coverageTime(lastSucc)
	if runID.Valid {
		if id, err := shared.IDFromString(runID.String); err == nil {
			row.LastRunID = &id
		}
	}
	return row, nil
}

func coverageTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// withExtra scans the row columns and then extra destinations.
type withExtra struct {
	sc    interface{ Scan(...any) error }
	extra []any
}

func (w withExtra) Scan(dest ...any) error { return w.sc.Scan(append(dest, w.extra...)...) }

// ListForAsset returns every ledger row of an asset of the tenant.
func (r *AssetCoverageRepository) ListForAsset(ctx context.Context, tenantID, assetID shared.ID) ([]coverage.Row, error) {
	// The observer of a target-side outcome is named only when it is the
	// tenant's own scan zone or sensor; a platform sensor stays unnamed.
	rows, err := r.db.QueryContext(ctx, `SELECT `+coverageRowColumns+`,
		       COALESCE(CASE
		         WHEN unreached_from LIKE 'zone:%' THEN (SELECT z.name FROM scan_zones z
		              WHERE z.tenant_id = $1 AND z.id::text = substr(unreached_from, 6))
		         WHEN unreached_from LIKE 'sensor:%' THEN (SELECT s.name FROM sensors s
		              WHERE s.tenant_id = $1 AND s.scope = 'organization' AND s.id::text = substr(unreached_from, 8))
		       END, '')
		FROM asset_coverage WHERE tenant_id = $1 AND asset_id = $2
		ORDER BY capability, vantage`, tenantID.String(), assetID.String())
	if err != nil {
		return nil, fmt.Errorf("list asset coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.Row
	for rows.Next() {
		var name string
		row, err := scanCoverageRow(withExtra{rows, []any{&name}}, tenantID, assetID)
		if err != nil {
			return nil, fmt.Errorf("scan asset coverage: %w", err)
		}
		row.UnreachedFromName = name
		out = append(out, row)
	}
	return out, rows.Err()
}

// TenantsWithAssets returns the tenants that have active assets.
func (r *AssetCoverageRepository) TenantsWithAssets(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = t.id AND a.deleted_at IS NULL AND a.status = 'active')
		ORDER BY t.id`)
	if err != nil {
		return nil, fmt.Errorf("list coverage tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// coveragePredicateSQL is the SQL condition of one rule predicate on the
// asset row "a". Only the closed set of predicates exists; an unknown one is
// false (the rule never applies) so a typo can never widen coverage.
func coveragePredicateSQL(p string) string {
	switch p {
	case coverage.RequiresResolves:
		// A resolves_to relation (a port scan of the name), an A/AAAA record
		// a DNS resolution stored, or addresses a probe saw; and the name is
		// not parked: its latest DNS resolution answered that it has no
		// address (those facts are then stale). A parked name gets no active
		// capability; the first resolution that answers un-parks it, and its
		// pairs become due and go through the full gate again.
		return `((EXISTS (SELECT 1 FROM asset_relationships rr
			WHERE rr.tenant_id = a.tenant_id AND rr.source_asset_id = a.id AND rr.relationship_type = 'resolves_to')
			OR jsonb_path_exists(COALESCE(a.properties, '{}'::jsonb), '$.dns_records[*] ? (@.type == "A" || @.type == "AAAA")')
			OR COALESCE(jsonb_typeof(a.properties->'ip_addresses') = 'array'
			            AND jsonb_array_length(a.properties->'ip_addresses') > 0, false))
			AND NOT EXISTS (SELECT 1 FROM asset_coverage pk
			WHERE pk.tenant_id = a.tenant_id AND pk.asset_id = a.id AND pk.capability = '` + coverage.CapabilityResolveDNS + `'
			  AND pk.vantage = '' AND pk.last_outcome = '` + coverage.OutcomeNoAnswer + `'))`
	case coverage.RequiresWebPort:
		return `COALESCE(a.properties->>'port', '') IN (` + webPortsSQL() + `)`
	case coverage.RequiresWebPortOrUnscanned:
		// The name's addresses: resolves_to edges (a port scan of the
		// address links its open ports with exposes edges).
		addrs := `SELECT rr.target_asset_id FROM asset_relationships rr
			WHERE rr.tenant_id = a.tenant_id AND rr.source_asset_id = a.id AND rr.relationship_type = 'resolves_to'`
		return `(EXISTS (SELECT 1 FROM asset_relationships rp
			JOIN assets p ON p.tenant_id = rp.tenant_id AND p.id = rp.target_asset_id
			WHERE rp.tenant_id = a.tenant_id AND rp.relationship_type = 'exposes' AND rp.source_asset_id IN (` + addrs + `)
			  AND p.deleted_at IS NULL AND p.status = 'active'
			  AND COALESCE(p.properties->>'port', '') IN (` + webPortsSQL() + `))
		OR EXISTS (SELECT 1 FROM assets o
			WHERE o.tenant_id = a.tenant_id AND o.name IN ('https://' || a.name, 'http://' || a.name)
			  AND o.asset_type = 'service' AND o.sub_type = 'http' AND o.deleted_at IS NULL)
		OR NOT (EXISTS (SELECT 1 FROM asset_coverage pc
			WHERE pc.tenant_id = a.tenant_id AND pc.capability = 'scan.ports' AND pc.vantage = ''
			  AND pc.last_success_at IS NOT NULL AND (pc.asset_id = a.id OR pc.asset_id IN (` + addrs + `)))
		    OR EXISTS (SELECT 1 FROM asset_relationships rp
			WHERE rp.tenant_id = a.tenant_id AND rp.relationship_type = 'exposes' AND rp.source_asset_id IN (` + addrs + `))))`
	case coverage.RequiresNoNamedTwin:
		// The URL host of an IPv4 web service, and a named web service
		// whose probe saw that address, on the same port.
		return `NOT (a.name ~ '^https?://[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?(/|$)'
			AND EXISTS (SELECT 1 FROM assets n
				WHERE n.tenant_id = a.tenant_id AND n.id <> a.id
				  AND n.asset_type = 'service' AND n.sub_type = 'http'
				  AND n.deleted_at IS NULL AND n.status = 'active'
				  AND n.name ~ '^https?://[^/:]*[a-zA-Z]'
				  AND COALESCE(n.properties->>'port', '') = COALESCE(a.properties->>'port', '')
				  AND jsonb_typeof(n.properties->'ip_addresses') = 'array'
				  AND n.properties->'ip_addresses' ? substring(a.name from '^https?://([0-9.]+)')))`
	case coverage.RequiresScopeEntry:
		return `EXISTS (SELECT 1 FROM scope_targets st
			WHERE st.tenant_id = a.tenant_id AND st.status = 'active'
			  AND (st.expires_at IS NULL OR st.expires_at > now())
			  AND st.target_type IN ('domain', 'subdomain')
			  AND ` + dnsScopeMatch("st.pattern") + `)`
	}
	return "false"
}

// webPortsSQL is coverage.WebPorts as a list of quoted literals.
func webPortsSQL() string {
	ports := make([]string, len(coverage.WebPorts))
	for i, n := range coverage.WebPorts {
		ports[i] = "'" + strconv.Itoa(n) + "'"
	}
	return strings.Join(ports, ", ")
}

// rulePredicates are the reasons reconcile itself sets. Only those flip
// back to due when the precondition holds again: a pair a capability found
// not applicable (a DNS check on a name that is not registrable) stays so.
var rulePredicates = []string{coverage.RequiresResolves, coverage.RequiresWebPort, coverage.RequiresWebPortOrUnscanned, coverage.RequiresScopeEntry, coverage.RequiresNoNamedTwin}

// coverageRuleSQL returns the applicability and reason expressions of a rule.
func coverageRuleSQL(rule coverage.Rule) (ok, reason string) {
	if len(rule.Requires) == 0 {
		return "true", "''"
	}
	conds := make([]string, 0, len(rule.Requires))
	var reasonCase strings.Builder
	reasonCase.WriteString("CASE")
	for _, p := range rule.Requires {
		// COALESCE: a predicate that is unknown (NULL) is false, so a rule
		// never applies by accident and the reason is always set.
		c := "COALESCE((" + coveragePredicateSQL(p) + "), false)"
		conds = append(conds, c)
		// p is from the closed predicate set (validated by the registry
		// generator); quote it anyway.
		reasonCase.WriteString(" WHEN NOT " + c + " THEN " + pq.QuoteLiteral(p))
	}
	reasonCase.WriteString(" ELSE '' END")
	return strings.Join(conds, " AND "), reasonCase.String()
}

// reconcileBatch is how many assets one reconcile statement reads. Short
// statements hold the referenced assets' key-share locks (the ledger's
// foreign key) only briefly.
const reconcileBatch = 500

// uuidBeforeAll sorts before every asset id (keyset start).
const uuidBeforeAll = "00000000-0000-0000-0000-000000000000"

// Reconcile adds the missing rows of every applicable rule for the tenant's
// active assets and flips rows whose precondition changed.
//
// Locking: inserting a ledger row takes a KEY SHARE lock on its asset (the
// foreign key). A writer that locks assets FOR UPDATE in id order (the asset
// business-context update) deadlocked with a reconcile that took those
// locks in another order. Each statement therefore reads one batch of
// assets in id order (keyset, no long transaction), inserts in id order,
// and a deadlock that still happens is retried once after a short jitter.
func (r *AssetCoverageRepository) Reconcile(ctx context.Context, tenantID shared.ID, rules []coverage.Rule) (added, changed int, err error) {
	for _, rule := range rules {
		if !coverage.ValidCapability(rule.Capability) {
			continue
		}
		after := uuidBeforeAll
		for {
			a, c, last, n, err := r.reconcileBatch(ctx, tenantID, rule, after)
			if err != nil {
				return added, changed, fmt.Errorf("reconcile coverage %s/%s %s: %w", rule.Type, rule.SubType, rule.Capability, err)
			}
			added += a
			changed += c
			if n < reconcileBatch || last == "" {
				break
			}
			after = last
		}
	}
	return added, changed, nil
}

// reconcileBatch reconciles one rule over the next batch of assets after
// the id after, retrying once on a deadlock. It returns the rows added and
// changed, the last asset id read and how many assets it read.
func (r *AssetCoverageRepository) reconcileBatch(ctx context.Context, tenantID shared.ID, rule coverage.Rule, after string) (added, changed int, last string, n int, err error) {
	ok, reason := coverageRuleSQL(rule)
	excluded := coverage.AliasSubTypes(rule.Type)
	if rule.SubType != "" {
		excluded = nil
	}
	// ok and reason are built from the closed predicate set and quoted
	// literals only; every value is a parameter.
	q := `
		WITH cand AS (
			SELECT a.id, (` + ok + `) AS ok, (` + reason + `) AS why
			FROM assets a
			WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.status = 'active'
			  AND a.asset_type = $2
			  AND ($3 = '' OR a.sub_type = $3)
			  AND NOT (COALESCE(a.sub_type, '') = ANY(COALESCE($5::text[], '{}')))
			  AND a.id > $7::uuid
			ORDER BY a.id
			LIMIT $8
		), ins AS (
			INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, reason, next_due_at)
			SELECT $1, c.id, $4::text, '', CASE WHEN c.ok THEN 'due' ELSE 'not_applicable' END, c.why, now()
			FROM cand c
			WHERE NOT EXISTS (SELECT 1 FROM asset_coverage x
			                  WHERE x.tenant_id = $1 AND x.asset_id = c.id AND x.capability = $4::text AND x.vantage = '')
			ORDER BY c.id
			ON CONFLICT (tenant_id, asset_id, capability, vantage) DO NOTHING
			RETURNING 1
		), upd AS (
			UPDATE asset_coverage s
			SET state = CASE WHEN c.ok THEN 'due' ELSE 'not_applicable' END,
			    reason = c.why,
			    next_due_at = CASE WHEN c.ok THEN now() ELSE s.next_due_at END,
			    updated_at = now()
			FROM cand c
			WHERE s.tenant_id = $1 AND s.asset_id = c.id AND s.capability = $4::text AND s.vantage = ''
			  AND ((c.ok AND s.state = 'not_applicable' AND s.reason = ANY($6::text[])) OR
			       (NOT c.ok AND s.state IN ('due', 'failed', 'covered', 'blocked', 'paused')))
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM ins), (SELECT count(*) FROM upd),
		       COALESCE((SELECT max(id::text) FROM cand), ''), (SELECT count(*) FROM cand)`
	err = retryOnDeadlock(ctx, func() error {
		return r.db.QueryRowContext(ctx, q, //nolint:gosec // built from a closed set; values are parameters
			tenantID.String(), string(rule.Type), rule.SubType, rule.Capability, pq.Array(excluded),
			pq.Array(rulePredicates), after, reconcileBatch,
		).Scan(&added, &changed, &last, &n)
	})
	return added, changed, last, n, err
}

// deadlockDetected is PostgreSQL's SQLSTATE for a deadlock.
const deadlockDetected = "40P01"

// retryOnDeadlock runs fn and, when it fails with a deadlock, once more
// after 50-250 ms of jitter (the other transaction has been rolled back or
// committed by then).
func retryOnDeadlock(ctx context.Context, fn func() error) error {
	err := fn()
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || string(pqErr.Code) != deadlockDetected {
		return err
	}
	var b [2]byte
	_, _ = rand.Read(b[:]) // jitter only; a zero on error is fine
	wait := 50*time.Millisecond + time.Duration(binary.LittleEndian.Uint16(b[:])%200)*time.Millisecond
	select {
	case <-ctx.Done():
		return err
	case <-time.After(wait):
	}
	return fn()
}

var _ coverage.Repository = (*AssetCoverageRepository)(nil)
