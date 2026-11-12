package postgres

// Passive lookalike-domain monitoring (docs/rfcs/RFC-083-lookalike-domains.md).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMLookalikeRepository stores lookalike watches and candidates.
type EASMLookalikeRepository struct {
	db *DB
}

// NewEASMLookalikeRepository creates the repository.
func NewEASMLookalikeRepository(db *DB) *EASMLookalikeRepository {
	return &EASMLookalikeRepository{db: db}
}

const lookalikeWatchColumns = `w.id, w.tenant_id, w.domain, w.enabled, w.techniques, w.max_candidates, w.generated_at, w.created_at,
	(SELECT count(*) FROM easm_lookalike_candidates c WHERE c.tenant_id = w.tenant_id AND c.watch_id = w.id),
	(SELECT count(*) FROM easm_lookalike_candidates c WHERE c.tenant_id = w.tenant_id AND c.watch_id = w.id AND c.state = 'registered'),
	(SELECT count(*) FROM easm_lookalike_candidates c WHERE c.tenant_id = w.tenant_id AND c.watch_id = w.id AND c.state <> 'unchecked')`

func scanLookalikeWatch(s interface{ Scan(...any) error }) (lookalike.Watch, error) {
	var w lookalike.Watch
	var techs pq.StringArray
	var gen sql.NullTime
	if err := s.Scan(&w.ID, &w.TenantID, &w.Domain, &w.Enabled, &techs, &w.MaxCandidates, &gen, &w.CreatedAt,
		&w.Candidates, &w.Registered, &w.Checked); err != nil {
		return w, err
	}
	w.Techniques = make([]lookalike.Technique, 0, len(techs))
	for _, t := range techs {
		w.Techniques = append(w.Techniques, lookalike.Technique(t))
	}
	w.GeneratedAt = nullTimeValue(gen)
	return w, nil
}

// OwnsRoot reports whether the domain is one of the tenant's own roots: an
// active permanent domain scope entry for it (exact or wildcard) or a
// verified domain.
func (r *EASMLookalikeRepository) OwnsRoot(ctx context.Context, tenantID shared.ID, domain string) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM scope_targets st
		                WHERE st.tenant_id = $1 AND st.status = 'active' AND st.expires_at IS NULL
		                  AND st.target_type IN ('domain', 'subdomain')
		                  AND lower(st.pattern) IN ($2, '*.' || $2))
		    OR EXISTS (SELECT 1 FROM verified_domains v
		                WHERE v.tenant_id = $1 AND v.status = 'verified' AND lower(v.domain) = $2)`,
		tenantID.String(), domain).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("lookalike root ownership: %w", err)
	}
	return ok, nil
}

// ListWatches returns the tenant's watches.
func (r *EASMLookalikeRepository) ListWatches(ctx context.Context, tenantID shared.ID) ([]lookalike.Watch, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+lookalikeWatchColumns+` FROM easm_lookalike_watches w
		WHERE w.tenant_id = $1 ORDER BY w.domain LIMIT $2`, tenantID.String(), lookalike.MaxWatchesPerTenant)
	if err != nil {
		return nil, fmt.Errorf("list lookalike watches: %w", err)
	}
	defer rows.Close()
	out := []lookalike.Watch{}
	for rows.Next() {
		w, err := scanLookalikeWatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// GetWatch returns one watch of the tenant (shared.ErrNotFound otherwise).
func (r *EASMLookalikeRepository) GetWatch(ctx context.Context, tenantID shared.ID, id string) (*lookalike.Watch, error) {
	if _, err := shared.IDFromString(id); err != nil {
		return nil, shared.ErrNotFound
	}
	w, err := scanLookalikeWatch(r.db.QueryRowContext(ctx, `SELECT `+lookalikeWatchColumns+` FROM easm_lookalike_watches w
		WHERE w.tenant_id = $1 AND w.id = $2`, tenantID.String(), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get lookalike watch: %w", err)
	}
	return &w, nil
}

func techStrings(ts []lookalike.Technique) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

// CreateWatch adds a watch unless the tenant has MaxWatchesPerTenant
// (shared.ErrConflict for that or a duplicate).
func (r *EASMLookalikeRepository) CreateWatch(ctx context.Context, tenantID shared.ID, domain string, techs []lookalike.Technique, maxN int, by *shared.ID) (*lookalike.Watch, error) {
	var createdBy any
	if by != nil {
		createdBy = by.String()
	}
	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO easm_lookalike_watches (tenant_id, domain, techniques, max_candidates, created_by)
		SELECT $1, $2, $3, $4, $5
		 WHERE (SELECT count(*) FROM easm_lookalike_watches WHERE tenant_id = $1) < $6
		ON CONFLICT (tenant_id, domain) DO NOTHING
		RETURNING id`, tenantID.String(), domain, pq.Array(techStrings(techs)), maxN, createdBy, lookalike.MaxWatchesPerTenant).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: the domain is watched already or the organization has %d watches", shared.ErrConflict, lookalike.MaxWatchesPerTenant)
	}
	if err != nil {
		return nil, fmt.Errorf("create lookalike watch: %w", err)
	}
	return r.GetWatch(ctx, tenantID, id)
}

// UpdateWatch changes a watch's settings; changed techniques or cap clear
// generated_at so candidates are generated again.
func (r *EASMLookalikeRepository) UpdateWatch(ctx context.Context, tenantID shared.ID, id string, enabled bool, techs []lookalike.Technique, maxN int) (*lookalike.Watch, error) {
	if _, err := shared.IDFromString(id); err != nil {
		return nil, shared.ErrNotFound
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE easm_lookalike_watches
		   SET enabled = $3,
		       generated_at = CASE WHEN techniques IS DISTINCT FROM $4 OR max_candidates <> $5 THEN NULL ELSE generated_at END,
		       techniques = $4, max_candidates = $5, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id, enabled, pq.Array(techStrings(techs)), maxN)
	if err != nil {
		return nil, fmt.Errorf("update lookalike watch: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, shared.ErrNotFound
	}
	return r.GetWatch(ctx, tenantID, id)
}

// DeleteWatch removes a watch and its candidates.
func (r *EASMLookalikeRepository) DeleteWatch(ctx context.Context, tenantID shared.ID, id string) error {
	if _, err := shared.IDFromString(id); err != nil {
		return shared.ErrNotFound
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM easm_lookalike_watches WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id)
	if err != nil {
		return fmt.Errorf("delete lookalike watch: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// ReplaceCandidates keeps the candidates still generated (with what was
// seen), adds new ones and drops the rest, then stamps generated_at.
func (r *EASMLookalikeRepository) ReplaceCandidates(ctx context.Context, tenantID shared.ID, watchID string, cands []lookalike.Candidate, now time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	domains := make([]string, 0, len(cands))
	techs := make([]string, 0, len(cands))
	for _, c := range cands {
		domains = append(domains, c.Domain)
		techs = append(techs, string(c.Technique))
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM easm_lookalike_candidates
		WHERE tenant_id = $1 AND watch_id = $2 AND NOT (domain = ANY($3))`, tenantID.String(), watchID, pq.Array(domains)); err != nil {
		return fmt.Errorf("drop lookalike candidates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO easm_lookalike_candidates (tenant_id, watch_id, domain, technique)
		SELECT $1, $2, d, t FROM unnest($3::text[], $4::text[]) AS u(d, t)
		ON CONFLICT (tenant_id, watch_id, domain) DO UPDATE SET technique = EXCLUDED.technique`,
		tenantID.String(), watchID, pq.Array(domains), pq.Array(techs)); err != nil {
		return fmt.Errorf("add lookalike candidates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE easm_lookalike_watches SET generated_at = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), watchID, now); err != nil {
		return err
	}
	return tx.Commit()
}

// DueCandidates returns up to limit candidates of the watch to check:
// never checked, registered ones checked before registeredBefore, others
// checked before otherBefore; oldest first.
func (r *EASMLookalikeRepository) DueCandidates(ctx context.Context, tenantID shared.ID, watchID string, registeredBefore, otherBefore time.Time, limit int) ([]lookalike.CandidateRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT watch_id, domain, technique, state, has_a, has_mx, name_servers, ct_certs, ct_checked_at, first_registered_at, last_checked_at
		  FROM easm_lookalike_candidates
		 WHERE tenant_id = $1 AND watch_id = $2
		   AND (last_checked_at IS NULL
		        OR (state = 'registered' AND last_checked_at < $3)
		        OR (state <> 'registered' AND last_checked_at < $4))
		 ORDER BY last_checked_at NULLS FIRST
		 LIMIT $5`, tenantID.String(), watchID, registeredBefore, otherBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("due lookalike candidates: %w", err)
	}
	return scanLookalikeCandidates(rows)
}

func scanLookalikeCandidates(rows *sql.Rows) ([]lookalike.CandidateRecord, error) {
	defer rows.Close()
	out := []lookalike.CandidateRecord{}
	for rows.Next() {
		var c lookalike.CandidateRecord
		var ns pq.StringArray
		var ct, first, last sql.NullTime
		if err := rows.Scan(&c.WatchID, &c.Domain, &c.Technique, &c.State, &c.HasA, &c.HasMX, &ns, &c.CTCerts, &ct, &first, &last); err != nil {
			return nil, err
		}
		c.NameServers = []string(ns)
		if c.NameServers == nil {
			c.NameServers = []string{}
		}
		c.CTCheckedAt, c.FirstRegisteredAt, c.LastCheckedAt = nullTimeValue(ct), nullTimeValue(first), nullTimeValue(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveObservation stores what a check saw. ctChecked says whether CT was
// queried in this check (else the stored CT data stays).
func (r *EASMLookalikeRepository) SaveObservation(ctx context.Context, tenantID shared.ID, watchID, domain string, o lookalike.Observation, ctChecked bool, now time.Time) error {
	state := "unregistered"
	if o.Registered {
		state = "registered"
	}
	ns := o.NS
	if ns == nil {
		ns = []string{}
	}
	if len(ns) > 13 {
		ns = ns[:13]
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE easm_lookalike_candidates
		   SET state = $4::varchar, has_a = $5, has_mx = $6, name_servers = $7,
		       ct_certs = CASE WHEN $8::boolean THEN $9::integer ELSE ct_certs END,
		       ct_checked_at = CASE WHEN $8::boolean THEN $10::timestamptz ELSE ct_checked_at END,
		       first_registered_at = CASE WHEN $4::varchar = 'registered' THEN COALESCE(first_registered_at, $10::timestamptz) ELSE NULL END,
		       last_checked_at = $10::timestamptz
		 WHERE tenant_id = $1 AND watch_id = $2 AND domain = $3`,
		tenantID.String(), watchID, domain, state, o.HasA, o.HasMX, pq.Array(ns), ctChecked, o.CTCerts, now)
	if err != nil {
		return fmt.Errorf("save lookalike observation: %w", err)
	}
	return nil
}

// Registered returns the watch's registered candidates, newest first.
func (r *EASMLookalikeRepository) Registered(ctx context.Context, tenantID shared.ID, watchID string, limit int) ([]lookalike.CandidateRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT watch_id, domain, technique, state, has_a, has_mx, name_servers, ct_certs, ct_checked_at, first_registered_at, last_checked_at
		  FROM easm_lookalike_candidates
		 WHERE tenant_id = $1 AND watch_id = $2 AND state = 'registered'
		 ORDER BY first_registered_at DESC NULLS LAST, domain
		 LIMIT $3`, tenantID.String(), watchID, limit)
	if err != nil {
		return nil, fmt.Errorf("registered lookalikes: %w", err)
	}
	return scanLookalikeCandidates(rows)
}

// RootAsset returns the id of the tenant's domain asset for the root, if any.
func (r *EASMLookalikeRepository) RootAsset(ctx context.Context, tenantID shared.ID, domain string) (*shared.ID, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL
		AND asset_type = 'domain' AND lower(name) = $2 ORDER BY created_at LIMIT 1`, tenantID.String(), domain).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookalike root asset: %w", err)
	}
	aid, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("lookalike root asset id: %w", err)
	}
	return &aid, nil
}

// TenantsWithWatches lists tenants that have an enabled watch.
func (r *EASMLookalikeRepository) TenantsWithWatches(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM easm_lookalike_watches WHERE enabled`)
	if err != nil {
		return nil, fmt.Errorf("lookalike tenants: %w", err)
	}
	defer rows.Close()
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
