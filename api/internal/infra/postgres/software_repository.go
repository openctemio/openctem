package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// SoftwareRepository is the software catalog and the per-tenant software
// links (RFC-066). Catalog reads see global rows and the caller tenant's
// private rows only; private rows are written only for the caller tenant.
type SoftwareRepository struct {
	db *DB
}

// NewSoftwareRepository creates a SoftwareRepository.
func NewSoftwareRepository(db *DB) *SoftwareRepository {
	return &SoftwareRepository{db: db}
}

var _ software.Repository = (*SoftwareRepository)(nil)

// EnsureCurated writes the curated products and their aliases to the global
// catalog. A product the feed created earlier with the same CPE becomes the
// curated one. An alias that already names another product is left alone.
func (r *SoftwareRepository) EnsureCurated(ctx context.Context, products []software.Curated) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// The curated list folds products too (alternate CPEs below).
	if err := aliasLocks(ctx, tx); err != nil {
		return err
	}
	for _, p := range products {
		var id string
		err := tx.QueryRowContext(ctx, `
			INSERT INTO software_products (part, vendor, name, cpe_vendor, cpe_product, source)
			VALUES ($1, $2, $3, $4, $5, 'curated')
			ON CONFLICT (part, cpe_vendor, cpe_product) WHERE tenant_id IS NULL AND cpe_vendor IS NOT NULL
			DO UPDATE SET vendor = EXCLUDED.vendor, name = EXCLUDED.name, source = 'curated', updated_at = now()
			RETURNING id`, p.Part, p.Vendor, p.Name, p.CPEVendor, p.CPEProduct).Scan(&id)
		if err != nil {
			return fmt.Errorf("curated product %s:%s: %w", p.CPEVendor, p.CPEProduct, err)
		}
		aliases := make([][2]string, 0, len(p.Names)+len(p.AltCPE)+1)
		for _, n := range p.Names {
			aliases = append(aliases, [2]string{"name", n})
		}
		aliases = append(aliases, [2]string{"cpe", p.Part + ":" + p.CPEVendor + ":" + p.CPEProduct})
		for _, c := range p.AltCPE {
			aliases = append(aliases, [2]string{"cpe", p.Part + ":" + c})
		}
		for _, a := range aliases {
			// A curated alias wins over a feed alias of the same value.
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO software_product_aliases (product_id, tenant_id, kind, value, source)
				VALUES ($1, NULL, $2, $3, 'curated')
				ON CONFLICT (kind, value) WHERE tenant_id IS NULL
				DO UPDATE SET product_id = EXCLUDED.product_id, source = 'curated'
				WHERE software_product_aliases.source = 'feed'`, id, a[0], a[1]); err != nil {
				return fmt.Errorf("curated alias %s: %w", a[1], err)
			}
		}
		// A product the feed created under an alternate CPE folds into
		// the curated one.
		for _, alt := range p.AltCPE {
			k, ok := software.SplitCPEAlias(p.Part + ":" + alt)
			if !ok {
				continue
			}
			var from string
			err := tx.QueryRowContext(ctx, `SELECT id FROM software_products
				WHERE tenant_id IS NULL AND source = 'nvd' AND part = $1 AND cpe_vendor = $2 AND cpe_product = $3 AND id <> $4`,
				k.Part, k.Vendor, k.Product, id).Scan(&from)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("curated alternate %s: %w", k, err)
			}
			cves, err := mergeGlobalProduct(ctx, tx, from, id, mergeReason{kind: "cpe", value: k.String(), basis: "platform-curated"})
			if err != nil {
				return err
			}
			if err := requeueCVEs(ctx, tx, setOf(cves)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// Resolve maps identities to catalog products (see software.Repository).
func (r *SoftwareRepository) Resolve(ctx context.Context, tenantID shared.ID, ids []software.Identity) (map[software.Identity]software.ProductRef, error) {
	out := make(map[software.Identity]software.ProductRef, len(ids))
	for _, id := range ids {
		if _, done := out[id]; done {
			continue
		}
		ref, err := r.resolveOne(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		out[id] = ref
	}
	return out, nil
}

func (r *SoftwareRepository) resolveOne(ctx context.Context, tenantID shared.ID, id software.Identity) (software.ProductRef, error) {
	kind, value := "name", id.Name
	if id.HasCPE() {
		kind, value = "cpe", id.CPEAlias()
	}
	if value == "" {
		return software.ProductRef{}, errors.New("software identity without a name or CPE")
	}
	// Global alias, then (for a CPE) a global product with that CPE, then
	// the tenant's private alias or product. Global first, so a tenant can
	// never shadow a public product with a private one.
	var pid string
	var ptenant sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT a.product_id, p.tenant_id::text
		FROM software_product_aliases a
		JOIN software_products p ON p.id = a.product_id
		WHERE a.kind = $1 AND a.value = $2 AND (a.tenant_id IS NULL OR a.tenant_id = $3)
		ORDER BY a.tenant_id NULLS FIRST
		LIMIT 1`, kind, value, tenantID.String()).Scan(&pid, &ptenant)
	if err == nil {
		return refOf(pid, ptenant)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return software.ProductRef{}, fmt.Errorf("resolve alias: %w", err)
	}
	if id.HasCPE() {
		err = r.db.QueryRowContext(ctx, `
			SELECT id, tenant_id::text FROM software_products
			WHERE part = $1 AND cpe_vendor = $2 AND cpe_product = $3 AND (tenant_id IS NULL OR tenant_id = $4)
			ORDER BY tenant_id NULLS FIRST
			LIMIT 1`, id.Part, id.CPEVendor, id.CPEProduct, tenantID.String()).Scan(&pid, &ptenant)
		if err == nil {
			return refOf(pid, ptenant)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return software.ProductRef{}, fmt.Errorf("resolve cpe: %w", err)
		}
	}
	return r.createPrivate(ctx, tenantID, id, kind, value)
}

// createPrivate creates a tenant-private product for an identity nothing
// public resolves, with its alias, tolerating a concurrent create.
func (r *SoftwareRepository) createPrivate(ctx context.Context, tenantID shared.ID, id software.Identity, kind, value string) (software.ProductRef, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return software.ProductRef{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Serialize creates of the same private identity in this tenant.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 66))`,
		"software:"+tenantID.String()+":"+kind+":"+value); err != nil {
		return software.ProductRef{}, fmt.Errorf("lock: %w", err)
	}
	var pid string
	err = tx.QueryRowContext(ctx, `SELECT product_id FROM software_product_aliases
		WHERE tenant_id = $1 AND kind = $2 AND value = $3`, tenantID.String(), kind, value).Scan(&pid)
	switch {
	case err == nil:
		return software.ProductRef{ID: shared.MustIDFromString(pid)}, tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return software.ProductRef{}, fmt.Errorf("private alias: %w", err)
	}
	name, vendor := id.Name, ""
	var cpeVendor, cpeProduct sql.NullString
	if id.HasCPE() {
		name, vendor = id.CPEProduct, id.CPEVendor
		cpeVendor = sql.NullString{String: id.CPEVendor, Valid: true}
		cpeProduct = sql.NullString{String: id.CPEProduct, Valid: true}
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO software_products (tenant_id, part, vendor, name, cpe_vendor, cpe_product, source)
		VALUES ($1, $2, $3, $4, $5, $6, 'observed')
		ON CONFLICT DO NOTHING
		RETURNING id`, tenantID.String(), id.Part, clipStr(vendor, 128), clipStr(name, 200), cpeVendor, cpeProduct).Scan(&pid)
	if errors.Is(err, sql.ErrNoRows) {
		// The product exists without the alias (same name or CPE).
		err = tx.QueryRowContext(ctx, `
			SELECT id FROM software_products
			WHERE tenant_id = $1 AND ((cpe_vendor IS NULL AND lower(name) = lower($2))
			   OR (part = $3 AND cpe_vendor = $4 AND cpe_product = $5))
			LIMIT 1`, tenantID.String(), clipStr(name, 200), id.Part, cpeVendor, cpeProduct).Scan(&pid)
	}
	if err != nil {
		return software.ProductRef{}, fmt.Errorf("create private product: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO software_product_aliases (product_id, tenant_id, kind, value, source)
		VALUES ($1, $2, $3, $4, 'observed')
		ON CONFLICT (tenant_id, kind, value) WHERE tenant_id IS NOT NULL DO NOTHING`,
		pid, tenantID.String(), kind, value); err != nil {
		return software.ProductRef{}, fmt.Errorf("private alias: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return software.ProductRef{}, fmt.Errorf("commit: %w", err)
	}
	return software.ProductRef{ID: shared.MustIDFromString(pid)}, nil
}

func refOf(pid string, tenant sql.NullString) (software.ProductRef, error) {
	id, err := shared.IDFromString(pid)
	if err != nil {
		return software.ProductRef{}, fmt.Errorf("product id: %w", err)
	}
	return software.ProductRef{ID: id, Global: !tenant.Valid}, nil
}

// EnsureVersion returns the catalog version (see software.Repository). A
// version of a global product is global; of a private product, private to
// the caller (the scope trigger refuses anything else).
func (r *SoftwareRepository) EnsureVersion(ctx context.Context, tenantID shared.ID, product software.ProductRef, v software.VersionKey) (shared.ID, error) {
	var tenant any
	if !product.Global {
		tenant = tenantID.String()
	}
	var normalized any
	if v.Normalized != "" {
		normalized = v.Normalized
	}
	scheme := string(v.Scheme)
	if scheme == "" {
		scheme = "generic"
	}
	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO software_versions (product_id, tenant_id, raw, normalized, scheme, qualifier, edition)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (product_id, scheme, COALESCE(normalized, 'raw:' || raw), qualifier, edition) DO NOTHING
		RETURNING id`, product.ID.String(), tenant, v.Raw, normalized, scheme, v.Qualifier, v.Edition).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = r.db.QueryRowContext(ctx, `
			SELECT id FROM software_versions
			WHERE product_id = $1 AND scheme = $2 AND COALESCE(normalized, 'raw:' || raw) = COALESCE($3, 'raw:' || $4::text)
			  AND qualifier = $5 AND edition = $6 AND (tenant_id IS NULL OR tenant_id = $7)`,
			product.ID.String(), scheme, normalized, v.Raw, v.Qualifier, v.Edition, tenantID.String()).Scan(&id)
	}
	if err != nil {
		return shared.ID{}, fmt.Errorf("software version: %w", err)
	}
	return shared.IDFromString(id)
}

// UpsertLinks writes the links of one ingest (see software.Repository).
// Each (asset, product, location) history is locked, read, advanced by
// software.ApplySightings and written back in one transaction, so two
// reports for the same place never interleave.
func (r *SoftwareRepository) UpsertLinks(ctx context.Context, tenantID shared.ID, links []software.Link) (software.LinkResult, error) {
	var res software.LinkResult
	if len(links) == 0 {
		return res, nil
	}
	type group struct {
		asset, product shared.ID
		location       string
	}
	var order []group
	byGroup := map[group][]software.Link{}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, l := range links {
		l.Location = clipStr(l.Location, software.MaxLocationLen)
		at := l.ObservedAt.UTC().Truncate(time.Microsecond)
		if at.IsZero() || at.After(now) {
			at = now
		}
		l.ObservedAt = at
		if !l.Class.Valid() {
			l.Class = software.ClassOf(software.Observation{Source: l.Source}, software.Parsed{Segments: 3})
		}
		g := group{asset: l.AssetID, product: l.ProductID, location: l.Location}
		if _, ok := byGroup[g]; !ok {
			order = append(order, g)
		}
		byGroup[g] = append(byGroup[g], l)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fillVersionKeys(ctx, tx, tenantID, byGroup); err != nil {
		return res, err
	}
	changed := map[shared.ID]bool{}
	for _, g := range order {
		gl := byGroup[g]
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('openctem.asset_software:' || $1::text), hashtext($2::text || '/' || $3::text))`,
			tenantID.String(), g.asset.String()+"/"+g.product.String(), g.location); err != nil {
			return res, fmt.Errorf("asset software lock: %w", err)
		}
		rows, err := loadHistory(ctx, tx, tenantID, g.asset, g.product, g.location)
		if err != nil {
			return res, err
		}
		batch := make([]software.Sighting, 0, len(gl))
		best := map[shared.ID]software.Link{}
		for _, l := range gl {
			batch = append(batch, software.Sighting{
				VersionID: l.VersionID, Raw: l.Version.Raw, Normalized: l.Version.Normalized, Qualifier: l.Version.Qualifier,
				Segments: l.Segments, At: l.ObservedAt, Class: l.Class, Confidence: l.Confidence,
			})
			if b, ok := best[l.VersionID]; !ok || l.Class.Rank() > b.Class.Rank() ||
				(l.Class == b.Class && l.Confidence > b.Confidence) {
				best[l.VersionID] = l
			}
		}
		out := software.ApplySightings(rows, batch)
		for _, row := range out.Rows {
			if !row.Dirty {
				continue
			}
			wasSuperseded := false
			for _, old := range rows {
				if old.VersionID == row.VersionID {
					wasSuperseded = old.Superseded
				}
			}
			if row.Superseded && !wasSuperseded {
				res.Superseded++
			}
			if row.New {
				res.Inserted++
			}
			if err := writeHistoryRow(ctx, tx, tenantID, g.asset, g.product, g.location, row, best[row.VersionID]); err != nil {
				return res, err
			}
		}
		if out.EstablishedChanged {
			changed[g.asset] = true
		}
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	for id := range changed {
		res.ChangedAssets = append(res.ChangedAssets, id)
	}
	return res, nil
}

// fillVersionKeys reads the catalog version of the links that came without
// one, so the history compares versions the same way for every caller.
func fillVersionKeys[K comparable](ctx context.Context, tx *sql.Tx, tenantID shared.ID, byGroup map[K][]software.Link) error {
	for _, gl := range byGroup {
		for i := range gl {
			l := &gl[i]
			if l.Version.Raw != "" || l.Version.Normalized != "" {
				continue
			}
			var norm sql.NullString
			err := tx.QueryRowContext(ctx, `SELECT raw, normalized, qualifier FROM software_versions
				WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2)`, l.VersionID.String(), tenantID.String()).
				Scan(&l.Version.Raw, &norm, &l.Version.Qualifier)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("software version: %w", err)
			}
			l.Version.Normalized = norm.String
			if l.Segments == 0 {
				if v, ok := vulnmatch.ParseVersion(l.Version.Raw); ok {
					l.Segments = v.Segments()
				}
			}
		}
	}
	return nil
}

// loadHistory reads the network version rows of one (asset, product,
// location) of the tenant.
func loadHistory(ctx context.Context, tx *sql.Tx, tenantID, assetID, productID shared.ID, location string) ([]software.HistoryRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT s.software_version_id, v.raw, COALESCE(v.normalized, ''), v.qualifier, s.version_state,
			s.superseded_at, s.first_seen_at, s.last_seen_at, s.sightings, s.streak, s.streak_since,
			s.evidence_class, s.confidence
		FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id
		WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.product_id = $3 AND s.location = $4 AND s.source <> 'package'
		ORDER BY s.first_seen_at, s.id
		LIMIT 1000`, tenantID.String(), assetID.String(), productID.String(), location)
	if err != nil {
		return nil, fmt.Errorf("asset software history: %w", err)
	}
	defer rows.Close()
	var out []software.HistoryRow
	for rows.Next() {
		var h software.HistoryRow
		var vid, state, class string
		var superseded, streakSince sql.NullTime
		if err := rows.Scan(&vid, &h.Raw, &h.Normalized, &h.Qualifier, &state, &superseded, &h.FirstSeen, &h.LastSeen,
			&h.Sightings, &h.Streak, &streakSince, &class, &h.Confidence); err != nil {
			return nil, fmt.Errorf("asset software history: %w", err)
		}
		h.VersionID = shared.MustIDFromString(vid)
		h.State, h.Class = software.VersionState(state), software.EvidenceClass(class)
		h.Superseded, h.SupersededAt = superseded.Valid, superseded.Time
		h.StreakSince = streakSince.Time
		h.FirstSeen, h.LastSeen = h.FirstSeen.UTC(), h.LastSeen.UTC()
		h.SupersededAt, h.StreakSince = h.SupersededAt.UTC(), h.StreakSince.UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

// writeHistoryRow stores one changed version row. l is the batch's best
// link for the version (zero when the batch did not see it): its port,
// transport, source and evidence describe the latest sighting.
func writeHistoryRow(ctx context.Context, tx *sql.Tx, tenantID, assetID, productID shared.ID, location string,
	row software.HistoryRow, l software.Link,
) error {
	var superseded, streakSince any
	if row.Superseded {
		superseded = row.SupersededAt
	}
	if !row.StreakSince.IsZero() {
		streakSince = row.StreakSince
	}
	streak := row.Streak
	if streak > 1000 {
		streak = 1000
	}
	if !row.Seen {
		_, err := tx.ExecContext(ctx, `
			UPDATE asset_software SET version_state = $5, superseded_at = $6, streak = $7, streak_since = $8, updated_at = now()
			WHERE tenant_id = $1 AND asset_id = $2 AND software_version_id = $3 AND location = $4`,
			tenantID.String(), assetID.String(), row.VersionID.String(), location,
			string(row.State), superseded, streak, streakSince)
		if err != nil {
			return fmt.Errorf("asset software: %w", err)
		}
		return nil
	}
	var port, transport any
	if l.Port > 0 && l.Port <= 65535 {
		port = l.Port
	}
	if l.Transport != "" {
		transport = l.Transport
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location,
			port, transport, source, evidence, confidence, first_seen_at, last_seen_at,
			version_state, evidence_class, sightings, streak, streak_since, superseded_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		ON CONFLICT ON CONSTRAINT uq_asset_software DO UPDATE SET
			port = COALESCE(EXCLUDED.port, asset_software.port),
			transport = COALESCE(EXCLUDED.transport, asset_software.transport),
			source = EXCLUDED.source, evidence = EXCLUDED.evidence, confidence = EXCLUDED.confidence,
			first_seen_at = EXCLUDED.first_seen_at, last_seen_at = EXCLUDED.last_seen_at,
			version_state = EXCLUDED.version_state, evidence_class = EXCLUDED.evidence_class,
			sightings = EXCLUDED.sightings, streak = EXCLUDED.streak, streak_since = EXCLUDED.streak_since,
			superseded_at = EXCLUDED.superseded_at, updated_at = now()`,
		tenantID.String(), assetID.String(), productID.String(), row.VersionID.String(), location,
		port, transport, l.Source, clipStr(l.Evidence, software.MaxEvidenceLen), row.Confidence,
		row.FirstSeen, row.LastSeen, string(row.State), string(row.Class), row.Sightings, streak, streakSince, superseded)
	if err != nil {
		return fmt.Errorf("asset software: %w", err)
	}
	return nil
}

func clipStr(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	return strings.ToValidUTF8(s, "")
}

// ListAssetLinks (see software.Repository). The catalog rows come only
// through the tenant's own links. Packages (source package) are listed by
// the components inventory, not here.
func (r *SoftwareRepository) ListAssetLinks(ctx context.Context, tenantID, assetID shared.ID) ([]software.AssetLink, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, p.id, p.name, p.vendor, COALESCE(p.cpe_vendor || ':' || p.cpe_product, ''), p.tenant_id IS NULL,
			v.id, v.raw, v.qualifier, s.location, COALESCE(s.port, 0), COALESCE(s.transport, ''),
			s.source, s.evidence, s.confidence, s.first_seen_at, s.last_seen_at, s.evidence_class, s.sightings
		FROM asset_software s
		JOIN software_products p ON p.id = s.product_id
		JOIN software_versions v ON v.id = s.software_version_id
		WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.superseded_at IS NULL AND s.version_state = 'established'
		  AND s.source <> 'package'
		ORDER BY s.last_seen_at DESC, p.name
		LIMIT $3`, tenantID.String(), assetID.String(), software.MaxAssetLinks)
	if err != nil {
		return nil, fmt.Errorf("asset software: %w", err)
	}
	defer rows.Close()
	var out []software.AssetLink
	for rows.Next() {
		var l software.AssetLink
		var id, pid, vid, class string
		if err := rows.Scan(&id, &pid, &l.Product, &l.Vendor, &l.CPE, &l.Global, &vid, &l.Version, &l.Qualifier,
			&l.Location, &l.Port, &l.Transport, &l.Source, &l.Evidence, &l.Confidence, &l.FirstSeen, &l.LastSeen,
			&class, &l.Sightings); err != nil {
			return nil, fmt.Errorf("asset software: %w", err)
		}
		l.ID, l.ProductID, l.VersionID = shared.MustIDFromString(id), shared.MustIDFromString(pid), shared.MustIDFromString(vid)
		l.Class = software.EvidenceClass(class)
		out = append(out, l)
	}
	return out, rows.Err()
}
