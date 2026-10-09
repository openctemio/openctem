package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
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
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO software_product_aliases (product_id, tenant_id, kind, value)
				VALUES ($1, NULL, $2, $3)
				ON CONFLICT (kind, value) WHERE tenant_id IS NULL DO NOTHING`, id, a[0], a[1]); err != nil {
				return fmt.Errorf("curated alias %s: %w", a[1], err)
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
		INSERT INTO software_product_aliases (product_id, tenant_id, kind, value)
		VALUES ($1, $2, $3, $4)
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
func (r *SoftwareRepository) UpsertLinks(ctx context.Context, tenantID shared.ID, links []software.Link) (software.LinkResult, error) {
	var res software.LinkResult
	if len(links) == 0 {
		return res, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	changed := map[shared.ID]bool{}
	type group struct {
		asset, product shared.ID
		location       string
	}
	groups := map[group]bool{}
	for _, l := range links {
		var port, transport any
		if l.Port > 0 && l.Port <= 65535 {
			port = l.Port
		}
		if l.Transport != "" {
			transport = l.Transport
		}
		loc := clipStr(l.Location, software.MaxLocationLen)
		// A link that was superseded and is seen again is a change too.
		var wasSuperseded bool
		err := tx.QueryRowContext(ctx, `SELECT superseded_at IS NOT NULL FROM asset_software
			WHERE tenant_id = $1 AND asset_id = $2 AND software_version_id = $3 AND location = $4`,
			tenantID.String(), l.AssetID.String(), l.VersionID.String(), loc).Scan(&wasSuperseded)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return res, fmt.Errorf("asset software: %w", err)
		}
		var inserted bool
		err = tx.QueryRowContext(ctx, `
			INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location,
				port, transport, source, evidence, confidence)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT ON CONSTRAINT uq_asset_software DO UPDATE SET
				last_seen_at = now(), updated_at = now(), superseded_at = NULL,
				port = EXCLUDED.port, transport = EXCLUDED.transport, source = EXCLUDED.source,
				evidence = EXCLUDED.evidence, confidence = EXCLUDED.confidence
			RETURNING (xmax = 0)`,
			tenantID.String(), l.AssetID.String(), l.ProductID.String(), l.VersionID.String(),
			loc, port, transport, l.Source, clipStr(l.Evidence, software.MaxEvidenceLen), l.Confidence).Scan(&inserted)
		if err != nil {
			return res, fmt.Errorf("asset software: %w", err)
		}
		if inserted {
			res.Inserted++
		}
		if inserted || wasSuperseded {
			changed[l.AssetID] = true
		}
		groups[group{asset: l.AssetID, product: l.ProductID, location: loc}] = true
	}
	// Every link written above has last_seen_at = now() (the transaction's
	// start), so "older than now()" is exactly "not seen by this write".
	for g := range groups {
		n, err := tx.ExecContext(ctx, `
			UPDATE asset_software SET superseded_at = now(), updated_at = now()
			WHERE tenant_id = $1 AND asset_id = $2 AND product_id = $3 AND location = $4
			  AND superseded_at IS NULL AND last_seen_at < now()`,
			tenantID.String(), g.asset.String(), g.product.String(), g.location)
		if err != nil {
			return res, fmt.Errorf("supersede: %w", err)
		}
		if k, _ := n.RowsAffected(); k > 0 {
			res.Superseded += int(k)
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

func clipStr(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	return strings.ToValidUTF8(s, "")
}
