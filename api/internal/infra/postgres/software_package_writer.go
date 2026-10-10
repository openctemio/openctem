package postgres

// Package observations into the software catalog. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
)

// SoftwarePackageWriter writes package observations: products and versions
// in the catalog (tenant-private unless a global row with the same identity
// exists) and the asset's links and dependency edges.
type SoftwarePackageWriter struct {
	db *DB
}

// NewSoftwarePackageWriter creates a SoftwarePackageWriter.
func NewSoftwarePackageWriter(db *DB) *SoftwarePackageWriter {
	return &SoftwarePackageWriter{db: db}
}

var _ software.PackageWriter = (*SoftwarePackageWriter)(nil)

type pkgIdentity struct{ typ, ns, name string }

type pkgProduct struct {
	id     string
	global bool
}

type pkgVersionKey struct {
	product   string
	scheme    string
	raw       string
	qualifier string
}

// queryer is satisfied by *sql.Tx and *DB.
type pkgQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// resolveProducts returns the product per identity: the tenant's own row,
// else the global row, else a new tenant-private row.
func resolvePackageProducts(ctx context.Context, q pkgQueryer, tenantID shared.ID,
	ids []pkgIdentity, names map[pkgIdentity]string) (map[pkgIdentity]pkgProduct, int, error) {
	out := make(map[pkgIdentity]pkgProduct, len(ids))
	if len(ids) == 0 {
		return out, 0, nil
	}
	types, nss, pnames := make([]string, len(ids)), make([]string, len(ids)), make([]string, len(ids))
	for i, id := range ids {
		types[i], nss[i], pnames[i] = id.typ, id.ns, id.name
	}
	load := func() error {
		rows, err := q.QueryContext(ctx, `
			SELECT p.id, p.tenant_id IS NULL, p.purl_type, p.purl_namespace, p.purl_name
			FROM software_products p
			JOIN unnest($2::text[], $3::text[], $4::text[]) AS k(t, ns, n)
			  ON p.purl_type = k.t AND p.purl_namespace = k.ns AND p.purl_name = k.n
			WHERE p.purl_type IS NOT NULL AND (p.tenant_id = $1 OR p.tenant_id IS NULL)`,
			tenantID.String(), pq.Array(types), pq.Array(nss), pq.Array(pnames))
		if err != nil {
			return fmt.Errorf("resolve packages: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p pkgProduct
			var k pkgIdentity
			if err := rows.Scan(&p.id, &p.global, &k.typ, &k.ns, &k.name); err != nil {
				return fmt.Errorf("resolve packages: %w", err)
			}
			// The tenant's own row wins over a global one.
			if cur, ok := out[k]; !ok || (cur.global && !p.global) {
				out[k] = p
			}
		}
		return rows.Err()
	}
	if err := load(); err != nil {
		return nil, 0, err
	}
	missT, missNS, missN, missDisplay := []string{}, []string{}, []string{}, []string{}
	for _, id := range ids {
		if _, ok := out[id]; ok {
			continue
		}
		display := names[id]
		if display == "" {
			display = id.name
		}
		missT, missNS, missN = append(missT, id.typ), append(missNS, id.ns), append(missN, id.name)
		missDisplay = append(missDisplay, clipStr(display, software.MaxNameLen))
	}
	if len(missT) == 0 {
		return out, 0, nil
	}
	res, err := q.ExecContext(ctx, `
		INSERT INTO software_products (tenant_id, part, vendor, name, purl_type, purl_namespace, purl_name, source)
		SELECT $1, 'a', left(k.ns, 128), k.d, k.t, k.ns, k.n, 'observed'
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS k(t, ns, n, d)
		ON CONFLICT (tenant_id, purl_type, purl_namespace, purl_name)
			WHERE tenant_id IS NOT NULL AND purl_type IS NOT NULL DO NOTHING`,
		tenantID.String(), pq.Array(missT), pq.Array(missNS), pq.Array(missN), pq.Array(missDisplay))
	if err != nil {
		return nil, 0, fmt.Errorf("create packages: %w", err)
	}
	created, _ := res.RowsAffected()
	if err := load(); err != nil {
		return nil, 0, err
	}
	for _, id := range ids {
		if _, ok := out[id]; !ok {
			return nil, 0, fmt.Errorf("package %s/%s/%s was not resolved", id.typ, id.ns, id.name)
		}
	}
	return out, int(created), nil
}

// ensurePackageVersions returns the version id per key; a version of a
// global product is global (RFC-066: one evaluation per version), a version
// of a private product is private.
func ensurePackageVersions(ctx context.Context, q pkgQueryer, tenantID shared.ID,
	keys []pkgVersionKey, global map[string]bool, purls map[pkgVersionKey]string) (map[pkgVersionKey]string, int, error) {
	out := make(map[pkgVersionKey]string, len(keys))
	if len(keys) == 0 {
		return out, 0, nil
	}
	n := len(keys)
	products, tenants, raws, schemes, quals, purlCol := make([]string, n), make([]sql.NullString, n),
		make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, k := range keys {
		products[i], raws[i], schemes[i], quals[i], purlCol[i] = k.product, k.raw, k.scheme, k.qualifier, purls[k]
		if !global[k.product] {
			tenants[i] = sql.NullString{String: tenantID.String(), Valid: true}
		}
	}
	res, err := q.ExecContext(ctx, `
		INSERT INTO software_versions (product_id, tenant_id, raw, normalized, scheme, qualifier, purl)
		SELECT k.p::uuid, k.t::uuid, k.r, NULLIF(k.r, ''), k.s, k.q, NULLIF(k.u, '')
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS k(p, t, r, s, q, u)
		ON CONFLICT (product_id, scheme, COALESCE(normalized, 'raw:' || raw), qualifier, edition) DO NOTHING`,
		pq.Array(products), pq.Array(tenants), pq.Array(raws), pq.Array(schemes), pq.Array(quals), pq.Array(purlCol))
	if err != nil {
		return nil, 0, fmt.Errorf("create package versions: %w", err)
	}
	created, _ := res.RowsAffected()
	rows, err := q.QueryContext(ctx, `
		SELECT v.id, v.product_id, v.scheme, v.raw, v.qualifier
		FROM software_versions v
		JOIN unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS k(p, r, s, q)
		  ON v.product_id = k.p::uuid AND v.scheme = k.s AND v.qualifier = k.q AND v.edition = ''
		 AND COALESCE(v.normalized, 'raw:' || v.raw) = COALESCE(NULLIF(k.r, ''), 'raw:' || k.r)
		WHERE v.tenant_id IS NULL OR v.tenant_id = $5`,
		pq.Array(products), pq.Array(raws), pq.Array(schemes), pq.Array(quals), tenantID.String())
	if err != nil {
		return nil, 0, fmt.Errorf("load package versions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var k pkgVersionKey
		if err := rows.Scan(&id, &k.product, &k.scheme, &k.raw, &k.qualifier); err != nil {
			return nil, 0, fmt.Errorf("load package versions: %w", err)
		}
		out[k] = id
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("load package versions: %w", err)
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			return nil, 0, fmt.Errorf("package version %q was not resolved", k.raw)
		}
	}
	return out, int(created), nil
}

func versionKeyFor(product string, p software.PURL) pkgVersionKey {
	return pkgVersionKey{product: product, scheme: software.SchemeForType(p.Type), raw: p.Version, qualifier: p.DistroQualifier()}
}

// EnsurePackageVersion returns the version id the tenant sees for a package URL.
func (w *SoftwarePackageWriter) EnsurePackageVersion(ctx context.Context, tenantID shared.ID, p software.PURL) (shared.ID, error) {
	id := pkgIdentity{typ: p.Type, ns: p.Namespace, name: p.Name}
	products, _, err := resolvePackageProducts(ctx, w.db, tenantID, []pkgIdentity{id}, nil)
	if err != nil {
		return shared.ID{}, err
	}
	prod := products[id]
	key := versionKeyFor(prod.id, p)
	versions, _, err := ensurePackageVersions(ctx, w.db, tenantID, []pkgVersionKey{key},
		map[string]bool{prod.id: prod.global}, map[pkgVersionKey]string{key: p.String()})
	if err != nil {
		return shared.ID{}, err
	}
	return shared.IDFromString(versions[key])
}

// WritePackages stores one snapshot (see software.PackageWriter).
//
//nolint:cyclop,funlen // one transaction: resolve, ensure, link, prune, edges, counters
func (w *SoftwarePackageWriter) WritePackages(ctx context.Context, tenantID shared.ID, snap software.PackageSnapshot) (software.PackageWriteResult, error) {
	var res software.PackageWriteResult
	nodes := snap.Packages
	if len(nodes) > software.MaxSnapshotPackages {
		return res, fmt.Errorf("%w: at most %d packages per report", shared.ErrValidation, software.MaxSnapshotPackages)
	}
	if len(nodes) == 0 && !snap.Replace {
		return res, nil
	}
	edges, depth := software.PlanGraph(nodes)

	idents := make([]pkgIdentity, 0, len(nodes))
	names := make(map[pkgIdentity]string, len(nodes))
	for _, n := range nodes {
		k := pkgIdentity{typ: n.PURL.Type, ns: n.PURL.Namespace, name: n.PURL.Name}
		if _, ok := names[k]; !ok {
			idents = append(idents, k)
			names[k] = n.DisplayName
		}
	}

	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	products, created, err := resolvePackageProducts(ctx, tx, tenantID, idents, names)
	if err != nil {
		return res, err
	}
	res.Products = created

	vkeys := make([]pkgVersionKey, 0, len(nodes))
	vseen := make(map[pkgVersionKey]bool, len(nodes))
	global := make(map[string]bool, len(products))
	purls := make(map[pkgVersionKey]string, len(nodes))
	nodeKey := make([]pkgVersionKey, len(nodes))
	for i, n := range nodes {
		prod := products[pkgIdentity{typ: n.PURL.Type, ns: n.PURL.Namespace, name: n.PURL.Name}]
		global[prod.id] = prod.global
		k := versionKeyFor(prod.id, n.PURL)
		nodeKey[i] = k
		if !vseen[k] {
			vseen[k] = true
			vkeys = append(vkeys, k)
			purls[k] = n.PURL.String()
		}
	}
	versions, vcreated, err := ensurePackageVersions(ctx, tx, tenantID, vkeys, global, purls)
	if err != nil {
		return res, err
	}
	res.Versions = vcreated

	// One link per (version, location); the first entry wins.
	type linkKey struct{ version, location string }
	linkIndex := make(map[linkKey]int, len(nodes))
	nodeLink := make([]int, len(nodes))
	n := len(nodes)
	lProduct, lVersion, lLocation, lEvidence := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	lRelationship, lScope, lLicenses := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	lConfidence, lDepth := make([]int, 0, n), make([]int, 0, n)
	locations := map[string]bool{}
	for i, n := range nodes {
		loc := software.CleanLocation(n.Location)
		locations[loc] = true
		k := linkKey{version: versions[nodeKey[i]], location: loc}
		if j, ok := linkIndex[k]; ok {
			nodeLink[i] = j
			continue
		}
		linkIndex[k] = len(lVersion)
		nodeLink[i] = len(lVersion)
		confidence := 100
		if n.Synthetic {
			confidence = 80
		}
		d := depth[i]
		lProduct = append(lProduct, nodeKey[i].product)
		lVersion = append(lVersion, k.version)
		lLocation = append(lLocation, loc)
		lEvidence = append(lEvidence, clipStr(n.PURL.String(), software.MaxEvidenceLen))
		lRelationship = append(lRelationship, n.Relationship)
		lScope = append(lScope, n.Scope)
		lLicenses = append(lLicenses, pqTextArrayLiteral(software.NormalizeLicenses(n.Licenses)))
		lConfidence = append(lConfidence, confidence)
		lDepth = append(lDepth, d)
	}
	var channel any
	if snap.Channel != "" {
		channel = snap.Channel
	}
	linkIDs := make([]string, len(lVersion))
	if len(lVersion) > 0 {
		written, err := upsertPackageLinks(ctx, tx, `
			INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location, source,
				evidence, confidence, relationship, dep_scope, depth, licenses, channel)
			SELECT $1, $2, k.p::uuid, k.v::uuid, k.l, 'package', k.e, k.c, k.r, NULLIF(k.s, ''),
			       NULLIF(k.d, -1)::smallint, k.lic::text[], $3
			FROM unnest($4::text[], $5::text[], $6::text[], $7::text[], $8::int[], $9::text[], $10::text[], $11::int[], $12::text[])
			     WITH ORDINALITY AS k(p, v, l, e, c, r, s, d, lic, ord)
			ORDER BY k.ord
			ON CONFLICT ON CONSTRAINT uq_asset_software DO UPDATE SET
				last_seen_at = now(), updated_at = now(), superseded_at = NULL,
				evidence = EXCLUDED.evidence, confidence = EXCLUDED.confidence,
				relationship = CASE WHEN EXCLUDED.relationship = 'unknown' THEN asset_software.relationship ELSE EXCLUDED.relationship END,
				dep_scope = COALESCE(EXCLUDED.dep_scope, asset_software.dep_scope),
				depth = COALESCE(EXCLUDED.depth, asset_software.depth),
				licenses = CASE WHEN cardinality(EXCLUDED.licenses) > 0 THEN EXCLUDED.licenses ELSE asset_software.licenses END,
				channel = COALESCE(EXCLUDED.channel, asset_software.channel)
			RETURNING id, software_version_id, location`,
			tenantID.String(), snap.AssetID.String(), channel,
			pq.Array(lProduct), pq.Array(lVersion), pq.Array(lLocation), pq.Array(lEvidence), pq.Array(lConfidence),
			pq.Array(lRelationship), pq.Array(lScope), pq.Array(lDepth), pq.Array(lLicenses))
		if err != nil {
			return res, fmt.Errorf("write package links: %w", err)
		}
		for _, l := range written {
			if j, ok := linkIndex[linkKey{version: l[1], location: l[2]}]; ok {
				linkIDs[j] = l[0]
			}
		}
		res.Links = len(lVersion)
	}

	locList := make([]string, 0, len(locations))
	for l := range locations {
		locList = append(locList, l)
	}
	if snap.Replace && len(locList) > 0 {
		// Rows written above carry last_seen_at = now() (the transaction start).
		r, err := tx.ExecContext(ctx, `
			DELETE FROM asset_software
			WHERE tenant_id = $1 AND asset_id = $2 AND source = 'package'
			  AND location = ANY($3) AND last_seen_at < now()`,
			tenantID.String(), snap.AssetID.String(), pq.Array(locList))
		if err != nil {
			return res, fmt.Errorf("prune package links: %w", err)
		}
		k, _ := r.RowsAffected()
		res.Removed = int(k)
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM asset_software_edges e
			USING asset_software s
			WHERE e.tenant_id = $1 AND e.asset_id = $2 AND s.id = e.child_id AND s.location = ANY($3)`,
			tenantID.String(), snap.AssetID.String(), pq.Array(locList)); err != nil {
			return res, fmt.Errorf("replace package edges: %w", err)
		}
	}

	if len(edges) > 0 {
		parents, children := make([]string, 0, len(edges)), make([]string, 0, len(edges))
		for _, e := range edges {
			p, c := linkIDs[nodeLink[e.Parent]], linkIDs[nodeLink[e.Child]]
			if p == "" || c == "" || p == c {
				continue
			}
			parents, children = append(parents, p), append(children, c)
		}
		r, err := tx.ExecContext(ctx, `
			INSERT INTO asset_software_edges (tenant_id, asset_id, parent_id, child_id)
			SELECT $1, $2, k.p::uuid, k.c::uuid FROM unnest($3::text[], $4::text[]) AS k(p, c)
			ON CONFLICT DO NOTHING`,
			tenantID.String(), snap.AssetID.String(), pq.Array(parents), pq.Array(children))
		if err != nil {
			return res, fmt.Errorf("write package edges: %w", err)
		}
		k, _ := r.RowsAffected()
		res.Edges = int(k)
	}

	if err := refreshRepositoryComponentCounts(ctx, tx, tenantID, snap.AssetID); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}

// upsertPackageLinks runs the link upsert and returns (id, version, location)
// per written row.
func upsertPackageLinks(ctx context.Context, q pkgQueryer, query string, args ...any) ([][3]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var l [3]string
		if err := rows.Scan(&l[0], &l[1], &l[2]); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// refreshRepositoryComponentCounts recomputes a repository asset's package
// counters (no-op for other asset types).
func refreshRepositoryComponentCounts(ctx context.Context, q pkgQueryer, tenantID, assetID shared.ID) error {
	_, err := q.ExecContext(ctx, `
		UPDATE asset_repositories ar SET
			component_count = (SELECT count(*) FROM asset_software s
				WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.source = 'package' AND s.superseded_at IS NULL),
			vulnerable_component_count = (SELECT count(DISTINCT s.software_version_id) FROM asset_software s
				JOIN findings f ON f.tenant_id = s.tenant_id AND f.asset_id = s.asset_id
				 AND f.component_id = s.software_version_id
				 AND f.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate')
				WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.source = 'package' AND s.superseded_at IS NULL)
		WHERE ar.asset_id = $2
		  AND EXISTS (SELECT 1 FROM assets a WHERE a.id = $2 AND a.tenant_id = $1)`,
		tenantID.String(), assetID.String())
	if err != nil {
		return fmt.Errorf("repository component counts: %w", err)
	}
	return nil
}

// pqTextArrayLiteral renders a text array literal ({"a","b"}) so a list of
// arrays can travel as one text[] parameter and be cast back per row.
func pqTextArrayLiteral(items []string) string {
	v, err := pq.Array(items).Value()
	if err != nil || v == nil {
		return "{}"
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "{}"
}
