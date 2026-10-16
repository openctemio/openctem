package postgres

// Content catalog (docs/rfcs/RFC-099-content-packages.md; migration
// 002571_content_catalog). Every query that takes a tenant id reads that
// organization's rows and the instance catalog (tenant_id IS NULL) only, and
// every write carries the tenant id.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/contentpkg"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentcatalog"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ContentCatalogRepository implements contentcatalog.Repository.
type ContentCatalogRepository struct {
	db *DB
	// q is db, or the transaction of an InTx repository.
	q ccQuerier
}

type ccQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// NewContentCatalogRepository creates a ContentCatalogRepository.
func NewContentCatalogRepository(db *DB) *ContentCatalogRepository {
	return &ContentCatalogRepository{db: db, q: db}
}

// errNestedTx: a method that opens its own transaction was called on an
// InTx repository.
var errNestedTx = errors.New("content catalog: nested transaction")

func (r *ContentCatalogRepository) begin(ctx context.Context) (*sql.Tx, error) {
	if r.db == nil {
		return nil, errNestedTx
	}
	return r.db.BeginTx(ctx, nil)
}

// InTx runs fn with a repository whose every statement is in one
// transaction; it commits when fn returns nil.
func (r *ContentCatalogRepository) InTx(ctx context.Context, fn func(dom.Repository) error) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(&ContentCatalogRepository{q: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

var _ dom.Repository = (*ContentCatalogRepository)(nil)

const contentPackageColumns = `p.id, p.tenant_id, p.package_id, p.version, p.type, p.origin, p.title, p.manifest_raw,
	p.manifest_digest, p.artifact_media_type, p.artifact_digest, p.artifact_size, p.statement, p.publisher_signature,
	p.publisher_identity, p.publisher_issuer, p.publisher_signed_at, p.tier, p.service_use, p.revoked_at,
	p.revoke_reason, p.revoke_severity, p.content_pack_id, p.platform_pack_id, p.created_by, p.created_at`

// visibleTo is the predicate of the rows an organization sees ($1 = tenant).
const visibleTo = `(p.tenant_id IS NULL OR p.tenant_id = $1)`

func optContentID(ns sql.NullString) *shared.ID {
	if !ns.Valid {
		return nil
	}
	id, err := shared.IDFromString(ns.String)
	if err != nil {
		return nil
	}
	return &id
}

func scanContentPackage(row interface{ Scan(...any) error }) (*dom.Package, error) {
	var (
		p                                             dom.Package
		tenant, identity, issuer, reason, sev, author sql.NullString
		contentPack, platformPack                     sql.NullString
		signedAt, revokedAt                           sql.NullTime
		typ                                           string
	)
	if err := row.Scan(&p.ID, &tenant, &p.PackageID, &p.Version, &typ, &p.Origin, &p.Title, &p.ManifestRaw,
		&p.ManifestDigest, &p.ArtifactMediaType, &p.ArtifactDigest, &p.ArtifactSize, &p.Statement, &p.PublisherSignature,
		&identity, &issuer, &signedAt, &p.Tier, &p.ServiceUse, &revokedAt, &reason, &sev, &contentPack, &platformPack,
		&author, &p.CreatedAt); err != nil {
		return nil, err
	}
	p.Type = contentpkg.Type(typ)
	p.TenantID, p.CreatedBy = optContentID(tenant), optContentID(author)
	p.ContentPackID, p.PlatformPackID = optContentID(contentPack), optContentID(platformPack)
	p.PublisherIdentity, p.PublisherIssuer = identity.String, issuer.String
	p.PublisherSignedAt, p.RevokedAt = nullTimeValue(signedAt), nullTimeValue(revokedAt)
	p.RevokeReason, p.RevokeSeverity = reason.String, sev.String
	m, err := contentpkg.ParseManifest(p.ManifestRaw)
	if err != nil {
		return nil, fmt.Errorf("stored manifest of %s@%s: %w", p.PackageID, p.Version, err)
	}
	p.Manifest = m
	return &p, nil
}

// GetTrust returns the applied signed state (zero values before the first
// import).
func (r *ContentCatalogRepository) GetTrust(ctx context.Context) (*dom.TrustState, error) {
	t := &dom.TrustState{}
	var digest, rvDigest sql.NullString
	var ixExp, rvIssued, rvExp, imported sql.NullTime
	var ksv, ixs, rvs int64
	err := r.q.QueryRowContext(ctx, `
		SELECT keyset_version, index_sequence, index_digest, index_expires_at, revocations_sequence,
			revocations_digest, revocations_issued_at, revocations_expires_at, imported_at
		FROM content_catalog_trust WHERE id = 1`).
		Scan(&ksv, &ixs, &digest, &ixExp, &rvs, &rvDigest, &rvIssued, &rvExp, &imported)
	if errors.Is(err, sql.ErrNoRows) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get content catalog trust: %w", err)
	}
	t.KeySetVersion, t.IndexSequence, t.RevocationsSequence = uint64(ksv), uint64(ixs), uint64(rvs) //nolint:gosec // non-negative (CHECK)
	t.IndexDigest, t.RevocationsDigest = digest.String, rvDigest.String
	t.IndexExpiresAt, t.RevocationsIssuedAt = nullTimeValue(ixExp), nullTimeValue(rvIssued)
	t.RevocationsExpiresAt, t.ImportedAt = nullTimeValue(rvExp), nullTimeValue(imported)
	return t, nil
}

// ListRevocations returns every applied revocation entry.
func (r *ContentCatalogRepository) ListRevocations(ctx context.Context) ([]contentpkg.RevocationEntry, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT COALESCE(package_id, ''), COALESCE(version, ''), COALESCE(digest, ''), reason, severity, revoked_at
		FROM content_revocations ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list content revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []contentpkg.RevocationEntry
	for rows.Next() {
		var e contentpkg.RevocationEntry
		if err := rows.Scan(&e.ID, &e.Version, &e.Digest, &e.Reason, &e.Severity, &e.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func toInt64(v uint64) (int64, error) {
	if v > 1<<62 {
		return 0, errors.New("counter out of range")
	}
	return int64(v), nil
}

// ApplyImport implements dom.Repository.
//
//nolint:cyclop // one transaction, linear steps
func (r *ContentCatalogRepository) ApplyImport(ctx context.Context, b *dom.ImportBatch) (*dom.ImportOutcome, error) {
	ksv, err1 := toInt64(b.KeySetVersion)
	ixs, err2 := toInt64(b.IndexSequence)
	rvs, err3 := toInt64(b.RevocationsSequence)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, err
	}
	tx, err := r.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("apply content import: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `INSERT INTO content_catalog_trust (id) VALUES (1) ON CONFLICT (id) DO NOTHING`); err != nil {
		return nil, fmt.Errorf("apply content import: %w", err)
	}
	var curKS, curIx, curRv int64
	var curDigest, curRvDigest sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT keyset_version, index_sequence, index_digest, revocations_sequence, revocations_digest
		FROM content_catalog_trust WHERE id = 1 FOR UPDATE`).Scan(&curKS, &curIx, &curDigest, &curRv, &curRvDigest); err != nil {
		return nil, fmt.Errorf("apply content import: %w", err)
	}
	if ksv < curKS || ixs < curIx || (ixs == curIx && curDigest.String != b.IndexDigest) ||
		rvs < curRv || (rvs == curRv && curRvDigest.String != b.RevocationsDigest) {
		return nil, dom.ErrStaleImport
	}

	out := &dom.ImportOutcome{}
	for _, p := range b.Packages {
		var taken bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM content_packages WHERE package_id = $1 AND origin = 'instance')`,
			p.PackageID).Scan(&taken); err != nil {
			return nil, fmt.Errorf("apply content import: %w", err)
		}
		if taken {
			return nil, fmt.Errorf("%w: %s", dom.ErrIDTaken, p.PackageID)
		}
		var existing string
		err := tx.QueryRowContext(ctx, `
			SELECT manifest_digest FROM content_packages
			WHERE tenant_id IS NULL AND package_id = $1 AND version = $2`, p.PackageID, p.Version).Scan(&existing)
		switch {
		case err == nil && existing == p.ManifestDigest:
			out.Existing++
			continue
		case err == nil:
			return nil, fmt.Errorf("%w: %s@%s", dom.ErrVersionConflict, p.PackageID, p.Version)
		case !errors.Is(err, sql.ErrNoRows):
			return nil, fmt.Errorf("apply content import: %w", err)
		}
		manifest, err := json.Marshal(p.Manifest)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO content_packages (id, tenant_id, package_id, version, type, origin, title, manifest, manifest_raw,
				manifest_digest, artifact_media_type, artifact_digest, artifact_size, statement, publisher_signature,
				publisher_identity, publisher_issuer, publisher_signed_at, tier, service_use, created_by, created_at)
			VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
			p.ID, p.PackageID, p.Version, string(p.Type), p.Origin, p.Title, manifest, p.ManifestRaw,
			p.ManifestDigest, p.ArtifactMediaType, p.ArtifactDigest, p.ArtifactSize, p.Statement, p.PublisherSignature,
			nullString(p.PublisherIdentity), nullString(p.PublisherIssuer), nullTime(p.PublisherSignedAt), p.Tier,
			p.ServiceUse, nullableID(p.CreatedBy), b.ImportedAt); err != nil {
			return nil, fmt.Errorf("store %s@%s: %w", p.PackageID, p.Version, err)
		}
		out.Added++
	}

	for _, e := range b.Revocations {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO content_revocations (package_id, version, digest, reason, severity, revoked_at, list_sequence)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (COALESCE(package_id, ''), COALESCE(version, ''), COALESCE(digest, '')) DO NOTHING`,
			nullString(e.ID), nullString(e.Version), nullString(e.Digest), e.Reason, e.Severity, e.RevokedAt, rvs); err != nil {
			return nil, fmt.Errorf("store revocation: %w", err)
		}
	}
	// Every version an applied entry names is revoked, wherever it came
	// from (instance or private), and so is every installation of it.
	res, err := tx.ExecContext(ctx, `
		UPDATE content_packages p SET revoked_at = $1, revoke_reason = r.reason, revoke_severity = r.severity
		FROM content_revocations r
		WHERE p.revoked_at IS NULL AND (
			(r.digest IS NOT NULL AND p.artifact_digest = r.digest)
			OR (r.digest IS NULL AND r.package_id = p.package_id AND (r.version IS NULL OR r.version = p.version)))`,
		b.ImportedAt)
	if err != nil {
		return nil, fmt.Errorf("revoke content packages: %w", err)
	}
	n, _ := res.RowsAffected()
	out.RevokedVersions = int(n)
	res, err = tx.ExecContext(ctx, `
		UPDATE content_installs i SET status = 'revoked', updated_at = $1
		FROM content_packages p
		WHERE i.package_row_id = p.id AND p.revoked_at IS NOT NULL AND i.status = 'active'`, b.ImportedAt)
	if err != nil {
		return nil, fmt.Errorf("revoke content installs: %w", err)
	}
	n, _ = res.RowsAffected()
	out.RevokedInstalls = int(n)

	if _, err := tx.ExecContext(ctx, `
		UPDATE content_catalog_trust SET keyset_version = $1, index_sequence = $2, index_digest = $3,
			index_expires_at = $4, revocations_sequence = $5, revocations_issued_at = $6, revocations_expires_at = $7,
			imported_at = $8, revocations_digest = $9
		WHERE id = 1`, ksv, ixs, b.IndexDigest, b.IndexExpiresAt, rvs, b.RevocationsIssuedAt, b.RevocationsExpiresAt,
		b.ImportedAt, b.RevocationsDigest); err != nil {
		return nil, fmt.Errorf("apply content import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("apply content import: %w", err)
	}
	return out, nil
}

// ListPackages returns the newest version of each package the organization
// sees, with its installation.
func (r *ContentCatalogRepository) ListPackages(ctx context.Context, tenantID shared.ID, f dom.Filter) ([]dom.Listing, int, error) {
	where := []string{visibleTo}
	args := []any{tenantID}
	if f.Type != "" {
		args = append(args, string(f.Type))
		where = append(where, fmt.Sprintf("p.type = $%d", len(args)))
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		args = append(args, wrapLikePattern(s))
		where = append(where, fmt.Sprintf("(p.package_id ILIKE $%d OR p.title ILIKE $%d)", len(args), len(args)))
	}
	if f.Installed != nil {
		op := "NOT EXISTS"
		if *f.Installed {
			op = "EXISTS"
		}
		where = append(where, op+" (SELECT 1 FROM content_installs i WHERE i.tenant_id = $1 AND i.package_id = p.package_id)")
	}
	limit, offset := f.Limit, f.Offset
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	// The newest non-revoked version (by semantic version order, done in Go
	// below on the candidates), else the newest revoked one.
	q := `
		WITH visible AS (
			SELECT ` + contentPackageColumns + `, COUNT(*) OVER (PARTITION BY p.package_id) AS versions
			FROM content_packages p WHERE ` + strings.Join(where, " AND ") + `
		), ids AS (
			SELECT DISTINCT package_id FROM visible ORDER BY package_id LIMIT $` + fmt.Sprint(len(args)-1) + ` OFFSET $` + fmt.Sprint(len(args)) + `
		)
		SELECT v.id, v.tenant_id, v.package_id, v.version, v.type, v.origin, v.title, v.manifest_raw,
			v.manifest_digest, v.artifact_media_type, v.artifact_digest, v.artifact_size, v.statement, v.publisher_signature,
			v.publisher_identity, v.publisher_issuer, v.publisher_signed_at, v.tier, v.service_use, v.revoked_at,
			v.revoke_reason, v.revoke_severity, v.content_pack_id, v.platform_pack_id, v.created_by, v.created_at, v.versions,
			(SELECT COUNT(DISTINCT package_id) FROM visible)
		FROM visible v JOIN ids USING (package_id)
		ORDER BY v.package_id`
	rows, err := r.q.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list content packages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		out   []dom.Listing
		total int
	)
	byID := map[string]int{}
	for rows.Next() {
		var versions int
		p, err := scanContentPackage(scanWithExtra{rows: rows, extra: []any{&versions, &total}})
		if err != nil {
			return nil, 0, err
		}
		i, seen := byID[p.PackageID]
		if !seen {
			byID[p.PackageID] = len(out)
			out = append(out, dom.Listing{Latest: p, Versions: versions})
			continue
		}
		if newer(p, out[i].Latest) {
			out[i].Latest = p
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	installs, err := r.ListInstalls(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	for _, in := range installs {
		if i, ok := byID[in.PackageID]; ok {
			out[i].Install = in
		}
	}
	return out, total, nil
}

// newer prefers a non-revoked version, then the higher semantic version.
func newer(a, b *dom.Package) bool {
	if a.Revoked() != b.Revoked() {
		return !a.Revoked()
	}
	return contentpkg.CompareVersions(a.Version, b.Version) > 0
}

// scanWithExtra scans the package columns followed by extra columns.
type scanWithExtra struct {
	rows  *sql.Rows
	extra []any
}

func (s scanWithExtra) Scan(dest ...any) error { return s.rows.Scan(append(dest, s.extra...)...) }

// ListVersions returns every version of a package the organization sees,
// newest first.
func (r *ContentCatalogRepository) ListVersions(ctx context.Context, tenantID shared.ID, packageID string) ([]*dom.Package, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+contentPackageColumns+`
		FROM content_packages p WHERE `+visibleTo+` AND p.package_id = $2`, tenantID, packageID)
	if err != nil {
		return nil, fmt.Errorf("list content package versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*dom.Package
	for rows.Next() {
		p, err := scanContentPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortVersionsDesc(out)
	return out, nil
}

func sortVersionsDesc(ps []*dom.Package) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && contentpkg.CompareVersions(ps[j].Version, ps[j-1].Version) > 0; j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}

// GetVersion returns one version the organization sees.
func (r *ContentCatalogRepository) GetVersion(ctx context.Context, tenantID shared.ID, packageID, version string) (*dom.Package, error) {
	p, err := scanContentPackage(r.q.QueryRowContext(ctx, `SELECT `+contentPackageColumns+`
		FROM content_packages p WHERE `+visibleTo+` AND p.package_id = $2 AND p.version = $3
		ORDER BY p.tenant_id NULLS LAST LIMIT 1`, tenantID, packageID, version))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, dom.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get content package: %w", err)
	}
	return p, nil
}

// GetPackageRow returns a version by row id when the organization sees it.
func (r *ContentCatalogRepository) GetPackageRow(ctx context.Context, tenantID, rowID shared.ID) (*dom.Package, error) {
	p, err := scanContentPackage(r.q.QueryRowContext(ctx, `SELECT `+contentPackageColumns+`
		FROM content_packages p WHERE `+visibleTo+` AND p.id = $2`, tenantID, rowID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, dom.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get content package: %w", err)
	}
	return p, nil
}

const contentInstallColumns = `i.id, i.tenant_id, i.package_id, i.package_row_id, i.previous_row_id, i.pinned, i.status,
	i.license_acknowledged, i.installed_by, i.updated_by, i.created_at, i.updated_at`

func scanContentInstall(row interface{ Scan(...any) error }) (*dom.Install, error) {
	var (
		in                  dom.Install
		prev, by, updatedBy sql.NullString
		status              string
	)
	if err := row.Scan(&in.ID, &in.TenantID, &in.PackageID, &in.PackageRowID, &prev, &in.Pinned, &status,
		&in.LicenseAcknowledged, &by, &updatedBy, &in.CreatedAt, &in.UpdatedAt); err != nil {
		return nil, err
	}
	in.Status = dom.InstallStatus(status)
	in.PreviousRowID, in.InstalledBy, in.UpdatedBy = optContentID(prev), optContentID(by), optContentID(updatedBy)
	return &in, nil
}

// loadVersions fills Package and Previous of installations.
func (r *ContentCatalogRepository) loadVersions(ctx context.Context, tenantID shared.ID, ins []*dom.Install) error {
	for _, in := range ins {
		p, err := r.GetPackageRow(ctx, tenantID, in.PackageRowID)
		if err != nil {
			return err
		}
		in.Package = p
		if in.PreviousRowID != nil {
			if prev, err := r.GetPackageRow(ctx, tenantID, *in.PreviousRowID); err == nil {
				in.Previous = prev
			}
		}
	}
	return nil
}

// GetInstall returns the organization's installation of a package.
func (r *ContentCatalogRepository) GetInstall(ctx context.Context, tenantID shared.ID, packageID string) (*dom.Install, error) {
	in, err := scanContentInstall(r.q.QueryRowContext(ctx, `SELECT `+contentInstallColumns+`
		FROM content_installs i WHERE i.tenant_id = $1 AND i.package_id = $2`, tenantID, packageID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, dom.ErrInstallNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get content install: %w", err)
	}
	if err := r.loadVersions(ctx, tenantID, []*dom.Install{in}); err != nil {
		return nil, err
	}
	return in, nil
}

// ListInstalls returns the organization's installations.
func (r *ContentCatalogRepository) ListInstalls(ctx context.Context, tenantID shared.ID) ([]*dom.Install, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+contentInstallColumns+`
		FROM content_installs i WHERE i.tenant_id = $1 ORDER BY i.package_id LIMIT 1000`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list content installs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*dom.Install
	for rows.Next() {
		in, err := scanContentInstall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := r.loadVersions(ctx, tenantID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// visibleRow is the guard every install write carries: the version must be
// in the instance catalog or the organization's own.
const visibleRow = `EXISTS (SELECT 1 FROM content_packages p WHERE p.id = $3 AND (p.tenant_id IS NULL OR p.tenant_id = $2))`

// CreateInstall stores a new installation.
func (r *ContentCatalogRepository) CreateInstall(ctx context.Context, in *dom.Install) error {
	res, err := r.q.ExecContext(ctx, `
		INSERT INTO content_installs (id, tenant_id, package_id, package_row_id, previous_row_id, pinned, status,
			license_acknowledged, installed_by, updated_by, created_at, updated_at)
		SELECT $1, $2, $4, $3, NULL, $5, $6, $7, $8, $8, $9, $9
		WHERE `+visibleRow+`
		ON CONFLICT (tenant_id, package_id) DO NOTHING`,
		in.ID, in.TenantID, in.PackageRowID, in.PackageID, in.Pinned, string(in.Status), in.LicenseAcknowledged,
		nullableID(in.InstalledBy), in.CreatedAt)
	if err != nil {
		return fmt.Errorf("create content install: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := r.GetInstall(ctx, in.TenantID, in.PackageID); err == nil {
			return dom.ErrAlreadyInstalled
		}
		return dom.ErrNotFound
	}
	return nil
}

// UpdateInstall stores a changed installation.
func (r *ContentCatalogRepository) UpdateInstall(ctx context.Context, in *dom.Install) error {
	res, err := r.q.ExecContext(ctx, `
		UPDATE content_installs SET package_row_id = $3, previous_row_id = $4, pinned = $5, status = $6,
			license_acknowledged = $7, updated_by = $8, updated_at = $9
		WHERE tenant_id = $2 AND id = $1 AND `+visibleRow,
		in.ID, in.TenantID, in.PackageRowID, nullableID(in.PreviousRowID), in.Pinned, string(in.Status),
		in.LicenseAcknowledged, nullableID(in.UpdatedBy), in.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update content install: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return dom.ErrInstallNotFound
	}
	return nil
}

// DeleteInstall removes an installation.
func (r *ContentCatalogRepository) DeleteInstall(ctx context.Context, tenantID shared.ID, packageID string) error {
	res, err := r.q.ExecContext(ctx, `DELETE FROM content_installs WHERE tenant_id = $1 AND package_id = $2`, tenantID, packageID)
	if err != nil {
		return fmt.Errorf("delete content install: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return dom.ErrInstallNotFound
	}
	return nil
}

// ListFollowing implements dom.Repository.
func (r *ContentCatalogRepository) ListFollowing(ctx context.Context, packageIDs []string) ([]*dom.Install, error) {
	if len(packageIDs) == 0 {
		return nil, nil
	}
	rows, err := r.q.QueryContext(ctx, `SELECT `+contentInstallColumns+`
		FROM content_installs i WHERE i.package_id = ANY($1) AND NOT i.pinned AND i.status = 'active'
		ORDER BY i.tenant_id, i.package_id LIMIT 10000`, pq.Array(packageIDs))
	if err != nil {
		return nil, fmt.Errorf("list following content installs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*dom.Install
	for rows.Next() {
		in, err := scanContentInstall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

const contentRequestColumns = `q.id, q.tenant_id, q.package_id, q.action, q.target_row_id, q.pinned, q.license_acknowledged,
	q.status, q.note, q.decision_reason, q.requested_by, q.decided_by, q.decided_at, q.created_at`

func scanContentRequest(row interface{ Scan(...any) error }) (*dom.Request, error) {
	var (
		q                   dom.Request
		target, by, decided sql.NullString
		action, status      string
		decidedAt           sql.NullTime
	)
	if err := row.Scan(&q.ID, &q.TenantID, &q.PackageID, &action, &target, &q.Pinned, &q.LicenseAcknowledged,
		&status, &q.Note, &q.DecisionReason, &by, &decided, &decidedAt, &q.CreatedAt); err != nil {
		return nil, err
	}
	q.Action, q.Status = dom.RequestAction(action), dom.RequestStatus(status)
	q.TargetRowID, q.RequestedBy, q.DecidedBy = optContentID(target), optContentID(by), optContentID(decided)
	q.DecidedAt = nullTimeValue(decidedAt)
	return &q, nil
}

// CreateRequest stores a pending request (ErrPendingRequest when the
// package has one).
func (r *ContentCatalogRepository) CreateRequest(ctx context.Context, q *dom.Request) error {
	var target any
	if q.TargetRowID != nil {
		target = *q.TargetRowID
	}
	res, err := r.q.ExecContext(ctx, `
		INSERT INTO content_install_requests (id, tenant_id, package_id, action, target_row_id, pinned,
			license_acknowledged, status, note, requested_by, created_at)
		SELECT $1, $2, $4, $5, $3, $6, $7, 'pending', $8, $9, $10
		WHERE $3::uuid IS NULL OR `+visibleRow,
		q.ID, q.TenantID, target, q.PackageID, string(q.Action), q.Pinned, q.LicenseAcknowledged, q.Note,
		nullableID(q.RequestedBy), q.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return dom.ErrPendingRequest
		}
		return fmt.Errorf("create content request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return dom.ErrNotFound
	}
	return nil
}

// GetRequest returns one of the organization's requests.
func (r *ContentCatalogRepository) GetRequest(ctx context.Context, tenantID, id shared.ID) (*dom.Request, error) {
	q, err := scanContentRequest(r.q.QueryRowContext(ctx, `SELECT `+contentRequestColumns+`
		FROM content_install_requests q WHERE q.tenant_id = $1 AND q.id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, dom.ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get content request: %w", err)
	}
	if q.TargetRowID != nil {
		if p, err := r.GetPackageRow(ctx, tenantID, *q.TargetRowID); err == nil {
			q.Target = p
		}
	}
	return q, nil
}

// ListRequests returns the organization's requests, newest first.
func (r *ContentCatalogRepository) ListRequests(ctx context.Context, tenantID shared.ID, status dom.RequestStatus, limit int) ([]*dom.Request, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := r.q.QueryContext(ctx, `SELECT `+contentRequestColumns+`
		FROM content_install_requests q WHERE q.tenant_id = $1 AND ($2 = '' OR q.status = $2)
		ORDER BY q.created_at DESC LIMIT $3`, tenantID, string(status), limit)
	if err != nil {
		return nil, fmt.Errorf("list content requests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*dom.Request
	for rows.Next() {
		q, err := scanContentRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, q := range out {
		if q.TargetRowID != nil {
			if p, err := r.GetPackageRow(ctx, tenantID, *q.TargetRowID); err == nil {
				q.Target = p
			}
		}
	}
	return out, nil
}

// DecideRequest implements dom.Repository.
func (r *ContentCatalogRepository) DecideRequest(ctx context.Context, tenantID, id shared.ID, status dom.RequestStatus, decidedBy *shared.ID, reason string, at time.Time) error {
	res, err := r.q.ExecContext(ctx, `
		UPDATE content_install_requests SET status = $3, decided_by = $4, decision_reason = $5, decided_at = $6
		WHERE tenant_id = $1 AND id = $2 AND (status = 'pending'
			OR (status = 'approved' AND $3 = 'failed' AND decided_by = $4))`,
		tenantID, id, string(status), nullableID(decidedBy), reason, at)
	if err != nil {
		return fmt.Errorf("decide content request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := r.GetRequest(ctx, tenantID, id); err != nil {
			return err
		}
		return dom.ErrRequestDecided
	}
	return nil
}

// GetSettings returns the organization's settings (defaults without a row).
func (r *ContentCatalogRepository) GetSettings(ctx context.Context, tenantID shared.ID) (*dom.Settings, error) {
	s := &dom.Settings{}
	var by sql.NullString
	var at, off sql.NullTime
	err := r.q.QueryRowContext(ctx, `SELECT require_approval, approval_off_at, updated_by, updated_at FROM content_catalog_settings WHERE tenant_id = $1`,
		tenantID).Scan(&s.RequireApproval, &off, &by, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get content catalog settings: %w", err)
	}
	s.UpdatedBy, s.UpdatedAt, s.ApprovalOffAt = optContentID(by), nullTimeValue(at), nullTimeValue(off)
	return s, nil
}

// PutSettings stores the organization's settings.
func (r *ContentCatalogRepository) PutSettings(ctx context.Context, tenantID shared.ID, s *dom.Settings) error {
	at := time.Now().UTC()
	if s.UpdatedAt != nil {
		at = *s.UpdatedAt
	}
	_, err := r.q.ExecContext(ctx, `
		INSERT INTO content_catalog_settings (tenant_id, require_approval, approval_off_at, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id) DO UPDATE SET require_approval = EXCLUDED.require_approval,
			approval_off_at = EXCLUDED.approval_off_at, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		tenantID, s.RequireApproval, nullTime(s.ApprovalOffAt), nullableID(s.UpdatedBy), at)
	if err != nil {
		return fmt.Errorf("put content catalog settings: %w", err)
	}
	return nil
}

// CreatePrivate implements dom.Repository.
func (r *ContentCatalogRepository) CreatePrivate(ctx context.Context, p *dom.Package) error {
	manifest, err := json.Marshal(p.Manifest)
	if err != nil {
		return err
	}
	tx, err := r.begin(ctx)
	if err != nil {
		return fmt.Errorf("create private content package: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// The id must not belong to a package of another origin in the same
	// scope: an organization package never shares an id with the instance
	// catalog, an instance package never with the signed catalog. The
	// advisory lock serializes publishers of one id.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('content_package:' || $1))`, p.PackageID); err != nil {
		return fmt.Errorf("create private content package: %w", err)
	}
	// An organization package must not share an id with the instance view;
	// an instance package (visible to everyone) must not share one with any
	// organization's package, nor use a namespace that is an organization's
	// slug (the namespace of its private packages).
	var taken bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM content_packages
			WHERE package_id = $1 AND origin <> $2
			  AND ($3::uuid IS NULL OR tenant_id IS NULL OR tenant_id = $3))`,
		p.PackageID, p.Origin, nullableID(p.TenantID)).Scan(&taken); err != nil {
		return fmt.Errorf("create private content package: %w", err)
	}
	if taken {
		return dom.ErrIDTaken
	}
	if p.TenantID == nil {
		ns, _, _ := strings.Cut(p.PackageID, "/")
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE lower(slug) = $1)`, ns).Scan(&taken); err != nil {
			return fmt.Errorf("create private content package: %w", err)
		}
		if taken {
			return dom.ErrNamespaceTaken
		}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO content_packages (id, tenant_id, package_id, version, type, origin, title, manifest, manifest_raw,
			manifest_digest, artifact_media_type, artifact_digest, artifact_size, statement, tier, service_use,
			content_pack_id, platform_pack_id, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
		p.ID, nullableID(p.TenantID), p.PackageID, p.Version, string(p.Type), p.Origin, p.Title, manifest, p.ManifestRaw,
		p.ManifestDigest, p.ArtifactMediaType, p.ArtifactDigest, p.ArtifactSize, p.Statement, p.Tier, p.ServiceUse,
		nullableID(p.ContentPackID), nullableID(p.PlatformPackID), nullableID(p.CreatedBy), p.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return dom.ErrVersionConflict
		}
		return fmt.Errorf("create private content package: %w", err)
	}
	return tx.Commit()
}

// RevokePrivate implements dom.Repository.
func (r *ContentCatalogRepository) RevokePrivate(ctx context.Context, tenantID *shared.ID, packageID, version, reason string, at time.Time) (*dom.Package, error) {
	tx, err := r.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("revoke private content package: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	scope, origin := "p.tenant_id = $1", "organization"
	arg := any(nullableID(tenantID))
	if tenantID == nil {
		scope, origin, arg = "p.tenant_id IS NULL AND $1::uuid IS NULL", "instance", nil
	}
	p, err := scanContentPackage(tx.QueryRowContext(ctx, `SELECT `+contentPackageColumns+`
		FROM content_packages p WHERE `+scope+` AND p.origin = $2 AND p.package_id = $3 AND p.version = $4 FOR UPDATE`,
		arg, origin, packageID, version))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, dom.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("revoke private content package: %w", err)
	}
	if p.Revoked() {
		return nil, dom.ErrAlreadyRevoked
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE content_packages SET revoked_at = $2, revoke_reason = $3, revoke_severity = 'high'
		WHERE id = $1 AND tenant_id IS NOT DISTINCT FROM $4`,
		p.ID, at, reason, nullableID(tenantID)); err != nil {
		return nil, fmt.Errorf("revoke private content package: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE content_installs SET status = 'revoked', updated_at = $2
		WHERE package_row_id = $1 AND status = 'active' AND ($3::uuid IS NULL OR tenant_id = $3)`,
		p.ID, at, nullableID(tenantID)); err != nil {
		return nil, fmt.Errorf("revoke private content package: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("revoke private content package: %w", err)
	}
	p.RevokedAt, p.RevokeReason, p.RevokeSeverity = &at, reason, "high"
	return p, nil
}

// ListAdmins returns the organization's active owners and administrators.
func (r *ContentCatalogRepository) ListAdmins(ctx context.Context, tenantID shared.ID) ([]shared.ID, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT user_id FROM tenant_members WHERE tenant_id = $1 AND role IN ('owner', 'admin') AND status = 'active' ORDER BY user_id LIMIT 200`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list content catalog administrators: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
