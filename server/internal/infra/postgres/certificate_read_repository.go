package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/certificate"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// CertificateReadRepository reads certificate assets for the Certificates
// view. Every read takes a filter compiled through the list query contract,
// so the tenant and the caller's data scope are always in the WHERE.
type CertificateReadRepository struct {
	db *DB
}

// NewCertificateReadRepository creates the repository.
func NewCertificateReadRepository(db *DB) *CertificateReadRepository {
	return &CertificateReadRepository{db: db}
}

const (
	certificateListTimeout  = "3s"
	certificateStatsTimeout = "1500ms"
)

var errUncompiledCertificateFilter = errors.New("certificate filter was not compiled for a tenant")

// certificateFrom lists live certificate assets only.
const certificateFrom = ` FROM assets a WHERE a.asset_type = 'certificate' AND a.deleted_at IS NULL`

var certificateColumns = `a.id, a.name, COALESCE(` + propText("subject_cn") + `, ''), COALESCE(` + propText("issuer_cn") + `, ''),
	COALESCE(` + propText("issuer_org") + `, ''), COALESCE(` + certificate.FingerprintSQL + `, ''),
	COALESCE(` + propText("signature_algorithm") + `, ''), ` + certificate.NotBeforeSQL + `, ` + certificate.NotAfterSQL + `,
	COALESCE((a.properties ->> 'is_self_signed') = 'true', false), COALESCE((a.properties ->> 'is_wildcard') = 'true', false),
	a.first_seen, a.last_seen`

func propText(key string) string { return "NULLIF(a.properties ->> '" + key + "', '')" }

func checkCertificateWhere(w *filterspec.Where) error {
	if w == nil || !strings.HasPrefix(w.SQL, certificate.Fields.TenantSQL+" = $") || w.OrderBy == "" {
		return errUncompiledCertificateFilter
	}
	return nil
}

func scanCertificate(s interface{ Scan(...any) error }) (*certificate.Certificate, error) {
	var (
		c                 certificate.Certificate
		notBefore, notAft sql.NullTime
	)
	if err := s.Scan(&c.AssetID, &c.Name, &c.SubjectCN, &c.IssuerCN, &c.IssuerOrg, &c.FingerprintSHA256,
		&c.SignatureAlg, &notBefore, &notAft, &c.IsSelfSigned, &c.IsWildcard, &c.FirstSeen, &c.LastSeen); err != nil {
		return nil, err
	}
	if notBefore.Valid {
		t := notBefore.Time
		c.NotBefore = &t
	}
	if notAft.Valid {
		t := notAft.Time
		c.NotAfter = &t
	}
	return &c, nil
}

// ListWhere lists one page of certificates matching a compiled filter, with
// the total, in one read-only transaction with a statement timeout.
func (r *CertificateReadRepository) ListWhere( //nolint:dupl // same shape as every read-layer list; the entity types differ
	ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*certificate.Certificate], error) {
	var empty pagination.Result[*certificate.Certificate]
	if err := checkCertificateWhere(w); err != nil {
		return empty, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, fmt.Errorf("begin certificate list: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+certificateListTimeout+"'"); err != nil {
		return empty, fmt.Errorf("set certificate list timeout: %w", err)
	}
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)"+certificateFrom+" AND "+w.SQL, w.Args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count certificates: %w", err)
	}
	// w.SQL and w.OrderBy come from filterspec.Compile (checked above):
	// registry constants and bound placeholders only.
	q := fmt.Sprintf("SELECT %s%s AND %s ORDER BY %s LIMIT %d OFFSET %d", //nolint:gosec // G201: compiled filter
		certificateColumns, certificateFrom, w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("list certificates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*certificate.Certificate, 0, 100)
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return empty, fmt.Errorf("scan certificate: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list certificates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit certificate list: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// StatsWhere counts the certificates of a compiled filter by status: the
// same WHERE as the list.
func (r *CertificateReadRepository) StatsWhere(ctx context.Context, w *filterspec.Where) (*certificate.Stats, error) {
	if err := checkCertificateWhere(w); err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin certificate stats: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+certificateStatsTimeout+"'"); err != nil {
		return nil, fmt.Errorf("set certificate stats timeout: %w", err)
	}
	q := "SELECT " + certificate.StatusSQL + ", count(*)" + certificateFrom + " AND " + w.SQL + " GROUP BY 1" //nolint:gosec // G202: compiled filter
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return nil, fmt.Errorf("certificate stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	st := &certificate.Stats{}
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("scan certificate stats: %w", err)
		}
		st.Total += n
		switch certificate.Status(status) {
		case certificate.StatusExpired:
			st.Expired = n
		case certificate.StatusExpiringSoon:
			st.ExpiringSoon = n
		case certificate.StatusOK:
			st.OK = n
		default:
			st.Unknown = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("certificate stats: %w", err)
	}
	return st, tx.Commit()
}
