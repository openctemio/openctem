package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FindingEvidenceRepository stores masked finding evidence and its encrypted
// secret values (docs/architecture/finding-evidence.md). Every query is
// tenant-scoped.
type FindingEvidenceRepository struct {
	db *DB
}

// NewFindingEvidenceRepository creates the repository.
func NewFindingEvidenceRepository(db *DB) *FindingEvidenceRepository {
	return &FindingEvidenceRepository{db: db}
}

// FindingExists reports whether the finding belongs to the tenant.
func (r *FindingEvidenceRepository) FindingExists(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM findings WHERE tenant_id = $1 AND id = $2)`,
		tenantID.String(), findingID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check finding: %w", err)
	}
	return ok, nil
}

// InsertForFingerprints stores detection records per fingerprint.
func (r *FindingEvidenceRepository) InsertForFingerprints(ctx context.Context, tenantID shared.ID,
	byFingerprint map[string][]evidencedom.NewRecord,
) (int, error) {
	if len(byFingerprint) == 0 {
		return 0, nil
	}
	fps := make([]string, 0, len(byFingerprint))
	for fp, recs := range byFingerprint {
		if len(recs) > 0 {
			fps = append(fps, fp)
		}
	}
	if len(fps) == 0 {
		return 0, nil
	}
	stored := 0
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		targets, err := evidenceTargets(ctx, tx, tenantID, fps)
		if err != nil {
			return err
		}
		touched := make([]string, 0)
		for fp, ts := range targets {
			for _, t := range ts {
				for i, nr := range byFingerprint[fp] {
					if i == 0 && nr.Record.ContentSHA256 == t.latest {
						// Same proof as last time: nothing new to keep.
						continue
					}
					rec := nr
					rec.Record.FindingID = t.id
					if len(ts) > 1 {
						// One record per finding: a fingerprint shared by two
						// findings gets its own record id (and secrets) each.
						rec = copyWithNewID(nr, t.id)
					}
					if err := insertEvidence(ctx, tx, tenantID, rec); err != nil {
						return err
					}
					stored++
				}
				touched = append(touched, t.id.String())
			}
		}
		return pruneEvidence(ctx, tx, tenantID, touched, evidencedom.OriginDetection, evidencedom.MaxDetectionPerFinding)
	})
	return stored, err
}

// evidenceTarget is a finding a fingerprint resolves to, with the content
// hash of its newest detection evidence.
type evidenceTarget struct {
	id     shared.ID
	latest string
}

// evidenceTargets resolves fingerprints to the tenant's findings.
func evidenceTargets(ctx context.Context, tx *sql.Tx, tenantID shared.ID, fps []string) (map[string][]evidenceTarget, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT f.id, f.fingerprint,
			(SELECT e.content_sha256 FROM finding_evidence e
			 WHERE e.tenant_id = f.tenant_id AND e.finding_id = f.id AND e.origin = 'detection'
			 ORDER BY e.created_at DESC LIMIT 1)
		FROM findings f
		WHERE f.tenant_id = $1 AND f.fingerprint = ANY($2)`, tenantID.String(), pq.Array(fps))
	if err != nil {
		return nil, fmt.Errorf("resolve findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	targets := map[string][]evidenceTarget{}
	for rows.Next() {
		var id, fp string
		var latest sql.NullString
		if err := rows.Scan(&id, &fp, &latest); err != nil {
			return nil, err
		}
		fid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		targets[fp] = append(targets[fp], evidenceTarget{id: fid, latest: latest.String})
	}
	return targets, rows.Err()
}

// copyWithNewID cannot re-encrypt (the service binds ciphertexts to the
// record id), so a duplicated record keeps only its masked item.
func copyWithNewID(nr evidencedom.NewRecord, findingID shared.ID) evidencedom.NewRecord {
	out := nr
	out.Record.ID = shared.NewID()
	out.Record.FindingID = findingID
	out.Record.MaskedCount = 0
	out.Record.Placeholders = nil
	out.Record.SecretsExpireAt = nil
	out.Secrets = nil
	return out
}

// InsertForFinding stores records for one finding and prunes its retest records.
func (r *FindingEvidenceRepository) InsertForFinding(ctx context.Context, tenantID, findingID shared.ID, recs []evidencedom.NewRecord) error {
	if len(recs) == 0 {
		return nil
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM findings WHERE tenant_id = $1 AND id = $2)`,
			tenantID.String(), findingID.String()).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return evidencedom.ErrNotFound
		}
		for _, nr := range recs {
			nr.Record.FindingID = findingID
			if err := insertEvidence(ctx, tx, tenantID, nr); err != nil {
				return err
			}
		}
		return pruneEvidence(ctx, tx, tenantID, []string{findingID.String()}, evidencedom.OriginRetest, evidencedom.MaxRetestPerFinding)
	})
}

func insertEvidence(ctx context.Context, tx *sql.Tx, tenantID shared.ID, nr evidencedom.NewRecord) error {
	rec := nr.Record
	content, err := json.Marshal(rec.Item)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	var retestID any
	if rec.RetestID != nil {
		retestID = rec.RetestID.String()
	}
	placeholders := rec.Placeholders
	if placeholders == nil {
		placeholders = []string{}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO finding_evidence (id, tenant_id, finding_id, retest_id, origin, kind, tool_name, rule_id,
			template_digest, content, content_sha256, size_bytes, truncated, masked_count, placeholders,
			secrets_expire_at, captured_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10, $11, $12, $13, $14, $15, $16, $17)`,
		rec.ID.String(), tenantID.String(), rec.FindingID.String(), retestID, string(rec.Origin), rec.Kind,
		rec.ToolName, rec.RuleID, rec.TemplateDigest, content, rec.ContentSHA256, len(content), rec.Truncated,
		rec.MaskedCount, pq.Array(placeholders), rec.SecretsExpireAt, rec.CapturedAt)
	if err != nil {
		return fmt.Errorf("insert evidence: %w", err)
	}
	for _, s := range nr.Secrets {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_evidence_secrets (tenant_id, evidence_id, placeholder, secret_kind, ciphertext, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			tenantID.String(), rec.ID.String(), s.Placeholder, s.Kind, s.Ciphertext, s.ExpiresAt); err != nil {
			return fmt.Errorf("insert evidence secret: %w", err)
		}
	}
	return nil
}

// pruneEvidence keeps the newest keep records of origin per finding.
func pruneEvidence(ctx context.Context, tx *sql.Tx, tenantID shared.ID, findingIDs []string, origin evidencedom.Origin, keep int) error {
	if len(findingIDs) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		DELETE FROM finding_evidence e
		USING (
			SELECT id FROM (
				SELECT id, row_number() OVER (PARTITION BY finding_id ORDER BY created_at DESC, id DESC) AS rn
				FROM finding_evidence
				WHERE tenant_id = $1 AND finding_id = ANY($2::uuid[]) AND origin = $3
			) ranked WHERE rn > $4
		) old
		WHERE e.tenant_id = $1 AND e.id = old.id`,
		tenantID.String(), pq.Array(findingIDs), string(origin), keep)
	if err != nil {
		return fmt.Errorf("prune evidence: %w", err)
	}
	return nil
}

const evidenceColumns = `id, tenant_id, finding_id, retest_id, origin, kind, COALESCE(tool_name, ''), COALESCE(rule_id, ''),
	COALESCE(template_digest, ''), content, content_sha256, size_bytes, truncated, masked_count, placeholders,
	secrets_expire_at, captured_at, created_at`

// List returns a finding's records, newest first.
func (r *FindingEvidenceRepository) List(ctx context.Context, tenantID, findingID shared.ID, retestID *shared.ID, limit int) ([]*evidencedom.Record, error) {
	if limit <= 0 || limit > evidencedom.MaxListItems {
		limit = evidencedom.MaxListItems
	}
	q := `SELECT ` + evidenceColumns + ` FROM finding_evidence WHERE tenant_id = $1 AND finding_id = $2`
	args := []any{tenantID.String(), findingID.String()}
	if retestID != nil {
		q += ` AND retest_id = $3`
		args = append(args, retestID.String())
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT %d`, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*evidencedom.Record, 0)
	for rows.Next() {
		rec, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Get returns one record of a finding.
func (r *FindingEvidenceRepository) Get(ctx context.Context, tenantID, findingID, id shared.ID) (*evidencedom.Record, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+evidenceColumns+` FROM finding_evidence
		WHERE tenant_id = $1 AND finding_id = $2 AND id = $3`, tenantID.String(), findingID.String(), id.String())
	rec, err := scanEvidence(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, evidencedom.ErrNotFound
	}
	return rec, err
}

type evidenceScanner interface {
	Scan(dest ...any) error
}

func scanEvidence(s evidenceScanner) (*evidencedom.Record, error) {
	var (
		rec                 evidencedom.Record
		id, tenant, finding string
		retest              sql.NullString
		origin              string
		content             []byte
		placeholders        pq.StringArray
		expires             sql.NullTime
	)
	if err := s.Scan(&id, &tenant, &finding, &retest, &origin, &rec.Kind, &rec.ToolName, &rec.RuleID,
		&rec.TemplateDigest, &content, &rec.ContentSHA256, &rec.SizeBytes, &rec.Truncated, &rec.MaskedCount,
		&placeholders, &expires, &rec.CapturedAt, &rec.CreatedAt); err != nil {
		return nil, err
	}
	rec.ID, _ = shared.IDFromString(id)
	rec.TenantID, _ = shared.IDFromString(tenant)
	rec.FindingID, _ = shared.IDFromString(finding)
	if retest.Valid {
		rid, err := shared.IDFromString(retest.String)
		if err == nil {
			rec.RetestID = &rid
		}
	}
	rec.Origin = evidencedom.Origin(origin)
	if err := json.Unmarshal(content, &rec.Item); err != nil {
		return nil, fmt.Errorf("decode evidence: %w", err)
	}
	rec.Placeholders = placeholders
	if expires.Valid {
		t := expires.Time
		rec.SecretsExpireAt = &t
	}
	return &rec, nil
}

// Secrets returns the stored, unexpired secrets of a record.
func (r *FindingEvidenceRepository) Secrets(ctx context.Context, tenantID, evidenceID shared.ID, placeholders []string) ([]evidencedom.StoredSecret, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT placeholder, secret_kind, ciphertext, expires_at
		FROM finding_evidence_secrets
		WHERE tenant_id = $1 AND evidence_id = $2 AND placeholder = ANY($3) AND expires_at > now()`,
		tenantID.String(), evidenceID.String(), pq.Array(placeholders))
	if err != nil {
		return nil, fmt.Errorf("read evidence secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]evidencedom.StoredSecret, 0, len(placeholders))
	for rows.Next() {
		var s evidencedom.StoredSecret
		if err := rows.Scan(&s.Placeholder, &s.Kind, &s.Ciphertext, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// CountSince counts a tenant's records created since t.
func (r *FindingEvidenceRepository) CountSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_evidence WHERE tenant_id = $1 AND created_at >= $2`,
		tenantID.String(), t).Scan(&n)
	return n, err
}

// DeleteExpired deletes expired secrets (and clears their records' reveal
// state) and records older than the retention. A maintenance sweep across
// tenants by design: it only deletes by age.
func (r *FindingEvidenceRepository) DeleteExpired(ctx context.Context, now time.Time, retention time.Duration) (int64, int64, error) {
	var secrets, records int64
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM finding_evidence_secrets WHERE expires_at <= $1`, now)
		if err != nil {
			return fmt.Errorf("delete expired evidence secrets: %w", err)
		}
		secrets, _ = res.RowsAffected()
		if _, err := tx.ExecContext(ctx, `
			UPDATE finding_evidence SET masked_count = 0, placeholders = '{}'
			WHERE secrets_expire_at <= $1 AND masked_count > 0`, now); err != nil {
			return fmt.Errorf("clear expired evidence reveal state: %w", err)
		}
		res, err = tx.ExecContext(ctx, `DELETE FROM finding_evidence WHERE created_at < $1`, now.Add(-retention))
		if err != nil {
			return fmt.Errorf("delete old evidence: %w", err)
		}
		records, _ = res.RowsAffected()
		return nil
	})
	return secrets, records, err
}
