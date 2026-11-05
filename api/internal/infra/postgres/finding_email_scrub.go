package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// E-mail addresses are personal data the platform never stores
// (research/292). Ingest masks them in every finding's text and evidence
// before anything is stored (internal/app/ingest/email_mask.go, Mask in
// pkg/domain/evidence); ScrubStoredEmails applies the same masking to the rows
// stored before that: the local part becomes "***", the domain is kept
// (safetext.MaskEmails). It is run by `refingerprint -mask-emails`.
//
// What it changes, and only when the value changes:
//
//   - findings: the descriptive columns in emailScrubColumns of the findings a
//     tool reported (human-reported findings are left as their author wrote
//     them, and counted). Identifiers are never touched: id, fingerprint,
//     partial_fingerprints, identity_key, identity_fields, location_key,
//     correlation_id, rule_id, tool names, CVE ids, file_path, asset refs,
//     work_item_uris. In a jsonb column only values change, never keys.
//     Status is not written; updated_at and row_version move with the row
//     (the BEFORE UPDATE triggers), so a stale edit cannot write the address
//     back and readers that sync by updated_at fetch the masked text.
//   - finding_evidence.content: the stored item, masked like Mask masks a new
//     item (evidence.MaskItemEmails), and size_bytes. content_sha256 (the
//     hash of the item before masking) and the finding's evidence_version
//     stay, so a pentest write-up stays current.
//
// Every statement is scoped to one tenant. Rows are read in id order, in
// batches; an applying batch locks the rows it re-reads (skipping rows
// another transaction holds, which a rerun picks up) and commits on its
// own, so a crash leaves whole batches done. Idempotent: a masked address is
// not an address, so a second run changes nothing.

// emailColumnKind is how a findings column holds text.
type emailColumnKind int

const (
	emailColText emailColumnKind = iota
	emailColTextArray
	emailColJSON
)

// emailScrubColumn is one findings column the scrub masks.
type emailScrubColumn struct {
	name string
	kind emailColumnKind
}

// emailScrubColumns are the findings columns that hold what a tool
// described, which the ingest walker now masks. A column left out is either
// an identifier (it binds the finding to its key, its asset, its tool or an
// external record: id, fingerprint, partial_fingerprints, identity_key,
// identity_fields, location_key, correlation_id, rule_id, tool_name,
// cve_id(s), file_path, misconfig_resource_*, native_*, template_*,
// work_item_uris, related_issue_url, related_pr_url, hosted_viewer_uri,
// source_meta, vulnerability_ids), the tool's vocabulary (rule_name, cwe and
// owasp ids, vulnerability_class, subcategory, compliance_*, secret_type,
// web3_*, asvs_*, mitre_*: names of checks, not observed data), or written by
// a person or the platform rather than ingest (resolution, the override and
// priority reasons, vex_*, attachments).
var emailScrubColumns = []emailScrubColumn{ //nolint:gochecknoglobals // static table
	{"title", emailColText}, //nolint:goconst // a column name of this table
	{"message", emailColText},
	{"description", emailColText},
	{"snippet", emailColText},         // matched source text
	{"context_snippet", emailColText}, // the lines around it
	{"attack_prerequisites", emailColText},
	{"misconfig_expected", emailColText},
	{"misconfig_actual", emailColText},
	{"scanner_output", emailColText},    // the tool's raw output
	{"tags", emailColTextArray},         // the report's tags
	{"remediation", emailColJSON},       // guidance text
	{"metadata", emailColJSON},          // the report's properties
	{"source_extra", emailColJSON},      // members the platform keeps as given
	{"type_details", emailColJSON},      //nolint:goconst // vulnerability, secret, compliance details
	{"related_locations", emailColJSON}, // further locations and their messages
	{"stacks", emailColJSON},            // stack frames and their messages
}

// humanFindingSQL: a person reported the finding (the sources nothing
// re-runs, a manual channel, a pentest campaign). Ingest masking never
// applied to what a person writes, so the scrub leaves it.
const humanFindingSQL = `COALESCE(source IN ('manual', 'pentest', 'bug_bounty', 'red_team')
	OR ingest_channel IS NOT DISTINCT FROM 'manual' OR pentest_campaign_id IS NOT NULL, false)`

// EmailScrubReport is the outcome of ScrubStoredEmails for one tenant. Counts
// only: never an address, a value or a row id.
type EmailScrubReport struct {
	TenantID string `json:"tenant_id"`
	Applied  bool   `json:"applied"`
	// FindingsRead counts the findings with an "@" or "%40" in a scrubbed
	// column that were read.
	FindingsRead int `json:"findings_read"`
	// FindingsMasked counts the findings that changed (a dry run: would).
	FindingsMasked int `json:"findings_masked"`
	// Columns counts, per column, the findings whose column changed.
	Columns map[string]int `json:"columns"`
	// HumanFindingsLeft counts the human-reported findings that hold an
	// address and are left as written.
	HumanFindingsLeft int `json:"human_findings_left"`
	EvidenceRead      int `json:"evidence_read"`
	// EvidenceMasked counts the evidence items that changed.
	EvidenceMasked int `json:"evidence_masked"`
	// EvidenceUnreadable counts the items whose stored content does not read
	// back as an item without loss (a shape this release does not know); they
	// are left, never rewritten partially.
	EvidenceUnreadable int `json:"evidence_unreadable"`
	// Remaining counts the rows an applying batch skipped because another
	// transaction held them: run it again.
	Remaining int `json:"remaining"`
}

// EmailScrubTenants lists every tenant, in id order, but the platform's
// reserved system tenant (the nil id): it is no organization, holds no
// reported findings, and an audit entry needs a real tenant.
func EmailScrubTenants(ctx context.Context, db *sql.DB) ([]shared.ID, error) {
	rows, err := db.QueryContext(ctx, `SELECT id FROM tenants WHERE id <> $1::uuid ORDER BY id`, uuidBeforeAll)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
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

// ScrubStoredEmails masks the e-mail addresses left in one tenant's findings
// and evidence (see the file comment). A dry run (apply false) reads and
// counts only.
func ScrubStoredEmails(ctx context.Context, db *sql.DB, tenantID shared.ID, apply bool, batchSize int) (*EmailScrubReport, error) {
	if batchSize <= 0 {
		return nil, fmt.Errorf("batch size must be positive")
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("a tenant is required")
	}
	rep := &EmailScrubReport{TenantID: tenantID.String(), Applied: apply, Columns: map[string]int{}}
	if err := scrubPages(ctx, db, tenantID, findingEmailCandidatesSQL, batchSize, func(ids []string) error {
		return scrubFindingBatch(ctx, db, tenantID, ids, apply, rep)
	}); err != nil {
		return rep, fmt.Errorf("findings: %w", err)
	}
	if err := scrubPages(ctx, db, tenantID, evidenceEmailCandidatesSQL, batchSize, func(ids []string) error {
		return scrubEvidenceBatch(ctx, db, tenantID, ids, apply, rep)
	}); err != nil {
		return rep, fmt.Errorf("evidence: %w", err)
	}
	return rep, nil
}

// findingEmailText is every scrubbed column as one text, to find the rows
// that may hold an address (a superset: jsonb text includes keys).
func findingEmailText() string {
	parts := make([]string, 0, len(emailScrubColumns))
	for _, c := range emailScrubColumns {
		switch c.kind {
		case emailColText:
			parts = append(parts, c.name)
		case emailColTextArray:
			parts = append(parts, "array_to_string("+c.name+", ' ')")
		case emailColJSON:
			parts = append(parts, c.name+"::text")
		}
	}
	return "concat_ws(' ', " + strings.Join(parts, ", ") + ")"
}

// The candidate statements take the tenant, the last id of the previous page
// and the page size. Only an "@" or a "%40" can be part of an address
// MaskEmails masks; an evidence body in base64 is read whatever it holds.
var ( //nolint:gochecknoglobals // SQL built once from the column table
	findingEmailCandidatesSQL = `
		SELECT id FROM findings
		WHERE tenant_id = $1::uuid AND id > $2::uuid
		  AND (strpos(` + findingEmailText() + `, '@') > 0 OR strpos(` + findingEmailText() + `, '%40') > 0)
		ORDER BY id LIMIT $3`
	evidenceEmailCandidatesSQL = `
		SELECT id FROM finding_evidence
		WHERE tenant_id = $1::uuid AND id > $2::uuid
		  AND (strpos(content::text, '@') > 0 OR strpos(content::text, '%40') > 0
		       OR content->'http'->'request'->>'body_encoding' = 'base64'
		       OR content->'http'->'response'->>'body_encoding' = 'base64')
		ORDER BY id LIMIT $3`
)

// scrubPages walks the candidate ids of one tenant in id order (keyset
// pagination) and hands each page to fn.
func scrubPages(ctx context.Context, db *sql.DB, tenantID shared.ID, query string, batchSize int, fn func(ids []string) error) error {
	after := uuidBeforeAll
	for {
		ids, err := candidatePage(ctx, db, query, tenantID, after, batchSize)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if err := fn(ids); err != nil {
			return err
		}
		if len(ids) < batchSize {
			return nil
		}
		after = ids[len(ids)-1]
	}
}

func candidatePage(ctx context.Context, db *sql.DB, query string, tenantID shared.ID, after string, batchSize int) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, tenantID.String(), after, batchSize)
	if err != nil {
		return nil, fmt.Errorf("list candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	ids := make([]string, 0, batchSize)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// scrubQueryer is a connection or a transaction.
type scrubQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// inBatchTx runs fn in one transaction when apply is set (the rows are
// locked), and on the read-only connection otherwise.
func inBatchTx(ctx context.Context, db *sql.DB, apply bool, fn func(q scrubQueryer, tx *sql.Tx) error) error {
	if !apply {
		return fn(db, nil)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// lockClause locks the re-read rows of an applying batch.
func lockClause(apply bool) string {
	if apply {
		return " FOR NO KEY UPDATE SKIP LOCKED"
	}
	return ""
}

func findingScrubSelectSQL(apply bool) string {
	cols := make([]string, 0, len(emailScrubColumns))
	for _, c := range emailScrubColumns {
		cols = append(cols, c.name)
	}
	return `SELECT id, ` + humanFindingSQL + `, ` + strings.Join(cols, ", ") + `
		FROM findings WHERE tenant_id = $1::uuid AND id = ANY($2::uuid[])
		ORDER BY id` + lockClause(apply)
}

// emailScrubValue is one scanned column value.
type emailScrubValue struct {
	text  sql.NullString
	array []sql.NullString // NULL elements are kept
	json  []byte
}

func (v *emailScrubValue) dest(kind emailColumnKind) any {
	switch kind {
	case emailColTextArray:
		return pq.Array(&v.array)
	case emailColJSON:
		return &v.json
	default:
		return &v.text
	}
}

// mask masks the value in place and reports whether it changed.
func (v *emailScrubValue) mask(kind emailColumnKind) (bool, error) {
	switch kind {
	case emailColTextArray:
		changed := false
		for i, s := range v.array {
			if m := safetext.MaskEmails(s.String); s.Valid && m != s.String {
				v.array[i].String, changed = m, true
			}
		}
		return changed, nil
	case emailColJSON:
		if v.json == nil {
			return false, nil
		}
		out, changed, err := safetext.MaskEmailsJSON(v.json)
		if err != nil {
			return false, err
		}
		v.json = out
		return changed, nil
	default:
		if !v.text.Valid {
			return false, nil
		}
		m := safetext.MaskEmails(v.text.String)
		changed := m != v.text.String
		v.text.String = m
		return changed, nil
	}
}

// arg is the value to write.
func (v *emailScrubValue) arg(kind emailColumnKind) any {
	switch kind {
	case emailColTextArray:
		return pq.Array(v.array)
	case emailColJSON:
		return string(v.json)
	default:
		return v.text.String
	}
}

// findingScrub is one finding whose scrubbed columns changed.
type findingScrub struct {
	id   string
	vals []emailScrubValue
	cols []int
}

func scrubFindingBatch(ctx context.Context, db *sql.DB, tenantID shared.ID, ids []string, apply bool, rep *EmailScrubReport) error {
	return inBatchTx(ctx, db, apply, func(q scrubQueryer, tx *sql.Tx) error {
		changes, read, err := readFindingScrubs(ctx, q, tenantID, ids, apply, rep)
		if err != nil {
			return err
		}
		rep.FindingsRead += read
		if apply {
			rep.Remaining += len(ids) - read
		}
		for _, ch := range changes {
			if apply {
				if err := writeFindingScrub(ctx, tx, tenantID, ch.id, ch.vals, ch.cols); err != nil {
					return err
				}
			}
			rep.FindingsMasked++
			for _, i := range ch.cols {
				rep.Columns[emailScrubColumns[i].name]++
			}
		}
		return nil
	})
}

// readFindingScrubs reads (an applying batch: locks) the findings of ids and
// masks them in memory. It returns the tool-reported findings that changed
// and how many rows it read; a human-reported finding that would change is
// only counted.
func readFindingScrubs(ctx context.Context, q scrubQueryer, tenantID shared.ID, ids []string, apply bool, rep *EmailScrubReport) ([]findingScrub, int, error) {
	rows, err := q.QueryContext(ctx, findingScrubSelectSQL(apply), tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, 0, fmt.Errorf("read findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var changes []findingScrub
	read := 0
	for rows.Next() {
		read++
		var id string
		var human bool
		vals := make([]emailScrubValue, len(emailScrubColumns))
		dest := make([]any, 0, len(emailScrubColumns)+2)
		dest = append(dest, &id, &human)
		for i, c := range emailScrubColumns {
			dest = append(dest, vals[i].dest(c.kind))
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, 0, fmt.Errorf("scan finding: %w", err)
		}
		cols := make([]int, 0, len(emailScrubColumns))
		for i, c := range emailScrubColumns {
			changed, err := vals[i].mask(c.kind)
			if err != nil {
				return nil, 0, fmt.Errorf("finding column %s: %w", c.name, err)
			}
			if changed {
				cols = append(cols, i)
			}
		}
		switch {
		case len(cols) == 0:
		case human:
			rep.HumanFindingsLeft++
		default:
			changes = append(changes, findingScrub{id: id, vals: vals, cols: cols})
		}
	}
	return changes, read, rows.Err()
}

// writeFindingScrub writes the changed columns of one finding, and nothing
// else.
func writeFindingScrub(ctx context.Context, tx *sql.Tx, tenantID shared.ID, id string, vals []emailScrubValue, cols []int) error {
	sets := make([]string, 0, len(cols))
	args := make([]any, 0, len(cols)+2)
	args = append(args, tenantID.String(), id)
	for _, i := range cols {
		c := emailScrubColumns[i]
		args = append(args, vals[i].arg(c.kind))
		p := "$" + strconv.Itoa(len(args))
		if c.kind == emailColJSON {
			p += "::jsonb"
		}
		sets = append(sets, c.name+" = "+p)
	}
	//nolint:gosec // G202: sets names only columns of the fixed emailScrubColumns table, values are placeholders
	res, err := tx.ExecContext(ctx, `UPDATE findings SET `+strings.Join(sets, ", ")+`
		WHERE tenant_id = $1::uuid AND id = $2::uuid`, args...)
	if err != nil {
		return fmt.Errorf("update finding: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("update finding: %d rows", n)
	}
	return nil
}

// evidenceScrub is one evidence item whose content changed.
type evidenceScrub struct {
	id      string
	content []byte
}

func scrubEvidenceBatch(ctx context.Context, db *sql.DB, tenantID shared.ID, ids []string, apply bool, rep *EmailScrubReport) error {
	return inBatchTx(ctx, db, apply, func(q scrubQueryer, tx *sql.Tx) error {
		changes, read, err := readEvidenceScrubs(ctx, q, tenantID, ids, apply, rep)
		if err != nil {
			return err
		}
		rep.EvidenceRead += read
		if apply {
			rep.Remaining += len(ids) - read
		}
		for _, ch := range changes {
			if apply {
				res, err := tx.ExecContext(ctx, `UPDATE finding_evidence SET content = $3::jsonb, size_bytes = $4
					WHERE tenant_id = $1::uuid AND id = $2::uuid`,
					tenantID.String(), ch.id, string(ch.content), len(ch.content))
				if err != nil {
					return fmt.Errorf("update evidence: %w", err)
				}
				if n, _ := res.RowsAffected(); n != 1 {
					return fmt.Errorf("update evidence: %d rows", n)
				}
			}
			rep.EvidenceMasked++
		}
		return nil
	})
}

// readEvidenceScrubs reads (an applying batch: locks) the evidence items of
// ids and masks them in memory. It returns the items that changed and how
// many rows it read; an item it cannot read without loss is only counted.
func readEvidenceScrubs(ctx context.Context, q scrubQueryer, tenantID shared.ID, ids []string, apply bool, rep *EmailScrubReport) ([]evidenceScrub, int, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, content FROM finding_evidence
		WHERE tenant_id = $1::uuid AND id = ANY($2::uuid[])
		ORDER BY id`+lockClause(apply), tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, 0, fmt.Errorf("read evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var changes []evidenceScrub
	read := 0
	for rows.Next() {
		read++
		var id string
		var content []byte
		if err := rows.Scan(&id, &content); err != nil {
			return nil, 0, fmt.Errorf("scan evidence: %w", err)
		}
		out, changed, err := maskEvidenceContent(content)
		switch {
		case errors.Is(err, errEvidenceShape):
			rep.EvidenceUnreadable++
		case err != nil:
			return nil, 0, err
		case changed:
			changes = append(changes, evidenceScrub{id: id, content: out})
		}
	}
	return changes, read, rows.Err()
}

// errEvidenceShape: the stored content does not read back as an item
// without loss.
var errEvidenceShape = errors.New("evidence content is not an item this release reads without loss")

// maskEvidenceContent masks a stored evidence item (evidence.MaskItemEmails)
// and returns it encoded as the evidence store writes it (size_bytes is its
// length). Content that would lose a member by passing through the item type
// is refused with errEvidenceShape rather than rewritten.
func maskEvidenceContent(content []byte) ([]byte, bool, error) {
	var it evidence.Item
	if err := json.Unmarshal(content, &it); err != nil {
		return nil, false, errEvidenceShape
	}
	same, err := json.Marshal(it)
	if err != nil {
		return nil, false, fmt.Errorf("encode evidence: %w", err)
	}
	if !sameJSON(same, content) {
		return nil, false, errEvidenceShape
	}
	if !evidence.MaskItemEmails(&it) {
		return nil, false, nil
	}
	out, err := json.Marshal(it)
	if err != nil {
		return nil, false, fmt.Errorf("encode evidence: %w", err)
	}
	return out, true, nil
}

// sameJSON reports whether two JSON documents hold the same value.
func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
