package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/aiknowledge"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIKnowledgeRepository stores the knowledge organizations give their AI
// agents (docs/architecture/ai-knowledge.md). Every statement filters on
// tenant_id; composite foreign keys keep every child row in its parent's
// organization.
type AIKnowledgeRepository struct {
	db *DB
}

// NewAIKnowledgeRepository creates the repository.
func NewAIKnowledgeRepository(db *DB) *AIKnowledgeRepository {
	return &AIKnowledgeRepository{db: db}
}

var _ aiknowledge.Repository = (*AIKnowledgeRepository)(nil)

// teamMemberSQL is true when user $member is an active member of one of the
// source's teams ($tenant is the organization). Used for the AI agent's own
// scope (search) and for a viewer (citations).
const knowledgeTeamMemberSQL = `EXISTS (
	SELECT 1 FROM ai_knowledge_source_teams st
	JOIN groups g ON g.id = st.group_id AND g.tenant_id = st.tenant_id AND g.is_active
	JOIN group_members gm ON gm.group_id = st.group_id AND (gm.expires_at IS NULL OR gm.expires_at > now())
	WHERE st.tenant_id = s.tenant_id AND st.source_id = s.id AND gm.user_id = %s)`

const knowledgeSourceColumns = `s.id, s.tenant_id, s.name, s.description, s.origin, s.visibility, s.data_class, s.status,
	s.created_by, s.decided_by, s.decided_at, s.self_approved, COALESCE(s.rejected_reason, ''), s.created_at, s.updated_at,
	COALESCE((SELECT array_agg(st.group_id ORDER BY st.group_id) FROM ai_knowledge_source_teams st
	          WHERE st.tenant_id = s.tenant_id AND st.source_id = s.id), '{}'),
	(SELECT count(*) FROM ai_knowledge_documents d WHERE d.tenant_id = s.tenant_id AND d.source_id = s.id
	     AND d.status IN ('approved', 'pending')),
	(SELECT count(*) FROM ai_knowledge_documents d WHERE d.tenant_id = s.tenant_id AND d.source_id = s.id
	     AND d.status = 'pending'),
	(SELECT COALESCE(sum(d.bytes), 0) FROM ai_knowledge_documents d WHERE d.tenant_id = s.tenant_id
	     AND d.source_id = s.id AND d.status IN ('approved', 'pending'))`

func scanKnowledgeSource(row interface{ Scan(...any) error }) (*aiknowledge.Source, error) {
	var s aiknowledge.Source
	var createdBy, decidedBy sql.NullString
	var decidedAt sql.NullTime
	var teams []string
	if err := row.Scan(&s.ID, &s.TenantID, &s.Name, &s.Description, &s.Origin, &s.Visibility, &s.Class, &s.Status,
		&createdBy, &decidedBy, &decidedAt, &s.SelfApproved, &s.RejectedReason, &s.CreatedAt, &s.UpdatedAt,
		pq.Array(&teams), &s.Documents, &s.PendingDocuments, &s.Bytes); err != nil {
		return nil, err
	}
	s.CreatedBy, s.DecidedBy, s.DecidedAt = parseNullID(createdBy), parseNullID(decidedBy), nullTimeValue(decidedAt)
	for _, t := range teams {
		if id, err := shared.IDFromString(t); err == nil {
			s.TeamIDs = append(s.TeamIDs, id)
		}
	}
	return &s, nil
}

// CreateSource stores a pending source and its teams in one transaction.
func (r *AIKnowledgeRepository) CreateSource(ctx context.Context, s *aiknowledge.Source) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ai_knowledge_sources (id, tenant_id, name, description, origin, visibility, data_class, status, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)`,
		s.ID, s.TenantID, s.Name, s.Description, s.Origin, s.Visibility, s.Class, nullID(s.CreatedBy)); err != nil {
		if isUniqueViolation(err) {
			return aiknowledge.ErrNameTaken
		}
		if isCheckViolation(err) {
			return fmt.Errorf("%w: knowledge source", shared.ErrValidation)
		}
		return fmt.Errorf("insert knowledge source: %w", err)
	}
	for _, g := range s.TeamIDs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ai_knowledge_source_teams (tenant_id, source_id, group_id) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, s.TenantID, s.ID, g); err != nil {
			if isCheckViolation(err) {
				return fmt.Errorf("%w: team is not in this organization", shared.ErrValidation)
			}
			return fmt.Errorf("insert knowledge source team: %w", err)
		}
	}
	return tx.Commit()
}

// GetSource reads one source of the tenant with its counts.
func (r *AIKnowledgeRepository) GetSource(ctx context.Context, tenantID, id shared.ID) (*aiknowledge.Source, error) {
	s, err := scanKnowledgeSource(r.db.QueryRowContext(ctx,
		`SELECT `+knowledgeSourceColumns+` FROM ai_knowledge_sources s WHERE s.tenant_id = $1 AND s.id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aiknowledge.ErrSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get knowledge source: %w", err)
	}
	return s, nil
}

// ListSources lists the tenant's sources by name (bounded by the source
// quota).
func (r *AIKnowledgeRepository) ListSources(ctx context.Context, tenantID shared.ID) ([]*aiknowledge.Source, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+knowledgeSourceColumns+` FROM ai_knowledge_sources s
		WHERE s.tenant_id = $1 ORDER BY lower(s.name) LIMIT 500`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list knowledge sources: %w", err)
	}
	defer rows.Close()
	var out []*aiknowledge.Source
	for rows.Next() {
		s, err := scanKnowledgeSource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan knowledge source: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateSourceText changes a source's name and description.
func (r *AIKnowledgeRepository) UpdateSourceText(ctx context.Context, tenantID, id shared.ID, name, description string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ai_knowledge_sources SET name = $3, description = $4, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, name, description)
	if err != nil {
		if isUniqueViolation(err) {
			return aiknowledge.ErrNameTaken
		}
		return fmt.Errorf("update knowledge source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aiknowledge.ErrSourceNotFound
	}
	return nil
}

// DeleteSource removes a source; its documents, chunks and teams cascade.
func (r *AIKnowledgeRepository) DeleteSource(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ai_knowledge_sources WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("delete knowledge source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aiknowledge.ErrSourceNotFound
	}
	return nil
}

func sourceStatusStrings(in []aiknowledge.SourceStatus) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, string(s))
	}
	return out
}

// Decide moves a source to a new status and, on approval, approves its
// pending document versions (superseding the versions they replace).
func (r *AIKnowledgeRepository) Decide(ctx context.Context, tenantID, id shared.ID, from []aiknowledge.SourceStatus,
	to aiknowledge.SourceStatus, by shared.ID, selfApproved bool, reason string, ackQuarantine bool,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var cur string
	err = tx.QueryRowContext(ctx, `SELECT status FROM ai_knowledge_sources WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenantID, id).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return aiknowledge.ErrSourceNotFound
	}
	if err != nil {
		return fmt.Errorf("lock knowledge source: %w", err)
	}
	allowed := false
	for _, f := range from {
		allowed = allowed || string(f) == cur
	}
	if !allowed {
		return aiknowledge.ErrStateChanged
	}
	if to == aiknowledge.SourceApproved {
		approved, err := approvePendingVersions(ctx, tx, tenantID, id, by, ackQuarantine)
		if err != nil {
			return err
		}
		if approved == 0 && cur == string(aiknowledge.SourceApproved) {
			return aiknowledge.ErrNotPending
		}
	}
	if to == aiknowledge.SourceRejected {
		if _, err := tx.ExecContext(ctx, `UPDATE ai_knowledge_documents SET status = 'rejected', decided_by = $3,
			decided_at = now(), updated_at = now()
			WHERE tenant_id = $1 AND source_id = $2 AND status = 'pending'`, tenantID, id, by); err != nil {
			return fmt.Errorf("reject pending versions: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ai_knowledge_sources SET status = $3, decided_by = $4, decided_at = now(),
		self_approved = $5, rejected_reason = $6, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND status = ANY($7::text[])`,
		tenantID, id, to, by, selfApproved, nullString(reason), pq.Array(sourceStatusStrings(from))); err != nil {
		return fmt.Errorf("decide knowledge source: %w", err)
	}
	return tx.Commit()
}

func approvePendingVersions(ctx context.Context, tx *sql.Tx, tenantID, sourceID, by shared.ID, ackQuarantine bool) (int64, error) {
	// The versions replaced by a pending one stop serving first (one
	// approved version per lineage), then the pending ones are approved.
	if _, err := tx.ExecContext(ctx, `
		UPDATE ai_knowledge_documents old SET status = 'superseded', updated_at = now()
		WHERE old.tenant_id = $1 AND old.source_id = $2 AND old.status = 'approved'
		  AND EXISTS (SELECT 1 FROM ai_knowledge_documents p WHERE p.tenant_id = old.tenant_id
		              AND p.lineage_id = old.lineage_id AND p.status = 'pending' AND (NOT p.quarantined OR $3))`,
		tenantID, sourceID, ackQuarantine); err != nil {
		return 0, fmt.Errorf("supersede versions: %w", err)
	}
	// Two pending versions of one lineage: only the latest is approved, the
	// older ones are superseded.
	if _, err := tx.ExecContext(ctx, `
		UPDATE ai_knowledge_documents p SET status = 'superseded', updated_at = now()
		WHERE p.tenant_id = $1 AND p.source_id = $2 AND p.status = 'pending'
		  AND EXISTS (SELECT 1 FROM ai_knowledge_documents n WHERE n.tenant_id = p.tenant_id
		              AND n.lineage_id = p.lineage_id AND n.status = 'pending' AND n.version > p.version
		              AND (NOT n.quarantined OR $3))`,
		tenantID, sourceID, ackQuarantine); err != nil {
		return 0, fmt.Errorf("supersede older pending versions: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE ai_knowledge_documents SET status = 'approved', decided_by = $3, decided_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND source_id = $2 AND status = 'pending' AND (NOT quarantined OR $4)`,
		tenantID, sourceID, by, ackQuarantine)
	if err != nil {
		return 0, fmt.Errorf("approve versions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RejectPending rejects a source's pending versions.
func (r *AIKnowledgeRepository) RejectPending(ctx context.Context, tenantID, id, by shared.ID) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ai_knowledge_documents SET status = 'rejected', decided_by = $3,
		decided_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND source_id = $2 AND status = 'pending'`, tenantID, id, by)
	if err != nil {
		return fmt.Errorf("reject pending versions: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aiknowledge.ErrNotPending
	}
	return nil
}

// Usage counts the tenant's sources, live documents and bytes.
func (r *AIKnowledgeRepository) Usage(ctx context.Context, tenantID shared.ID) (aiknowledge.Usage, error) {
	var u aiknowledge.Usage
	err := r.db.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM ai_knowledge_sources WHERE tenant_id = $1),
		       (SELECT count(*) FROM ai_knowledge_documents WHERE tenant_id = $1 AND status IN ('approved', 'pending')),
		       (SELECT COALESCE(sum(bytes), 0) FROM ai_knowledge_documents WHERE tenant_id = $1 AND status IN ('approved', 'pending'))`,
		tenantID).Scan(&u.Sources, &u.Documents, &u.Bytes)
	if err != nil {
		return u, fmt.Errorf("knowledge usage: %w", err)
	}
	return u, nil
}

// AddDocument stores a pending version and its chunks in one transaction.
func (r *AIKnowledgeRepository) AddDocument(ctx context.Context, in aiknowledge.NewDocument) error {
	d := in.Document
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if d.LineageID.IsZero() {
		d.LineageID, d.Version = d.ID, 1
	} else {
		// Lock the lineage (any version row) so two edits get distinct versions.
		var maxVersion int
		err := tx.QueryRowContext(ctx, `
			SELECT max(version) FROM (
			    SELECT version FROM ai_knowledge_documents
			    WHERE tenant_id = $1 AND source_id = $2 AND lineage_id = $3 FOR UPDATE) v`,
			d.TenantID, d.SourceID, d.LineageID).Scan(&maxVersion)
		if err != nil || maxVersion == 0 {
			return aiknowledge.ErrDocumentNotFound
		}
		d.Version = maxVersion + 1
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ai_knowledge_documents (id, tenant_id, source_id, lineage_id, version, title, status, quarantined,
			quarantine_reason, content_sha256, bytes, chunks, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, $10, $11, $12)`,
		d.ID, d.TenantID, d.SourceID, d.LineageID, d.Version, d.Title, d.Quarantined, nullString(d.QuarantineReason),
		d.ContentSHA256, d.Bytes, len(in.Chunks), nullID(d.CreatedBy)); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return aiknowledge.ErrSourceNotFound
		}
		if isCheckViolation(err) {
			return fmt.Errorf("%w: knowledge document", shared.ErrValidation)
		}
		return fmt.Errorf("insert knowledge document: %w", err)
	}
	if len(in.Chunks) > 0 {
		ords := make([]int64, 0, len(in.Chunks))
		titles := make([]string, 0, len(in.Chunks))
		bodies := make([]string, 0, len(in.Chunks))
		for _, c := range in.Chunks {
			ords, titles, bodies = append(ords, int64(c.Ordinal)), append(titles, c.Title), append(bodies, c.Body)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ai_knowledge_chunks (tenant_id, document_id, ordinal, title, body)
			SELECT $1, $2, o, t, b FROM unnest($3::int[], $4::text[], $5::text[]) AS x(o, t, b)`,
			d.TenantID, d.ID, pq.Array(ords), pq.Array(titles), pq.Array(bodies)); err != nil {
			return fmt.Errorf("insert knowledge chunks: %w", err)
		}
	}
	d.Chunks, d.Status = len(in.Chunks), aiknowledge.DocumentPending
	return tx.Commit()
}

const knowledgeDocumentColumns = `id, tenant_id, source_id, lineage_id, version, title, status, quarantined,
	COALESCE(quarantine_reason, ''), content_sha256, bytes, chunks, created_by, decided_by, decided_at, created_at`

func scanKnowledgeDocument(row interface{ Scan(...any) error }) (*aiknowledge.Document, error) {
	var d aiknowledge.Document
	var createdBy, decidedBy sql.NullString
	var decidedAt sql.NullTime
	if err := row.Scan(&d.ID, &d.TenantID, &d.SourceID, &d.LineageID, &d.Version, &d.Title, &d.Status, &d.Quarantined,
		&d.QuarantineReason, &d.ContentSHA256, &d.Bytes, &d.Chunks, &createdBy, &decidedBy, &decidedAt, &d.CreatedAt); err != nil {
		return nil, err
	}
	d.CreatedBy, d.DecidedBy, d.DecidedAt = parseNullID(createdBy), parseNullID(decidedBy), nullTimeValue(decidedAt)
	return &d, nil
}

// ListDocuments lists a source's document versions that still matter
// (approved, pending, and the latest rejected), newest first per document.
func (r *AIKnowledgeRepository) ListDocuments(ctx context.Context, tenantID, sourceID shared.ID) ([]*aiknowledge.Document, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+knowledgeDocumentColumns+` FROM ai_knowledge_documents
		WHERE tenant_id = $1 AND source_id = $2 AND status <> 'superseded'
		ORDER BY lower(title), lineage_id, version DESC LIMIT 2500`, tenantID, sourceID)
	if err != nil {
		return nil, fmt.Errorf("list knowledge documents: %w", err)
	}
	defer rows.Close()
	var out []*aiknowledge.Document
	for rows.Next() {
		d, err := scanKnowledgeDocument(rows)
		if err != nil {
			return nil, fmt.Errorf("scan knowledge document: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDocument reads one document version of the tenant.
func (r *AIKnowledgeRepository) GetDocument(ctx context.Context, tenantID, id shared.ID) (*aiknowledge.Document, error) {
	d, err := scanKnowledgeDocument(r.db.QueryRowContext(ctx, `SELECT `+knowledgeDocumentColumns+`
		FROM ai_knowledge_documents WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aiknowledge.ErrDocumentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get knowledge document: %w", err)
	}
	return d, nil
}

// DeleteDocument removes every version of the document's lineage (chunks
// cascade; run citations keep ids and digests only).
func (r *AIKnowledgeRepository) DeleteDocument(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ai_knowledge_documents
		WHERE tenant_id = $1 AND lineage_id = (SELECT lineage_id FROM ai_knowledge_documents WHERE tenant_id = $1 AND id = $2)`,
		tenantID, id)
	if err != nil {
		return fmt.Errorf("delete knowledge document: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return aiknowledge.ErrDocumentNotFound
	}
	return nil
}

// Search returns the best approved chunks the AI agent may see: approved
// source and version, class within the agent's ceiling, and organization
// visibility or the agent's own team membership. Full-text rank over the
// 'simple' configuration plus title similarity.
func (r *AIKnowledgeRepository) Search(ctx context.Context, rt aiknowledge.Retriever, query string, limit int) ([]aiknowledge.Hit, error) {
	if limit <= 0 || limit > 8 {
		limit = 8
	}
	restricted := rt.MaxClass == aiknowledge.ClassRestricted
	rows, err := r.db.QueryContext(ctx, `
		WITH q AS (SELECT websearch_to_tsquery('simple', $3) AS tsq)
		SELECT c.id, d.id, s.id, s.name, s.visibility, s.data_class, d.title, c.title, c.body, d.content_sha256,
		       d.updated_at, (ts_rank_cd(c.search, q.tsq, 32) + 0.3 * word_similarity($4, c.title))::float8 AS score
		FROM ai_knowledge_chunks c
		JOIN ai_knowledge_documents d ON d.id = c.document_id AND d.tenant_id = c.tenant_id
		JOIN ai_knowledge_sources s ON s.id = d.source_id AND s.tenant_id = d.tenant_id
		CROSS JOIN q
		WHERE c.tenant_id = $1 AND d.status = 'approved' AND s.status = 'approved'
		  AND (s.data_class = 'internal' OR $5)
		  AND (s.visibility = 'organization' OR `+fmt.Sprintf(knowledgeTeamMemberSQL, "$2")+`)
		  AND (c.search @@ q.tsq OR word_similarity($4, c.title) > 0.5)
		ORDER BY score DESC, d.updated_at DESC, c.id
		LIMIT $6`,
		rt.TenantID, rt.AIAgentID, orTerms(query), query, restricted, limit)
	if err != nil {
		return nil, fmt.Errorf("search knowledge: %w", err)
	}
	defer rows.Close()
	var out []aiknowledge.Hit
	for rows.Next() {
		var h aiknowledge.Hit
		if err := rows.Scan(&h.ChunkID, &h.DocumentID, &h.SourceID, &h.SourceName, &h.Visibility, &h.Class,
			&h.DocumentTitle, &h.ChunkTitle, &h.Body, &h.VersionDigest, &h.UpdatedAt, &h.Score); err != nil {
			return nil, fmt.Errorf("scan knowledge hit: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// orTerms turns a query into "a or b or c" for websearch_to_tsquery, which
// never fails on user syntax; quotes and minus signs are dropped so a term
// can neither be a phrase nor a negation.
func orTerms(query string) string {
	return strings.Join(aiknowledge.Terms(query), " or ")
}

// RecordRun stores the run's retrieval mode and its excerpts.
func (r *AIKnowledgeRepository) RecordRun(ctx context.Context, tenantID, runID shared.ID, mode aiknowledge.RetrievalMode,
	index string, ex []aiknowledge.RunExcerpt,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE ai_runs SET retrieval_mode = $3, retrieval_index = $4, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID, runID, mode, nullString(index))
	if err != nil {
		return fmt.Errorf("record run retrieval: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: ai run", shared.ErrNotFound)
	}
	for _, e := range ex {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ai_run_knowledge (tenant_id, run_id, ordinal, chunk_id, document_id, source_id, version_digest, score, cited)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (run_id, ordinal) DO UPDATE SET cited = EXCLUDED.cited`,
			tenantID, runID, e.Ordinal, e.ChunkID, e.DocumentID, e.SourceID, e.VersionDigest, e.Score, e.Cited); err != nil {
			return fmt.Errorf("record run excerpt: %w", err)
		}
	}
	return tx.Commit()
}

// Citations lists a run's excerpts as the viewer may see them.
func (r *AIKnowledgeRepository) Citations(ctx context.Context, tenantID, runID, viewer shared.ID, viewerAll bool,
) ([]aiknowledge.Citation, aiknowledge.RetrievalMode, error) {
	var mode sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT retrieval_mode FROM ai_runs WHERE tenant_id = $1 AND id = $2`, tenantID, runID).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", fmt.Errorf("%w: ai run", shared.ErrNotFound)
	}
	if err != nil {
		return nil, "", fmt.Errorf("read run retrieval: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT k.ordinal, k.document_id, k.source_id, k.version_digest, k.score, k.cited,
		       s.id IS NOT NULL AND d.id IS NOT NULL AS present,
		       COALESCE(s.visibility = 'organization' OR $4 OR `+fmt.Sprintf(knowledgeTeamMemberSQL, "$3")+`, false) AS visible,
		       COALESCE(s.name, ''), COALESCE(d.title, ''), COALESCE(c.title, '')
		FROM ai_run_knowledge k
		LEFT JOIN ai_knowledge_documents d ON d.id = k.document_id AND d.tenant_id = k.tenant_id
		LEFT JOIN ai_knowledge_sources s ON s.id = k.source_id AND s.tenant_id = k.tenant_id
		LEFT JOIN ai_knowledge_chunks c ON c.id = k.chunk_id AND c.tenant_id = k.tenant_id
		WHERE k.tenant_id = $1 AND k.run_id = $2
		ORDER BY k.ordinal`, tenantID, runID, viewer, viewerAll)
	if err != nil {
		return nil, "", fmt.Errorf("list run citations: %w", err)
	}
	defer rows.Close()
	var out []aiknowledge.Citation
	for rows.Next() {
		var c aiknowledge.Citation
		var doc, src sql.NullString
		var present, visible bool
		var sourceName, docTitle, chunkTitle string
		if err := rows.Scan(&c.Ordinal, &doc, &src, &c.VersionDigest, &c.Score, &c.Cited, &present, &visible,
			&sourceName, &docTitle, &chunkTitle); err != nil {
			return nil, "", fmt.Errorf("scan run citation: %w", err)
		}
		c.Deleted = !present
		c.Restricted = present && !visible
		if present && visible {
			c.DocumentID, c.SourceID = parseNullID(doc), parseNullID(src)
			c.SourceName, c.DocumentTitle, c.ChunkTitle = sourceName, docTitle, chunkTitle
		}
		out = append(out, c)
	}
	return out, aiknowledge.RetrievalMode(mode.String), rows.Err()
}
