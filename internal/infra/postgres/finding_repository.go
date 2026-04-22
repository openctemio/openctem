package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

const maxJSONSize = 64 * 1024 * 1024 // 64MB upper bound for marshaled JSON fields

// FindingRepository implements vulnerability.FindingRepository using PostgreSQL.
type FindingRepository struct {
	db *DB
}

// NewFindingRepository creates a new FindingRepository.
func NewFindingRepository(db *DB) *FindingRepository {
	return &FindingRepository{db: db}
}

// marshalFindingSARIFFields marshals SARIF JSONB fields for a finding.
func marshalFindingSARIFFields(finding *vulnerability.Finding) (partialFingerprints, relatedLocations, stacks, attachments []byte, err error) {
	partialFingerprints, err = json.Marshal(finding.PartialFingerprints())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal partial_fingerprints: %w", err)
	}
	if len(partialFingerprints) > maxJSONSize {
		return nil, nil, nil, nil, fmt.Errorf("partial_fingerprints JSON too large")
	}
	relatedLocations, err = json.Marshal(finding.RelatedLocations())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal related_locations: %w", err)
	}
	if len(relatedLocations) > maxJSONSize {
		return nil, nil, nil, nil, fmt.Errorf("related_locations JSON too large")
	}
	stacks, err = json.Marshal(finding.Stacks())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal stacks: %w", err)
	}
	if len(stacks) > maxJSONSize {
		return nil, nil, nil, nil, fmt.Errorf("stacks JSON too large")
	}
	attachments, err = json.Marshal(finding.Attachments())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal attachments: %w", err)
	}
	if len(attachments) > maxJSONSize {
		return nil, nil, nil, nil, fmt.Errorf("attachments JSON too large")
	}
	return partialFingerprints, relatedLocations, stacks, attachments, nil
}

// nullPriorityClass converts a *PriorityClass to sql.NullString.
// nil is treated as NULL.
func nullPriorityClass(pc *vulnerability.PriorityClass) sql.NullString {
	if pc == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*pc), Valid: true}
}

// marshalRemediation marshals the FindingRemediation value object to JSONB.
// Returns nil interface{} if remediation is nil or empty (proper SQL NULL for JSONB).
func marshalRemediation(r *vulnerability.FindingRemediation) interface{} {
	if r == nil || r.IsEmpty() {
		return nil // Return nil interface{} for proper SQL NULL handling
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	if len(data) > maxJSONSize {
		return nil
	}
	return data // Return []byte for valid JSONB
}

// getRecommendationFromRemediation extracts recommendation string from remediation JSONB.
func getRecommendationFromRemediation(r *vulnerability.FindingRemediation) string {
	if r == nil {
		return ""
	}
	return r.Recommendation
}

// Create persists a new finding.
func (r *FindingRepository) Create(ctx context.Context, finding *vulnerability.Finding) error {
	metadata, err := json.Marshal(finding.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	partialFingerprints, relatedLocations, stacks, attachments, err := marshalFindingSARIFFields(finding)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO findings (
			id, tenant_id, vulnerability_id, asset_id, branch_id, component_id, source,
			tool_name, tool_id, tool_version, rule_id, file_path, start_line, end_line,
			start_column, end_column, snippet, context_snippet, context_start_line,
			title, description, message, severity, status,
			resolution, resolved_at, resolved_by, scan_id, fingerprint,
			agent_id, metadata, created_at, updated_at,
			first_detected_branch, first_detected_commit, last_seen_branch, last_seen_commit,
			confidence, impact, likelihood, vulnerability_class, subcategory,
			baseline_state, kind, rank, occurrence_count, correlation_id,
			partial_fingerprints, related_locations, stacks, attachments, work_item_uris, hosted_viewer_uri,
			exposure_vector, is_network_accessible, is_internet_accessible, attack_prerequisites,
			epss_score, epss_percentile, is_in_kev, kev_due_date,
			priority_class, priority_class_reason, priority_class_override, priority_class_overridden_by, priority_class_overridden_at,
			is_reachable, reachable_from_count,
			remediation_type, estimated_fix_time, fix_complexity, remedy_available,
			data_exposure_risk, reputational_impact, compliance_impact,
			asvs_section, asvs_control_id, asvs_control_url, asvs_level,
			remediation, pentest_campaign_id, created_by
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34,
			$35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50,
			$51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, $70, $71,
			$72, $73, $74, $75, $76, $77, $78, $79, $80, $81, $82)
	`

	remediationJSON := marshalRemediation(finding.Remediation())

	_, err = r.db.ExecContext(ctx, query,
		finding.ID().String(),
		finding.TenantID().String(),
		nullID(finding.VulnerabilityID()),
		nullIDValue(finding.AssetID()), // pentest findings may have no asset
		nullID(finding.BranchID()),
		nullID(finding.ComponentID()),
		finding.Source().String(),
		finding.ToolName(),
		nullID(finding.ToolID()),
		nullString(finding.ToolVersion()),
		nullString(finding.RuleID()),
		nullString(finding.FilePath()),
		finding.StartLine(),
		finding.EndLine(),
		finding.StartColumn(),
		finding.EndColumn(),
		nullString(finding.Snippet()),
		nullString(finding.ContextSnippet()),
		nullInt(finding.ContextStartLine()),
		nullString(finding.Title()),
		nullString(finding.Description()),
		finding.Message(),
		finding.Severity().String(),
		finding.Status().String(),
		nullString(finding.Resolution()),
		nullTime(finding.ResolvedAt()),
		nullID(finding.ResolvedBy()),
		nullString(finding.ScanID()),
		finding.Fingerprint(),
		nullID(finding.AgentID()),
		metadata,
		finding.CreatedAt(),
		finding.UpdatedAt(),
		nullString(finding.FirstDetectedBranch()),
		nullString(finding.FirstDetectedCommit()),
		nullString(finding.LastSeenBranch()),
		nullString(finding.LastSeenCommit()),
		// SARIF fields
		nullIntPtr(finding.Confidence()),
		nullString(finding.Impact()),
		nullString(finding.Likelihood()),
		pq.Array(finding.VulnerabilityClass()),
		pq.Array(finding.Subcategory()),
		nullString(finding.BaselineState()),
		nullString(finding.Kind()),
		nullFloat64(finding.Rank()),
		finding.OccurrenceCount(),
		nullString(finding.CorrelationID()),
		partialFingerprints,
		relatedLocations,
		stacks,
		attachments,
		pq.Array(finding.WorkItemURIs()),
		nullString(finding.HostedViewerURI()),
		// CTEM fields
		nullString(finding.ExposureVector().String()),
		finding.IsNetworkAccessible(),
		finding.IsInternetAccessible(),
		nullString(finding.AttackPrerequisites()),
		// Priority classification fields (RFC-004)
		nullFloat64(finding.EPSSScore()),
		nullFloat64(finding.EPSSPercentile()),
		finding.IsInKEV(),
		nullTime(finding.KEVDueDate()),
		nullPriorityClass(finding.PriorityClass()),
		nullString(finding.PriorityClassReason()),
		finding.PriorityClassOverride(),
		nullID(finding.PriorityClassOverriddenBy()),
		nullTime(finding.PriorityClassOverriddenAt()),
		finding.IsReachable(),
		finding.ReachableFromCount(),
		nullString(finding.RemediationType().String()),
		nullIntPtr(finding.EstimatedFixTime()),
		nullString(finding.FixComplexity().String()),
		finding.RemedyAvailable(),
		nullString(finding.DataExposureRisk().String()),
		finding.ReputationalImpact(),
		pq.Array(finding.ComplianceImpact()),
		// ASVS fields
		nullString(finding.ASVSSection()),
		nullString(finding.ASVSControlID()),
		nullString(finding.ASVSControlURL()),
		nullIntPtr(finding.ASVSLevel()),
		// Remediation JSONB (contains recommendation, fix_code, fix_regex, steps, references, etc.)
		remediationJSON,
		// Pentest campaign FK (NULL for non-pentest findings)
		nullID(finding.PentestCampaignID()),
		// Creator (NULL for automated scanner findings, set for manually-authored pentest findings)
		nullID(finding.CreatedBy()),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return vulnerability.FindingAlreadyExistsError(finding.Fingerprint())
		}
		return fmt.Errorf("failed to create finding: %w", err)
	}

	return nil
}

// CreateInTx persists a new finding within an existing transaction.
func (r *FindingRepository) CreateInTx(ctx context.Context, tx *sql.Tx, finding *vulnerability.Finding) error {
	metadata, err := json.Marshal(finding.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	partialFingerprints, relatedLocations, stacks, attachments, err := marshalFindingSARIFFields(finding)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO findings (
			id, tenant_id, vulnerability_id, asset_id, branch_id, component_id, source,
			tool_name, tool_id, tool_version, rule_id, file_path, start_line, end_line,
			start_column, end_column, snippet, context_snippet, context_start_line,
			title, description, message, severity, status,
			resolution, resolved_at, resolved_by, scan_id, fingerprint,
			agent_id, metadata, created_at, updated_at,
			first_detected_branch, first_detected_commit, last_seen_branch, last_seen_commit,
			confidence, impact, likelihood, vulnerability_class, subcategory,
			baseline_state, kind, rank, occurrence_count, correlation_id,
			partial_fingerprints, related_locations, stacks, attachments, work_item_uris, hosted_viewer_uri,
			exposure_vector, is_network_accessible, is_internet_accessible, attack_prerequisites,
			epss_score, epss_percentile, is_in_kev, kev_due_date,
			priority_class, priority_class_reason, priority_class_override, priority_class_overridden_by, priority_class_overridden_at,
			is_reachable, reachable_from_count,
			remediation_type, estimated_fix_time, fix_complexity, remedy_available,
			data_exposure_risk, reputational_impact, compliance_impact,
			asvs_section, asvs_control_id, asvs_control_url, asvs_level,
			remediation, pentest_campaign_id, created_by
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34,
			$35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50,
			$51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, $70, $71,
			$72, $73, $74, $75, $76, $77, $78, $79, $80, $81, $82)
	`

	remediationJSON := marshalRemediation(finding.Remediation())

	_, err = tx.ExecContext(ctx, query,
		finding.ID().String(),
		finding.TenantID().String(),
		nullID(finding.VulnerabilityID()),
		nullIDValue(finding.AssetID()), // pentest findings may have no asset
		nullID(finding.BranchID()),
		nullID(finding.ComponentID()),
		finding.Source().String(),
		finding.ToolName(),
		nullID(finding.ToolID()),
		nullString(finding.ToolVersion()),
		nullString(finding.RuleID()),
		nullString(finding.FilePath()),
		finding.StartLine(),
		finding.EndLine(),
		finding.StartColumn(),
		finding.EndColumn(),
		nullString(finding.Snippet()),
		nullString(finding.ContextSnippet()),
		nullInt(finding.ContextStartLine()),
		nullString(finding.Title()),
		nullString(finding.Description()),
		finding.Message(),
		finding.Severity().String(),
		finding.Status().String(),
		nullString(finding.Resolution()),
		nullTime(finding.ResolvedAt()),
		nullID(finding.ResolvedBy()),
		nullString(finding.ScanID()),
		finding.Fingerprint(),
		nullID(finding.AgentID()),
		metadata,
		finding.CreatedAt(),
		finding.UpdatedAt(),
		nullString(finding.FirstDetectedBranch()),
		nullString(finding.FirstDetectedCommit()),
		nullString(finding.LastSeenBranch()),
		nullString(finding.LastSeenCommit()),
		// SARIF fields
		nullIntPtr(finding.Confidence()),
		nullString(finding.Impact()),
		nullString(finding.Likelihood()),
		pq.Array(finding.VulnerabilityClass()),
		pq.Array(finding.Subcategory()),
		nullString(finding.BaselineState()),
		nullString(finding.Kind()),
		nullFloat64(finding.Rank()),
		finding.OccurrenceCount(),
		nullString(finding.CorrelationID()),
		partialFingerprints,
		relatedLocations,
		stacks,
		attachments,
		pq.Array(finding.WorkItemURIs()),
		nullString(finding.HostedViewerURI()),
		// CTEM fields
		nullString(finding.ExposureVector().String()),
		finding.IsNetworkAccessible(),
		finding.IsInternetAccessible(),
		nullString(finding.AttackPrerequisites()),
		// Priority classification fields (RFC-004)
		nullFloat64(finding.EPSSScore()),
		nullFloat64(finding.EPSSPercentile()),
		finding.IsInKEV(),
		nullTime(finding.KEVDueDate()),
		nullPriorityClass(finding.PriorityClass()),
		nullString(finding.PriorityClassReason()),
		finding.PriorityClassOverride(),
		nullID(finding.PriorityClassOverriddenBy()),
		nullTime(finding.PriorityClassOverriddenAt()),
		finding.IsReachable(),
		finding.ReachableFromCount(),
		nullString(finding.RemediationType().String()),
		nullIntPtr(finding.EstimatedFixTime()),
		nullString(finding.FixComplexity().String()),
		finding.RemedyAvailable(),
		nullString(finding.DataExposureRisk().String()),
		finding.ReputationalImpact(),
		pq.Array(finding.ComplianceImpact()),
		// ASVS fields
		nullString(finding.ASVSSection()),
		nullString(finding.ASVSControlID()),
		nullString(finding.ASVSControlURL()),
		nullIntPtr(finding.ASVSLevel()),
		// Remediation JSONB
		remediationJSON,
		// Pentest campaign FK
		nullID(finding.PentestCampaignID()),
		// Creator user ID
		nullID(finding.CreatedBy()),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return vulnerability.FindingAlreadyExistsError(finding.Fingerprint())
		}
		return fmt.Errorf("failed to create finding in tx: %w", err)
	}

	return nil
}

// CreateBatch persists multiple findings.
// Deprecated: Use CreateBatchWithResult for better error handling.
func (r *FindingRepository) CreateBatch(ctx context.Context, findings []*vulnerability.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Note: ON CONFLICT preserves user-set status (false_positive, accepted, ignored, resolved)
	// by not including status in the UPDATE SET clause. This ensures findings marked
	// as false_positive by security team remain so across subsequent scans.
	// Only scan metadata (scan_id, updated_at, last_seen_at) is updated for existing findings.
	stmt, err := tx.PrepareContext(ctx, r.upsertQuery())
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, finding := range findings {
		if err := r.execFindingInsert(ctx, stmt, finding); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DefaultBatchChunkSize is the default number of findings per chunk for batch operations.
const DefaultBatchChunkSize = 100

// CreateBatchWithResult persists multiple findings with partial success support.
// Uses chunked transactions to isolate failures - if one chunk fails,
// only that chunk is retried individually to identify the bad finding.
func (r *FindingRepository) CreateBatchWithResult(ctx context.Context, findings []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	result := &vulnerability.BatchCreateResult{
		Errors: make(map[int]string),
	}

	if len(findings) == 0 {
		return result, nil
	}

	// Process in chunks for better error isolation
	chunkSize := DefaultBatchChunkSize
	for chunkStart := 0; chunkStart < len(findings); chunkStart += chunkSize {
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > len(findings) {
			chunkEnd = len(findings)
		}
		chunk := findings[chunkStart:chunkEnd]

		// Try to insert the entire chunk
		err := r.insertChunk(ctx, chunk)
		if err == nil {
			// Chunk succeeded
			result.Created += len(chunk)
			continue
		}

		// Chunk failed - retry individually to identify bad findings
		for i, finding := range chunk {
			globalIndex := chunkStart + i
			if err := r.insertSingleFinding(ctx, finding); err != nil {
				result.Skipped++
				result.Errors[globalIndex] = err.Error()
			} else {
				result.Created++
			}
		}
	}

	return result, nil
}

// insertChunk inserts a chunk of findings in a single transaction.
func (r *FindingRepository) insertChunk(ctx context.Context, findings []*vulnerability.Finding) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, r.upsertQuery())
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, finding := range findings {
		if err := r.execFindingInsert(ctx, stmt, finding); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// insertSingleFinding inserts a single finding with its own transaction.
func (r *FindingRepository) insertSingleFinding(ctx context.Context, finding *vulnerability.Finding) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, r.upsertQuery())
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	if err := r.execFindingInsert(ctx, stmt, finding); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// upsertQuery returns the INSERT ... ON CONFLICT query for findings.
func (r *FindingRepository) upsertQuery() string {
	return `
		INSERT INTO findings (
			id, tenant_id, vulnerability_id, asset_id, branch_id, component_id, source,
			tool_name, tool_id, tool_version, rule_id, file_path, start_line, end_line,
			start_column, end_column, snippet, context_snippet, context_start_line,
			title, description, message, severity, status,
			resolution, resolved_at, resolved_by, scan_id, fingerprint,
			agent_id, metadata, created_at, updated_at,
			first_detected_branch, first_detected_commit, last_seen_branch, last_seen_commit,
			confidence, impact, likelihood, vulnerability_class, subcategory,
			baseline_state, kind, rank, occurrence_count, correlation_id,
			partial_fingerprints, related_locations, stacks, attachments, work_item_uris, hosted_viewer_uri,
			exposure_vector, is_network_accessible, is_internet_accessible, attack_prerequisites,
			epss_score, epss_percentile, is_in_kev, kev_due_date,
			priority_class, priority_class_reason, priority_class_override, priority_class_overridden_by, priority_class_overridden_at,
			is_reachable, reachable_from_count,
			remediation_type, estimated_fix_time, fix_complexity, remedy_available,
			data_exposure_risk, reputational_impact, compliance_impact,
			asvs_section, asvs_control_id, asvs_control_url, asvs_level,
			remediation, pentest_campaign_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34,
			$35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50,
			$51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, $70,
			$71, $72, $73, $74, $75, $76, $77, $78, $79, $80, $81)
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
			vulnerability_id = EXCLUDED.vulnerability_id,
			component_id = EXCLUDED.component_id,
			branch_id = COALESCE(EXCLUDED.branch_id, findings.branch_id),
			tool_id = COALESCE(EXCLUDED.tool_id, findings.tool_id),
			tool_version = EXCLUDED.tool_version,
			snippet = COALESCE(EXCLUDED.snippet, findings.snippet),
			context_snippet = COALESCE(EXCLUDED.context_snippet, findings.context_snippet),
			context_start_line = COALESCE(EXCLUDED.context_start_line, findings.context_start_line),
			title = COALESCE(EXCLUDED.title, findings.title),
			description = COALESCE(EXCLUDED.description, findings.description),
			message = EXCLUDED.message,
			severity = EXCLUDED.severity,
			scan_id = EXCLUDED.scan_id,
			agent_id = EXCLUDED.agent_id,
			metadata = EXCLUDED.metadata,
			updated_at = EXCLUDED.updated_at,
			last_seen_branch = EXCLUDED.last_seen_branch,
			last_seen_commit = EXCLUDED.last_seen_commit,
			confidence = EXCLUDED.confidence,
			impact = EXCLUDED.impact,
			likelihood = EXCLUDED.likelihood,
			vulnerability_class = EXCLUDED.vulnerability_class,
			subcategory = EXCLUDED.subcategory,
			baseline_state = EXCLUDED.baseline_state,
			kind = EXCLUDED.kind,
			rank = EXCLUDED.rank,
			occurrence_count = EXCLUDED.occurrence_count,
			correlation_id = EXCLUDED.correlation_id,
			partial_fingerprints = EXCLUDED.partial_fingerprints,
			related_locations = EXCLUDED.related_locations,
			stacks = EXCLUDED.stacks,
			attachments = EXCLUDED.attachments,
			work_item_uris = EXCLUDED.work_item_uris,
			hosted_viewer_uri = EXCLUDED.hosted_viewer_uri,
			exposure_vector = EXCLUDED.exposure_vector,
			is_network_accessible = EXCLUDED.is_network_accessible,
			is_internet_accessible = EXCLUDED.is_internet_accessible,
			attack_prerequisites = EXCLUDED.attack_prerequisites,
			epss_score = EXCLUDED.epss_score,
			epss_percentile = EXCLUDED.epss_percentile,
			is_in_kev = EXCLUDED.is_in_kev,
			kev_due_date = EXCLUDED.kev_due_date,
			priority_class = CASE WHEN findings.priority_class_override THEN findings.priority_class ELSE EXCLUDED.priority_class END,
			priority_class_reason = CASE WHEN findings.priority_class_override THEN findings.priority_class_reason ELSE EXCLUDED.priority_class_reason END,
			priority_class_override = findings.priority_class_override,
			priority_class_overridden_by = findings.priority_class_overridden_by,
			priority_class_overridden_at = findings.priority_class_overridden_at,
			is_reachable = EXCLUDED.is_reachable,
			reachable_from_count = EXCLUDED.reachable_from_count,
			remediation_type = EXCLUDED.remediation_type,
			estimated_fix_time = EXCLUDED.estimated_fix_time,
			fix_complexity = EXCLUDED.fix_complexity,
			remedy_available = EXCLUDED.remedy_available,
			data_exposure_risk = EXCLUDED.data_exposure_risk,
			reputational_impact = EXCLUDED.reputational_impact,
			compliance_impact = EXCLUDED.compliance_impact,
			asvs_section = COALESCE(EXCLUDED.asvs_section, findings.asvs_section),
			asvs_control_id = COALESCE(EXCLUDED.asvs_control_id, findings.asvs_control_id),
			asvs_control_url = COALESCE(EXCLUDED.asvs_control_url, findings.asvs_control_url),
			asvs_level = COALESCE(EXCLUDED.asvs_level, findings.asvs_level),
			remediation = COALESCE(EXCLUDED.remediation, findings.remediation)
	`
}

// execFindingInsert executes the insert for a single finding using prepared statement.
func (r *FindingRepository) execFindingInsert(ctx context.Context, stmt *sql.Stmt, finding *vulnerability.Finding) error {
	metadata, err := json.Marshal(finding.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	partialFingerprints, relatedLocations, stacks, attachments, err := marshalFindingSARIFFields(finding)
	if err != nil {
		return err
	}

	remediationJSON := marshalRemediation(finding.Remediation())

	_, err = stmt.ExecContext(ctx,
		finding.ID().String(),
		finding.TenantID().String(),
		nullID(finding.VulnerabilityID()),
		nullIDValue(finding.AssetID()), // pentest findings may have no asset
		nullID(finding.BranchID()),
		nullID(finding.ComponentID()),
		finding.Source().String(),
		finding.ToolName(),
		nullID(finding.ToolID()),
		nullString(finding.ToolVersion()),
		nullString(finding.RuleID()),
		nullString(finding.FilePath()),
		finding.StartLine(),
		finding.EndLine(),
		finding.StartColumn(),
		finding.EndColumn(),
		nullString(finding.Snippet()),
		nullString(finding.ContextSnippet()),
		nullInt(finding.ContextStartLine()),
		nullString(finding.Title()),
		nullString(finding.Description()),
		finding.Message(),
		finding.Severity().String(),
		finding.Status().String(),
		nullString(finding.Resolution()),
		nullTime(finding.ResolvedAt()),
		nullID(finding.ResolvedBy()),
		nullString(finding.ScanID()),
		finding.Fingerprint(),
		nullID(finding.AgentID()),
		metadata,
		finding.CreatedAt(),
		finding.UpdatedAt(),
		nullString(finding.FirstDetectedBranch()),
		nullString(finding.FirstDetectedCommit()),
		nullString(finding.LastSeenBranch()),
		nullString(finding.LastSeenCommit()),
		// SARIF fields
		nullIntPtr(finding.Confidence()),
		nullString(finding.Impact()),
		nullString(finding.Likelihood()),
		pq.Array(finding.VulnerabilityClass()),
		pq.Array(finding.Subcategory()),
		nullString(finding.BaselineState()),
		nullString(finding.Kind()),
		nullFloat64(finding.Rank()),
		finding.OccurrenceCount(),
		nullString(finding.CorrelationID()),
		partialFingerprints,
		relatedLocations,
		stacks,
		attachments,
		pq.Array(finding.WorkItemURIs()),
		nullString(finding.HostedViewerURI()),
		// CTEM fields
		nullString(finding.ExposureVector().String()),
		finding.IsNetworkAccessible(),
		finding.IsInternetAccessible(),
		nullString(finding.AttackPrerequisites()),
		// Priority classification fields (RFC-004)
		nullFloat64(finding.EPSSScore()),
		nullFloat64(finding.EPSSPercentile()),
		finding.IsInKEV(),
		nullTime(finding.KEVDueDate()),
		nullPriorityClass(finding.PriorityClass()),
		nullString(finding.PriorityClassReason()),
		finding.PriorityClassOverride(),
		nullID(finding.PriorityClassOverriddenBy()),
		nullTime(finding.PriorityClassOverriddenAt()),
		finding.IsReachable(),
		finding.ReachableFromCount(),
		nullString(finding.RemediationType().String()),
		nullIntPtr(finding.EstimatedFixTime()),
		nullString(finding.FixComplexity().String()),
		finding.RemedyAvailable(),
		nullString(finding.DataExposureRisk().String()),
		finding.ReputationalImpact(),
		pq.Array(finding.ComplianceImpact()),
		// ASVS fields
		nullString(finding.ASVSSection()),
		nullString(finding.ASVSControlID()),
		nullString(finding.ASVSControlURL()),
		nullIntPtr(finding.ASVSLevel()),
		// Remediation JSONB (contains recommendation, fix_code, fix_regex)
		remediationJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to insert finding: %w", err)
	}

	return nil
}

// GetByID retrieves a finding by ID.
// Security: Requires tenantID to prevent cross-tenant data access (IDOR prevention).
func (r *FindingRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	query := r.selectQuery() + " WHERE id = $1 AND tenant_id = $2"
	row := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String())
	return r.scanFinding(row, vulnerability.FindingNotFoundError(id))
}

// GetByIDs retrieves multiple findings by IDs within a tenant (batch fetch).
func (r *FindingRepository) GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}

	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = ANY($2::uuid[])"
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(idStrs))
	if err != nil {
		return nil, fmt.Errorf("failed to get findings by ids: %w", err)
	}
	defer rows.Close()

	results := make([]*vulnerability.Finding, 0, len(ids))
	for rows.Next() {
		f, err := r.scanFindingFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		results = append(results, f)
	}
	return results, rows.Err()
}

// Update updates an existing finding.
// Security: Uses finding.TenantID() to ensure tenant isolation in SQL WHERE clause.
func (r *FindingRepository) Update(ctx context.Context, finding *vulnerability.Finding) error {
	// Merge sourceMetadata INTO metadata for persistence. The pentest module
	// stores steps_to_reproduce, poc_code, business_impact, etc. in
	// sourceMetadata, but the DB has a single `metadata` JSONB column.
	// During Create, this merge happens in the service. During Update, we
	// need to re-merge here to persist pentest field changes.
	mergedMeta := finding.Metadata()
	if mergedMeta == nil {
		mergedMeta = make(map[string]any)
	}
	if sm := finding.SourceMetadata(); sm != nil {
		for k, v := range sm {
			mergedMeta[k] = v
		}
	}
	metadata, err := json.Marshal(mergedMeta)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	remediationJSON := marshalRemediation(finding.Remediation())

	// Security: Include tenant_id in WHERE clause to prevent cross-tenant updates.
	// NOTE: This UPDATE covers ALL mutable columns — including title, description,
	// tags, classification, and source_metadata. The original version only updated
	// scanner-oriented fields, which meant pentest edit operations silently lost data.
	query := `
		UPDATE findings SET
			vulnerability_id = $2, component_id = $3, tool_id = $4, tool_version = $5, snippet = $6,
			message = $7, severity = $8, status = $9, resolution = $10, resolution_method = $11,
			resolved_at = $12, resolved_by = $13, scan_id = $14, metadata = $15, updated_at = $16,
			assigned_to = $17, assigned_at = $18, assigned_by = $19,
			title = $21, description = $22, tags = $23,
			cvss_score = $24, cvss_vector = $25, cve_id = $26, cwe_ids = $27, owasp_ids = $28,
			remediation = $29,
			epss_score = $30, epss_percentile = $31, is_in_kev = $32, kev_due_date = $33,
			priority_class = $34, priority_class_reason = $35,
			priority_class_override = $36, priority_class_overridden_by = $37, priority_class_overridden_at = $38,
			is_reachable = $39, reachable_from_count = $40
		WHERE id = $1 AND tenant_id = $20
	`

	result, err := r.db.ExecContext(ctx, query,
		finding.ID().String(),                 // $1
		nullID(finding.VulnerabilityID()),     // $2
		nullID(finding.ComponentID()),         // $3
		nullID(finding.ToolID()),              // $4
		nullString(finding.ToolVersion()),     // $5
		nullString(finding.Snippet()),         // $6
		finding.Message(),                     // $7
		finding.Severity().String(),           // $8
		finding.Status().String(),             // $9
		nullString(finding.Resolution()),      // $10
		nullString(finding.ResolutionMethod()), // $11
		nullTime(finding.ResolvedAt()),        // $12
		nullID(finding.ResolvedBy()),          // $13
		nullString(finding.ScanID()),          // $14
		metadata,                              // $15
		finding.UpdatedAt(),                   // $16
		nullID(finding.AssignedTo()),          // $17
		nullTime(finding.AssignedAt()),        // $18
		nullID(finding.AssignedBy()),          // $19
		finding.TenantID().String(),           // $20 (WHERE)
		nullString(finding.Title()),           // $21
		nullString(finding.Description()),     // $22
		pq.Array(finding.Tags()),              // $23
		nullFloat64(finding.CVSSScore()),       // $24
		nullString(finding.CVSSVector()),      // $25
		nullString(finding.CVEID()),           // $26
		pq.Array(finding.CWEIDs()),            // $27
		pq.Array(finding.OWASPIDs()),          // $28
		remediationJSON,                       // $29
		// Priority classification (RFC-004)
		nullFloat64(finding.EPSSScore()),              // $30
		nullFloat64(finding.EPSSPercentile()),         // $31
		finding.IsInKEV(),                             // $32
		nullTime(finding.KEVDueDate()),                // $33
		nullPriorityClass(finding.PriorityClass()),    // $34
		nullString(finding.PriorityClassReason()),     // $35
		finding.PriorityClassOverride(),               // $36
		nullID(finding.PriorityClassOverriddenBy()),   // $37
		nullTime(finding.PriorityClassOverriddenAt()), // $38
		finding.IsReachable(),                         // $39
		finding.ReachableFromCount(),                  // $40
	)

	if err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return vulnerability.FindingNotFoundError(finding.ID())
	}

	return nil
}

// Delete removes a finding by ID.
// Security: Requires tenantID to prevent cross-tenant deletion (IDOR prevention).
func (r *FindingRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	// Security: Include tenant_id in WHERE clause to prevent cross-tenant deletion
	query := `DELETE FROM findings WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to delete finding: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return vulnerability.FindingNotFoundError(id)
	}

	return nil
}

// UpdateWorkItemURIs sets the work_item_uris column for a finding.
// Only modifies work_item_uris — all other fields are untouched.
func (r *FindingRepository) UpdateWorkItemURIs(ctx context.Context, tenantID, id shared.ID, uris []string) error {
	if uris == nil {
		uris = []string{}
	}
	query := `UPDATE findings SET work_item_uris = $3, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String(), pq.Array(uris))
	if err != nil {
		return fmt.Errorf("failed to update work item uris: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return vulnerability.FindingNotFoundError(id)
	}
	return nil
}

// GetByWorkItemURI retrieves a finding that contains the given work item URI.
// Used by the Jira webhook receiver to route inbound status updates back to findings.
func (r *FindingRepository) GetByWorkItemURI(ctx context.Context, tenantID shared.ID, uri string) (*vulnerability.Finding, error) {
	query := r.selectQuery() + ` WHERE tenant_id = $1 AND $2 = ANY(work_item_uris) LIMIT 1`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), uri)
	finding, err := r.scanFinding(row, fmt.Errorf("%w: finding not found for work item URI", shared.ErrNotFound))
	if err != nil {
		return nil, fmt.Errorf("failed to get finding by work item URI: %w", err)
	}
	return finding, nil
}

// List retrieves findings matching the filter with pagination.
func (r *FindingRepository) List(ctx context.Context, filter vulnerability.FindingFilter, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	baseQuery := r.selectQuery()
	countQuery := `SELECT COUNT(*) FROM findings`

	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Apply sorting (default to created_at DESC)
	orderBy := defaultSortOrder
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderBy = opts.Sort.SQLWithDefault(defaultSortOrder)
	}
	baseQuery += " ORDER BY " + orderBy
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*vulnerability.Finding]{}, fmt.Errorf("failed to count findings: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*vulnerability.Finding]{}, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []*vulnerability.Finding
	for rows.Next() {
		finding, err := r.scanFindingFromRows(rows)
		if err != nil {
			return pagination.Result[*vulnerability.Finding]{}, err
		}
		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.Finding]{}, fmt.Errorf("failed to iterate findings: %w", err)
	}

	return pagination.NewResult(findings, total, page), nil
}

// ListByVulnerabilityID retrieves findings for a vulnerability.
// Security: Requires tenantID to prevent cross-tenant data access.
func (r *FindingRepository) ListByVulnerabilityID(ctx context.Context, tenantID, vulnID shared.ID, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID).WithVulnerabilityID(vulnID)
	return r.List(ctx, filter, opts, page)
}

// ListByComponentID retrieves findings for a component.
// Security: Requires tenantID to prevent cross-tenant data access.
func (r *FindingRepository) ListByComponentID(ctx context.Context, tenantID, compID shared.ID, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID).WithComponentID(compID)
	return r.List(ctx, filter, opts, page)
}

// Count returns the count of findings matching the filter.
func (r *FindingRepository) Count(ctx context.Context, filter vulnerability.FindingFilter) (int64, error) {
	query := `SELECT COUNT(*) FROM findings`

	whereClause, args := r.buildWhereClause(filter)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}

	return count, nil
}

// GetByFingerprint retrieves a finding by fingerprint.
func (r *FindingRepository) GetByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (*vulnerability.Finding, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND fingerprint = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), fingerprint)
	return r.scanFinding(row, vulnerability.FindingNotFoundError(shared.ID{}))
}

// ExistsByFingerprint checks if a finding with the given fingerprint exists.
func (r *FindingRepository) ExistsByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM findings WHERE tenant_id = $1 AND fingerprint = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), fingerprint).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check finding existence: %w", err)
	}

	return exists, nil
}

// CheckFingerprintsExist checks which fingerprints already exist in the database.
// Returns a map of fingerprint -> exists boolean.
func (r *FindingRepository) CheckFingerprintsExist(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error) {
	if len(fingerprints) == 0 {
		return map[string]bool{}, nil
	}

	// Initialize result with all fingerprints as non-existent
	result := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		result[fp] = false
	}

	// Build query with placeholders
	placeholders := make([]string, len(fingerprints))
	args := make([]any, len(fingerprints)+1)
	args[0] = tenantID.String()
	for i, fp := range fingerprints {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = fp
	}

	query := fmt.Sprintf(`
		SELECT fingerprint
		FROM findings
		WHERE tenant_id = $1 AND fingerprint IN (%s)
	`, strings.Join(placeholders, ", "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to check fingerprints: %w", err)
	}
	defer rows.Close()

	// Mark existing fingerprints
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("failed to scan fingerprint: %w", err)
		}
		result[fp] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating fingerprints: %w", err)
	}

	return result, nil
}

// UpdateStatusBatch updates the status of multiple findings.
// Security: Requires tenantID to prevent cross-tenant status modification.
func (r *FindingRepository) UpdateStatusBatch(ctx context.Context, tenantID shared.ID, ids []shared.ID, status vulnerability.FindingStatus, resolution string, resolvedBy *shared.ID) error {
	if len(ids) == 0 {
		return nil
	}

	// Security: tenant_id is first parameter for isolation
	placeholders := make([]string, len(ids))
	args := []any{tenantID.String(), status.String(), nullString(resolution), nullID(resolvedBy)}

	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+5)
		args = append(args, id.String())
	}

	var resolvedClause string
	if status.IsClosed() {
		resolvedClause = ", resolved_at = NOW()"
	} else {
		resolvedClause = ", resolved_at = NULL"
	}

	// Security: Include tenant_id in WHERE clause
	// Security: Exclude pentest findings — they must be managed via the pentest module
	query := fmt.Sprintf(`
		UPDATE findings
		SET status = $2, resolution = $3, resolved_by = $4%s, updated_at = NOW()
		WHERE tenant_id = $1 AND source != 'pentest' AND id IN (%s)
	`, resolvedClause, strings.Join(placeholders, ", "))

	_, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update findings status: %w", err)
	}

	return nil
}

// DeleteByScanID removes all findings for a scan.
func (r *FindingRepository) DeleteByScanID(ctx context.Context, tenantID shared.ID, scanID string) error {
	query := `DELETE FROM findings WHERE tenant_id = $1 AND scan_id = $2`

	_, err := r.db.ExecContext(ctx, query, tenantID.String(), scanID)
	if err != nil {
		return fmt.Errorf("failed to delete findings: %w", err)
	}

	return nil
}

// UpdateScanIDBatchByFingerprints updates scan metadata for existing findings by their fingerprints.
// This preserves user-set status (false_positive, accepted, etc.) while updating scan tracking.
// Returns the count of updated findings.
func (r *FindingRepository) UpdateScanIDBatchByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string, scanID string) (int64, error) {
	if len(fingerprints) == 0 {
		return 0, nil
	}

	// Use ANY with array for better performance with large fingerprint lists
	// Note: Status is intentionally NOT updated to preserve user-set values (false_positive, accepted, etc.)
	query := `
		UPDATE findings
		SET scan_id = $1, updated_at = NOW(), last_seen_at = NOW()
		WHERE tenant_id = $2 AND fingerprint = ANY($3)
	`

	result, err := r.db.ExecContext(ctx, query, scanID, tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return 0, fmt.Errorf("failed to update findings scan_id: %w", err)
	}

	return result.RowsAffected()
}

// UpdateSnippetBatchByFingerprints updates snippet for findings that have invalid snippets
// ("requires login" or empty). Only updates if new snippet is valid and non-empty.
// snippets is a map of fingerprint -> new snippet
func (r *FindingRepository) UpdateSnippetBatchByFingerprints(ctx context.Context, tenantID shared.ID, snippets map[string]string) (int64, error) {
	if len(snippets) == 0 {
		return 0, nil
	}

	// Build batch update using CASE WHEN for efficiency
	// Only update if:
	// 1. Current snippet is NULL, empty, or "requires login"
	// 2. New snippet is valid (non-empty and not "requires login")
	var totalUpdated int64

	// Process in batches to avoid query size limits
	const batchSize = 100
	fingerprints := make([]string, 0, len(snippets))
	for fp := range snippets {
		fingerprints = append(fingerprints, fp)
	}

	for i := 0; i < len(fingerprints); i += batchSize {
		end := i + batchSize
		if end > len(fingerprints) {
			end = len(fingerprints)
		}
		batch := fingerprints[i:end]

		// Build CASE statement for batch update
		var caseBuilder strings.Builder
		caseBuilder.WriteString("CASE fingerprint ")
		args := []interface{}{tenantID.String()}
		argIdx := 2

		validFingerprints := make([]string, 0, len(batch))
		for _, fp := range batch {
			snippet := snippets[fp]
			// Skip if new snippet is invalid
			if snippet == "" || snippet == "requires login" {
				continue
			}
			validFingerprints = append(validFingerprints, fp)
			caseBuilder.WriteString(fmt.Sprintf("WHEN $%d THEN $%d ", argIdx, argIdx+1))
			args = append(args, fp, snippet)
			argIdx += 2
		}

		if len(validFingerprints) == 0 {
			continue
		}

		caseBuilder.WriteString("END")
		args = append(args, pq.Array(validFingerprints))

		query := fmt.Sprintf(`
			UPDATE findings
			SET snippet = %s, updated_at = NOW()
			WHERE tenant_id = $1
			AND fingerprint = ANY($%d)
			AND (snippet IS NULL OR snippet = '' OR snippet = 'requires login')
		`, caseBuilder.String(), argIdx)

		result, err := r.db.ExecContext(ctx, query, args...)
		if err != nil {
			return totalUpdated, fmt.Errorf("failed to update snippets: %w", err)
		}

		affected, _ := result.RowsAffected()
		totalUpdated += affected
	}

	return totalUpdated, nil
}

// BatchCountByAssetIDs returns the count of findings for multiple assets in one query.
// Security: Requires tenantID to prevent cross-tenant data access.
// Returns a map of assetID -> count.
func (r *FindingRepository) BatchCountByAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]int64, error) {
	if len(assetIDs) == 0 {
		return map[shared.ID]int64{}, nil
	}

	// Convert to string array for query
	idStrings := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		idStrings[i] = id.String()
	}

	// Security: Include tenant_id in WHERE clause
	query := `
		SELECT asset_id, COUNT(*) as count
		FROM findings
		WHERE tenant_id = $1 AND asset_id = ANY($2)
		GROUP BY asset_id
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(idStrings))
	if err != nil {
		return nil, fmt.Errorf("failed to count findings by assets: %w", err)
	}
	defer rows.Close()

	result := make(map[shared.ID]int64, len(assetIDs))
	// Initialize all assets with 0 count
	for _, id := range assetIDs {
		result[id] = 0
	}

	for rows.Next() {
		var assetIDStr string
		var count int64
		if err := rows.Scan(&assetIDStr, &count); err != nil {
			return nil, fmt.Errorf("failed to scan count: %w", err)
		}
		assetID, err := shared.IDFromString(assetIDStr)
		if err != nil {
			continue
		}
		result[assetID] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating counts: %w", err)
	}

	return result, nil
}

// Helper methods

func (r *FindingRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, vulnerability_id, asset_id, branch_id, component_id, source,
			tool_name, tool_id, tool_version, rule_id, rule_name, file_path, start_line, end_line,
			start_column, end_column, snippet, context_snippet, context_start_line,
			title, description, message,
			severity, cvss_score, cvss_vector, cve_id, cwe_ids, owasp_ids, tags,
			status, resolution, resolution_method, resolved_at, resolved_by,
			assigned_to, assigned_at, assigned_by,
			verified_at, verified_by,
			sla_deadline, sla_status,
			first_detected_at, last_seen_at, first_detected_branch, first_detected_commit, last_seen_branch, last_seen_commit,
			related_issue_url, related_pr_url,
			duplicate_of, duplicate_count, comments_count,
			acceptance_expires_at,
			scan_id, fingerprint, agent_id, metadata, pentest_campaign_id, created_at, updated_at,
			confidence, impact, likelihood, vulnerability_class, subcategory,
			baseline_state, kind, rank, occurrence_count, correlation_id,
			partial_fingerprints, related_locations, stacks, attachments, work_item_uris, hosted_viewer_uri,
			exposure_vector, is_network_accessible, is_internet_accessible, attack_prerequisites,
			epss_score, epss_percentile, is_in_kev, kev_due_date,
			priority_class, priority_class_reason, priority_class_override, priority_class_overridden_by, priority_class_overridden_at,
			is_reachable, reachable_from_count,
			remediation_type, estimated_fix_time, fix_complexity, remedy_available,
			data_exposure_risk, reputational_impact, compliance_impact,
			remediation, created_by,
			EXISTS(SELECT 1 FROM finding_data_flows df WHERE df.finding_id = findings.id) AS has_data_flow
		FROM findings
	`
}

func (r *FindingRepository) scanFinding(row *sql.Row, notFoundErr error) (*vulnerability.Finding, error) {
	finding, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, notFoundErr
		}
		return nil, fmt.Errorf("failed to scan finding: %w", err)
	}
	return finding, nil
}

func (r *FindingRepository) scanFindingFromRows(rows *sql.Rows) (*vulnerability.Finding, error) {
	return r.doScan(rows.Scan)
}

func (r *FindingRepository) doScan(scan func(dest ...any) error) (*vulnerability.Finding, error) {
	var (
		idStr               string
		tenantIDStr         string
		vulnerabilityID     sql.NullString
		assetIDStr          sql.NullString
		branchID            sql.NullString
		componentID         sql.NullString
		source              string
		toolName            string
		toolID              sql.NullString
		toolVersion         sql.NullString
		ruleID              sql.NullString
		ruleName            sql.NullString
		filePath            sql.NullString
		startLine           sql.NullInt64
		endLine             sql.NullInt64
		startColumn         sql.NullInt64
		endColumn           sql.NullInt64
		snippet             sql.NullString
		contextSnippet      sql.NullString
		contextStartLine    sql.NullInt64
		title               sql.NullString
		description         sql.NullString
		message             string
		severity            string
		cvssScore           sql.NullFloat64
		cvssVector          sql.NullString
		cveID               sql.NullString
		cweIDs              []string
		owaspIDs            []string
		tags                []string
		status              string
		resolution          sql.NullString
		resolutionMethod    sql.NullString
		resolvedAt          sql.NullTime
		resolvedBy          sql.NullString
		assignedTo          sql.NullString
		assignedAt          sql.NullTime
		assignedBy          sql.NullString
		verifiedAt          sql.NullTime
		verifiedBy          sql.NullString
		slaDeadline         sql.NullTime
		slaStatus           sql.NullString
		firstDetectedAt     time.Time
		lastSeenAt          time.Time
		firstBranch         sql.NullString
		firstCommit         sql.NullString
		lastBranch          sql.NullString
		lastCommit          sql.NullString
		relatedIssue        sql.NullString
		relatedPR           sql.NullString
		duplicateOf         sql.NullString
		duplicateCount      int
		commentsCount       int
		acceptanceExpiresAt sql.NullTime
		scanID              sql.NullString
		fingerprint         string
		agentID             sql.NullString
		metadata            []byte
		pentestCampaignID   sql.NullString
		createdAt           time.Time
		updatedAt           time.Time
		// SARIF 2.1.0 fields
		confidence          sql.NullInt64
		impact              sql.NullString
		likelihood          sql.NullString
		vulnerabilityClass  []string
		subcategory         []string
		baselineState       sql.NullString
		kind                sql.NullString
		rank                sql.NullFloat64
		occurrenceCount     sql.NullInt64
		correlationID       sql.NullString
		partialFingerprints []byte
		relatedLocations    []byte
		stacks              []byte
		attachments         []byte
		workItemURIs        []string
		hostedViewerURI     sql.NullString
		// CTEM fields
		exposureVector       sql.NullString
		isNetworkAccessible  sql.NullBool
		isInternetAccessible sql.NullBool
		attackPrerequisites  sql.NullString
		// Priority classification (RFC-004)
		epssScore                 sql.NullFloat64
		epssPercentile            sql.NullFloat64
		isInKEV                   sql.NullBool
		kevDueDate                sql.NullTime
		priorityClass             sql.NullString
		priorityClassReason       sql.NullString
		priorityClassOverride     sql.NullBool
		priorityClassOverriddenBy sql.NullString
		priorityClassOverriddenAt sql.NullTime
		isReachable               sql.NullBool
		reachableFromCount        sql.NullInt64
		remediationType           sql.NullString
		estimatedFixTime          sql.NullInt64
		fixComplexity             sql.NullString
		remedyAvailable           sql.NullBool
		dataExposureRisk          sql.NullString
		reputationalImpact        sql.NullBool
		complianceImpact          []string
		// Remediation JSONB
		remediation []byte
		// Creator (pentest ownership)
		createdBy sql.NullString
		// Data flow flag
		hasDataFlow bool
	)

	err := scan(
		&idStr, &tenantIDStr, &vulnerabilityID, &assetIDStr, &branchID, &componentID, &source,
		&toolName, &toolID, &toolVersion, &ruleID, &ruleName, &filePath, &startLine, &endLine,
		&startColumn, &endColumn, &snippet, &contextSnippet, &contextStartLine,
		&title, &description, &message,
		&severity, &cvssScore, &cvssVector, &cveID, pq.Array(&cweIDs), pq.Array(&owaspIDs), pq.Array(&tags),
		&status, &resolution, &resolutionMethod, &resolvedAt, &resolvedBy,
		&assignedTo, &assignedAt, &assignedBy,
		&verifiedAt, &verifiedBy,
		&slaDeadline, &slaStatus,
		&firstDetectedAt, &lastSeenAt, &firstBranch, &firstCommit, &lastBranch, &lastCommit,
		&relatedIssue, &relatedPR,
		&duplicateOf, &duplicateCount, &commentsCount,
		&acceptanceExpiresAt,
		&scanID, &fingerprint, &agentID, &metadata, &pentestCampaignID, &createdAt, &updatedAt,
		&confidence, &impact, &likelihood, pq.Array(&vulnerabilityClass), pq.Array(&subcategory),
		&baselineState, &kind, &rank, &occurrenceCount, &correlationID,
		&partialFingerprints, &relatedLocations, &stacks, &attachments, pq.Array(&workItemURIs), &hostedViewerURI,
		&exposureVector, &isNetworkAccessible, &isInternetAccessible, &attackPrerequisites,
		&epssScore, &epssPercentile, &isInKEV, &kevDueDate,
		&priorityClass, &priorityClassReason, &priorityClassOverride, &priorityClassOverriddenBy, &priorityClassOverriddenAt,
		&isReachable, &reachableFromCount,
		&remediationType, &estimatedFixTime, &fixComplexity, &remedyAvailable,
		&dataExposureRisk, &reputationalImpact, pq.Array(&complianceImpact),
		&remediation, &createdBy,
		&hasDataFlow,
	)
	if err != nil {
		return nil, err
	}

	return r.reconstruct(findingRow{
		idStr, tenantIDStr, vulnerabilityID, assetIDStr, branchID, componentID, source,
		toolName, toolID, toolVersion, ruleID, ruleName, filePath,
		int(startLine.Int64), int(endLine.Int64), int(startColumn.Int64), int(endColumn.Int64),
		snippet, contextSnippet, int(contextStartLine.Int64),
		title, description, message,
		severity, cvssScore, cvssVector, cveID, cweIDs, owaspIDs, tags,
		status, resolution, resolutionMethod, resolvedAt, resolvedBy,
		assignedTo, assignedAt, assignedBy,
		verifiedAt, verifiedBy,
		slaDeadline, slaStatus,
		firstDetectedAt, lastSeenAt, firstBranch, firstCommit, lastBranch, lastCommit,
		relatedIssue, relatedPR,
		duplicateOf, duplicateCount, commentsCount,
		acceptanceExpiresAt,
		scanID, fingerprint, agentID, metadata, pentestCampaignID, createdAt, updatedAt,
		// SARIF fields
		confidence, impact, likelihood, vulnerabilityClass, subcategory,
		baselineState, kind, rank, occurrenceCount, correlationID,
		partialFingerprints, relatedLocations, stacks, attachments, workItemURIs, hostedViewerURI,
		// CTEM fields
		exposureVector, isNetworkAccessible, isInternetAccessible, attackPrerequisites,
		// Priority classification (RFC-004)
		epssScore, epssPercentile, isInKEV, kevDueDate,
		priorityClass, priorityClassReason, priorityClassOverride, priorityClassOverriddenBy, priorityClassOverriddenAt,
		isReachable, reachableFromCount,
		remediationType, estimatedFixTime, fixComplexity, remedyAvailable,
		dataExposureRisk, reputationalImpact, complianceImpact,
		// Remediation JSONB
		remediation,
		// Creator (pentest ownership)
		createdBy,
		// Data flow flag
		hasDataFlow,
	})
}

// findingRow contains scanned row data for a finding.
type findingRow struct {
	idStr               string
	tenantIDStr         string
	vulnerabilityID     sql.NullString
	assetIDStr          sql.NullString // nullable since migration 000112
	branchID            sql.NullString
	componentID         sql.NullString
	source              string
	toolName            string
	toolID              sql.NullString
	toolVersion         sql.NullString
	ruleID              sql.NullString
	ruleName            sql.NullString
	filePath            sql.NullString
	startLine           int
	endLine             int
	startColumn         int
	endColumn           int
	snippet             sql.NullString
	contextSnippet      sql.NullString
	contextStartLine    int
	title               sql.NullString
	description         sql.NullString
	message             string
	severity            string
	cvssScore           sql.NullFloat64
	cvssVector          sql.NullString
	cveID               sql.NullString
	cweIDs              []string
	owaspIDs            []string
	tags                []string
	status              string
	resolution          sql.NullString
	resolutionMethod    sql.NullString
	resolvedAt          sql.NullTime
	resolvedBy          sql.NullString
	assignedTo          sql.NullString
	assignedAt          sql.NullTime
	assignedBy          sql.NullString
	verifiedAt          sql.NullTime
	verifiedBy          sql.NullString
	slaDeadline         sql.NullTime
	slaStatus           sql.NullString
	firstDetectedAt     time.Time
	lastSeenAt          time.Time
	firstBranch         sql.NullString
	firstCommit         sql.NullString
	lastBranch          sql.NullString
	lastCommit          sql.NullString
	relatedIssue        sql.NullString
	relatedPR           sql.NullString
	duplicateOf         sql.NullString
	duplicateCount      int
	commentsCount       int
	acceptanceExpiresAt sql.NullTime
	scanID              sql.NullString
	fingerprint         string
	agentID             sql.NullString
	metadata            []byte
	pentestCampaignID   sql.NullString
	createdAt           time.Time
	updatedAt           time.Time
	// SARIF 2.1.0 fields
	confidence          sql.NullInt64
	impact              sql.NullString
	likelihood          sql.NullString
	vulnerabilityClass  []string
	subcategory         []string
	baselineState       sql.NullString
	kind                sql.NullString
	rank                sql.NullFloat64
	occurrenceCount     sql.NullInt64
	correlationID       sql.NullString
	partialFingerprints []byte
	relatedLocations    []byte
	stacks              []byte
	attachments         []byte
	workItemURIs        []string
	hostedViewerURI     sql.NullString
	// CTEM fields
	exposureVector       sql.NullString
	isNetworkAccessible  sql.NullBool
	isInternetAccessible sql.NullBool
	attackPrerequisites  sql.NullString
	// Priority classification (RFC-004)
	epssScore                 sql.NullFloat64
	epssPercentile            sql.NullFloat64
	isInKEV                   sql.NullBool
	kevDueDate                sql.NullTime
	priorityClass             sql.NullString
	priorityClassReason       sql.NullString
	priorityClassOverride     sql.NullBool
	priorityClassOverriddenBy sql.NullString
	priorityClassOverriddenAt sql.NullTime
	isReachable               sql.NullBool
	reachableFromCount        sql.NullInt64
	remediationType           sql.NullString
	estimatedFixTime          sql.NullInt64
	fixComplexity             sql.NullString
	remedyAvailable           sql.NullBool
	dataExposureRisk          sql.NullString
	reputationalImpact        sql.NullBool
	complianceImpact          []string
	// Remediation JSONB
	remediation []byte
	// Creator (pentest ownership)
	createdBy sql.NullString
	// Data flow flag
	hasDataFlow bool
}

func (r *FindingRepository) reconstruct(row findingRow) (*vulnerability.Finding, error) {
	parsedID, err := shared.IDFromString(row.idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	parsedTenantID, err := shared.IDFromString(row.tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tenant_id: %w", err)
	}

	// asset_id is nullable for pentest findings (migration 000112).
	// Zero ID indicates "no linked asset".
	var parsedAssetID shared.ID
	if row.assetIDStr.Valid && row.assetIDStr.String != "" {
		id, err := shared.IDFromString(row.assetIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset id: %w", err)
		}
		parsedAssetID = id
	}

	var vulnID *shared.ID
	if row.vulnerabilityID.Valid {
		id, err := shared.IDFromString(row.vulnerabilityID.String)
		if err == nil {
			vulnID = &id
		}
	}

	var parsedBranchID *shared.ID
	if row.branchID.Valid {
		id, err := shared.IDFromString(row.branchID.String)
		if err == nil {
			parsedBranchID = &id
		}
	}

	var compID *shared.ID
	if row.componentID.Valid {
		id, err := shared.IDFromString(row.componentID.String)
		if err == nil {
			compID = &id
		}
	}

	source, _ := vulnerability.ParseFindingSource(row.source)
	severity, _ := vulnerability.ParseSeverity(row.severity)
	status, _ := vulnerability.ParseFindingStatus(row.status)

	var meta map[string]any
	if len(row.metadata) > 0 {
		if err := json.Unmarshal(row.metadata, &meta); err != nil {
			meta = make(map[string]any)
		}
	}

	var cvssScore *float64
	if row.cvssScore.Valid {
		cvssScore = &row.cvssScore.Float64
	}

	// Parse SARIF JSONB fields
	var partialFingerprints map[string]string
	if len(row.partialFingerprints) > 0 {
		if err := json.Unmarshal(row.partialFingerprints, &partialFingerprints); err != nil {
			partialFingerprints = make(map[string]string)
		}
	}

	var relatedLocations []vulnerability.FindingLocation
	if len(row.relatedLocations) > 0 {
		if err := json.Unmarshal(row.relatedLocations, &relatedLocations); err != nil {
			relatedLocations = []vulnerability.FindingLocation{}
		}
	}

	var stacks []vulnerability.StackTrace
	if len(row.stacks) > 0 {
		if err := json.Unmarshal(row.stacks, &stacks); err != nil {
			stacks = []vulnerability.StackTrace{}
		}
	}

	var attachments []vulnerability.Attachment
	if len(row.attachments) > 0 {
		if err := json.Unmarshal(row.attachments, &attachments); err != nil {
			attachments = []vulnerability.Attachment{}
		}
	}

	var confidence *int
	if row.confidence.Valid {
		c := int(row.confidence.Int64)
		confidence = &c
	}

	var rank *float64
	if row.rank.Valid {
		rank = &row.rank.Float64
	}

	// Parse CTEM fields
	var estimatedFixTime *int
	if row.estimatedFixTime.Valid {
		t := int(row.estimatedFixTime.Int64)
		estimatedFixTime = &t
	}

	exposureVector, _ := vulnerability.ParseExposureVector(nullStringValue(row.exposureVector))
	remediationType, _ := vulnerability.ParseRemediationType(nullStringValue(row.remediationType))
	fixComplexity, _ := vulnerability.ParseFixComplexity(nullStringValue(row.fixComplexity))
	dataExposureRisk, _ := vulnerability.ParseDataExposureRisk(nullStringValue(row.dataExposureRisk))

	// Parse priority classification fields (RFC-004)
	var epssScore *float64
	if row.epssScore.Valid {
		epssScore = &row.epssScore.Float64
	}

	var epssPercentile *float64
	if row.epssPercentile.Valid {
		epssPercentile = &row.epssPercentile.Float64
	}

	var priorityClass *vulnerability.PriorityClass
	if row.priorityClass.Valid && row.priorityClass.String != "" {
		pc, pcErr := vulnerability.ParsePriorityClass(row.priorityClass.String)
		if pcErr == nil {
			priorityClass = &pc
		}
	}

	var reachableFromCount int
	if row.reachableFromCount.Valid {
		reachableFromCount = int(row.reachableFromCount.Int64)
	}

	// Parse remediation JSONB
	var remediation *vulnerability.FindingRemediation
	if len(row.remediation) > 0 {
		remediation = &vulnerability.FindingRemediation{}
		if err := json.Unmarshal(row.remediation, remediation); err != nil {
			remediation = nil // Ignore unmarshal errors, use nil
		}
	}

	data := vulnerability.FindingData{
		ID:                  parsedID,
		TenantID:            parsedTenantID,
		VulnerabilityID:     vulnID,
		AssetID:             parsedAssetID,
		BranchID:            parsedBranchID,
		ComponentID:         compID,
		Source:              source,
		ToolName:            row.toolName,
		ToolID:              parseNullID(row.toolID),
		ToolVersion:         nullStringValue(row.toolVersion),
		RuleID:              nullStringValue(row.ruleID),
		RuleName:            nullStringValue(row.ruleName),
		FilePath:            nullStringValue(row.filePath),
		StartLine:           row.startLine,
		EndLine:             row.endLine,
		StartColumn:         row.startColumn,
		EndColumn:           row.endColumn,
		Snippet:             nullStringValue(row.snippet),
		ContextSnippet:      nullStringValue(row.contextSnippet),
		ContextStartLine:    row.contextStartLine,
		Title:               nullStringValue(row.title),
		Description:         nullStringValue(row.description),
		Message:             row.message,
		Recommendation:      getRecommendationFromRemediation(remediation),
		Remediation:         remediation,
		Severity:            severity,
		CVSSScore:           cvssScore,
		CVSSVector:          nullStringValue(row.cvssVector),
		CVEID:               nullStringValue(row.cveID),
		CWEIDs:              row.cweIDs,
		OWASPIDs:            row.owaspIDs,
		Tags:                row.tags,
		Status:              status,
		Resolution:          nullStringValue(row.resolution),
		ResolutionMethod:    nullStringValue(row.resolutionMethod),
		ResolvedAt:          nullTimeValue(row.resolvedAt),
		ResolvedBy:          parseNullID(row.resolvedBy),
		AssignedTo:          parseNullID(row.assignedTo),
		AssignedAt:          nullTimeValue(row.assignedAt),
		AssignedBy:          parseNullID(row.assignedBy),
		VerifiedAt:          nullTimeValue(row.verifiedAt),
		VerifiedBy:          parseNullID(row.verifiedBy),
		SLADeadline:         nil,
		SLAStatus:           vulnerability.SLAStatusNotApplicable,
		FirstDetectedAt:     row.firstDetectedAt,
		LastSeenAt:          row.lastSeenAt,
		FirstDetectedBranch: nullStringValue(row.firstBranch),
		FirstDetectedCommit: nullStringValue(row.firstCommit),
		LastSeenBranch:      nullStringValue(row.lastBranch),
		LastSeenCommit:      nullStringValue(row.lastCommit),
		RelatedIssueURL:     nullStringValue(row.relatedIssue),
		RelatedPRURL:        nullStringValue(row.relatedPR),
		DuplicateOf:         parseNullID(row.duplicateOf),
		DuplicateCount:      row.duplicateCount,
		CommentsCount:       row.commentsCount,
		AcceptanceExpiresAt: nullTimeValue(row.acceptanceExpiresAt),
		ScanID:              nullStringValue(row.scanID),
		Fingerprint:         row.fingerprint,
		AgentID:             parseNullID(row.agentID),
		Metadata:            meta,
		// For pentest findings, source_metadata keys live inside the same
		// metadata JSONB column. Copy the full map so the handler's
		// toUnifiedPentestFindingResponse() can read steps_to_reproduce,
		// poc_code, business_impact, etc. from SourceMetadata().
		SourceMetadata:      meta,
		PentestCampaignID:   parseNullID(row.pentestCampaignID),
		CreatedAt:           row.createdAt,
		UpdatedAt:           row.updatedAt,
		CreatedBy:           parseNullID(row.createdBy),
		// SARIF 2.1.0 fields
		Confidence:          confidence,
		Impact:              nullStringValue(row.impact),
		Likelihood:          nullStringValue(row.likelihood),
		VulnerabilityClass:  row.vulnerabilityClass,
		Subcategory:         row.subcategory,
		BaselineState:       nullStringValue(row.baselineState),
		Kind:                nullStringValue(row.kind),
		Rank:                rank,
		OccurrenceCount:     int(row.occurrenceCount.Int64),
		CorrelationID:       nullStringValue(row.correlationID),
		PartialFingerprints: partialFingerprints,
		RelatedLocations:    relatedLocations,
		Stacks:              stacks,
		Attachments:         attachments,
		WorkItemURIs:        row.workItemURIs,
		HostedViewerURI:     nullStringValue(row.hostedViewerURI),
		// CTEM fields
		ExposureVector:       exposureVector,
		IsNetworkAccessible:  nullBoolValue(row.isNetworkAccessible) != nil && *nullBoolValue(row.isNetworkAccessible),
		IsInternetAccessible: nullBoolValue(row.isInternetAccessible) != nil && *nullBoolValue(row.isInternetAccessible),
		AttackPrerequisites:  nullStringValue(row.attackPrerequisites),
		// Priority classification (RFC-004)
		EPSSScore:                 epssScore,
		EPSSPercentile:            epssPercentile,
		IsInKEV:                   row.isInKEV.Valid && row.isInKEV.Bool,
		KEVDueDate:                nullTimeValue(row.kevDueDate),
		PriorityClass:             priorityClass,
		PriorityClassReason:       nullStringValue(row.priorityClassReason),
		PriorityClassOverride:     row.priorityClassOverride.Valid && row.priorityClassOverride.Bool,
		PriorityClassOverriddenBy: parseNullID(row.priorityClassOverriddenBy),
		PriorityClassOverriddenAt: nullTimeValue(row.priorityClassOverriddenAt),
		IsReachable:               row.isReachable.Valid && row.isReachable.Bool,
		ReachableFromCount:        reachableFromCount,
		RemediationType:           remediationType,
		EstimatedFixTime:          estimatedFixTime,
		FixComplexity:             fixComplexity,
		RemedyAvailable:           nullBoolValue(row.remedyAvailable) != nil && *nullBoolValue(row.remedyAvailable),
		DataExposureRisk:          dataExposureRisk,
		ReputationalImpact:        nullBoolValue(row.reputationalImpact) != nil && *nullBoolValue(row.reputationalImpact),
		ComplianceImpact:          row.complianceImpact,
		// Data flow flag (from subquery)
		HasDataFlow: row.hasDataFlow,
	}

	return vulnerability.ReconstituteFinding(data), nil
}

// ListByAssetID retrieves findings for an asset.
// Security: Requires tenantID to prevent cross-tenant data access.
func (r *FindingRepository) ListByAssetID(ctx context.Context, tenantID, assetID shared.ID, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID).WithAssetID(assetID)
	return r.List(ctx, filter, opts, page)
}

// CountByAssetID returns the count of findings for an asset.
// Security: Requires tenantID to prevent cross-tenant data access.
func (r *FindingRepository) CountByAssetID(ctx context.Context, tenantID, assetID shared.ID) (int64, error) {
	// Security: Include tenant_id in WHERE clause
	query := `SELECT COUNT(*) FROM findings WHERE asset_id = $1 AND tenant_id = $2`

	var count int64
	err := r.db.QueryRowContext(ctx, query, assetID.String(), tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}

	return count, nil
}

// CountOpenByAssetID returns the count of open findings for an asset.
// Security: Requires tenantID to prevent cross-tenant data access.
func (r *FindingRepository) CountOpenByAssetID(ctx context.Context, tenantID, assetID shared.ID) (int64, error) {
	// Security: Include tenant_id in WHERE clause
	query := `SELECT COUNT(*) FROM findings WHERE asset_id = $1 AND tenant_id = $2 AND status IN ('open', 'in_progress')`

	var count int64
	err := r.db.QueryRowContext(ctx, query, assetID.String(), tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count open findings: %w", err)
	}

	return count, nil
}

// DeleteByAssetID removes all findings for an asset.
// Security: Requires tenantID to prevent cross-tenant deletion.
func (r *FindingRepository) DeleteByAssetID(ctx context.Context, tenantID, assetID shared.ID) error {
	// Security: Include tenant_id in WHERE clause
	query := `DELETE FROM findings WHERE asset_id = $1 AND tenant_id = $2`

	_, err := r.db.ExecContext(ctx, query, assetID.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to delete findings: %w", err)
	}

	return nil
}

// GetStats returns aggregated statistics for findings of a tenant.
// dataScopeUserID: if non-nil, only count findings for assets accessible to this user.
// assetID: if non-nil, only count findings for that specific asset.
func (r *FindingRepository) GetStats(ctx context.Context, tenantID shared.ID, dataScopeUserID *shared.ID, assetID *shared.ID) (*vulnerability.FindingStats, error) {
	stats := vulnerability.NewFindingStats()

	// Query for total and counts by severity, status, source in one go
	// Statuses: new, confirmed, in_progress, resolved, false_positive, accepted, duplicate
	query := `
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0) as critical,
			COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0) as high,
			COALESCE(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END), 0) as medium,
			COALESCE(SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END), 0) as low,
			COALESCE(SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END), 0) as info,
			COALESCE(SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END), 0) as status_new,
			COALESCE(SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END), 0) as status_confirmed,
			COALESCE(SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END), 0) as status_in_progress,
			COALESCE(SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END), 0) as status_resolved,
			COALESCE(SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END), 0) as status_false_positive,
			COALESCE(SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END), 0) as status_accepted,
			COALESCE(SUM(CASE WHEN status = 'duplicate' THEN 1 ELSE 0 END), 0) as status_duplicate,
			COALESCE(SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END), 0) as status_draft,
			COALESCE(SUM(CASE WHEN status = 'in_review' THEN 1 ELSE 0 END), 0) as status_in_review,
			COALESCE(SUM(CASE WHEN status = 'remediation' THEN 1 ELSE 0 END), 0) as status_remediation,
			COALESCE(SUM(CASE WHEN status = 'retest' THEN 1 ELSE 0 END), 0) as status_retest,
			COALESCE(SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END), 0) as status_verified,
			COALESCE(SUM(CASE WHEN status = 'accepted_risk' THEN 1 ELSE 0 END), 0) as status_accepted_risk,
			COALESCE(SUM(CASE WHEN source = 'sast' THEN 1 ELSE 0 END), 0) as source_sast,
			COALESCE(SUM(CASE WHEN source = 'dast' THEN 1 ELSE 0 END), 0) as source_dast,
			COALESCE(SUM(CASE WHEN source = 'sca' THEN 1 ELSE 0 END), 0) as source_sca,
			COALESCE(SUM(CASE WHEN source = 'secret' THEN 1 ELSE 0 END), 0) as source_secret,
			COALESCE(SUM(CASE WHEN source = 'iac' THEN 1 ELSE 0 END), 0) as source_iac,
			COALESCE(SUM(CASE WHEN source = 'container' THEN 1 ELSE 0 END), 0) as source_container,
			COALESCE(SUM(CASE WHEN source = 'manual' THEN 1 ELSE 0 END), 0) as source_manual,
			COALESCE(SUM(CASE WHEN source = 'pentest' THEN 1 ELSE 0 END), 0) as source_pentest,
			COALESCE(SUM(CASE WHEN source = 'external' THEN 1 ELSE 0 END), 0) as source_external
		FROM findings
		WHERE tenant_id = $1
	`

	args := []any{tenantID.String()}

	// Layer 2: Data Scope - filter stats by user's group membership
	if dataScopeUserID != nil {
		query += ` AND (
			NOT EXISTS (SELECT 1 FROM user_accessible_assets WHERE user_id = $2 AND tenant_id = $1)
			OR asset_id IN (SELECT asset_id FROM user_accessible_assets WHERE user_id = $2 AND tenant_id = $1)
		)`
		args = append(args, dataScopeUserID.String())
	}

	// Asset filter — used when the page is `/findings?assetId=…` so
	// the severity cards reflect the same filtered table the user is
	// looking at, not the global tenant counts.
	if assetID != nil {
		args = append(args, assetID.String())
		query += fmt.Sprintf(" AND asset_id = $%d", len(args))
	}

	var (
		total, critical, high, medium, low, info                     int64
		statusNew, statusConfirmed, statusInProgress, statusResolved int64
		statusFalsePositive, statusAccepted, statusDuplicate         int64
		statusDraft, statusInReview, statusRemediation               int64
		statusRetest, statusVerified, statusAcceptedRisk             int64
		sourceSast, sourceDast, sourceSca, sourceSecret              int64
		sourceIac, sourceContainer, sourceManual, sourcePentest      int64
		sourceExternal                                               int64
	)

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&total,
		&critical, &high, &medium, &low, &info,
		&statusNew, &statusConfirmed, &statusInProgress, &statusResolved,
		&statusFalsePositive, &statusAccepted, &statusDuplicate,
		&statusDraft, &statusInReview, &statusRemediation,
		&statusRetest, &statusVerified, &statusAcceptedRisk,
		&sourceSast, &sourceDast, &sourceSca, &sourceSecret,
		&sourceIac, &sourceContainer, &sourceManual, &sourcePentest,
		&sourceExternal,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding stats: %w", err)
	}

	stats.Total = total

	// By severity
	stats.BySeverity[vulnerability.SeverityCritical] = critical
	stats.BySeverity[vulnerability.SeverityHigh] = high
	stats.BySeverity[vulnerability.SeverityMedium] = medium
	stats.BySeverity[vulnerability.SeverityLow] = low
	stats.BySeverity[vulnerability.SeverityNone] = info // Map 'info' to SeverityNone

	// By status (7 statuses: new, confirmed, in_progress, resolved, false_positive, accepted, duplicate)
	stats.ByStatus[vulnerability.FindingStatusNew] = statusNew
	stats.ByStatus[vulnerability.FindingStatusConfirmed] = statusConfirmed
	stats.ByStatus[vulnerability.FindingStatusInProgress] = statusInProgress
	stats.ByStatus[vulnerability.FindingStatusResolved] = statusResolved
	stats.ByStatus[vulnerability.FindingStatusFalsePositive] = statusFalsePositive
	stats.ByStatus[vulnerability.FindingStatusAccepted] = statusAccepted
	stats.ByStatus[vulnerability.FindingStatusDuplicate] = statusDuplicate
	stats.ByStatus[vulnerability.FindingStatusDraft] = statusDraft
	stats.ByStatus[vulnerability.FindingStatusInReview] = statusInReview
	stats.ByStatus[vulnerability.FindingStatusRemediation] = statusRemediation
	stats.ByStatus[vulnerability.FindingStatusRetest] = statusRetest
	stats.ByStatus[vulnerability.FindingStatusVerified] = statusVerified
	stats.ByStatus[vulnerability.FindingStatusAcceptedRisk] = statusAcceptedRisk

	// By source
	stats.BySource[vulnerability.FindingSourceSAST] = sourceSast
	stats.BySource[vulnerability.FindingSourceDAST] = sourceDast
	stats.BySource[vulnerability.FindingSourceSCA] = sourceSca
	stats.BySource[vulnerability.FindingSourceSecret] = sourceSecret
	stats.BySource[vulnerability.FindingSourceIaC] = sourceIac
	stats.BySource[vulnerability.FindingSourceContainer] = sourceContainer
	stats.BySource[vulnerability.FindingSourceManual] = sourceManual
	stats.BySource[vulnerability.FindingSourcePentest] = sourcePentest
	stats.BySource[vulnerability.FindingSourceExternal] = sourceExternal

	// Calculate open and resolved counts
	// Open = new + confirmed + in_progress + pentest active (draft, in_review, remediation, retest)
	stats.OpenCount = statusNew + statusConfirmed + statusInProgress + statusDraft + statusInReview + statusRemediation + statusRetest
	stats.ResolvedCount = statusResolved + statusVerified

	return stats, nil
}

func (r *FindingRepository) buildWhereClause(filter vulnerability.FindingFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.AssetID != nil {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", argIndex))
		args = append(args, filter.AssetID.String())
		argIndex++
	}

	if filter.BranchID != nil {
		conditions = append(conditions, fmt.Sprintf("branch_id = $%d", argIndex))
		args = append(args, filter.BranchID.String())
		argIndex++
	}

	if filter.ComponentID != nil {
		conditions = append(conditions, fmt.Sprintf("component_id = $%d", argIndex))
		args = append(args, filter.ComponentID.String())
		argIndex++
	}

	if filter.VulnerabilityID != nil {
		conditions = append(conditions, fmt.Sprintf("vulnerability_id = $%d", argIndex))
		args = append(args, filter.VulnerabilityID.String())
		argIndex++
	}

	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, sev := range filter.Severities {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, sev.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, st.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.ExcludeStatuses) > 0 {
		placeholders := make([]string, len(filter.ExcludeStatuses))
		for i, st := range filter.ExcludeStatuses {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, st.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("status NOT IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.Sources) > 0 {
		placeholders := make([]string, len(filter.Sources))
		for i, src := range filter.Sources {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, src.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.ToolName != nil && *filter.ToolName != "" {
		conditions = append(conditions, fmt.Sprintf("tool_name = $%d", argIndex))
		args = append(args, *filter.ToolName)
		argIndex++
	}

	if filter.RuleID != nil && *filter.RuleID != "" {
		conditions = append(conditions, fmt.Sprintf("rule_id = $%d", argIndex))
		args = append(args, *filter.RuleID)
		argIndex++
	}

	if filter.ScanID != nil && *filter.ScanID != "" {
		conditions = append(conditions, fmt.Sprintf("scan_id = $%d", argIndex))
		args = append(args, *filter.ScanID)
		argIndex++
	}

	if filter.FilePath != nil && *filter.FilePath != "" {
		conditions = append(conditions, fmt.Sprintf("file_path ILIKE $%d", argIndex))
		args = append(args, wrapLikePattern(*filter.FilePath))
		argIndex++
	}

	// Pentest campaign filter
	if filter.PentestCampaignID != nil {
		conditions = append(conditions, fmt.Sprintf("pentest_campaign_id = $%d", argIndex))
		args = append(args, filter.PentestCampaignID.String())
		argIndex++
	}

	// Pentest campaign visibility filter: restrict findings to a set of campaigns
	// the caller has access to. Empty slice means "no campaigns" → return nothing.
	if filter.PentestCampaignIDs != nil {
		if len(filter.PentestCampaignIDs) == 0 {
			conditions = append(conditions, "FALSE")
		} else {
			placeholders := make([]string, len(filter.PentestCampaignIDs))
			for i, id := range filter.PentestCampaignIDs {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, id.String())
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("pentest_campaign_id IN (%s)", strings.Join(placeholders, ",")))
		}
	}

	// Pentest campaign membership visibility filter (single SQL subquery).
	// Preferred over PentestCampaignIDs when caller has a user ID — lets the
	// PG planner pick the cheapest join strategy. Requires filter.TenantID set.
	if filter.PentestCampaignMemberUserID != nil && filter.TenantID != nil {
		userIdx := argIndex
		tenantIdx := argIndex + 1
		args = append(args, filter.PentestCampaignMemberUserID.String(), filter.TenantID.String())
		argIndex += 2
		conditions = append(conditions, fmt.Sprintf(
			`pentest_campaign_id IN (
				SELECT campaign_id FROM pentest_campaign_members
				WHERE user_id = $%d AND tenant_id = $%d
			)`, userIdx, tenantIdx))
	}

	// Layer 2: Data Scope - filter findings by user's group membership on assets
	// Backward compat: if user has no rows in user_accessible_assets, show all (NOT EXISTS bypasses)
	if filter.DataScopeUserID != nil && filter.TenantID != nil {
		userIDIdx := argIndex
		tenantIDIdx := argIndex + 1
		args = append(args, filter.DataScopeUserID.String(), filter.TenantID.String())
		// argIndex not incremented — this is the last block that consumes it.
		conditions = append(conditions, fmt.Sprintf(`(
			NOT EXISTS (SELECT 1 FROM user_accessible_assets WHERE user_id = $%d AND tenant_id = $%d)
			OR asset_id IN (SELECT asset_id FROM user_accessible_assets WHERE user_id = $%d AND tenant_id = $%d)
		)`, userIDIdx, tenantIDIdx, userIDIdx, tenantIDIdx))
	}

	return strings.Join(conditions, " AND "), args
}

// AutoResolveStale marks findings as resolved when not found in current full scan.
// Only affects findings on the default branch (via branch_id FK to repository_branches.is_default).
// Only affects active statuses (new, open, confirmed, in_progress).
// Protected statuses (false_positive, accepted, duplicate) are never auto-resolved.
// If branchID is provided, only auto-resolves findings on that specific branch (if it's default).
// If branchID is nil, auto-resolves findings where branch_id points to any default branch.
// Returns the IDs of auto-resolved findings for activity logging.
func (r *FindingRepository) AutoResolveStale(ctx context.Context, tenantID shared.ID, assetID shared.ID, toolName string, currentScanID string, branchID *shared.ID) ([]shared.ID, error) {
	// Auto-resolve findings that:
	// 1. Belong to the same tenant, asset, and tool
	// 2. Are on the default branch (via JOIN to repository_branches.is_default = true)
	// 3. Have an active status (new, open, confirmed, in_progress)
	// 4. Were NOT updated by the current scan (scan_id != currentScanID)
	// Protected statuses (false_positive, accepted, duplicate, resolved) are excluded
	var query string
	var args []interface{}

	if branchID != nil {
		// Auto-resolve only for the specific branch if it's a default branch
		query = `
			UPDATE findings f
			SET status = 'resolved',
				resolution = 'auto_fixed',
				resolution_method = 'scan_verified',
				resolved_at = NOW(),
				updated_at = NOW()
			FROM repository_branches rb
			WHERE f.tenant_id = $1
				AND f.asset_id = $2
				AND f.tool_name = $3
				AND f.scan_id != $4
				AND f.branch_id = $5
				AND f.branch_id = rb.id
				AND rb.is_default = true
				AND f.status IN ('new', 'open', 'confirmed', 'in_progress', 'fix_applied')
				AND f.source NOT IN ('pentest', 'manual', 'bug_bounty', 'red_team')
			RETURNING f.id
		`
		args = []interface{}{tenantID.String(), assetID.String(), toolName, currentScanID, branchID.String()}
	} else {
		// Auto-resolve for any findings on a default branch
		query = `
			UPDATE findings f
			SET status = 'resolved',
				resolution = 'auto_fixed',
				resolution_method = 'scan_verified',
				resolved_at = NOW(),
				updated_at = NOW()
			FROM repository_branches rb
			WHERE f.tenant_id = $1
				AND f.asset_id = $2
				AND f.tool_name = $3
				AND f.scan_id != $4
				AND f.branch_id = rb.id
				AND rb.is_default = true
				AND f.status IN ('new', 'open', 'confirmed', 'in_progress', 'fix_applied')
				AND f.source NOT IN ('pentest', 'manual', 'bug_bounty', 'red_team')
			RETURNING f.id
		`
		args = []interface{}{tenantID.String(), assetID.String(), toolName, currentScanID}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to auto-resolve stale findings: %w", err)
	}
	defer rows.Close()

	var resolvedIDs []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan resolved finding id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		resolvedIDs = append(resolvedIDs, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating resolved findings: %w", err)
	}

	return resolvedIDs, nil
}

// AutoReopenByFingerprint reopens a previously auto-resolved finding if it reappears.
// Only reopens findings with resolution = 'auto_fixed'.
// Protected resolutions (false_positive, accepted_risk) are never reopened.
// Returns the finding ID if reopened, nil if not found or protected.
func (r *FindingRepository) AutoReopenByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (*shared.ID, error) {
	// Only reopen findings that were auto-resolved (resolution = 'auto_fixed')
	// Do NOT reopen manually resolved, false_positive, or accepted findings
	query := `
		UPDATE findings
		SET status = 'open',
			resolution = NULL,
			resolved_at = NULL,
			resolved_by = NULL,
			updated_at = NOW()
		WHERE tenant_id = $1
			AND fingerprint = $2
			AND status = 'resolved'
			AND resolution = 'auto_fixed'
		RETURNING id
	`

	var idStr string
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), fingerprint).Scan(&idStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Finding not found or not eligible for reopen (protected status)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to auto-reopen finding: %w", err)
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reopened finding id: %w", err)
	}

	return &id, nil
}

// AutoReopenByFingerprintsBatch reopens multiple previously auto-resolved findings in a single query.
// This is the batch version of AutoReopenByFingerprint for better performance.
// Only reopens findings with resolution = 'auto_fixed'.
// Protected resolutions (false_positive, accepted_risk) are never reopened.
// Returns a map of fingerprint -> reopened finding ID.
func (r *FindingRepository) AutoReopenByFingerprintsBatch(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]shared.ID, error) {
	result := make(map[string]shared.ID)

	if len(fingerprints) == 0 {
		return result, nil
	}

	// Only reopen findings that were auto-resolved (resolution = 'auto_fixed')
	// Do NOT reopen manually resolved, false_positive, or accepted findings
	// Use ANY($2) for batch lookup efficiency
	query := `
		UPDATE findings
		SET status = 'confirmed',
			resolution = NULL,
			resolution_method = NULL,
			resolved_at = NULL,
			resolved_by = NULL,
			updated_at = NOW()
		WHERE tenant_id = $1
			AND fingerprint = ANY($2)
			AND status = 'resolved'
			AND resolution = 'auto_fixed'
		RETURNING id, fingerprint
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("failed to batch auto-reopen findings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var idStr, fp string
		if err := rows.Scan(&idStr, &fp); err != nil {
			return nil, fmt.Errorf("failed to scan reopened finding: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		result[fp] = id
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating reopened findings: %w", err)
	}

	return result, nil
}

// ExpireFeatureBranchFindings marks stale feature branch findings as resolved.
// This is called by a background job to clean up findings on non-default branches
// that have not been seen for a configurable period.
// Uses JOIN with repository_branches to determine default branch status.
func (r *FindingRepository) ExpireFeatureBranchFindings(ctx context.Context, tenantID shared.ID, defaultExpiryDays int) (int64, error) {
	// Expire findings that:
	// 1. Have a branch_id linked to a non-default branch (via repository_branches.is_default = false)
	// 2. The branch allows expiry (keep_when_inactive = false)
	// 3. Have active status (new, open)
	// 4. Have not been seen for the configured expiry period (per-branch or default)
	// Resolution is set to 'branch_expired' to distinguish from other auto-resolve types
	query := `
		UPDATE findings f
		SET status = 'resolved',
			resolution = 'branch_expired',
			resolved_at = NOW(),
			updated_at = NOW()
		FROM repository_branches rb
		WHERE f.tenant_id = $1
			AND f.branch_id = rb.id
			AND rb.is_default = false
			AND rb.keep_when_inactive = false
			AND f.status IN ('new', 'open')
			AND f.last_seen_at < NOW() - make_interval(days => COALESCE(rb.retention_days, $2))
	`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), defaultExpiryDays)
	if err != nil {
		return 0, fmt.Errorf("failed to expire feature branch findings: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return affected, nil
}

// CountBySeverityForScan returns the count of findings grouped by severity for a scan.
// Used for quality gate evaluation.
func (r *FindingRepository) CountBySeverityForScan(ctx context.Context, tenantID shared.ID, scanID string) (vulnerability.SeverityCounts, error) {
	var counts vulnerability.SeverityCounts

	query := `
		SELECT
			COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0) AS critical,
			COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0) AS high,
			COALESCE(SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END), 0) AS medium,
			COALESCE(SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END), 0) AS low,
			COALESCE(SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END), 0) AS info,
			COUNT(*) AS total
		FROM findings
		WHERE tenant_id = $1 AND scan_id = $2 AND status NOT IN ('false_positive', 'resolved')
	`

	err := r.db.QueryRowContext(ctx, query, tenantID.String(), scanID).Scan(
		&counts.Critical,
		&counts.High,
		&counts.Medium,
		&counts.Low,
		&counts.Info,
		&counts.Total,
	)

	if err != nil {
		return counts, fmt.Errorf("failed to count findings by severity: %w", err)
	}

	return counts, nil
}

// ExistsByIDs checks which finding IDs exist in the database.
// Returns a map of finding ID -> exists boolean.
// Security: Requires tenantID to prevent cross-tenant data access.
// Used for batch validation in bulk operations (e.g., bulk AI triage).
func (r *FindingRepository) ExistsByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	if len(ids) == 0 {
		return make(map[shared.ID]bool), nil
	}

	// Initialize result map with all IDs as false
	result := make(map[shared.ID]bool, len(ids))
	for _, id := range ids {
		result[id] = false
	}

	// Convert IDs to strings for query
	idStrings := make([]string, len(ids))
	for i, id := range ids {
		idStrings[i] = id.String()
	}

	query := `
		SELECT id FROM findings
		WHERE tenant_id = $1 AND id = ANY($2)
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(idStrings))
	if err != nil {
		return nil, fmt.Errorf("failed to check finding IDs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan finding ID: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err == nil {
			result[id] = true
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return result, nil
}

// GetByFingerprintsBatch retrieves multiple findings by their fingerprints in a single query.
// Returns a map of fingerprint -> *Finding for all found findings.
// Security: Requires tenantID to enforce tenant isolation.
func (r *FindingRepository) GetByFingerprintsBatch(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]*vulnerability.Finding, error) {
	if len(fingerprints) == 0 {
		return make(map[string]*vulnerability.Finding), nil
	}

	// Use enrichment-optimized query (no correlated subquery for has_data_flow)
	// since callers of this method don't need the data flow flag.
	query := r.selectQueryForEnrichment() + " WHERE tenant_id = $1 AND fingerprint = ANY($2)"

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("failed to query findings by fingerprints: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*vulnerability.Finding, len(fingerprints))
	for rows.Next() {
		finding, err := r.scanFindingFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		result[finding.Fingerprint()] = finding
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating findings: %w", err)
	}

	return result, nil
}

// selectQueryForEnrichment returns a SELECT query without the correlated subquery
// for has_data_flow. This avoids N+1 subqueries when batch-loading findings
// purely for enrichment purposes (where we don't need the data flow flag).
func (r *FindingRepository) selectQueryForEnrichment() string {
	return `
		SELECT id, tenant_id, vulnerability_id, asset_id, branch_id, component_id, source,
			tool_name, tool_id, tool_version, rule_id, rule_name, file_path, start_line, end_line,
			start_column, end_column, snippet, context_snippet, context_start_line,
			title, description, message,
			severity, cvss_score, cvss_vector, cve_id, cwe_ids, owasp_ids, tags,
			status, resolution, resolution_method, resolved_at, resolved_by,
			assigned_to, assigned_at, assigned_by,
			verified_at, verified_by,
			sla_deadline, sla_status,
			first_detected_at, last_seen_at, first_detected_branch, first_detected_commit, last_seen_branch, last_seen_commit,
			related_issue_url, related_pr_url,
			duplicate_of, duplicate_count, comments_count,
			acceptance_expires_at,
			scan_id, fingerprint, agent_id, metadata, pentest_campaign_id, created_at, updated_at,
			confidence, impact, likelihood, vulnerability_class, subcategory,
			baseline_state, kind, rank, occurrence_count, correlation_id,
			partial_fingerprints, related_locations, stacks, attachments, work_item_uris, hosted_viewer_uri,
			exposure_vector, is_network_accessible, is_internet_accessible, attack_prerequisites,
			epss_score, epss_percentile, is_in_kev, kev_due_date,
			priority_class, priority_class_reason, priority_class_override, priority_class_overridden_by, priority_class_overridden_at,
			is_reachable, reachable_from_count,
			remediation_type, estimated_fix_time, fix_complexity, remedy_available,
			data_exposure_risk, reputational_impact, compliance_impact,
			remediation, created_by,
			FALSE AS has_data_flow
		FROM findings
	`
}

// enrichColumnsPerRow is the number of columns per finding in the batch enrichment VALUES clause.
const enrichColumnsPerRow = 61

// enrichBatchChunkSize limits rows per batch UPDATE to stay under PostgreSQL's 65535 parameter limit.
// 1000 rows × 50 columns = 50,000 params (safely under limit).
const enrichBatchChunkSize = 1000

// enrichColumnDef defines a column name and its PostgreSQL type for VALUES clause casting.
type enrichColumnDef struct {
	name   string
	pgType string
}

// enrichColumnDefs defines the column order for batch enrichment VALUES clause.
// First 2 columns (id, tenant_id) are used in WHERE, rest are SET columns.
//
//nolint:gochecknoglobals // Package-level column definitions for batch enrichment query builder
var enrichColumnDefs = []enrichColumnDef{
	{"id", "uuid"},
	{"tenant_id", "uuid"},
	{"title", "text"},
	{"description", "text"},
	{"snippet", "text"},
	{"message", "text"},
	{"severity", "text"},
	{"cvss_score", "float8"},
	{"cvss_vector", "text"},
	{"cve_id", "text"},
	{"rule_id", "text"},
	{"rule_name", "text"},
	{"cwe_ids", "text[]"},
	{"owasp_ids", "text[]"},
	{"tags", "text[]"},
	{"metadata", "jsonb"},
	{"updated_at", "timestamptz"},
	{"last_seen_at", "timestamptz"},
	{"scan_id", "text"},
	{"confidence", "int"},
	{"impact", "text"},
	{"likelihood", "text"},
	{"vulnerability_class", "text[]"},
	{"subcategory", "text[]"},
	{"rank", "float8"},
	{"occurrence_count", "int"},
	{"correlation_id", "text"},
	{"partial_fingerprints", "jsonb"},
	{"related_locations", "jsonb"},
	{"stacks", "jsonb"},
	{"attachments", "jsonb"},
	{"work_item_uris", "text[]"},
	{"hosted_viewer_uri", "text"},
	{"exposure_vector", "text"},
	{"is_network_accessible", "boolean"},
	{"is_internet_accessible", "boolean"},
	{"attack_prerequisites", "text"},
	{"epss_score", "float8"},
	{"epss_percentile", "float8"},
	{"is_in_kev", "boolean"},
	{"kev_due_date", "date"},
	{"priority_class", "varchar(2)"},
	{"priority_class_reason", "text"},
	{"priority_class_override", "boolean"},
	{"priority_class_overridden_by", "uuid"},
	{"priority_class_overridden_at", "timestamptz"},
	{"is_reachable", "boolean"},
	{"reachable_from_count", "int"},
	{"remediation_type", "text"},
	{"estimated_fix_time", "int"},
	{"fix_complexity", "text"},
	{"remedy_available", "boolean"},
	{"data_exposure_risk", "text"},
	{"reputational_impact", "boolean"},
	{"compliance_impact", "text[]"},
	{"remediation", "jsonb"},
	{"file_path", "text"},
	{"start_line", "int"},
	{"end_line", "int"},
	{"start_column", "int"},
	{"end_column", "int"},
}

// EnrichBatchByFingerprints enriches existing findings with new scan data using domain EnrichFrom() rules.
// It loads existing findings by fingerprint, applies enrichment, and batch updates enrichable columns
// using a chunked VALUES-based UPDATE (1 query per chunk instead of N individual UPDATEs).
// Protected fields (status, resolution, assigned_to, etc.) are never modified.
// Returns the count of enriched findings.
//
//nolint:cyclop // Enrichment batch update inherently has many columns to persist
func (r *FindingRepository) EnrichBatchByFingerprints(ctx context.Context, tenantID shared.ID, newFindings []*vulnerability.Finding, scanID string) (int64, error) {
	if len(newFindings) == 0 {
		return 0, nil
	}

	// Collect fingerprints and build lookup map from new findings
	fingerprints := make([]string, 0, len(newFindings))
	newByFP := make(map[string]*vulnerability.Finding, len(newFindings))
	for _, f := range newFindings {
		fp := f.Fingerprint()
		fingerprints = append(fingerprints, fp)
		newByFP[fp] = f
	}

	// Load existing findings from DB
	existingByFP, err := r.GetByFingerprintsBatch(ctx, tenantID, fingerprints)
	if err != nil {
		return 0, fmt.Errorf("failed to load existing findings for enrichment: %w", err)
	}

	if len(existingByFP) == 0 {
		return 0, nil
	}

	// Apply enrichment and collect args for batch UPDATE
	allArgs := make([][]interface{}, 0, len(existingByFP))
	for fp, existing := range existingByFP {
		newData, ok := newByFP[fp]
		if !ok {
			continue
		}
		existing.EnrichFrom(newData)
		args, argErr := collectEnrichArgs(existing)
		if argErr != nil {
			return 0, fmt.Errorf("failed to collect enrich args for %s: %w", fp, argErr)
		}
		allArgs = append(allArgs, args)
	}

	if len(allArgs) == 0 {
		return 0, nil
	}

	// Batch UPDATE in transaction using chunked VALUES clause
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin enrichment transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var totalEnriched int64
	for i := 0; i < len(allArgs); i += enrichBatchChunkSize {
		end := i + enrichBatchChunkSize
		if end > len(allArgs) {
			end = len(allArgs)
		}
		chunk := allArgs[i:end]

		query := buildBatchEnrichQuery(len(chunk))

		// Flatten chunk args into a single slice
		capNeeded64 := uint64(len(chunk)) * uint64(enrichColumnsPerRow)
		if capNeeded64 > uint64(int(^uint(0)>>1)) {
			return totalEnriched, fmt.Errorf("enrichment batch too large")
		}
		flatArgs := make([]interface{}, 0, int(capNeeded64))
		for _, row := range chunk {
			flatArgs = append(flatArgs, row...)
		}

		result, execErr := tx.ExecContext(ctx, query, flatArgs...)
		if execErr != nil {
			return totalEnriched, fmt.Errorf("failed to batch update enriched findings: %w", execErr)
		}
		affected, _ := result.RowsAffected()
		totalEnriched += affected
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit enrichment transaction: %w", err)
	}

	return totalEnriched, nil
}

// collectEnrichArgs marshals a single finding into the ordered parameter slice
// matching enrichColumnDefs (50 values: id, tenant_id, then 48 SET columns).
func collectEnrichArgs(f *vulnerability.Finding) ([]interface{}, error) {
	metadata, err := json.Marshal(f.Metadata())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}
	if len(metadata) > maxJSONSize {
		return nil, fmt.Errorf("metadata JSON too large")
	}

	partialFingerprints, relatedLocations, stacks, attachments, err := marshalFindingSARIFFields(f)
	if err != nil {
		return nil, err
	}

	remediationJSON := marshalRemediation(f.Remediation())

	return []interface{}{
		// WHERE columns
		f.ID().String(),
		f.TenantID().String(),
		// SET columns
		nullString(f.Title()),
		nullString(f.Description()),
		nullString(f.Snippet()),
		f.Message(),
		f.Severity().String(),
		nullFloat64(f.CVSSScore()),
		nullString(f.CVSSVector()),
		nullString(f.CVEID()),
		nullString(f.RuleID()),
		nullString(f.RuleName()),
		pq.Array(f.CWEIDs()),
		pq.Array(f.OWASPIDs()),
		pq.Array(f.Tags()),
		metadata,
		f.UpdatedAt(),
		f.LastSeenAt(),
		nullString(f.ScanID()),
		nullIntPtr(f.Confidence()),
		nullString(f.Impact()),
		nullString(f.Likelihood()),
		pq.Array(f.VulnerabilityClass()),
		pq.Array(f.Subcategory()),
		nullFloat64(f.Rank()),
		f.OccurrenceCount(),
		nullString(f.CorrelationID()),
		partialFingerprints,
		relatedLocations,
		stacks,
		attachments,
		pq.Array(f.WorkItemURIs()),
		nullString(f.HostedViewerURI()),
		nullString(f.ExposureVector().String()),
		f.IsNetworkAccessible(),
		f.IsInternetAccessible(),
		nullString(f.AttackPrerequisites()),
		nullFloat64(f.EPSSScore()),
		nullFloat64(f.EPSSPercentile()),
		f.IsInKEV(),
		nullTime(f.KEVDueDate()),
		nullPriorityClass(f.PriorityClass()),
		nullString(f.PriorityClassReason()),
		f.PriorityClassOverride(),
		nullID(f.PriorityClassOverriddenBy()),
		nullTime(f.PriorityClassOverriddenAt()),
		f.IsReachable(),
		f.ReachableFromCount(),
		nullString(f.RemediationType().String()),
		nullIntPtr(f.EstimatedFixTime()),
		nullString(f.FixComplexity().String()),
		f.RemedyAvailable(),
		nullString(f.DataExposureRisk().String()),
		f.ReputationalImpact(),
		pq.Array(f.ComplianceImpact()),
		remediationJSON,
		nullString(f.FilePath()),
		f.StartLine(),
		f.EndLine(),
		f.StartColumn(),
		f.EndColumn(),
	}, nil
}

// buildBatchEnrichQuery builds a VALUES-based UPDATE query for the given number of rows.
// Uses type casts on the first row only; PostgreSQL infers types for subsequent rows.
//
// Generated query format:
//
//	UPDATE findings AS f SET title = d.title, description = d.description, ...
//	FROM (VALUES ($1::uuid, $2::uuid, $3::text, ...), ($51, $52, $53, ...), ...)
//	AS d(id, tenant_id, title, description, ...)
//	WHERE f.id = d.id AND f.tenant_id = d.tenant_id
func buildBatchEnrichQuery(rowCount int) string {
	colCount := len(enrichColumnDefs)
	var sb strings.Builder

	// Estimate capacity: ~3000 for SET clause + ~100 per row for VALUES
	sb.Grow(3000 + rowCount*120)

	sb.WriteString("UPDATE findings AS f SET ")

	// SET clause: columns 2..N (skip id, tenant_id which are WHERE columns)
	for i := 2; i < colCount; i++ {
		if i > 2 {
			sb.WriteString(", ")
		}
		col := enrichColumnDefs[i].name
		sb.WriteString(col)
		sb.WriteString(" = d.")
		sb.WriteString(col)
	}

	sb.WriteString(" FROM (VALUES ")

	// VALUES rows with parameter placeholders
	for row := 0; row < rowCount; row++ {
		if row > 0 {
			sb.WriteString(", ")
		}
		sb.WriteByte('(')
		for col := 0; col < colCount; col++ {
			if col > 0 {
				sb.WriteString(", ")
			}
			paramNum := row*colCount + col + 1
			fmt.Fprintf(&sb, "$%d", paramNum)
			// Type casts on first row only so PostgreSQL knows column types
			if row == 0 {
				sb.WriteString("::")
				sb.WriteString(enrichColumnDefs[col].pgType)
			}
		}
		sb.WriteByte(')')
	}

	sb.WriteString(") AS d(")

	// Column aliases for the derived table
	for i, col := range enrichColumnDefs {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(col.name)
	}

	sb.WriteString(") WHERE f.id = d.id AND f.tenant_id = d.tenant_id")

	return sb.String()
}
