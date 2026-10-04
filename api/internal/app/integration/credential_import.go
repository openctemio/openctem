package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

const csvBoolTrue = "true"

// CredentialImportService handles credential leak import operations.
type CredentialImportService struct {
	exposureRepo exposure.Repository
	historyRepo  exposure.StateHistoryRepository
	// secrets seals the leaked secret before it is stored and opens it for the
	// audited reveal. Never nil: the constructor installs a development
	// (no-key) protector that SetSecretProtector replaces.
	secrets *credential.SecretProtector
	// dataScope narrows every read and state change to leaks on assets in
	// the caller's data scope (Layer 2). A leak with no asset is in nobody's
	// asset scope, so only unrestricted callers see it. Nil: unrestricted.
	dataScope *datascope.Enforcer
	logger    *logger.Logger
}

// SetDataScope wires the Layer 2 data-scope enforcer.
func (s *CredentialImportService) SetDataScope(e *datascope.Enforcer) { s.dataScope = e }

// scoped applies the caller's data scope to a credential filter.
func (s *CredentialImportService) scoped(ctx context.Context, tenantID string, filter exposure.Filter) (exposure.Filter, error) {
	if s.dataScope == nil {
		return filter, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return filter, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	scope, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return filter, fmt.Errorf("resolve data scope: %w", err)
	}
	filter.DataScope = scope
	return filter, nil
}

// assertInScope returns shared.ErrNotFound unless the caller may see the
// leak's asset (an asset-less leak: unrestricted callers only), the same
// rule as /exposures/{id} for the same row.
func (s *CredentialImportService) assertInScope(ctx context.Context, event *exposure.ExposureEvent) error {
	if s.dataScope == nil {
		return nil
	}
	var assetID shared.ID
	if event.AssetID() != nil {
		assetID = *event.AssetID()
	}
	return s.dataScope.AssertAsset(ctx, event.TenantID(), assetID)
}

// NewCredentialImportService creates a new CredentialImportService.
func NewCredentialImportService(
	exposureRepo exposure.Repository,
	historyRepo exposure.StateHistoryRepository,
	log *logger.Logger,
) *CredentialImportService {
	return &CredentialImportService{
		exposureRepo: exposureRepo,
		historyRepo:  historyRepo,
		secrets:      credential.NewSecretProtector(nil, nil),
		logger:       log.With("service", "credential_import"),
	}
}

// SetSecretProtector installs the protector built from the platform
// encryption key. nil is ignored.
func (s *CredentialImportService) SetSecretProtector(p *credential.SecretProtector) {
	if p != nil {
		s.secrets = p
	}
}

// Import imports credentials with deduplication support.
func (s *CredentialImportService) Import(
	ctx context.Context,
	tenantID string,
	req credential.ImportRequest,
) (*credential.ImportResult, error) {
	s.logger.Info("starting credential import",
		"tenant_id", tenantID,
		"count", len(req.Credentials),
		"source_tool", req.Metadata.SourceTool,
	)

	// Parse tenant ID
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Ensure options have defaults
	options := req.Options
	if options.DedupStrategy == "" {
		options.DedupStrategy = credential.DedupStrategyUpdateLastSeen
	}

	result := &credential.ImportResult{
		Details: make([]credential.ImportItemResult, 0, len(req.Credentials)),
		Errors:  make([]credential.ImportError, 0),
	}

	criticalCount := 0

	for i, cred := range req.Credentials {
		itemResult, isCritical, err := s.processCredential(ctx, parsedTenantID, tenantID, cred, options, i)
		if err != nil {
			result.Errors = append(result.Errors, credential.ImportError{
				Index:      i,
				Identifier: cred.Identifier,
				Error:      err.Error(),
			})
			continue
		}

		result.Details = append(result.Details, itemResult)

		// Update counters
		switch itemResult.Action {
		case "imported":
			result.Imported++
			if isCritical {
				criticalCount++
			}
		case "updated":
			result.Updated++
		case "reactivated":
			result.Reactivated++
			if isCritical {
				criticalCount++
			}
		case "skipped":
			result.Skipped++
		}
	}

	// Build summary
	result.Summary = credential.ImportSummary{
		TotalProcessed:       len(req.Credentials),
		SuccessCount:         result.Imported + result.Updated + result.Reactivated,
		ErrorCount:           len(result.Errors),
		CriticalCount:        criticalCount,
		ReactivatedAlertSent: result.Reactivated > 0 && options.NotifyReactivated,
	}

	s.logger.Info("credential import completed",
		"tenant_id", tenantID,
		"imported", result.Imported,
		"updated", result.Updated,
		"reactivated", result.Reactivated,
		"skipped", result.Skipped,
		"errors", len(result.Errors),
	)

	return result, nil
}

// processCredential processes a single credential import.
func (s *CredentialImportService) processCredential(
	ctx context.Context,
	tenantID shared.ID,
	tenantIDStr string,
	cred credential.CredentialImport,
	options credential.ImportOptions,
	index int,
) (credential.ImportItemResult, bool, error) {
	// Validate credential type
	if !cred.CredentialType.IsValid() {
		return credential.ImportItemResult{}, false, fmt.Errorf("invalid credential type: %s", cred.CredentialType)
	}

	// Validate source type
	if !cred.Source.Type.IsValid() {
		return credential.ImportItemResult{}, false, fmt.Errorf("invalid source type: %s", cred.Source.Type)
	}

	// The credential fingerprint (identifier, type, source and its breach,
	// repository/file or paste) is the credential's identity and the key it
	// is stored under, so a re-import finds and updates it.
	fingerprint := cred.CalculateFingerprint(tenantIDStr)

	existing, err := s.findExistingCredential(ctx, tenantID, tenantIDStr, cred, fingerprint)
	if err != nil {
		return credential.ImportItemResult{}, false, err
	}

	// Determine severity
	severity := cred.GetSeverity(options.AutoClassifySeverity)
	isCritical := severity == "critical"

	if existing == nil {
		res, critical, err := s.createCredentialExposure(ctx, tenantID, cred, fingerprint, severity, index)
		if err == nil || !exposure.IsExposureEventExists(err) {
			return res, critical, err
		}
		// Lost a race with a concurrent import of the same credential.
		existing, err = s.exposureRepo.GetByFingerprint(ctx, tenantID, fingerprint)
		if err != nil {
			return credential.ImportItemResult{}, false, fmt.Errorf("failed to load existing credential: %w", err)
		}
	}

	// Handle existing credential based on state and strategy
	return s.handleExistingCredential(ctx, existing, cred, options, index, isCritical)
}

// findExistingCredential returns the stored credential with this fingerprint,
// or nil. Credentials imported before the fingerprint fix are stored under
// the exposure event's generic fingerprint (identifier and source only); such
// a row is adopted, and re-keyed, when its stored details identify the same
// credential, so re-importing it updates rather than duplicates it.
func (s *CredentialImportService) findExistingCredential(
	ctx context.Context,
	tenantID shared.ID,
	tenantIDStr string,
	cred credential.CredentialImport,
	fingerprint string,
) (*exposure.ExposureEvent, error) {
	existing, err := s.exposureRepo.GetByFingerprint(ctx, tenantID, fingerprint)
	if err == nil {
		return existing, nil
	}
	if !exposure.IsExposureEventNotFound(err) {
		return nil, fmt.Errorf("failed to check existing: %w", err)
	}

	probe, err := exposure.NewExposureEvent(tenantID, exposure.EventTypeCredentialLeaked, exposure.SeverityMedium,
		cred.Identifier, cred.GetSourceString(), cred.ToDetails())
	if err != nil {
		return nil, nil //nolint:nilerr // no generic fingerprint to look up; treat as new
	}
	legacy, err := s.exposureRepo.GetByFingerprint(ctx, tenantID, probe.Fingerprint())
	if err != nil {
		if exposure.IsExposureEventNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to check existing: %w", err)
	}
	if storedCredentialFingerprint(legacy, tenantIDStr) != fingerprint {
		return nil, nil // another credential that shares the generic fingerprint
	}
	legacy.UseFingerprint(fingerprint)
	return legacy, nil
}

// storedCredentialFingerprint recomputes the credential fingerprint of a
// stored credential exposure from the details the import wrote.
func storedCredentialFingerprint(e *exposure.ExposureEvent, tenantIDStr string) string {
	d := e.Details()
	str := func(k string) string { v, _ := d[k].(string); return v }
	c := credential.CredentialImport{
		Identifier:     e.Title(),
		CredentialType: credential.CredentialType(str("credential_type")),
		Source:         credential.CredentialSource{Type: credential.SourceType(str("source_type")), URL: str("source_url")},
		DedupKey: credential.DedupKey{
			BreachName: str("breach_name"),
			BreachDate: str("breach_date"),
			Repository: str("repository"),
			FilePath:   str("file_path"),
			CommitHash: str("commit_hash"),
			PasteID:    str("paste_id"),
		},
	}
	return c.CalculateFingerprint(tenantIDStr)
}

// createCredentialExposure creates a new exposure event for a credential.
func (s *CredentialImportService) createCredentialExposure(
	ctx context.Context,
	tenantID shared.ID,
	cred credential.CredentialImport,
	fingerprint string,
	severity string,
	index int,
) (credential.ImportItemResult, bool, error) {
	// Parse severity
	sev, err := exposure.ParseSeverity(severity)
	if err != nil {
		sev = exposure.SeverityMedium
	}

	details := cred.ToDetails()
	if err := s.secrets.Seal(details); err != nil {
		return credential.ImportItemResult{}, false, err
	}

	// Create exposure event
	event, err := exposure.NewExposureEvent(
		tenantID,
		exposure.EventTypeCredentialLeaked,
		sev,
		cred.Identifier,
		cred.GetSourceString(),
		details,
	)
	if err != nil {
		return credential.ImportItemResult{}, false, fmt.Errorf("failed to create exposure event: %w", err)
	}

	// Store under the credential fingerprint, the key re-imports look up.
	event.UseFingerprint(fingerprint)

	// Set description if notes provided
	if cred.Notes != "" {
		event.UpdateDescription(cred.Notes)
	}

	// Create in repository
	if err := s.exposureRepo.Create(ctx, event); err != nil {
		return credential.ImportItemResult{}, false, fmt.Errorf("failed to save exposure event: %w", err)
	}

	isCritical := severity == "critical"

	return credential.ImportItemResult{
		Index:      index,
		Identifier: cred.Identifier,
		Action:     "imported",
		ID:         event.ID().String(),
	}, isCritical, nil
}

// handleExistingCredential handles an existing credential based on its state.
func (s *CredentialImportService) handleExistingCredential(
	ctx context.Context,
	existing *exposure.ExposureEvent,
	cred credential.CredentialImport,
	options credential.ImportOptions,
	index int,
	isCritical bool,
) (credential.ImportItemResult, bool, error) {
	switch existing.State() {
	case exposure.StateFalsePositive:
		// User marked as false positive - skip
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "skipped",
			Reason:     "marked_as_false_positive",
			ID:         existing.ID().String(),
		}, false, nil

	case exposure.StateResolved:
		// Handle resolved credential
		if options.ReactivateResolved {
			// Reactivate - credential found again after resolution
			return s.reactivateCredential(ctx, existing, cred, index, isCritical)
		}
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "skipped",
			Reason:     "already_resolved",
			ID:         existing.ID().String(),
		}, false, nil

	case exposure.StateActive, exposure.StateAccepted:
		// Update based on strategy
		return s.updateExistingCredential(ctx, existing, cred, options, index)

	default:
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "skipped",
			Reason:     "unknown_state",
			ID:         existing.ID().String(),
		}, false, nil
	}
}

// reactivateCredential reactivates a resolved credential.
func (s *CredentialImportService) reactivateCredential(
	ctx context.Context,
	existing *exposure.ExposureEvent,
	cred credential.CredentialImport,
	index int,
	isCritical bool,
) (credential.ImportItemResult, bool, error) {
	previousState := existing.State()

	// Reactivate
	if err := existing.Reactivate(); err != nil {
		return credential.ImportItemResult{}, false, fmt.Errorf("failed to reactivate: %w", err)
	}

	// Update last seen
	existing.MarkSeen()

	// Save
	if err := s.exposureRepo.Update(ctx, existing); err != nil {
		return credential.ImportItemResult{}, false, fmt.Errorf("failed to update: %w", err)
	}

	// Record state change history
	history, err := exposure.NewStateHistory(
		existing.ID(),
		previousState,
		exposure.StateActive,
		nil,
		fmt.Sprintf("Reactivated via import (source: %s)", cred.GetSourceString()),
	)
	if err == nil {
		_ = s.historyRepo.Create(ctx, history)
	}

	s.logger.Warn("credential reactivated after resolution",
		"id", existing.ID().String(),
		"identifier", cred.Identifier,
		"source", cred.GetSourceString(),
	)

	return credential.ImportItemResult{
		Index:      index,
		Identifier: cred.Identifier,
		Action:     "reactivated",
		Reason:     "found_after_resolution",
		ID:         existing.ID().String(),
	}, isCritical, nil
}

// updateExistingCredential updates an existing credential based on strategy.
func (s *CredentialImportService) updateExistingCredential(
	ctx context.Context,
	existing *exposure.ExposureEvent,
	cred credential.CredentialImport,
	options credential.ImportOptions,
	index int,
) (credential.ImportItemResult, bool, error) {
	switch options.DedupStrategy {
	case credential.DedupStrategySkip:
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "skipped",
			Reason:     "duplicate",
			ID:         existing.ID().String(),
		}, false, nil

	case credential.DedupStrategyUpdateLastSeen:
		// Only update last_seen_at
		existing.MarkSeen()
		if err := s.exposureRepo.Update(ctx, existing); err != nil {
			return credential.ImportItemResult{}, false, fmt.Errorf("failed to update: %w", err)
		}
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "updated",
			Reason:     "last_seen_updated",
			ID:         existing.ID().String(),
		}, false, nil

	case credential.DedupStrategyUpdateAll:
		// Update all relevant fields
		existing.MarkSeen()
		if cred.Notes != "" {
			existing.UpdateDescription(cred.Notes)
		}
		// Update details
		newDetails := cred.ToDetails()
		if err := s.secrets.Seal(newDetails); err != nil {
			return credential.ImportItemResult{}, false, err
		}
		for k, v := range newDetails {
			existing.SetDetail(k, v)
		}
		if _, sealed := newDetails[credential.DetailSecretCiphertext]; sealed {
			// A legacy row's plaintext must not survive next to the new ciphertext.
			existing.RemoveDetail(credential.DetailSecretValue)
		}
		if err := s.exposureRepo.Update(ctx, existing); err != nil {
			return credential.ImportItemResult{}, false, fmt.Errorf("failed to update: %w", err)
		}
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "updated",
			Reason:     "all_fields_updated",
			ID:         existing.ID().String(),
		}, false, nil

	case credential.DedupStrategyCreateNew:
		// This strategy should create a new record, but since we have unique fingerprint,
		// we need to modify the fingerprint or treat this as update_last_seen
		existing.MarkSeen()
		if err := s.exposureRepo.Update(ctx, existing); err != nil {
			return credential.ImportItemResult{}, false, fmt.Errorf("failed to update: %w", err)
		}
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "updated",
			Reason:     "fingerprint_exists",
			ID:         existing.ID().String(),
		}, false, nil

	default:
		// Default to update_last_seen
		existing.MarkSeen()
		if err := s.exposureRepo.Update(ctx, existing); err != nil {
			return credential.ImportItemResult{}, false, fmt.Errorf("failed to update: %w", err)
		}
		return credential.ImportItemResult{
			Index:      index,
			Identifier: cred.Identifier,
			Action:     "updated",
			Reason:     "last_seen_updated",
			ID:         existing.ID().String(),
		}, false, nil
	}
}

// ImportCSV imports credentials from CSV data.
func (s *CredentialImportService) ImportCSV(
	ctx context.Context,
	tenantID string,
	records [][]string,
	options credential.ImportOptions,
) (*credential.ImportResult, error) {
	if len(records) < 2 {
		return nil, fmt.Errorf("%w: CSV must have header and at least one data row", shared.ErrValidation)
	}

	// Parse header
	header := records[0]
	columnMap := make(map[string]int)
	for i, col := range header {
		columnMap[col] = i
	}

	// Required columns
	requiredCols := []string{"identifier", "credential_type", "source_type"}
	for _, col := range requiredCols {
		if _, ok := columnMap[col]; !ok {
			return nil, fmt.Errorf("%w: missing required column: %s", shared.ErrValidation, col)
		}
	}

	// Parse data rows
	credentials := make([]credential.CredentialImport, 0, len(records)-1)
	for i, row := range records[1:] {
		cred, err := s.parseCSVRow(row, columnMap, i+1)
		if err != nil {
			s.logger.Warn("failed to parse CSV row", "row", i+1, "error", err)
			continue
		}
		credentials = append(credentials, cred)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("%w: no valid credentials found in CSV", shared.ErrValidation)
	}

	// Create import request
	req := credential.ImportRequest{
		Credentials: credentials,
		Options:     options,
		Metadata: credential.ImportMetadata{
			SourceTool: "csv_import",
			ImportDate: time.Now().UTC(),
		},
	}

	return s.Import(ctx, tenantID, req)
}

// parseCSVRow parses a single CSV row into a CredentialImport.
func (s *CredentialImportService) parseCSVRow(
	row []string,
	columnMap map[string]int,
	rowNum int,
) (credential.CredentialImport, error) {
	getCol := func(name string) string {
		if idx, ok := columnMap[name]; ok && idx < len(row) {
			return row[idx]
		}
		return ""
	}

	// Parse credential type
	credType, err := credential.ParseCredentialType(getCol("credential_type"))
	if err != nil {
		return credential.CredentialImport{}, fmt.Errorf("row %d: %w", rowNum, err)
	}

	// Parse source type
	sourceType, err := credential.ParseSourceType(getCol("source_type"))
	if err != nil {
		return credential.CredentialImport{}, fmt.Errorf("row %d: %w", rowNum, err)
	}

	// Parse discovered_at if present
	var discoveredAt *time.Time
	if dateStr := getCol("discovered_at"); dateStr != "" {
		if t, err := time.Parse("2006-01-02", dateStr); err == nil {
			discoveredAt = &t
		} else if t, err := time.Parse(time.RFC3339, dateStr); err == nil {
			discoveredAt = &t
		}
	}

	// Parse classification
	classification, _ := credential.ParseClassification(getCol("classification"))

	// Parse tags
	var tags []string
	if tagsStr := getCol("tags"); tagsStr != "" {
		for _, tag := range splitAndTrim(tagsStr, ",") {
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}

	return credential.CredentialImport{
		Identifier:     getCol("identifier"),
		CredentialType: credType,
		Source: credential.CredentialSource{
			Type:         sourceType,
			Name:         getCol("source_name"),
			URL:          getCol("source_url"),
			DiscoveredAt: discoveredAt,
		},
		Severity:       getCol("severity"),
		Classification: classification,
		DedupKey: credential.DedupKey{
			BreachName: getCol("breach_name"),
			BreachDate: getCol("breach_date"),
			Repository: getCol("repository"),
			FilePath:   getCol("file_path"),
			CommitHash: getCol("commit_hash"),
			Branch:     getCol("branch"),
			SourceURL:  getCol("dedup_source_url"),
			PasteID:    getCol("paste_id"),
		},
		Context: credential.CredentialContext{
			Username:  getCol("username"),
			Email:     getCol("email"),
			Domain:    getCol("domain"),
			IPAddress: getCol("ip_address"),
		},
		IsVerified: getCol("is_verified") == csvBoolTrue || getCol("is_verified") == "1",
		IsRevoked:  getCol("is_revoked") == csvBoolTrue || getCol("is_revoked") == "1",
		Tags:       tags,
		Notes:      getCol("notes"),
	}, nil
}

// splitAndTrim splits a string and trims each part.
func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, p := range splitString(s, sep) {
		p = trimString(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// splitString splits string by separator.
func splitString(s, sep string) []string {
	if s == "" {
		return nil
	}
	result := make([]string, 0)
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
		}
	}
	result = append(result, s[start:])
	return result
}

// trimString trims whitespace.
func trimString(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

// CredentialListOptions contains options for listing credentials.
type CredentialListOptions struct {
	Severities []string
	States     []string
	Sources    []string
	Search     string
	SortField  string
	SortOrder  string
}

// CredentialListResult represents the result of listing credentials.
type CredentialListResult struct {
	Items      []CredentialItem `json:"items"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

// CredentialItem represents a credential leak item. It never carries the
// plaintext secret: only a mask and a keyed fingerprint. The plaintext is
// returned by RevealSecret alone.
type CredentialItem struct {
	ID                string         `json:"id"`
	Identifier        string         `json:"identifier"`
	CredentialType    string         `json:"credential_type"`
	HasSecret         bool           `json:"has_secret"`
	SecretMasked      string         `json:"secret_masked,omitempty"`
	SecretFingerprint string         `json:"secret_fingerprint,omitempty"`
	Source            string         `json:"source"`
	Severity          string         `json:"severity"`
	State             string         `json:"state"`
	FirstSeenAt       time.Time      `json:"first_seen_at"`
	LastSeenAt        time.Time      `json:"last_seen_at"`
	IsVerified        bool           `json:"is_verified"`
	IsRevoked         bool           `json:"is_revoked"`
	Details           map[string]any `json:"details,omitempty"`
}

// List retrieves credential leaks with filtering and pagination.
func (s *CredentialImportService) List(
	ctx context.Context,
	tenantID string,
	opts CredentialListOptions,
	page, pageSize int,
) (*CredentialListResult, error) {
	// Create filter for credential_leaked events
	filter := exposure.NewFilter().
		WithTenantID(tenantID).
		WithEventTypes(exposure.EventTypeCredentialLeaked)

	// Add severity filter
	if len(opts.Severities) > 0 {
		severities := make([]exposure.Severity, 0, len(opts.Severities))
		for _, sev := range opts.Severities {
			if parsed, err := exposure.ParseSeverity(sev); err == nil {
				severities = append(severities, parsed)
			}
		}
		if len(severities) > 0 {
			filter = filter.WithSeverities(severities...)
		}
	}

	// Add state filter
	if len(opts.States) > 0 {
		states := make([]exposure.State, 0, len(opts.States))
		for _, st := range opts.States {
			if parsed, err := exposure.ParseState(st); err == nil {
				states = append(states, parsed)
			}
		}
		if len(states) > 0 {
			filter = filter.WithStates(states...)
		}
	}

	// Add source filter
	if len(opts.Sources) > 0 {
		filter = filter.WithSources(opts.Sources...)
	}

	// Add search filter
	if opts.Search != "" {
		filter = filter.WithSearch(opts.Search)
	}

	// Create list options with sorting
	listOpts := exposure.NewListOptions()
	if opts.SortField != "" {
		sortOpt := pagination.NewSortOption(exposure.AllowedSortFields()).Parse(opts.SortField)
		listOpts = listOpts.WithSort(sortOpt)
	}

	filter, err := s.scoped(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}

	// Create pagination
	pag := pagination.New(page, pageSize)

	// Execute query
	result, err := s.exposureRepo.List(ctx, filter, listOpts, pag)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	// Convert to credential items
	items := make([]CredentialItem, 0, len(result.Data))
	for _, event := range result.Data {
		items = append(items, s.toCredentialItem(event))
	}

	totalPages := int(result.Total) / pageSize
	if int(result.Total)%pageSize > 0 {
		totalPages++
	}

	return &CredentialListResult{
		Items:      items,
		Total:      result.Total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetByID retrieves a credential leak by its ID.
func (s *CredentialImportService) GetByID(ctx context.Context, tenantID, id string) (*CredentialItem, error) {
	parsedID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid credential ID", shared.ErrValidation)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	event, err := s.exposureRepo.GetByTenantAndID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ID matches
	if event.TenantID().String() != tenantID {
		return nil, exposure.NewExposureEventNotFoundError(id)
	}

	// Verify event type
	if event.EventType() != exposure.EventTypeCredentialLeaked {
		return nil, exposure.NewExposureEventNotFoundError(id)
	}
	if err := s.assertInScope(ctx, event); err != nil {
		return nil, exposure.NewExposureEventNotFoundError(id)
	}

	item := s.toCredentialItem(event)
	return &item, nil
}

// toCredentialItem converts an exposure event to a credential item.
func (s *CredentialImportService) toCredentialItem(event *exposure.ExposureEvent) CredentialItem {
	details := event.Details()

	// Extract credential-specific fields from details
	credType, _ := details["credential_type"].(string)
	isVerified, _ := details["is_verified"].(bool)
	isRevoked, _ := details["is_revoked"].(bool)

	hasSecret := credential.HasSecret(details)
	safe := credential.RedactDetails(details)
	masked, _ := safe[credential.DetailSecretMasked].(string)
	fingerprint, _ := safe[credential.DetailSecretFingerprint].(string)

	return CredentialItem{
		ID:                event.ID().String(),
		Identifier:        event.Title(),
		CredentialType:    credType,
		HasSecret:         hasSecret,
		SecretMasked:      masked,
		SecretFingerprint: fingerprint,
		Source:            event.Source(),
		Severity:          event.Severity().String(),
		State:             event.State().String(),
		FirstSeenAt:       event.FirstSeenAt(),
		LastSeenAt:        event.LastSeenAt(),
		IsVerified:        isVerified,
		IsRevoked:         isRevoked,
		Details:           safe,
	}
}

// ErrNoSecret is returned by RevealSecret when the credential has no stored
// secret value.
var ErrNoSecret = fmt.Errorf("%w: credential has no stored secret", shared.ErrNotFound)

// RevealSecret returns the plaintext secret of one leaked credential in the
// tenant. Callers must gate it on findings:credentials:reveal and audit it.
func (s *CredentialImportService) RevealSecret(ctx context.Context, tenantID, id string) (string, error) {
	parsedID, err := shared.IDFromString(id)
	if err != nil {
		return "", fmt.Errorf("%w: invalid credential ID", shared.ErrValidation)
	}
	parsedTenant, err := shared.IDFromString(tenantID)
	if err != nil {
		return "", fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	event, err := s.exposureRepo.GetByTenantAndID(ctx, parsedTenant, parsedID)
	if err != nil {
		return "", err
	}
	if event == nil || event.TenantID() != parsedTenant || event.EventType() != exposure.EventTypeCredentialLeaked {
		return "", exposure.NewExposureEventNotFoundError(id)
	}
	if err := s.assertInScope(ctx, event); err != nil {
		return "", exposure.NewExposureEventNotFoundError(id)
	}
	secret, ok, err := s.secrets.Open(event.Details())
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrNoSecret
	}
	return secret, nil
}

// IdentityExposure represents aggregated exposures for a single identity.
type IdentityExposure struct {
	Identity        string         `json:"identity"`      // username or email
	IdentityType    string         `json:"identity_type"` // "username" or "email"
	ExposureCount   int            `json:"exposure_count"`
	Sources         []string       `json:"sources"`
	CredentialTypes []string       `json:"credential_types"`
	HighestSeverity string         `json:"highest_severity"`
	States          map[string]int `json:"states"` // count by state
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	// Note: Exposures are NOT included here for performance
	// Use GetExposuresForIdentity() to fetch them on-demand
}

// IdentityListResult represents the result of listing identities.
type IdentityListResult struct {
	Items      []IdentityExposure `json:"items"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

// ListByIdentity lists credential exposures grouped by identity (username/email).
func (s *CredentialImportService) ListByIdentity(
	ctx context.Context,
	tenantID string,
	opts CredentialListOptions,
	page, pageSize int,
) (*IdentityListResult, error) {
	// First, get all credential leaks (we'll group them in memory)
	// In production, this should be done via SQL GROUP BY for better performance
	filter := exposure.NewFilter().
		WithTenantID(tenantID).
		WithEventTypes(exposure.EventTypeCredentialLeaked)

	// Add filters
	if len(opts.States) > 0 {
		states := make([]exposure.State, 0, len(opts.States))
		for _, st := range opts.States {
			if parsed, err := exposure.ParseState(st); err == nil {
				states = append(states, parsed)
			}
		}
		if len(states) > 0 {
			filter = filter.WithStates(states...)
		}
	}

	if opts.Search != "" {
		filter = filter.WithSearch(opts.Search)
	}

	filter, err := s.scoped(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}

	// Get all matching credentials (limit to reasonable number for grouping)
	events, err := s.listCredentialEvents(ctx, filter, maxCredentialsForGrouping)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	// Group by identity (aggregate only, don't load individual exposures)
	identityMap := make(map[string]*IdentityExposure)
	for _, event := range events {
		item := s.toCredentialItem(event)
		identity, identityType := s.extractIdentity(item)
		if identity == "" {
			identity = item.Identifier // fallback to identifier
			identityType = "identifier"
		}

		if existing, ok := identityMap[identity]; ok {
			// Update existing identity aggregates
			existing.ExposureCount++
			existing.Sources = appendUnique(existing.Sources, item.Source)
			existing.CredentialTypes = appendUnique(existing.CredentialTypes, item.CredentialType)
			existing.States[item.State]++
			if s.severityRank(item.Severity) > s.severityRank(existing.HighestSeverity) {
				existing.HighestSeverity = item.Severity
			}
			if item.FirstSeenAt.Before(existing.FirstSeenAt) {
				existing.FirstSeenAt = item.FirstSeenAt
			}
			if item.LastSeenAt.After(existing.LastSeenAt) {
				existing.LastSeenAt = item.LastSeenAt
			}
			// Note: we don't store individual exposures here for performance
		} else {
			// Create new identity entry (aggregates only)
			identityMap[identity] = &IdentityExposure{
				Identity:        identity,
				IdentityType:    identityType,
				ExposureCount:   1,
				Sources:         []string{item.Source},
				CredentialTypes: []string{item.CredentialType},
				HighestSeverity: item.Severity,
				States:          map[string]int{item.State: 1},
				FirstSeenAt:     item.FirstSeenAt,
				LastSeenAt:      item.LastSeenAt,
			}
		}
	}

	// Convert to slice and sort by severity (critical first)
	identities := make([]IdentityExposure, 0, len(identityMap))
	for _, identity := range identityMap {
		identities = append(identities, *identity)
	}

	// Sort by highest severity, then by exposure count
	for i := 0; i < len(identities)-1; i++ {
		for j := i + 1; j < len(identities); j++ {
			if s.severityRank(identities[j].HighestSeverity) > s.severityRank(identities[i].HighestSeverity) ||
				(identities[j].HighestSeverity == identities[i].HighestSeverity && identities[j].ExposureCount > identities[i].ExposureCount) {
				identities[i], identities[j] = identities[j], identities[i]
			}
		}
	}

	// Apply pagination
	total := int64(len(identities))
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > len(identities) {
		start = len(identities)
	}
	if end > len(identities) {
		end = len(identities)
	}

	pagedItems := identities[start:end]

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	return &IdentityListResult{
		Items:      pagedItems,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetRelatedCredentials gets all credentials related to a given identifier.
func (s *CredentialImportService) GetRelatedCredentials(
	ctx context.Context,
	tenantID string,
	credentialID string,
) ([]CredentialItem, error) {
	// First get the credential to find its identity
	credential, err := s.GetByID(ctx, tenantID, credentialID)
	if err != nil {
		return nil, err
	}

	identity, _ := s.extractIdentity(*credential)
	if identity == "" {
		identity = credential.Identifier
	}

	// Find all credentials with same identity
	filter := exposure.NewFilter().
		WithTenantID(tenantID).
		WithEventTypes(exposure.EventTypeCredentialLeaked).
		WithSearch(identity)

	filter, err = s.scoped(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}

	listOpts := exposure.NewListOptions()
	pag := pagination.New(1, 100) // Limit to 100 related items

	result, err := s.exposureRepo.List(ctx, filter, listOpts, pag)
	if err != nil {
		return nil, fmt.Errorf("failed to find related credentials: %w", err)
	}

	// Filter and convert
	items := make([]CredentialItem, 0)
	for _, event := range result.Data {
		item := s.toCredentialItem(event)
		itemIdentity, _ := s.extractIdentity(item)
		if itemIdentity == "" {
			itemIdentity = item.Identifier
		}

		// Only include if identity matches and it's not the same credential
		if itemIdentity == identity && item.ID != credentialID {
			items = append(items, item)
		}
	}

	return items, nil
}

// maxCredentialsForGrouping bounds how many leaked-credential exposures the
// identity views read and group in memory.
const maxCredentialsForGrouping = 1000

// listCredentialEvents reads up to max exposures matching filter, page by
// page. Both identity views asked for one page of 1000, which pagination
// clamps to 100: a tenant with more than 100 leaked credentials saw only the
// identities among the first 100, and an identity's own exposures past them
// were missing.
func (s *CredentialImportService) listCredentialEvents(ctx context.Context, filter exposure.Filter, maxRows int) ([]*exposure.ExposureEvent, error) {
	var out []*exposure.ExposureEvent
	for pageNum := 1; len(out) < maxRows; pageNum++ {
		res, err := s.exposureRepo.List(ctx, filter, exposure.NewListOptions(), pagination.New(pageNum, 100))
		if err != nil {
			return nil, err
		}
		out = append(out, res.Data...)
		if len(res.Data) == 0 || int64(len(out)) >= res.Total {
			break
		}
	}
	if len(out) > maxRows {
		out = out[:maxRows]
	}
	return out, nil
}

// GetExposuresForIdentity gets all credential exposures for a specific identity (lazy loading).
func (s *CredentialImportService) GetExposuresForIdentity(
	ctx context.Context,
	tenantID string,
	identity string,
	page, pageSize int,
) (*CredentialListResult, error) {
	// Get all credentials for this tenant (identity is in details JSONB, not searchable via title)
	// We need to filter client-side for now
	filter := exposure.NewFilter().
		WithTenantID(tenantID).
		WithEventTypes(exposure.EventTypeCredentialLeaked)

	filter, err := s.scoped(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}

	// Fetch more records to filter client-side
	events, err := s.listCredentialEvents(ctx, filter, maxCredentialsForGrouping)
	if err != nil {
		return nil, fmt.Errorf("failed to find credentials for identity: %w", err)
	}

	// Filter to exact identity matches
	allMatches := make([]CredentialItem, 0)
	for _, event := range events {
		item := s.toCredentialItem(event)
		itemIdentity, _ := s.extractIdentity(item)
		if itemIdentity == "" {
			itemIdentity = item.Identifier
		}

		// Only include if identity matches exactly
		if itemIdentity == identity {
			allMatches = append(allMatches, item)
		}
	}

	// Apply pagination to filtered results
	total := int64(len(allMatches))
	start := (page - 1) * pageSize
	end := start + pageSize

	if start > len(allMatches) {
		start = len(allMatches)
	}
	if end > len(allMatches) {
		end = len(allMatches)
	}

	items := allMatches[start:end]

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	return &CredentialListResult{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// extractIdentity extracts the identity (username or email) from a credential item.
func (s *CredentialImportService) extractIdentity(item CredentialItem) (string, string) {
	if item.Details == nil {
		return "", ""
	}

	// Prefer email over username
	if email, ok := item.Details["email"].(string); ok && email != "" {
		return email, "email"
	}
	if username, ok := item.Details["username"].(string); ok && username != "" {
		return username, "username"
	}

	return "", ""
}

// severityRank returns a numeric rank for severity (higher = more severe).
func (s *CredentialImportService) severityRank(severity string) int {
	ranks := map[string]int{
		"info":     1,
		"low":      2,
		"medium":   3,
		"high":     4,
		"critical": 5,
	}
	if rank, ok := ranks[severity]; ok {
		return rank
	}
	return 0
}

// appendUnique appends a value to a slice if it doesn't already exist.
func appendUnique(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// GetCredentialStats returns statistics for credential leaks.
func (s *CredentialImportService) GetCredentialStats(ctx context.Context, tenantID string) (map[string]any, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Create filter for credential_leaked events
	filter := exposure.NewFilter().
		WithTenantID(tenantID).
		WithEventTypes(exposure.EventTypeCredentialLeaked)

	filter, err = s.scoped(ctx, parsedTenantID.String(), filter)
	if err != nil {
		return nil, err
	}

	// Get total count
	total, err := s.exposureRepo.Count(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count credentials: %w", err)
	}

	// Counts by state and severity over the same (credential, in-scope)
	// filter. CountByState/CountBySeverity count every exposure type of the
	// tenant regardless of scope, which is neither this view nor the
	// caller's data.
	stateMap := make(map[string]int64)
	for _, st := range exposure.AllStates() {
		n, err := s.exposureRepo.Count(ctx, filter.WithStates(st))
		if err != nil {
			return nil, fmt.Errorf("failed to get state counts: %w", err)
		}
		if n > 0 {
			stateMap[st.String()] = n
		}
	}

	severityMap := make(map[string]int64)
	for _, sev := range exposure.AllSeverities() {
		n, err := s.exposureRepo.Count(ctx, filter.WithSeverities(sev))
		if err != nil {
			return nil, fmt.Errorf("failed to get severity counts: %w", err)
		}
		if n > 0 {
			severityMap[sev.String()] = n
		}
	}

	return map[string]any{
		"total":       total,
		"by_state":    stateMap,
		"by_severity": severityMap,
	}, nil
}

// ResolveCredential marks a credential as resolved.
func (s *CredentialImportService) ResolveCredential(ctx context.Context, tenantID, credentialID, userID, notes string) (*CredentialItem, error) {
	return s.changeCredentialState(ctx, tenantID, credentialID, userID, exposure.StateResolved, notes)
}

// AcceptCredential marks a credential as accepted risk.
func (s *CredentialImportService) AcceptCredential(ctx context.Context, tenantID, credentialID, userID, notes string) (*CredentialItem, error) {
	return s.changeCredentialState(ctx, tenantID, credentialID, userID, exposure.StateAccepted, notes)
}

// MarkCredentialFalsePositive marks a credential as a false positive.
func (s *CredentialImportService) MarkCredentialFalsePositive(ctx context.Context, tenantID, credentialID, userID, notes string) (*CredentialItem, error) {
	return s.changeCredentialState(ctx, tenantID, credentialID, userID, exposure.StateFalsePositive, notes)
}

// ReactivateCredential marks a credential as active again.
func (s *CredentialImportService) ReactivateCredential(ctx context.Context, tenantID, credentialID string) (*CredentialItem, error) {
	parsedID, err := shared.IDFromString(credentialID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid credential id", shared.ErrValidation)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	event, err := s.exposureRepo.GetByTenantAndID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership, type and the caller's data scope
	if event.TenantID().String() != tenantID || event.EventType() != exposure.EventTypeCredentialLeaked {
		return nil, shared.ErrNotFound
	}
	if err := s.assertInScope(ctx, event); err != nil {
		return nil, shared.ErrNotFound
	}

	previousState := event.State()

	if err := event.Reactivate(); err != nil {
		return nil, err
	}

	if err := s.exposureRepo.Update(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to update credential: %w", err)
	}

	// Record state change history
	history, err := exposure.NewStateHistory(
		event.ID(),
		previousState,
		exposure.StateActive,
		nil,
		"Reactivated manually",
	)
	if err == nil {
		_ = s.historyRepo.Create(ctx, history)
	}

	s.logger.Info("credential reactivated",
		"id", credentialID,
		"previous_state", previousState.String(),
	)

	item := s.toCredentialItem(event)
	return &item, nil
}

// changeCredentialState changes the state of a credential.
func (s *CredentialImportService) changeCredentialState(ctx context.Context, tenantID, credentialID, userID string, newState exposure.State, notes string) (*CredentialItem, error) {
	parsedID, err := shared.IDFromString(credentialID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid credential id", shared.ErrValidation)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	event, err := s.exposureRepo.GetByTenantAndID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership, type and the caller's data scope
	if event.TenantID().String() != tenantID || event.EventType() != exposure.EventTypeCredentialLeaked {
		return nil, shared.ErrNotFound
	}
	if err := s.assertInScope(ctx, event); err != nil {
		return nil, shared.ErrNotFound
	}

	previousState := event.State()

	// Parse user ID
	var parsedUserID shared.ID
	if userID != "" {
		parsedUserID, _ = shared.IDFromString(userID)
	}

	// Apply state change
	switch newState {
	case exposure.StateResolved:
		if err := event.Resolve(parsedUserID, notes); err != nil {
			return nil, err
		}
	case exposure.StateAccepted:
		if err := event.Accept(parsedUserID, notes); err != nil {
			return nil, err
		}
	case exposure.StateFalsePositive:
		if err := event.MarkFalsePositive(parsedUserID, notes); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: unsupported state transition", shared.ErrValidation)
	}

	if err := s.exposureRepo.Update(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to update credential: %w", err)
	}

	// Record state change history
	history, err := exposure.NewStateHistory(
		event.ID(),
		previousState,
		newState,
		&parsedUserID,
		notes,
	)
	if err == nil {
		_ = s.historyRepo.Create(ctx, history)
	}

	s.logger.Info("credential state changed",
		"id", credentialID,
		"previous_state", previousState.String(),
		"new_state", newState.String(),
		"user_id", userID,
	)

	item := s.toCredentialItem(event)
	return &item, nil
}
