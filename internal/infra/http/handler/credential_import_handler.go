package handler

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/credential"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// queryParamFalse is the expected query parameter value for false
const queryParamFalse = "false"

// CredentialImportHandler handles credential import HTTP requests.
type CredentialImportHandler struct {
	service   *app.CredentialImportService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewCredentialImportHandler creates a new credential import handler.
func NewCredentialImportHandler(
	svc *app.CredentialImportService,
	v *validator.Validator,
	log *logger.Logger,
) *CredentialImportHandler {
	return &CredentialImportHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// CredentialImportRequest represents the API request for importing credentials.
type CredentialImportRequest struct {
	Credentials []CredentialImportItem `json:"credentials" validate:"required,min=1,max=1000,dive"`
	Options     ImportOptionsRequest   `json:"options"`
	Metadata    ImportMetadataRequest  `json:"metadata"`
}

// CredentialImportItem represents a single credential in the import request.
type CredentialImportItem struct {
	Identifier     string               `json:"identifier" validate:"required,max=500"`
	CredentialType string               `json:"credential_type" validate:"required"`
	SecretValue    string               `json:"secret_value,omitempty"` // The actual leaked secret (password, API key, etc.)
	Source         CredentialSourceReq  `json:"source" validate:"required"`
	Severity       string               `json:"severity,omitempty"`
	Classification string               `json:"classification,omitempty"`
	DedupKey       DedupKeyRequest      `json:"dedup_key"`
	Context        CredentialContextReq `json:"context"`
	IsVerified     bool                 `json:"is_verified"`
	IsRevoked      bool                 `json:"is_revoked"`
	Tags           []string             `json:"tags,omitempty"`
	Notes          string               `json:"notes,omitempty"`
}

// CredentialSourceReq represents source information in the request.
type CredentialSourceReq struct {
	Type         string  `json:"type" validate:"required"`
	Name         string  `json:"name,omitempty"`
	URL          string  `json:"url,omitempty"`
	DiscoveredAt *string `json:"discovered_at,omitempty"` // ISO8601 format
}

// DedupKeyRequest represents deduplication key in the request.
type DedupKeyRequest struct {
	BreachName string `json:"breach_name,omitempty"`
	BreachDate string `json:"breach_date,omitempty"`
	Repository string `json:"repository,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	CommitHash string `json:"commit_hash,omitempty"`
	Branch     string `json:"branch,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	PasteID    string `json:"paste_id,omitempty"`
}

// CredentialContextReq represents context information in the request.
type CredentialContextReq struct {
	Username   string         `json:"username,omitempty"`
	Email      string         `json:"email,omitempty"`
	Domain     string         `json:"domain,omitempty"`
	IPAddress  string         `json:"ip_address,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	LineNumber int            `json:"line_number,omitempty"`
	Extra      map[string]any `json:"extra,omitempty"`
}

// ImportOptionsRequest represents import options in the request.
type ImportOptionsRequest struct {
	DedupStrategy        string `json:"dedup_strategy,omitempty"`
	ReactivateResolved   bool   `json:"reactivate_resolved"`
	NotifyReactivated    bool   `json:"notify_reactivated"`
	NotifyNewCritical    bool   `json:"notify_new_critical"`
	AutoClassifySeverity bool   `json:"auto_classify_severity"`
}

// ImportMetadataRequest represents import metadata in the request.
type ImportMetadataRequest struct {
	SourceTool  string `json:"source_tool,omitempty"`
	BatchID     string `json:"batch_id,omitempty"`
	Description string `json:"description,omitempty"`
}

// Import handles POST /api/v1/credentials/import
// @Summary Import credential leaks
// @Description Import credential leaks with deduplication support
// @Tags Credentials
// @Accept json
// @Produce json
// @Param request body CredentialImportRequest true "Import request"
// @Success 201 {object} credential.ImportResult
// @Failure 400 {object} apierror.Error
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials/import [post]
func (h *CredentialImportHandler) Import(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CredentialImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Convert request to domain types
	importReq, err := h.toImportRequest(req)
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	// Perform import
	result, err := h.service.Import(r.Context(), tenantID, importReq)
	if err != nil {
		h.logger.Error("credential import failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

// ImportCSV handles POST /api/v1/credentials/import/csv
// @Summary Import credential leaks from CSV
// @Description Import credential leaks from CSV file
// @Tags Credentials
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "CSV file"
// @Param dedup_strategy query string false "Deduplication strategy"
// @Param reactivate_resolved query bool false "Reactivate resolved credentials"
// @Success 201 {object} credential.ImportResult
// @Failure 400 {object} apierror.Error
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials/import/csv [post]
func (h *CredentialImportHandler) ImportCSV(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	// Parse multipart form (max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		apierror.BadRequest("Invalid multipart form").WriteJSON(w)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		apierror.BadRequest("Missing file in request").WriteJSON(w)
		return
	}
	defer file.Close()

	// Read CSV
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		apierror.BadRequest("Invalid CSV format").WriteJSON(w)
		return
	}

	// Parse options from query params
	options := credential.ImportOptions{
		DedupStrategy:        credential.ParseDedupStrategy(r.URL.Query().Get("dedup_strategy")),
		ReactivateResolved:   r.URL.Query().Get("reactivate_resolved") != queryParamFalse,
		NotifyReactivated:    r.URL.Query().Get("notify_reactivated") != queryParamFalse,
		NotifyNewCritical:    r.URL.Query().Get("notify_new_critical") != queryParamFalse,
		AutoClassifySeverity: r.URL.Query().Get("auto_classify_severity") != queryParamFalse,
	}

	// Perform import
	result, err := h.service.ImportCSV(r.Context(), tenantID, records, options)
	if err != nil {
		h.logger.Error("CSV import failed", "error", err)
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

// List handles GET /api/v1/credentials
// @Summary List credential leaks
// @Description List credential leaks with filtering and pagination
// @Tags Credentials
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param severity query string false "Filter by severity (comma-separated)"
// @Param state query string false "Filter by state (comma-separated)"
// @Param source query string false "Filter by source (comma-separated)"
// @Param search query string false "Search in identifier"
// @Param sort query string false "Sort field (prefix - for desc)"
// @Success 200 {object} app.CredentialListResult
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials [get]
func (h *CredentialImportHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	// Parse pagination
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := parseIntParam(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := parseIntParam(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Parse filters
	opts := app.CredentialListOptions{
		Search:    r.URL.Query().Get("search"),
		SortField: r.URL.Query().Get("sort"),
	}

	if severity := r.URL.Query().Get("severity"); severity != "" {
		opts.Severities = splitCommaSeparated(severity)
	}
	if state := r.URL.Query().Get("state"); state != "" {
		opts.States = splitCommaSeparated(state)
	}
	if source := r.URL.Query().Get("source"); source != "" {
		opts.Sources = splitCommaSeparated(source)
	}

	result, err := h.service.List(r.Context(), tenantID, opts, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list credentials", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// GetByID handles GET /api/v1/credentials/{id}
// @Summary Get credential leak by ID
// @Description Get a single credential leak by its ID
// @Tags Credentials
// @Produce json
// @Param id path string true "Credential ID"
// @Success 200 {object} app.CredentialItem
// @Failure 404 {object} apierror.Error
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials/{id} [get]
func (h *CredentialImportHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("missing credential id").WriteJSON(w)
		return
	}

	item, err := h.service.GetByID(r.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("failed to get credential", "error", err, "id", id)
		apierror.NotFound("credential not found").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(item)
}

// GetStats handles GET /api/v1/credentials/stats
// @Summary Get credential leak statistics
// @Description Get statistics for credential leaks
// @Tags Credentials
// @Produce json
// @Success 200 {object} map[string]any
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials/stats [get]
func (h *CredentialImportHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetCredentialStats(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to get credential stats", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}

// ListByIdentity handles GET /api/v1/credentials/identities
// @Summary List credential leaks grouped by identity
// @Description List credential leaks grouped by identity (username/email)
// @Tags Credentials
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param state query string false "Filter by state (comma-separated)"
// @Param search query string false "Search in identifier"
// @Success 200 {object} app.IdentityListResult
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials/identities [get]
func (h *CredentialImportHandler) ListByIdentity(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	// Parse pagination
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := parseIntParam(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := parseIntParam(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Parse filters
	opts := app.CredentialListOptions{
		Search: r.URL.Query().Get("search"),
	}

	if state := r.URL.Query().Get("state"); state != "" {
		opts.States = splitCommaSeparated(state)
	}

	result, err := h.service.ListByIdentity(r.Context(), tenantID, opts, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list credentials by identity", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// GetRelatedCredentials handles GET /api/v1/credentials/{id}/related
// @Summary Get related credential leaks
// @Description Get all credentials related to the same identity
// @Tags Credentials
// @Produce json
// @Param id path string true "Credential ID"
// @Success 200 {array} app.CredentialItem
// @Failure 404 {object} apierror.Error
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials/{id}/related [get]
func (h *CredentialImportHandler) GetRelatedCredentials(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("missing credential id").WriteJSON(w)
		return
	}

	items, err := h.service.GetRelatedCredentials(r.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("failed to get related credentials", "error", err, "id", id)
		apierror.NotFound("credential not found").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(items)
}

// GetExposuresForIdentity handles GET /api/v1/credentials/identities/{identity}/exposures
// @Summary Get exposures for a specific identity (lazy load)
// @Description Get all credential exposures for a specific identity with pagination
// @Tags Credentials
// @Produce json
// @Param identity path string true "Identity (username or email)"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} app.CredentialListResult
// @Failure 401 {object} apierror.Error
// @Router /api/v1/credentials/identities/{identity}/exposures [get]
func (h *CredentialImportHandler) GetExposuresForIdentity(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	identity := r.PathValue("identity")
	if identity == "" {
		apierror.BadRequest("missing identity").WriteJSON(w)
		return
	}

	// Parse pagination
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := parseIntParam(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := parseIntParam(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	result, err := h.service.GetExposuresForIdentity(r.Context(), tenantID, identity, page, pageSize)
	if err != nil {
		h.logger.Error("failed to get exposures for identity", "error", err, "identity", identity)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// GetTemplate handles GET /api/v1/credentials/import/template
// @Summary Get CSV import template
// @Description Download CSV template for credential import
// @Tags Credentials
// @Produce text/csv
// @Success 200 {file} file "CSV template"
// @Router /api/v1/credentials/import/template [get]
func (h *CredentialImportHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=credential_import_template.csv")

	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// Write header
	header := []string{
		"identifier",
		"credential_type",
		"secret_value",
		"source_type",
		"source_name",
		"severity",
		"classification",
		"username",
		"email",
		"domain",
		"breach_name",
		"breach_date",
		"repository",
		"file_path",
		"commit_hash",
		"discovered_at",
		"is_verified",
		"is_revoked",
		"tags",
		"notes",
	}
	_ = csvWriter.Write(header)

	// Write example rows
	examples := [][]string{
		{
			"admin@company.com",
			"password",
			"P@ssw0rd123!", // secret_value - example leaked password
			"data_breach",
			"HIBP",
			"critical",
			"internal",
			"admin@company.com",
			"admin@company.com",
			"company.com",
			"CompanyXYZ Breach 2024",
			"2024-07-01",
			"",
			"",
			"",
			"2024-08-15",
			"true",
			"false",
			"critical,production",
			"Admin account found in breach",
		},
		{
			"api-key-prod",
			"api_key",
			"AKIAIOSFODNN7EXAMPLE", // secret_value - example leaked API key
			"code_repository",
			"GitGuardian",
			"critical",
			"internal",
			"service-account",
			"",
			"github.com/company",
			"",
			"",
			"github.com/company/repo",
			"config/secrets.yaml",
			"abc123def",
			"2024-09-20",
			"true",
			"false",
			"api-key-leak",
			"Found in public repo",
		},
		{
			"db-password",
			"database_cred",
			"db_secret_password", // secret_value - example leaked DB password
			"ci_cd",
			"Jenkins",
			"high",
			"internal",
			"dbuser",
			"",
			"internal.company.com",
			"",
			"",
			"",
			"",
			"",
			"2024-10-01",
			"false",
			"false",
			"database",
			"Found in CI logs",
		},
	}
	for _, row := range examples {
		_ = csvWriter.Write(row)
	}
}

// GetEnums handles GET /api/v1/credentials/enums
// @Summary Get available enum values
// @Description Get available credential types, source types, and other enums
// @Tags Credentials
// @Produce json
// @Success 200 {object} map[string]any
// @Router /api/v1/credentials/enums [get]
func (h *CredentialImportHandler) GetEnums(w http.ResponseWriter, _ *http.Request) {
	credentialTypes := make([]string, 0, len(credential.AllCredentialTypes()))
	for _, t := range credential.AllCredentialTypes() {
		credentialTypes = append(credentialTypes, t.String())
	}

	sourceTypes := make([]string, 0, len(credential.AllSourceTypes()))
	for _, s := range credential.AllSourceTypes() {
		sourceTypes = append(sourceTypes, s.String())
	}

	classifications := make([]string, 0, len(credential.AllClassifications()))
	for _, c := range credential.AllClassifications() {
		classifications = append(classifications, c.String())
	}

	dedupStrategies := make([]string, 0, len(credential.AllDedupStrategies()))
	for _, d := range credential.AllDedupStrategies() {
		dedupStrategies = append(dedupStrategies, d.String())
	}

	response := map[string]any{
		"credential_types": credentialTypes,
		"source_types":     sourceTypes,
		"classifications":  classifications,
		"dedup_strategies": dedupStrategies,
		"severities":       []string{"critical", "high", "medium", "low", "info"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// toImportRequest converts API request to domain import request.
func (h *CredentialImportHandler) toImportRequest(req CredentialImportRequest) (credential.ImportRequest, error) {
	credentials := make([]credential.CredentialImport, 0, len(req.Credentials))

	for _, item := range req.Credentials {
		// Parse credential type
		credType, err := credential.ParseCredentialType(item.CredentialType)
		if err != nil {
			return credential.ImportRequest{}, err
		}

		// Parse source type
		sourceType, err := credential.ParseSourceType(item.Source.Type)
		if err != nil {
			return credential.ImportRequest{}, err
		}

		// Parse discovered_at
		var discoveredAt *time.Time
		if item.Source.DiscoveredAt != nil && *item.Source.DiscoveredAt != "" {
			if t, err := time.Parse(time.RFC3339, *item.Source.DiscoveredAt); err == nil {
				discoveredAt = &t
			} else if t, err := time.Parse("2006-01-02", *item.Source.DiscoveredAt); err == nil {
				discoveredAt = &t
			}
		}

		// Parse classification
		classification, _ := credential.ParseClassification(item.Classification)

		cred := credential.CredentialImport{
			Identifier:     item.Identifier,
			CredentialType: credType,
			SecretValue:    item.SecretValue,
			Source: credential.CredentialSource{
				Type:         sourceType,
				Name:         item.Source.Name,
				URL:          item.Source.URL,
				DiscoveredAt: discoveredAt,
			},
			Severity:       item.Severity,
			Classification: classification,
			DedupKey: credential.DedupKey{
				BreachName: item.DedupKey.BreachName,
				BreachDate: item.DedupKey.BreachDate,
				Repository: item.DedupKey.Repository,
				FilePath:   item.DedupKey.FilePath,
				CommitHash: item.DedupKey.CommitHash,
				Branch:     item.DedupKey.Branch,
				SourceURL:  item.DedupKey.SourceURL,
				PasteID:    item.DedupKey.PasteID,
			},
			Context: credential.CredentialContext{
				Username:   item.Context.Username,
				Email:      item.Context.Email,
				Domain:     item.Context.Domain,
				IPAddress:  item.Context.IPAddress,
				UserAgent:  item.Context.UserAgent,
				LineNumber: item.Context.LineNumber,
				Extra:      item.Context.Extra,
			},
			IsVerified: item.IsVerified,
			IsRevoked:  item.IsRevoked,
			Tags:       item.Tags,
			Notes:      item.Notes,
		}
		credentials = append(credentials, cred)
	}

	return credential.ImportRequest{
		Credentials: credentials,
		Options: credential.ImportOptions{
			DedupStrategy:        credential.ParseDedupStrategy(req.Options.DedupStrategy),
			ReactivateResolved:   req.Options.ReactivateResolved,
			NotifyReactivated:    req.Options.NotifyReactivated,
			NotifyNewCritical:    req.Options.NotifyNewCritical,
			AutoClassifySeverity: req.Options.AutoClassifySeverity,
		},
		Metadata: credential.ImportMetadata{
			SourceTool:  req.Metadata.SourceTool,
			ImportDate:  time.Now().UTC(),
			BatchID:     req.Metadata.BatchID,
			Description: req.Metadata.Description,
		},
	}, nil
}

// handleValidationError handles validation errors.
func (h *CredentialImportHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

// parseIntParam parses an integer from a string query parameter.
func parseIntParam(s string) (int, error) {
	var result int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid integer")
		}
		result = result*10 + int(c-'0')
	}
	return result, nil
}

// splitCommaSeparated splits a comma-separated string into a slice.
func splitCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			part := trimWhitespace(s[start:i])
			if part != "" {
				result = append(result, part)
			}
			start = i + 1
		}
	}
	// Add last part
	part := trimWhitespace(s[start:])
	if part != "" {
		result = append(result, part)
	}
	return result
}

// trimWhitespace trims leading and trailing whitespace.
func trimWhitespace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// CredentialStateChangeRequest represents the request to change credential state.
type CredentialStateChangeRequest struct {
	Notes string `json:"notes" validate:"max=500"`
}

// Resolve handles POST /api/v1/credentials/{id}/resolve
// @Summary Mark credential as resolved
// @Description Mark a credential leak as resolved
// @Tags Credentials
// @Accept json
// @Produce json
// @Param id path string true "Credential ID"
// @Param request body CredentialStateChangeRequest false "Resolution notes"
// @Success 200 {object} app.CredentialItem
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/credentials/{id}/resolve [post]
func (h *CredentialImportHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("missing credential id").WriteJSON(w)
		return
	}

	var req CredentialStateChangeRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	item, err := h.service.ResolveCredential(r.Context(), tenantID, id, userID, req.Notes)
	if err != nil {
		h.logger.Error("failed to resolve credential", "error", err, "id", id)
		apierror.NotFound("credential not found").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(item)
}

// Accept handles POST /api/v1/credentials/{id}/accept
// @Summary Mark credential as accepted risk
// @Description Mark a credential leak as accepted risk
// @Tags Credentials
// @Accept json
// @Produce json
// @Param id path string true "Credential ID"
// @Param request body CredentialStateChangeRequest false "Acceptance notes"
// @Success 200 {object} app.CredentialItem
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/credentials/{id}/accept [post]
func (h *CredentialImportHandler) Accept(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("missing credential id").WriteJSON(w)
		return
	}

	var req CredentialStateChangeRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	item, err := h.service.AcceptCredential(r.Context(), tenantID, id, userID, req.Notes)
	if err != nil {
		h.logger.Error("failed to accept credential", "error", err, "id", id)
		apierror.NotFound("credential not found").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(item)
}

// MarkFalsePositive handles POST /api/v1/credentials/{id}/false-positive
// @Summary Mark credential as false positive
// @Description Mark a credential leak as a false positive
// @Tags Credentials
// @Accept json
// @Produce json
// @Param id path string true "Credential ID"
// @Param request body CredentialStateChangeRequest false "Notes"
// @Success 200 {object} app.CredentialItem
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/credentials/{id}/false-positive [post]
func (h *CredentialImportHandler) MarkFalsePositive(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("missing credential id").WriteJSON(w)
		return
	}

	var req CredentialStateChangeRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	item, err := h.service.MarkCredentialFalsePositive(r.Context(), tenantID, id, userID, req.Notes)
	if err != nil {
		h.logger.Error("failed to mark credential as false positive", "error", err, "id", id)
		apierror.NotFound("credential not found").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(item)
}

// Reactivate handles POST /api/v1/credentials/{id}/reactivate
// @Summary Reactivate a resolved credential
// @Description Mark a resolved credential as active again
// @Tags Credentials
// @Produce json
// @Param id path string true "Credential ID"
// @Success 200 {object} app.CredentialItem
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/credentials/{id}/reactivate [post]
func (h *CredentialImportHandler) Reactivate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("missing credential id").WriteJSON(w)
		return
	}

	item, err := h.service.ReactivateCredential(r.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("failed to reactivate credential", "error", err, "id", id)
		apierror.NotFound("credential not found").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(item)
}
