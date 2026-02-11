package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/sdk/pkg/chunk"
	"github.com/openctemio/sdk/pkg/ctis"
)

// contextKey is a custom type for context keys.
type contextKey string

const agentContextKey contextKey = "agent"

// IngestHandler handles ingestion-related HTTP requests.
// It supports CTIS, SARIF, and Recon formats.
type IngestHandler struct {
	ingestService *ingest.Service
	agentService  *app.AgentService
	logger        *logger.Logger
}

// NewIngestHandler creates a new ingest handler.
func NewIngestHandler(
	ingestSvc *ingest.Service,
	agentSvc *app.AgentService,
	log *logger.Logger,
) *IngestHandler {
	return &IngestHandler{
		ingestService: ingestSvc,
		agentService:  agentSvc,
		logger:        log,
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// IngestResponse represents the response from ingestion.
type IngestResponse struct {
	ScanID          string   `json:"scan_id"`
	AssetsCreated   int      `json:"assets_created"`
	AssetsUpdated   int      `json:"assets_updated"`
	FindingsCreated int      `json:"findings_created"`
	FindingsUpdated int      `json:"findings_updated"`
	FindingsSkipped int      `json:"findings_skipped"`
	Errors          []string `json:"errors,omitempty"`
}

// CTISIngestRequest represents the request body for CTIS ingestion.
type CTISIngestRequest struct {
	Report ctis.Report `json:"report"`
}

// ReconIngestRequest represents reconnaissance scan results to ingest.
type ReconIngestRequest struct {
	// Scanner info
	ScannerName    string `json:"scanner_name"`
	ScannerVersion string `json:"scanner_version,omitempty"`
	ReconType      string `json:"recon_type"` // subdomain, dns, port, http_probe, url_crawl

	// Target
	Target string `json:"target"`

	// Timing
	StartedAt  int64 `json:"started_at,omitempty"`
	FinishedAt int64 `json:"finished_at,omitempty"`
	DurationMs int64 `json:"duration_ms,omitempty"`

	// Results (populated based on recon_type)
	Subdomains []SubdomainResult     `json:"subdomains,omitempty"`
	DNSRecords []DNSRecordResult     `json:"dns_records,omitempty"`
	OpenPorts  []OpenPortResult      `json:"open_ports,omitempty"`
	LiveHosts  []LiveHostResult      `json:"live_hosts,omitempty"`
	URLs       []DiscoveredURLResult `json:"urls,omitempty"`
}

// SubdomainResult represents a discovered subdomain.
type SubdomainResult struct {
	Host   string   `json:"host"`
	Domain string   `json:"domain,omitempty"`
	Source string   `json:"source,omitempty"`
	IPs    []string `json:"ips,omitempty"`
}

// DNSRecordResult represents a DNS record.
type DNSRecordResult struct {
	Host       string   `json:"host"`
	RecordType string   `json:"record_type"`
	Values     []string `json:"values"`
	TTL        int      `json:"ttl,omitempty"`
	Resolver   string   `json:"resolver,omitempty"`
	StatusCode string   `json:"status_code,omitempty"`
}

// OpenPortResult represents an open port.
type OpenPortResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// LiveHostResult represents an HTTP/HTTPS live host.
type LiveHostResult struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	IP            string   `json:"ip,omitempty"`
	Port          int      `json:"port,omitempty"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	ContentLength int64    `json:"content_length,omitempty"`
	Title         string   `json:"title,omitempty"`
	WebServer     string   `json:"web_server,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	CDN           string   `json:"cdn,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	Redirect      string   `json:"redirect,omitempty"`
	ResponseTime  int64    `json:"response_time_ms,omitempty"`
}

// DiscoveredURLResult represents a discovered URL/endpoint.
type DiscoveredURLResult struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Source     string `json:"source,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Depth      int    `json:"depth,omitempty"`
	Parent     string `json:"parent,omitempty"`
	Type       string `json:"type,omitempty"`
	Extension  string `json:"extension,omitempty"`
}

// HeartbeatRequest represents the heartbeat payload from agents.
type HeartbeatRequest struct {
	Name          string   `json:"name,omitempty"`
	Status        string   `json:"status"`
	Version       string   `json:"version,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	Message       string   `json:"message,omitempty"`
	Scanners      []string `json:"scanners,omitempty"`
	Collectors    []string `json:"collectors,omitempty"`
	Uptime        int64    `json:"uptime_seconds,omitempty"`
	TotalScans    int64    `json:"total_scans,omitempty"`
	Errors        int64    `json:"errors,omitempty"`
	CPUPercent    float64  `json:"cpu_percent,omitempty"`
	MemoryPercent float64  `json:"memory_percent,omitempty"`
	ActiveJobs    int      `json:"active_jobs,omitempty"`
	Region        string   `json:"region,omitempty"`
}

// CheckFingerprintsRequest represents the request for checking fingerprint existence.
type CheckFingerprintsRequest struct {
	Fingerprints []string `json:"fingerprints"`
}

// CheckFingerprintsResponse represents the response for fingerprint check.
type CheckFingerprintsResponse struct {
	Existing []string `json:"existing"` // Fingerprints that already exist
	Missing  []string `json:"missing"`  // Fingerprints that don't exist
}

// ChunkIngestRequest represents the request body for chunked ingestion.
// This is used by SDK when reports are too large for single upload.
type ChunkIngestRequest struct {
	ReportID    string `json:"report_id"`             // Unique ID for the chunked report
	ChunkIndex  int    `json:"chunk_index"`           // 0-indexed chunk number
	TotalChunks int    `json:"total_chunks"`          // Total number of chunks
	Compression string `json:"compression,omitempty"` // Compression algorithm (zstd, gzip, none)
	Data        string `json:"data"`                  // Base64-encoded chunk data
	IsFinal     bool   `json:"is_final"`              // True for the last chunk
}

// ChunkIngestResponse represents the response from chunk ingestion.
type ChunkIngestResponse struct {
	ChunkID         string `json:"chunk_id"`
	ReportID        string `json:"report_id"`
	ChunkIndex      int    `json:"chunk_index"`
	Status          string `json:"status"`
	AssetsCreated   int    `json:"assets_created"`
	AssetsUpdated   int    `json:"assets_updated"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	FindingsSkipped int    `json:"findings_skipped"`
}

// =============================================================================
// Authentication Middleware
// =============================================================================

// AuthenticateSource is middleware that authenticates the agent by API key.
func (h *IngestHandler) AuthenticateSource(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := extractAPIKey(r)
		if apiKey == "" {
			apierror.Unauthorized("API key required").WriteJSON(w)
			return
		}

		agt, err := h.agentService.AuthenticateByAPIKey(r.Context(), apiKey)
		if err != nil {
			h.logger.Debug("authentication failed", "error", err)
			apierror.Unauthorized("Invalid API key").WriteJSON(w)
			return
		}

		// Add agent to context
		ctx := context.WithValue(r.Context(), agentContextKey, agt)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AgentFromContext retrieves the authenticated agent from context.
func AgentFromContext(ctx context.Context) *agent.Agent {
	agt, _ := ctx.Value(agentContextKey).(*agent.Agent)
	return agt
}

// WorkerFromContext is an alias for AgentFromContext for backward compatibility.
// Deprecated: Use AgentFromContext instead.
func WorkerFromContext(ctx context.Context) *agent.Agent {
	return AgentFromContext(ctx)
}

// SourceFromContext is an alias for AgentFromContext for backward compatibility.
// Deprecated: Use AgentFromContext instead.
func SourceFromContext(ctx context.Context) *agent.Agent {
	return AgentFromContext(ctx)
}

// =============================================================================
// CTIS Ingestion Endpoint
// =============================================================================

// IngestCTIS handles POST /api/v1/agent/ingest/ctis
// @Summary      Ingest CTIS report
// @Description  Ingest a full CTIS (CTEM Ingest Schema) report containing assets and findings
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        request  body      CTISIngestRequest  true  "CTIS report"
// @Success      201  {object}  IngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/ctis [post]
func (h *IngestHandler) IngestCTIS(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	// Read body once for multiple parse attempts
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Debug("failed to read request body", "error", err)
		apierror.BadRequest("Failed to read request body").WriteJSON(w)
		return
	}

	var report ctis.Report

	// Try wrapped format first: { "report": { ... } }
	var req CTISIngestRequest
	if err := json.Unmarshal(bodyBytes, &req); err == nil && req.Report.Version != "" {
		report = req.Report
	} else {
		// Try flat format (SDK format): { "version": ..., "metadata": ..., ... }
		if err := json.Unmarshal(bodyBytes, &report); err != nil {
			h.logger.Debug("failed to parse CTIS ingest request", "error", err)
			apierror.BadRequest("Invalid JSON request body").WriteJSON(w)
			return
		}
	}

	// Validate report
	if report.Version == "" {
		report.Version = "1.0"
	}

	input := ingest.Input{
		Report: &report,
	}

	output, err := h.ingestService.Ingest(r.Context(), agt, input)
	if err != nil {
		h.logger.Error("CTIS ingestion failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := IngestResponse{
		ScanID:          output.ReportID,
		AssetsCreated:   output.AssetsCreated,
		AssetsUpdated:   output.AssetsUpdated,
		FindingsCreated: output.FindingsCreated,
		FindingsUpdated: output.FindingsUpdated,
		FindingsSkipped: output.FindingsSkipped,
		Errors:          output.Errors,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// SARIF Ingestion Endpoint
// =============================================================================

// IngestSARIF handles POST /api/v1/agent/ingest/sarif
// @Summary      Ingest SARIF results
// @Description  Ingest scan results in SARIF 2.1.0 format
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        request  body      object  true  "SARIF data"
// @Success      201  {object}  IngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/sarif [post]
func (h *IngestHandler) IngestSARIF(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	// Read raw body for SARIF processing
	body, err := io.ReadAll(r.Body)
	if err != nil {
		apierror.BadRequest("Failed to read request body").WriteJSON(w)
		return
	}

	if len(body) == 0 {
		apierror.BadRequest("SARIF data is required").WriteJSON(w)
		return
	}

	output, err := h.ingestService.IngestSARIF(r.Context(), agt, body)
	if err != nil {
		h.logger.Error("SARIF ingestion failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := IngestResponse{
		ScanID:          output.ReportID,
		AssetsCreated:   output.AssetsCreated,
		AssetsUpdated:   output.AssetsUpdated,
		FindingsCreated: output.FindingsCreated,
		FindingsUpdated: output.FindingsUpdated,
		FindingsSkipped: output.FindingsSkipped,
		Errors:          output.Errors,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Recon Ingestion Endpoint
// =============================================================================

// IngestReconReport handles POST /api/v1/agent/ingest/recon
// @Summary      Ingest recon results
// @Description  Ingest reconnaissance scan results (subdomains, DNS, ports, etc.)
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        request  body      ReconIngestRequest  true  "Recon results"
// @Success      201  {object}  IngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/recon [post]
func (h *IngestHandler) IngestReconReport(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	var req ReconIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("failed to parse recon ingest request", "error", err)
		apierror.BadRequest("Invalid JSON request body").WriteJSON(w)
		return
	}

	// Validate required fields
	if req.Target == "" {
		apierror.BadRequest("Target is required").WriteJSON(w)
		return
	}
	if req.ScannerName == "" {
		apierror.BadRequest("Scanner name is required").WriteJSON(w)
		return
	}

	// Convert recon request to CTIS input
	reconInput := h.buildReconToCTISInput(&req)

	output, err := h.ingestService.IngestRecon(r.Context(), agt, reconInput)
	if err != nil {
		h.logger.Error("recon ingestion failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := IngestResponse{
		ScanID:          output.ReportID,
		AssetsCreated:   output.AssetsCreated,
		AssetsUpdated:   output.AssetsUpdated,
		FindingsCreated: output.FindingsCreated,
		FindingsUpdated: output.FindingsUpdated,
		FindingsSkipped: output.FindingsSkipped,
		Errors:          output.Errors,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Heartbeat Endpoint
// =============================================================================

// Heartbeat handles POST /api/v1/agent/heartbeat
// @Summary      Agent heartbeat
// @Description  Send a heartbeat to indicate agent is alive
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        request  body      HeartbeatRequest  false  "Heartbeat data"
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/heartbeat [post]
func (h *IngestHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	// Parse heartbeat request (optional body)
	var req HeartbeatRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.logger.Debug("failed to parse heartbeat body", "error", err)
			// Continue anyway - body is optional
		}
	}

	// Update agent metrics via service
	if err := h.agentService.UpdateHeartbeat(r.Context(), agt.ID, app.AgentHeartbeatData{
		Version:       req.Version,
		Hostname:      req.Hostname,
		CPUPercent:    req.CPUPercent,
		MemoryPercent: req.MemoryPercent,
		CurrentJobs:   req.ActiveJobs,
		Region:        req.Region,
	}); err != nil {
		h.logger.Error("failed to update agent heartbeat", "error", err, "agent_id", agt.ID)
		// Don't fail the request - heartbeat should be resilient
	}

	resp := map[string]interface{}{
		"status":    "ok",
		"agent_id":  agt.ID.String(),
		"tenant_id": agt.TenantID.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Fingerprint Check Endpoint
// =============================================================================

// CheckFingerprints handles POST /api/v1/ingest/check
// @Summary      Check fingerprints
// @Description  Check if fingerprints already exist for deduplication
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        request  body      CheckFingerprintsRequest  true  "Fingerprints to check"
// @Success      200  {object}  CheckFingerprintsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /ingest/check [post]
func (h *IngestHandler) CheckFingerprints(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	var req CheckFingerprintsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if len(req.Fingerprints) == 0 {
		// Return empty response for empty input
		resp := CheckFingerprintsResponse{
			Existing: []string{},
			Missing:  []string{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	output, err := h.ingestService.CheckFingerprints(r.Context(), agt, ingest.CheckFingerprintsInput{
		Fingerprints: req.Fingerprints,
	})
	if err != nil {
		h.logger.Error("fingerprint check failed", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := CheckFingerprintsResponse{
		Existing: output.Existing,
		Missing:  output.Missing,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Chunked Ingestion Endpoint
// =============================================================================

// IngestChunk handles POST /api/v1/agent/ingest/chunk
// @Summary      Ingest CTIS report chunk
// @Description  Ingest a single chunk of a large CTIS report. Used for reports that exceed single upload limits.
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        request  body      ChunkIngestRequest  true  "Chunk data"
// @Success      201  {object}  ChunkIngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/ingest/chunk [post]
//
//nolint:cyclop // Chunk ingestion requires handling many result types
func (h *IngestHandler) IngestChunk(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	var req ChunkIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("failed to parse chunk ingest request", "error", err)
		apierror.BadRequest("Invalid JSON request body").WriteJSON(w)
		return
	}

	// SECURITY: Define limits to prevent DoS attacks
	const (
		MaxTotalChunks   = 10000            // Maximum chunks per report
		MaxChunkDataSize = 10 * 1024 * 1024 // 10MB base64 data per chunk
		MaxReportIDLen   = 256              // Maximum report ID length
	)

	// Validate required fields with security bounds
	if req.ReportID == "" {
		apierror.BadRequest("report_id is required").WriteJSON(w)
		return
	}
	if len(req.ReportID) > MaxReportIDLen {
		apierror.BadRequest("report_id too long").WriteJSON(w)
		return
	}

	// SECURITY: Validate ReportID format to prevent injection
	// Must be alphanumeric with dashes/underscores only
	for _, c := range req.ReportID {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			apierror.BadRequest("report_id contains invalid characters").WriteJSON(w)
			return
		}
	}

	if req.TotalChunks <= 0 {
		apierror.BadRequest("total_chunks must be positive").WriteJSON(w)
		return
	}
	// SECURITY: Prevent unbounded chunk allocation
	if req.TotalChunks > MaxTotalChunks {
		apierror.BadRequest("total_chunks exceeds maximum of 10000").WriteJSON(w)
		return
	}
	if req.ChunkIndex < 0 || req.ChunkIndex >= req.TotalChunks {
		apierror.BadRequest("chunk_index out of range").WriteJSON(w)
		return
	}
	if req.Data == "" {
		apierror.BadRequest("data is required").WriteJSON(w)
		return
	}
	// SECURITY: Limit chunk data size to prevent memory exhaustion
	if len(req.Data) > MaxChunkDataSize {
		apierror.BadRequest("chunk data too large").WriteJSON(w)
		return
	}

	// Decode base64 data
	compressedData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		h.logger.Debug("failed to decode base64 data", "error", err)
		apierror.BadRequest("Invalid base64 data").WriteJSON(w)
		return
	}

	// Decompress data based on compression algorithm
	var decompressedData []byte
	switch strings.ToLower(req.Compression) {
	case "zstd", "":
		// Default to ZSTD (most common)
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			h.logger.Error("failed to create zstd decoder", "error", err)
			apierror.InternalError(err).WriteJSON(w)
			return
		}
		defer decoder.Close()
		decompressedData, err = decoder.DecodeAll(compressedData, nil)
		if err != nil {
			h.logger.Debug("failed to decompress zstd data", "error", err)
			apierror.BadRequest("Failed to decompress chunk data").WriteJSON(w)
			return
		}
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(compressedData))
		if err != nil {
			h.logger.Debug("failed to create gzip reader", "error", err)
			apierror.BadRequest("Failed to decompress gzip data").WriteJSON(w)
			return
		}
		defer reader.Close()
		decompressedData, err = io.ReadAll(reader)
		if err != nil {
			h.logger.Debug("failed to read gzip data", "error", err)
			apierror.BadRequest("Failed to decompress gzip data").WriteJSON(w)
			return
		}
	case "none":
		decompressedData = compressedData
	default:
		apierror.BadRequest("Unsupported compression algorithm: " + req.Compression).WriteJSON(w)
		return
	}

	// Unmarshal chunk data
	var chunkData chunk.ChunkData
	if err := json.Unmarshal(decompressedData, &chunkData); err != nil {
		h.logger.Debug("failed to unmarshal chunk data", "error", err)
		apierror.BadRequest("Invalid chunk data format").WriteJSON(w)
		return
	}

	// Build CTIS report from chunk data
	report := &ctis.Report{
		Version:  "1.0",
		Assets:   chunkData.Assets,
		Findings: chunkData.Findings,
	}

	// Only set Tool and Metadata on first chunk
	if chunkData.Tool != nil {
		report.Tool = chunkData.Tool
	}
	if chunkData.Metadata != nil {
		report.Metadata = *chunkData.Metadata
	}

	// If metadata ID is empty, use the report ID from chunk
	if report.Metadata.ID == "" {
		report.Metadata.ID = req.ReportID
	}

	// Process the chunk through normal ingestion
	input := ingest.Input{
		Report: report,
	}

	output, err := h.ingestService.Ingest(r.Context(), agt, input)
	if err != nil {
		h.logger.Error("chunk ingestion failed",
			"error", err,
			"report_id", req.ReportID,
			"chunk_index", req.ChunkIndex,
		)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// AUDIT: Log chunk ingestion with full context for security monitoring
	h.logger.Info("chunk ingested successfully",
		"report_id", req.ReportID,
		"chunk_index", req.ChunkIndex,
		"total_chunks", req.TotalChunks,
		"is_final", req.IsFinal,
		"assets_created", output.AssetsCreated,
		"findings_created", output.FindingsCreated,
		"agent_id", agt.ID.String(),
		"tenant_id", agt.TenantID.String(),
		"compressed_size", len(compressedData),
		"decompressed_size", len(decompressedData),
	)

	resp := ChunkIngestResponse{
		ChunkID:         uuid.New().String(),
		ReportID:        req.ReportID,
		ChunkIndex:      req.ChunkIndex,
		Status:          "accepted",
		AssetsCreated:   output.AssetsCreated,
		AssetsUpdated:   output.AssetsUpdated,
		FindingsCreated: output.FindingsCreated,
		FindingsUpdated: output.FindingsUpdated,
		FindingsSkipped: output.FindingsSkipped,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Helper Functions
// =============================================================================

// extractAPIKey extracts the API key from the request.
// Supports: Authorization: Bearer <key> or X-API-Key: <key>
//
// SECURITY: Query parameter authentication is NOT supported.
// API keys in query parameters are logged by proxies, CDNs, and access logs,
// exposing credentials across the infrastructure stack.
func extractAPIKey(r *http.Request) string {
	// Try Authorization header first (preferred method)
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// Try X-API-Key header (alternative for clients that can't set Authorization)
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		return apiKey
	}

	// SECURITY: DO NOT use query parameter for API key
	// Query params are logged by proxies, CDNs, WAFs, and access logs
	return ""
}

// buildReconToCTISInput converts handler request to CTIS input.
func (h *IngestHandler) buildReconToCTISInput(req *ReconIngestRequest) *ctis.ReconToCTISInput {
	ctisInput := &ctis.ReconToCTISInput{
		ScannerName:    req.ScannerName,
		ScannerVersion: req.ScannerVersion,
		ReconType:      req.ReconType,
		Target:         req.Target,
		StartedAt:      req.StartedAt,
		FinishedAt:     req.FinishedAt,
		DurationMs:     req.DurationMs,
	}

	// Convert subdomains
	for _, sub := range req.Subdomains {
		ctisInput.Subdomains = append(ctisInput.Subdomains, ctis.SubdomainInput{
			Host:   sub.Host,
			Domain: sub.Domain,
			Source: sub.Source,
			IPs:    sub.IPs,
		})
	}

	// Convert DNS records
	for _, rec := range req.DNSRecords {
		ctisInput.DNSRecords = append(ctisInput.DNSRecords, ctis.DNSRecordInput{
			Host:       rec.Host,
			RecordType: rec.RecordType,
			Values:     rec.Values,
			TTL:        rec.TTL,
			Resolver:   rec.Resolver,
			StatusCode: rec.StatusCode,
		})
	}

	// Convert open ports
	for _, port := range req.OpenPorts {
		ctisInput.OpenPorts = append(ctisInput.OpenPorts, ctis.OpenPortInput{
			Host:     port.Host,
			IP:       port.IP,
			Port:     port.Port,
			Protocol: port.Protocol,
			Service:  port.Service,
			Version:  port.Version,
			Banner:   port.Banner,
		})
	}

	// Convert live hosts
	for _, host := range req.LiveHosts {
		ctisInput.LiveHosts = append(ctisInput.LiveHosts, ctis.LiveHostInput{
			URL:           host.URL,
			Host:          host.Host,
			IP:            host.IP,
			Port:          host.Port,
			Scheme:        host.Scheme,
			StatusCode:    host.StatusCode,
			ContentLength: host.ContentLength,
			Title:         host.Title,
			WebServer:     host.WebServer,
			ContentType:   host.ContentType,
			Technologies:  host.Technologies,
			CDN:           host.CDN,
			TLSVersion:    host.TLSVersion,
			Redirect:      host.Redirect,
			ResponseTime:  host.ResponseTime,
		})
	}

	// Convert discovered URLs
	for _, url := range req.URLs {
		ctisInput.URLs = append(ctisInput.URLs, ctis.DiscoveredURLInput{
			URL:        url.URL,
			Method:     url.Method,
			Source:     url.Source,
			StatusCode: url.StatusCode,
			Depth:      url.Depth,
			Parent:     url.Parent,
			Type:       url.Type,
			Extension:  url.Extension,
		})
	}

	return ctisInput
}
