package handler

// Compliance check reads (docs/architecture/compliance-checks.md, "Reads"):
// the posture per benchmark, a benchmark's controls, the assets of a
// control, and the history of the control a finding fails. All need
// findings:read and run in the caller's data scope.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	ccapp "github.com/openctemio/openctem/server/internal/app/compliancecheck"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	ccdom "github.com/openctemio/openctem/server/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/safetext"
)

// SetComplianceChecks wires the compliance check reads. Without it the
// routes answer 503.
func (h *VulnerabilityHandler) SetComplianceChecks(s *ccapp.Service) { h.complianceChecks = s }

// ComplianceCheckCountsResponse are controls per result. Excepted failures are
// counted in fail too.
type ComplianceCheckCountsResponse struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Manual        int `json:"manual"`
	NotApplicable int `json:"not_applicable"`
	Error         int `json:"error"`
	Excepted      int `json:"excepted"`
	// Applicable is pass + fail, the denominator of the pass rate.
	Applicable int `json:"applicable"`
}

func toComplianceCounts(c ccdom.Counts) ComplianceCheckCountsResponse {
	return ComplianceCheckCountsResponse{Pass: c.Pass, Fail: c.Fail, Manual: c.Manual, NotApplicable: c.NotApplicable,
		Error: c.Error, Excepted: c.Excepted, Applicable: c.Applicable()}
}

// ComplianceCheckBenchmarkResponse is one benchmark's posture.
type ComplianceCheckBenchmarkResponse struct {
	Key           string                        `json:"key"`
	Name          string                        `json:"name"`
	Version       string                        `json:"version,omitempty"`
	Framework     string                        `json:"framework,omitempty"`
	Assets        int                           `json:"assets"`
	FailingAssets int                           `json:"failing_assets"`
	Counts        ComplianceCheckCountsResponse `json:"counts"`
	// PassRate is pass / (pass + fail) in [0, 1]; null when no control applies.
	PassRate      *float64  `json:"pass_rate"`
	LastCheckedAt time.Time `json:"last_checked_at"`
}

// ComplianceCheckBenchmarksResponse lists benchmarks and their sum.
type ComplianceCheckBenchmarksResponse struct {
	Data []ComplianceCheckBenchmarkResponse `json:"data"`
}

// ComplianceCheckControlResponse is one control of a benchmark.
type ComplianceCheckControlResponse struct {
	ControlID     string                        `json:"control_id"`
	ControlName   string                        `json:"control_name,omitempty"`
	Level         int16                         `json:"level,omitempty"`
	Counts        ComplianceCheckCountsResponse `json:"counts"`
	PassRate      *float64                      `json:"pass_rate"`
	LastCheckedAt time.Time                     `json:"last_checked_at"`
}

// ComplianceCheckEvidenceResponse is what a check saw (secrets redacted).
type ComplianceCheckEvidenceResponse struct {
	Actual    string `json:"actual,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Message   string `json:"message,omitempty"`
	AuditFile string `json:"audit_file,omitempty"`
}

func toComplianceEvidence(e ccdom.Evidence) ComplianceCheckEvidenceResponse {
	return ComplianceCheckEvidenceResponse{Actual: safetext.RedactSecrets(e.Actual), Expected: safetext.RedactSecrets(e.Expected),
		Message: safetext.RedactSecrets(e.Message), AuditFile: e.AuditFile}
}

// ComplianceCheckControlAssetResponse is one control's state on one asset.
type ComplianceCheckControlAssetResponse struct {
	AssetID          string                          `json:"asset_id"`
	AssetName        string                          `json:"asset_name"`
	AssetType        string                          `json:"asset_type"`
	Result           string                          `json:"result"`
	BenchmarkVersion string                          `json:"benchmark_version,omitempty"`
	Evidence         ComplianceCheckEvidenceResponse `json:"evidence"`
	ScannerSeverity  string                          `json:"scanner_severity,omitempty"`
	FindingID        string                          `json:"finding_id,omitempty"`
	FindingStatus    string                          `json:"finding_status,omitempty"`
	LastCheckedAt    time.Time                       `json:"last_checked_at"`
	LastChangedAt    time.Time                       `json:"last_changed_at"`
}

// ComplianceCheckHistoryEntryResponse is one change of a control's result or
// evidence.
type ComplianceCheckHistoryEntryResponse struct {
	Result           string                          `json:"result"`
	PreviousResult   string                          `json:"previous_result,omitempty"`
	Evidence         ComplianceCheckEvidenceResponse `json:"evidence"`
	BenchmarkVersion string                          `json:"benchmark_version,omitempty"`
	ToolName         string                          `json:"tool_name,omitempty"`
	// Source: ingest (a scan or an import) or backfill (the operator command).
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`
	RecordedAt time.Time `json:"recorded_at"`
}

// ComplianceCheckHistoryResponse is the control a finding fails and its history,
// newest first; control is null for a finding without a check state.
type ComplianceCheckHistoryResponse struct {
	Control *ComplianceCheckHistoryControl        `json:"control"`
	Data    []ComplianceCheckHistoryEntryResponse `json:"data"`
}

// ComplianceCheckHistoryControl names the control and its current state.
type ComplianceCheckHistoryControl struct {
	BenchmarkKey  string    `json:"benchmark_key"`
	BenchmarkName string    `json:"benchmark_name"`
	ControlID     string    `json:"control_id"`
	ControlName   string    `json:"control_name,omitempty"`
	Level         int16     `json:"level,omitempty"`
	Result        string    `json:"result"`
	LastCheckedAt time.Time `json:"last_checked_at"`
}

func (h *VulnerabilityHandler) complianceError(w http.ResponseWriter, err error) {
	if errors.Is(err, ccapp.ErrNotConfigured) {
		apierror.ServiceUnavailable("compliance checks are not available").WriteJSON(w)
		return
	}
	h.handleServiceError(w, err, "Compliance checks")
}

// ListComplianceBenchmarks handles GET /api/v1/findings/compliance/benchmarks.
//
// @Summary      List benchmark posture
// @Description  One row per benchmark over the caller's assets (or one asset): assets checked, assets failing, controls per result and the pass rate (passed / (passed + failed); not applicable, error and manual are shown, never counted). Precomputed per asset by the dashboard maintainer. An asset outside the caller's data scope reads as no benchmark.
// @Tags         Findings
// @Produce      json
// @Param        asset_id  query  string  false  "One asset"
// @Success      200  {object}  ComplianceCheckBenchmarksResponse
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/compliance/benchmarks [get]
func (h *VulnerabilityHandler) ListComplianceBenchmarks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.Unauthorized("tenant required").WriteJSON(w)
		return
	}
	var assetID *shared.ID
	if v := strings.TrimSpace(r.URL.Query().Get("asset_id")); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("asset_id must be an id").WriteJSON(w)
			return
		}
		assetID = &id
	}
	list, err := h.complianceChecks.ListBenchmarks(ctx, tenantID, assetID)
	if err != nil {
		h.complianceError(w, err)
		return
	}
	out := ComplianceCheckBenchmarksResponse{Data: make([]ComplianceCheckBenchmarkResponse, 0, len(list))}
	for _, b := range list {
		out.Data = append(out.Data, ComplianceCheckBenchmarkResponse{Key: b.Key, Name: b.Name, Version: b.Version, Framework: b.Framework,
			Assets: b.Assets, FailingAssets: b.FailingAssets, Counts: toComplianceCounts(b.Counts), PassRate: b.Counts.PassRate(),
			LastCheckedAt: b.LastCheckedAt.UTC()})
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, out)
}

// ListComplianceControls handles GET /api/v1/findings/compliance/benchmarks/{key}/controls.
//
// @Summary      List a benchmark's controls
// @Description  The controls of one benchmark over the caller's assets, failed first, with the assets per result and the pass rate. result keeps the controls with at least one asset in one of the results; q matches the control id or name.
// @Tags         Findings
// @Produce      json
// @Param        key       path   string  true   "Benchmark key"
// @Param        result    query  string  false  "Comma list of pass, fail, manual, not_applicable, error"
// @Param        q         query  string  false  "Control id or name contains"
// @Param        page      query  int     false  "Page"
// @Param        per_page  query  int     false  "Per page (max 100)"
// @Success      200  {object}  ListResponse[ComplianceCheckControlResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/compliance/benchmarks/{key}/controls [get]
func (h *VulnerabilityHandler) ListComplianceControls(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.Unauthorized("tenant required").WriteJSON(w)
		return
	}
	page, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	results, err := ccapp.ParseResults(r.URL.Query().Get("result"))
	if err != nil {
		apierror.BadRequest("result must be a comma list of pass, fail, manual, not_applicable, error").WriteJSON(w)
		return
	}
	res, err := h.complianceChecks.ListControls(ctx, tenantID, r.PathValue("key"),
		ccdom.ControlFilter{Results: results, Search: r.URL.Query().Get("q")}, page)
	if err != nil {
		h.complianceError(w, err)
		return
	}
	items := make([]ComplianceCheckControlResponse, 0, len(res.Data))
	for _, c := range res.Data {
		items = append(items, ComplianceCheckControlResponse{ControlID: c.ControlID, ControlName: c.ControlName, Level: c.Level,
			Counts: toComplianceCounts(c.Counts), PassRate: c.Counts.PassRate(), LastCheckedAt: c.LastCheckedAt.UTC()})
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, ListResponse[ComplianceCheckControlResponse]{Data: items, Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages})
}

// ListComplianceControlAssets handles GET /api/v1/findings/compliance/benchmarks/{key}/assets.
//
// @Summary      List the assets of a control
// @Description  The state of one control on each of the caller's assets, failed first: result, evidence (secrets redacted), the scanner's severity, the finding and its status, when it was last checked and last changed.
// @Tags         Findings
// @Produce      json
// @Param        key       path   string  true   "Benchmark key"
// @Param        control   query  string  true   "Control id"
// @Param        result    query  string  false  "Comma list of pass, fail, manual, not_applicable, error"
// @Param        page      query  int     false  "Page"
// @Param        per_page  query  int     false  "Per page (max 100)"
// @Success      200  {object}  ListResponse[ComplianceCheckControlAssetResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/compliance/benchmarks/{key}/assets [get]
func (h *VulnerabilityHandler) ListComplianceControlAssets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.Unauthorized("tenant required").WriteJSON(w)
		return
	}
	page, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	results, err := ccapp.ParseResults(r.URL.Query().Get("result"))
	if err != nil {
		apierror.BadRequest("result must be a comma list of pass, fail, manual, not_applicable, error").WriteJSON(w)
		return
	}
	res, err := h.complianceChecks.ListControlAssets(ctx, tenantID, r.PathValue("key"), r.URL.Query().Get("control"), results, page)
	if err != nil {
		h.complianceError(w, err)
		return
	}
	items := make([]ComplianceCheckControlAssetResponse, 0, len(res.Data))
	for _, a := range res.Data {
		item := ComplianceCheckControlAssetResponse{AssetID: a.AssetID.String(), AssetName: a.AssetName, AssetType: a.AssetType,
			Result: string(a.Result), BenchmarkVersion: a.BenchmarkVersion, Evidence: toComplianceEvidence(a.Evidence),
			ScannerSeverity: a.ScannerSeverity, FindingStatus: a.FindingStatus, LastCheckedAt: a.LastCheckedAt.UTC(),
			LastChangedAt: a.LastChangedAt.UTC()}
		if a.FindingID != nil {
			item.FindingID = a.FindingID.String()
		}
		items = append(items, item)
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, ListResponse[ComplianceCheckControlAssetResponse]{Data: items, Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages})
}

// GetFindingComplianceHistory handles GET /api/v1/findings/{id}/compliance-history.
//
// @Summary      Get the history of a finding's benchmark control
// @Description  The control a compliance finding fails on its asset, its current result, and every change of its result or evidence, newest first (at most 200). control is null for a finding without a check state. Out of the caller's data scope or another organization's: 404.
// @Tags         Findings
// @Produce      json
// @Param        id   path  string  true  "Finding id"
// @Success      200  {object}  ComplianceCheckHistoryResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/compliance-history [get]
func (h *VulnerabilityHandler) GetFindingComplianceHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := middleware.MustGetTenantID(ctx)
	// Tenant, data scope and pentest membership, as the finding detail.
	f, err := h.service.GetFindingWithScope(ctx, tenant, r.PathValue("id"), middleware.GetUserID(ctx), middleware.IsAdmin(ctx))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	hist, err := h.complianceChecks.FindingControlHistory(ctx, f.TenantID(), f.ID())
	if err != nil {
		h.complianceError(w, err)
		return
	}
	out := ComplianceCheckHistoryResponse{Data: []ComplianceCheckHistoryEntryResponse{}}
	if hist != nil {
		out.Control = &ComplianceCheckHistoryControl{BenchmarkKey: hist.BenchmarkKey, BenchmarkName: hist.BenchmarkName,
			ControlID: hist.ControlID, ControlName: hist.ControlName, Level: hist.Level, Result: string(hist.Result),
			LastCheckedAt: hist.LastCheckedAt.UTC()}
		for _, e := range hist.Entries {
			out.Data = append(out.Data, ComplianceCheckHistoryEntryResponse{Result: string(e.Result), PreviousResult: string(e.PreviousResult),
				Evidence: toComplianceEvidence(e.Evidence), BenchmarkVersion: e.BenchmarkVersion, ToolName: e.ToolName,
				Source: e.Source, ObservedAt: e.ObservedAt, RecordedAt: e.RecordedAt})
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, out)
}
