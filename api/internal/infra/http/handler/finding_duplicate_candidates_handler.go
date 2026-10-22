package handler

// Duplicate candidates of a finding.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-121-bug-bounty-reports.md

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// DuplicateCandidatesResponse lists the duplicate candidates of a finding.
type DuplicateCandidatesResponse struct {
	FindingID string `json:"finding_id"`
	// ReportSubmittedAt: the finding's bounty report submission time.
	ReportSubmittedAt *time.Time `json:"report_submitted_at,omitempty"`
	// KnownSince: the earliest first detection among the candidates.
	KnownSince *time.Time `json:"known_since,omitempty"`
	// KnownBeforeReport: a candidate was first detected before the report
	// was submitted. Omitted without a submission time or candidates.
	KnownBeforeReport *bool                `json:"known_before_report,omitempty"`
	Candidates        []DuplicateCandidate `json:"candidates"`
	Limit             int                  `json:"limit"`
}

// DuplicateCandidate is one candidate finding.
type DuplicateCandidate struct {
	FindingID       string    `json:"finding_id"`
	Title           string    `json:"title"`
	Source          string    `json:"source"`
	Status          string    `json:"status"`
	Severity        string    `json:"severity"`
	AssetID         string    `json:"asset_id"`
	AssetName       string    `json:"asset_name"`
	FirstDetectedAt time.Time `json:"first_detected_at"`
	// MatchedOn: same_asset or same_host, then any of cwe, cve, path.
	MatchedOn []string `json:"matched_on"`
	// KnownBeforeReport: first detected before the report was submitted.
	KnownBeforeReport *bool `json:"known_before_report,omitempty"`
}

// GetFindingDuplicateCandidates handles GET /api/v1/findings/{id}/duplicate-candidates.
//
//	@Summary		Duplicate candidates of a finding
//	@Description	Up to 20 findings that may describe the same issue: on the same asset or an asset with the same host, sharing a CWE, a CVE or the vulnerable path; any source and status except folded duplicates. Only findings in the caller's data scope are considered; the finding itself must be in it (404 otherwise, also for another tenant's id). Each candidate carries its first detection, and for a bug-bounty report whether it was known before the report was submitted. Nothing is merged: use POST /findings/{id}/duplicates.
//	@Tags			Findings
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Finding ID"
//	@Success		200	{object}	DuplicateCandidatesResponse
//	@Failure		403	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/findings/{id}/duplicate-candidates [get]
func (h *VulnerabilityHandler) GetFindingDuplicateCandidates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.service.DuplicateCandidates(ctx, middleware.MustGetTenantID(ctx), r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	out := DuplicateCandidatesResponse{
		FindingID:         res.FindingID.String(),
		ReportSubmittedAt: res.ReportSubmittedAt,
		KnownSince:        res.KnownSince(),
		Candidates:        make([]DuplicateCandidate, 0, len(res.Candidates)),
		Limit:             vulnerability.MaxDuplicateSuggestions,
	}
	anyBefore := false
	for _, c := range res.Candidates {
		dc := DuplicateCandidate{
			FindingID: c.FindingID.String(), Title: c.Title, Source: c.Source, Status: c.Status,
			Severity: c.Severity, AssetID: c.AssetID.String(), AssetName: c.AssetName,
			FirstDetectedAt: c.FirstDetectedAt, MatchedOn: c.MatchedOn(),
		}
		if res.ReportSubmittedAt != nil {
			before := c.FirstDetectedAt.Before(*res.ReportSubmittedAt)
			anyBefore = anyBefore || before
			dc.KnownBeforeReport = &before
		}
		out.Candidates = append(out.Candidates, dc)
	}
	if res.ReportSubmittedAt != nil && len(res.Candidates) > 0 {
		out.KnownBeforeReport = &anyBefore
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
