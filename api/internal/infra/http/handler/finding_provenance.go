package handler

import (
	"context"
	"net/url"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingProvenanceLister reads where a finding was seen: its branches and
// the CI runs that reported it (tenant-scoped).
type FindingProvenanceLister interface {
	ListFindingBranches(ctx context.Context, tenantID, findingID shared.ID, limit int) ([]vulnerability.BranchSighting, error)
	ListFindingRuns(ctx context.Context, tenantID shared.ID, fingerprint string, limit int) ([]vulnerability.RunSighting, *vulnerability.RunSighting, error)
}

// SetProvenanceLister wires the provenance of the single-finding response.
// Safe after construction; nil leaves it out.
func (h *VulnerabilityHandler) SetProvenanceLister(l FindingProvenanceLister) {
	h.provenance = l
}

// FindingProvenance says where and when a finding was seen: on which
// branches (first and last commit each) and, for a caller who may read CI
// runs, which pipelines reported it, the first one included. Run actors and
// tokens are never part of it.
type FindingProvenance struct {
	Branches []FindingBranchResponse `json:"branches,omitempty"`
	Runs     []FindingRunResponse    `json:"runs,omitempty"`
	FirstRun *FindingRunResponse     `json:"first_run,omitempty"`
}

// FindingBranchResponse is one branch a finding was seen on.
type FindingBranchResponse struct {
	Name        string    `json:"name"`
	IsDefault   bool      `json:"is_default"`
	Status      string    `json:"status"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	FirstCommit string    `json:"first_commit,omitempty"`
	LastCommit  string    `json:"last_commit,omitempty"`
}

// FindingRunResponse is one CI run that reported a finding.
type FindingRunResponse struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	ExternalRunID   string    `json:"external_run_id,omitempty"`
	PipelineURL     string    `json:"pipeline_url,omitempty"`
	Branch          string    `json:"branch,omitempty"`
	CommitSHA       string    `json:"commit_sha,omitempty"`
	PullRequest     string    `json:"pull_request,omitempty"`
	IsDefaultBranch bool      `json:"is_default_branch"`
	Event           string    `json:"event,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

const (
	provenanceBranchCap = 20
	provenanceRunCap    = 5
)

func toFindingRunResponse(s vulnerability.RunSighting) FindingRunResponse {
	return FindingRunResponse{
		ID: s.ID, Provider: s.Provider, ExternalRunID: s.ExternalRunID, PipelineURL: httpURL(s.PipelineURL),
		Branch: s.Branch, CommitSHA: s.CommitSHA, PullRequest: s.PullRequest,
		IsDefaultBranch: s.IsDefaultBranch, Event: s.Event, CreatedAt: s.CreatedAt,
	}
}

// httpURL keeps an http(s) URL with a host and drops anything else.
func httpURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP) || u.Host == "" || u.User != nil {
		return ""
	}
	return raw
}

func (h *VulnerabilityHandler) enrichFindingWithProvenance(ctx context.Context, tenantID string, f *vulnerability.Finding, resp *FindingResponse) {
	if h.provenance == nil {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	var p FindingProvenance
	branches, err := h.provenance.ListFindingBranches(ctx, tid, f.ID(), provenanceBranchCap)
	if err != nil {
		h.logger.Debug("failed to list finding branches", "finding_id", f.ID().String(), "error", err)
	}
	for _, b := range branches {
		p.Branches = append(p.Branches, FindingBranchResponse{
			Name: b.Name, IsDefault: b.IsDefault, Status: b.Status, FirstSeenAt: b.FirstSeenAt,
			LastSeenAt: b.LastSeenAt, FirstCommit: b.FirstCommit, LastCommit: b.LastCommit,
		})
	}
	// CI runs are CI data: listed only for a caller who may read CI runs.
	if f.Fingerprint() != "" && middleware.HasPermission(ctx, permission.CIRead.String()) {
		runs, first, err := h.provenance.ListFindingRuns(ctx, tid, f.Fingerprint(), provenanceRunCap)
		if err != nil {
			h.logger.Debug("failed to list finding runs", "finding_id", f.ID().String(), "error", err)
		}
		for _, r := range runs {
			p.Runs = append(p.Runs, toFindingRunResponse(r))
		}
		if first != nil {
			fr := toFindingRunResponse(*first)
			p.FirstRun = &fr
		}
	}
	if len(p.Branches) == 0 && len(p.Runs) == 0 {
		return
	}
	resp.Provenance = &p
}
