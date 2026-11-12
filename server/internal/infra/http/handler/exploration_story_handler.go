package handler

// "How we found this" for a finding or an asset
// (docs/architecture/exploration.md).

import (
	"context"
	"errors"
	"net/http"
	"time"

	explorationapp "github.com/openctemio/openctem/server/internal/app/exploration"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// StoryReader composes stories.
type StoryReader interface {
	FindingStory(ctx context.Context, tenantID, findingID string, acc explorationapp.Access) (*exploration.Story, error)
	AssetStory(ctx context.Context, tenantID, assetID string, acc explorationapp.Access) (*exploration.Story, error)
}

// StoryHandler serves GET /findings/{id}/story and GET /assets/{id}/story.
type StoryHandler struct {
	stories StoryReader
	logger  *logger.Logger
}

// NewStoryHandler creates the handler.
func NewStoryHandler(stories StoryReader, log *logger.Logger) *StoryHandler {
	return &StoryHandler{stories: stories, logger: log}
}

// StorySubject names what a story is about.
type StorySubject struct {
	// Kind: finding or asset.
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// StoryAsset is an asset of the discovery chain.
type StoryAsset struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	// Via is how this asset leads to the next one down the chain: parent,
	// contains, exposes, serves_certificate or resolves_to. Kept on a hidden
	// step.
	Via             string `json:"via,omitempty"`
	DiscoverySource string `json:"discovery_source,omitempty"`
	DiscoveryTool   string `json:"discovery_tool,omitempty"`
	// Subject is set on the asset the story is about.
	Subject bool `json:"subject,omitempty"`
}

// StoryScopeEntry is the scope entry in effect that covers the chain.
type StoryScopeEntry struct {
	ID         string `json:"id"`
	TargetType string `json:"target_type"`
	Pattern    string `json:"pattern"`
	// AssetID is the asset of the chain the entry matches.
	AssetID string `json:"asset_id"`
	// ExcludedBy is the pattern of an exclusion in effect that also matches
	// the subject asset.
	ExcludedBy string `json:"excluded_by,omitempty"`
}

// StoryScan is a scan run, with its step when known.
type StoryScan struct {
	// Role: discovered (the run derived the asset from a parent), scanned
	// (the latest run that targeted the asset) or reported (the run of a
	// source that reported the finding).
	Role       string `json:"role"`
	RunID      string `json:"run_id"`
	ScanID     string `json:"scan_id,omitempty"`
	ScanName   string `json:"scan_name,omitempty"`
	RunStatus  string `json:"run_status,omitempty"`
	StepRunID  string `json:"step_run_id,omitempty"`
	StepName   string `json:"step_name,omitempty"`
	Capability string `json:"capability,omitempty"`
	Tool       string `json:"tool,omitempty"`
	// Relation is how a discovered asset was derived from its parent.
	Relation string `json:"relation,omitempty"`
}

// StoryReport is one source that reported the subject.
type StoryReport struct {
	// Channel: scan, task, sensor, upload, ci, connector, platform, unknown.
	Channel     string `json:"channel"`
	Tool        string `json:"tool,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	// Sensor is the organization's sensor; shown with sensors:read only.
	Sensor *FindingSightingSensor `json:"sensor,omitempty"`
	// Sender is the CI repository or connector source name.
	Sender string `json:"sender,omitempty"`
	// ReceiptID is the ingest receipt, while it is kept.
	ReceiptID   string    `json:"receipt_id,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	SeenCount   int       `json:"seen_count"`
	Backfilled  bool      `json:"backfilled"`
}

// StoryFinding is the finding at the end of a finding story.
type StoryFinding struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// StoryStep is one step of the chain. A hidden step is one the caller may
// not see: it carries its kind only (an asset also its via).
type StoryStep struct {
	// Kind: scope_entry, asset, scan, report or finding.
	Kind       string           `json:"kind"`
	Hidden     bool             `json:"hidden"`
	At         *time.Time       `json:"at,omitempty"`
	Asset      *StoryAsset      `json:"asset,omitempty"`
	ScopeEntry *StoryScopeEntry `json:"scope_entry,omitempty"`
	Scan       *StoryScan       `json:"scan,omitempty"`
	Report     *StoryReport     `json:"report,omitempty"`
	Finding    *StoryFinding    `json:"finding,omitempty"`
}

// StoryResponse is how a finding or an asset was found, scope first and the
// subject last.
type StoryResponse struct {
	Subject StorySubject `json:"subject"`
	Steps   []StoryStep  `json:"steps"`
	// Hidden counts the steps the caller may not see.
	Hidden int `json:"hidden"`
	// Truncated is set when the discovery chain goes on above its first
	// asset, or the chain was cut at its maximum length.
	Truncated bool `json:"truncated"`
	// MoreReports counts the sources that reported the finding beyond the
	// first three (all are listed by GET /findings/{id}/sightings).
	MoreReports int        `json:"more_reports"`
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	MaxSteps    int        `json:"max_steps"`
}

// FindingStory handles GET /api/v1/findings/{id}/story.
//
// @Summary      How a finding was found
// @Description  A short ordered chain from data already stored: the scope entry in effect that covers the finding's asset (with attack_surface:scope:read), the asset's discovery chain (at most 5 ancestors), the first three sources that reported it with the scan run and step of each (runs with scans:read, sensors with sensors:read) and the finding. Readable by whoever may read the finding. A step the caller may not see (an asset outside their data scope, a run without scans:read) is returned with hidden set and no identifying field, and counted in hidden.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Finding id"
// @Success      200  {object}  StoryResponse
// @Failure      404  {object}  apierror.Error
// @Router       /findings/{id}/story [get]
func (h *StoryHandler) FindingStory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, err := h.stories.FindingStory(ctx, middleware.MustGetTenantID(ctx), r.PathValue("id"), storyAccess(r))
	h.write(w, s, err, "Finding")
}

// AssetStory handles GET /api/v1/assets/{id}/story.
//
// @Summary      How an asset was found
// @Description  A short ordered chain from data already stored: the scope entry in effect that covers the asset or its closest visible ancestor (with attack_surface:scope:read), its discovery chain (at most 5 ancestors), the scan run that derived it from a parent, the upload that created it and the latest scan run that targeted it (runs with scans:read). Out of the caller's data scope: 404. A step the caller may not see is returned with hidden set and no identifying field, and counted in hidden.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Asset id"
// @Success      200  {object}  StoryResponse
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/story [get]
func (h *StoryHandler) AssetStory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, err := h.stories.AssetStory(ctx, middleware.MustGetTenantID(ctx), r.PathValue("id"), storyAccess(r))
	h.write(w, s, err, "Asset")
}

func storyAccess(r *http.Request) explorationapp.Access {
	ctx := r.Context()
	return explorationapp.Access{
		UserID:  middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx),
		Scans:   middleware.HasPermission(ctx, string(permission.ScansRead)),
		Sensors: middleware.HasPermission(ctx, string(permission.SensorsRead)),
		Scope:   middleware.HasPermission(ctx, string(permission.ScopeRead)),
	}
}

func (h *StoryHandler) write(w http.ResponseWriter, s *exploration.Story, err error, what string) {
	switch {
	case errors.Is(err, shared.ErrNotFound), errors.Is(err, shared.ErrValidation), errors.Is(err, shared.ErrForbidden):
		apierror.NotFound(what).WriteJSON(w)
	case err != nil:
		h.logger.Error("story: compose", "subject", what, "error", err)
		apierror.InternalServerError("could not read how this was found").WriteJSON(w)
	default:
		writeJSON(w, http.StatusOK, toStoryResponse(s))
	}
}

func toStoryResponse(s *exploration.Story) StoryResponse {
	out := StoryResponse{Subject: StorySubject{Kind: s.Subject.Kind, ID: s.Subject.ID.String()},
		Steps: make([]StoryStep, 0, len(s.Steps)), Hidden: s.Hidden, Truncated: s.Truncated,
		MoreReports: s.MoreReports, FirstSeenAt: s.FirstSeenAt, LastSeenAt: s.LastSeenAt, MaxSteps: exploration.MaxSteps}
	for _, st := range s.Steps {
		step := StoryStep{Kind: string(st.Kind), Hidden: st.Hidden}
		if st.Hidden {
			if st.Asset != nil {
				step.Asset = &StoryAsset{Via: st.Asset.Via}
			}
			out.Steps = append(out.Steps, step)
			continue
		}
		step.At = st.At
		switch {
		case st.Asset != nil:
			a := st.Asset
			step.Asset = &StoryAsset{ID: a.ID.String(), Name: a.Name, Type: a.Type, Via: a.Via,
				DiscoverySource: a.DiscoverySource, DiscoveryTool: a.DiscoveryTool, Subject: a.Subject}
		case st.Scope != nil:
			sc := st.Scope
			step.ScopeEntry = &StoryScopeEntry{ID: sc.ID.String(), TargetType: sc.TargetType, Pattern: sc.Pattern,
				AssetID: sc.AssetID.String(), ExcludedBy: sc.ExcludedBy}
		case st.Scan != nil:
			sc := st.Scan
			step.Scan = &StoryScan{Role: sc.Role, RunID: sc.RunID.String(), ScanID: sightingID(sc.ScanID), ScanName: sc.ScanName,
				RunStatus: sc.RunStatus, StepRunID: sightingID(sc.StepRunID), StepName: sc.StepName,
				Capability: sc.Capability, Tool: sc.Tool, Relation: sc.Relation}
		case st.Report != nil:
			rp := st.Report
			step.Report = &StoryReport{Channel: rp.Channel, Tool: rp.Tool, ToolVersion: rp.ToolVersion, Sender: rp.Sender,
				ReceiptID: sightingID(rp.ReceiptID), FirstSeenAt: rp.FirstSeenAt, LastSeenAt: rp.LastSeenAt,
				SeenCount: rp.SeenCount, Backfilled: rp.Backfilled}
			if rp.SensorID != nil {
				step.Report.Sensor = &FindingSightingSensor{ID: rp.SensorID.String(), Name: rp.SensorName}
			}
		case st.Finding != nil:
			step.Finding = &StoryFinding{ID: st.Finding.ID.String(), Title: st.Finding.Title}
		}
		out.Steps = append(out.Steps, step)
	}
	return out
}
