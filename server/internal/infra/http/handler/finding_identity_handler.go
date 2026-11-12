package handler

// Identity explanation of a finding (docs/architecture/deduplication.md,
// "Why a finding is one").

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingIdentityResponse says why a finding is one finding. It carries
// recipe and field NAMES only: never a key, fingerprint or field value.
type FindingIdentityResponse struct {
	// Algo is the recipe that keyed the finding ("v2/sca", "v1/ingest",
	// "manual/v1", "pentest/v1"); empty when unknown.
	Algo    string `json:"algo"`
	Version int    `json:"version"`
	// Fields are the names of the key's fields, in recipe order.
	Fields []string `json:"fields"`
	// Derived: read from the stored identity tuple (recorded before recipes
	// were kept).
	Derived bool `json:"derived"`
	// Legacy: a version-1 key with no recorded recipe.
	Legacy  bool                    `json:"legacy"`
	Sources []FindingIdentitySource `json:"sources"`
	Merged  []FindingIdentityMerged `json:"merged"`
}

// FindingIdentitySource is a tool that reported the finding or a duplicate
// merged into it.
type FindingIdentitySource struct {
	Tool       string     `json:"tool"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

// FindingIdentityMerged is a finding merged into this one, in the caller's
// data scope.
type FindingIdentityMerged struct {
	ID       string    `json:"id"`
	ToolName string    `json:"tool_name"`
	MergedAt time.Time `json:"merged_at"`
	// Reason: manual, asset_merge, refingerprint, dast_identity_repair, …;
	// empty when none was recorded.
	Reason string `json:"reason"`
}

func toFindingIdentityResponse(e *vulnerability.IdentityExplanation) FindingIdentityResponse {
	out := FindingIdentityResponse{
		Algo: e.Algo, Version: e.Version, Fields: e.Fields, Derived: e.Derived, Legacy: e.Legacy,
		Sources: make([]FindingIdentitySource, 0, len(e.Sources)),
		Merged:  make([]FindingIdentityMerged, 0, len(e.Merged)),
	}
	if out.Fields == nil {
		out.Fields = []string{}
	}
	for _, s := range e.Sources {
		out.Sources = append(out.Sources, FindingIdentitySource{Tool: s.Tool, LastSeenAt: s.LastSeenAt})
	}
	for _, m := range e.Merged {
		out.Merged = append(out.Merged, FindingIdentityMerged{ID: m.ID.String(), ToolName: m.ToolName, MergedAt: m.MergedAt, Reason: m.Reason})
	}
	return out
}

// GetFindingIdentity handles GET /api/v1/findings/{id}/identity.
//
//	@Summary		Why this is one finding
//	@Description	The recipe and field names of the finding's identity key, the tools that reported it, and the duplicates merged into it that the caller may see. The finding must be in the caller's data scope (404 otherwise). Never returns a key, fingerprint or field value.
//	@Tags			Findings
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Finding ID"
//	@Success		200	{object}	FindingIdentityResponse
//	@Failure		400	{object}	apierror.Error
//	@Failure		404	{object}	apierror.Error
//	@Router			/findings/{id}/identity [get]
func (h *VulnerabilityHandler) GetFindingIdentity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}
	exp, err := h.service.ExplainFindingIdentity(ctx, middleware.MustGetTenantID(ctx), id,
		middleware.GetUserID(ctx), middleware.IsAdmin(ctx))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toFindingIdentityResponse(exp))
}
