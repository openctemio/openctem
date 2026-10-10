package handler

// The public program catalog and subscriptions (RFC-065 §16).

import (
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PublicProgramResponse is one program of the catalog.
type PublicProgramResponse struct {
	ID             string `json:"id"`
	FeedID         string `json:"feed_id"`
	Source         string `json:"source"`
	Platform       string `json:"platform"`
	Handle         string `json:"handle"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Type           string `json:"type"`
	Status         string `json:"status"`
	OffersBounty   bool   `json:"offers_bounty"`
	ScopePublished bool   `json:"scope_published"`
	// InScope counts published in-scope targets; Suggested counts targets
	// the feed only inferred (never permission to test).
	InScope        int       `json:"in_scope"`
	Suggested      int       `json:"suggested"`
	OutOfScope     int       `json:"out_of_scope"`
	Items          []bp.Item `json:"items"`
	Rules          bp.Rules  `json:"rules"`
	TermsText      string    `json:"terms_text"`
	TermsURL       string    `json:"terms_url,omitempty"`
	TermsDocSHA256 string    `json:"terms_doc_sha256,omitempty"`
	AsOf           time.Time `json:"as_of"`
	// Provenance names the source of the record and, for a record read
	// through a public dataset, the dataset, its commit, the original
	// platform and program page (that platform's terms apply).
	Provenance bp.FeedProvenance `json:"provenance"`
}

// ProgramConfirmTargetsRequest names suggested targets to confirm.
type ProgramConfirmTargetsRequest struct {
	Targets []string `json:"targets"`
}

// ProgramSubscribeRequest is the body of a subscription.
type ProgramSubscribeRequest struct {
	PublicProgramID string `json:"public_program_id"`
}

func toPublicProgramResponse(p bp.PublicProgram) PublicProgramResponse {
	out := PublicProgramResponse{ID: p.ID.String(), FeedID: p.FeedID, Source: p.Source, Platform: p.Platform,
		Handle: p.Handle, Name: p.Name, URL: p.URL, Type: p.Type, Status: p.Status, OffersBounty: p.OffersBounty,
		ScopePublished: p.ScopePublished, Items: p.Items, Rules: p.Rules, TermsText: p.TermsText,
		TermsURL: p.TermsURL, TermsDocSHA256: p.TermsDocSHA256, AsOf: p.AsOf, Provenance: p.Provenance}
	if out.Items == nil {
		out.Items = []bp.Item{}
	}
	for _, it := range p.Items {
		switch {
		case !it.InScope:
			out.OutOfScope++
		case it.Confidence != bp.ConfidencePublished:
			out.Suggested++
		default:
			out.InScope++
		}
	}
	return out
}

// Catalog handles GET /api/v1/programs/catalog
// @Summary      List public programs
// @Description  The public bug-bounty programs of the platform catalog, imported from the signed program feed (RFC-065 §16): published scope, rules and terms. Public data; subscribing creates the organization's own program.
// @Tags         Programs
// @Produce      json
// @Param        search  query     string  false  "Name or id"
// @Param        page      query     int     false  "Page" default(1)
// @Param        per_page  query     int     false  "Items per page" default(50)
// @Success      200  {object}  map[string]any
// @Security     BearerAuth
// @Router       /programs/catalog [get]
func (h *BountyProgramHandler) Catalog(w http.ResponseWriter, r *http.Request) {
	paging, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	page, perPage := paging.Page, paging.PerPage
	search := r.URL.Query().Get("search")
	if len(search) > 100 {
		search = search[:100]
	}
	list, total, err := h.svc.Catalog(r.Context(), search, perPage, (page-1)*perPage)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := make([]PublicProgramResponse, 0, len(list))
	for _, p := range list {
		out = append(out, toPublicProgramResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out, "total": total, "page": page, "per_page": perPage})
}

// Subscribe handles POST /api/v1/programs/subscriptions
// @Summary      Follow a public program
// @Description  Create the organization's program from a catalog program: its group (the caller joins), its program exclusions and its entries, all inactive (status pending_attestation). Only passive monitoring runs until a member accepts the terms (POST /programs/{id}/reactivate with its terms_sha256, step-up). Feed changes narrow at once; anything that widens or changes the terms asks for a new acceptance. Audited.
// @Tags         Programs
// @Accept       json
// @Produce      json
// @Param        body  body      ProgramSubscribeRequest  true  "Catalog program"
// @Success      201   {object}  ProgramChangeResponse
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/subscriptions [post]
func (h *BountyProgramHandler) Subscribe(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req ProgramSubscribeRequest
	if !h.decode(w, r, &req) {
		return
	}
	pid, err := shared.IDFromString(req.PublicProgramID)
	if err != nil {
		apierror.BadRequest("public_program_id is not a valid id").WriteJSON(w)
		return
	}
	p, pv, err := h.svc.Subscribe(r.Context(), tenantID, actor, pid)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.auditProgram(r, audit.ActionBountyProgramSubscribed, p, "Public program followed; entries wait for an acceptance of the terms", planCounts(pv))
	writeJSON(w, http.StatusCreated, ProgramChangeResponse{Program: toProgramResponse(p), Preview: pv})
}

// ConfirmTargets handles POST /api/v1/programs/{id}/targets/confirm
// @Summary      Confirm suggested targets
// @Description  Add targets the program feed only suggested (inferred) for a followed program to its scope. Only the program's own suggestions are accepted (400 PROGRAM_TARGET_NOT_SUGGESTED). It widens the program: every entry waits until a member accepts the new terms (POST /programs/{id}/reactivate). Audited.
// @Tags         Programs
// @Accept       json
// @Produce      json
// @Param        id    path      string                        true  "Program ID"
// @Param        body  body      ProgramConfirmTargetsRequest  true  "Targets"
// @Success      200   {object}  ProgramChangeResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /programs/{id}/targets/confirm [post]
func (h *BountyProgramHandler) ConfirmTargets(w http.ResponseWriter, r *http.Request) {
	tenantID, actor, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, ok := h.programID(w, r)
	if !ok {
		return
	}
	var req ProgramConfirmTargetsRequest
	if !h.decode(w, r, &req) {
		return
	}
	p, pv, err := h.svc.ConfirmTargets(r.Context(), tenantID, actor, id, req.Targets)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.auditProgram(r, audit.ActionBountyProgramScopeReplaced, p, "Suggested program targets confirmed; entries wait for an acceptance of the terms",
		map[string]any{"targets_confirmed": len(req.Targets)})
	writeJSON(w, http.StatusOK, ProgramChangeResponse{Program: toProgramResponse(p), Preview: pv})
}
