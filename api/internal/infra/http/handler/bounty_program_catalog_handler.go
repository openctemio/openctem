package handler

// The public program catalog and subscriptions (RFC-065 §16).

import (
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PublicProgramResponse is one program of the catalog.
type PublicProgramResponse struct {
	ID           string    `json:"id"`
	FeedID       string    `json:"feed_id"`
	Platform     string    `json:"platform"`
	Handle       string    `json:"handle"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	OffersBounty bool      `json:"offers_bounty"`
	InScope      int       `json:"in_scope"`
	OutOfScope   int       `json:"out_of_scope"`
	Items        []bp.Item `json:"items"`
	Rules        bp.Rules  `json:"rules"`
	TermsText    string    `json:"terms_text"`
	TermsSHA256  string    `json:"terms_sha256"`
	Source       string    `json:"source"`
	AsOf         time.Time `json:"as_of"`
}

// ProgramSubscribeRequest is the body of a subscription.
type ProgramSubscribeRequest struct {
	PublicProgramID string `json:"public_program_id"`
}

func toPublicProgramResponse(p bp.PublicProgram) PublicProgramResponse {
	out := PublicProgramResponse{ID: p.ID.String(), FeedID: p.FeedID, Platform: p.Platform, Handle: p.Handle,
		Name: p.Name, URL: p.URL, OffersBounty: p.OffersBounty, Items: p.Items, Rules: p.Rules,
		TermsText: p.TermsText, TermsSHA256: p.TermsSHA256, Source: p.Source, AsOf: p.AsOf}
	if out.Items == nil {
		out.Items = []bp.Item{}
	}
	for _, it := range p.Items {
		if it.InScope {
			out.InScope++
		} else {
			out.OutOfScope++
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
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}
	search := q.Get("search")
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
