package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/api/internal/app/auth/domainverify"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/verifieddomain"
	"github.com/openctemio/api/pkg/logger"
)

// VerifiedDomainHandler handles tenant-scoped domain-ownership verification.
type VerifiedDomainHandler struct {
	service *domainverify.Service
	logger  *logger.Logger
}

// NewVerifiedDomainHandler creates a new VerifiedDomainHandler.
func NewVerifiedDomainHandler(service *domainverify.Service, log *logger.Logger) *VerifiedDomainHandler {
	return &VerifiedDomainHandler{
		service: service,
		logger:  log.With("handler", "verified-domain"),
	}
}

// AddDomainRequest is the request body for adding a domain to verify.
type AddDomainRequest struct {
	Domain string `json:"domain" validate:"required,max=253"`
}

// VerifiedDomainResponse is the JSON representation of a verified-domain row.
type VerifiedDomainResponse struct {
	ID            string                 `json:"id"`
	Domain        string                 `json:"domain"`
	Status        string                 `json:"status"`
	Instructions  domainverify.TXTRecord `json:"instructions"`
	VerifiedAt    *string                `json:"verified_at,omitempty"`
	LastCheckedAt *string                `json:"last_checked_at,omitempty"`
	CreatedAt     string                 `json:"created_at"`
	UpdatedAt     string                 `json:"updated_at"`
}

// AddDomain adds a domain and returns the DNS TXT record to publish.
// POST /api/v1/settings/verified-domains
func (h *VerifiedDomainHandler) AddDomain(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}

	limitBody(w, r)
	var req AddDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Domain == "" {
		apierror.BadRequest("domain is required").WriteJSON(w)
		return
	}

	vd, txt, err := h.service.AddDomain(r.Context(), tenantID, req.Domain)
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toVerifiedDomainResponse(vd, txt))
}

// List lists the tenant's verified domains.
// GET /api/v1/settings/verified-domains
func (h *VerifiedDomainHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}

	domains, err := h.service.List(r.Context(), tenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	result := make([]VerifiedDomainResponse, 0, len(domains))
	for _, vd := range domains {
		txt := domainverify.Instructions(vd.Domain(), vd.VerificationToken())
		result = append(result, toVerifiedDomainResponse(vd, txt))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"verified_domains": result})
}

// Verify runs verification for a domain now.
// POST /api/v1/settings/verified-domains/{id}/verify
func (h *VerifiedDomainHandler) Verify(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	id, ok := h.pathID(w, r)
	if !ok {
		return
	}

	vd, err := h.service.VerifyByID(r.Context(), tenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}

	txt := domainverify.Instructions(vd.Domain(), vd.VerificationToken())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toVerifiedDomainResponse(vd, txt))
}

// Delete removes a verified domain.
// DELETE /api/v1/settings/verified-domains/{id}
func (h *VerifiedDomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	id, ok := h.pathID(w, r)
	if !ok {
		return
	}

	if err := h.service.Delete(r.Context(), tenantID, id); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tenantID extracts and parses the JWT-scoped tenant id.
func (h *VerifiedDomainHandler) tenantID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant context").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

// pathID extracts and parses the {id} path value.
func (h *VerifiedDomainHandler) pathID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("invalid id").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *VerifiedDomainHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, verifieddomain.ErrNotFound):
		apierror.NotFound("Domain not found").WriteJSON(w)
	case errors.Is(err, verifieddomain.ErrAlreadyExists):
		apierror.Conflict("Domain already added for this organization").WriteJSON(w)
	case errors.Is(err, verifieddomain.ErrBlockedDomain):
		apierror.BadRequest("This is a shared/public email domain and cannot be verified").WriteJSON(w)
	case errors.Is(err, verifieddomain.ErrInvalidDomain), errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid domain").WriteJSON(w)
	default:
		h.logger.Error("verified domain error", "error", err)
		apierror.InternalServerError("An internal error occurred").WriteJSON(w)
	}
}

func toVerifiedDomainResponse(vd *verifieddomain.VerifiedDomain, txt domainverify.TXTRecord) VerifiedDomainResponse {
	const layout = "2006-01-02T15:04:05Z"
	resp := VerifiedDomainResponse{
		ID:           vd.ID().String(),
		Domain:       vd.Domain(),
		Status:       string(vd.Status()),
		Instructions: txt,
		CreatedAt:    vd.CreatedAt().Format(layout),
		UpdatedAt:    vd.UpdatedAt().Format(layout),
	}
	if t := vd.VerifiedAt(); t != nil {
		s := t.Format(layout)
		resp.VerifiedAt = &s
	}
	if t := vd.LastCheckedAt(); t != nil {
		s := t.Format(layout)
		resp.LastCheckedAt = &s
	}
	return resp
}
