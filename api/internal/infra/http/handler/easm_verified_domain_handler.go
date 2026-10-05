package handler

// Tenant self-service domain verification for EASM (research/22 P0-10,
// owner decision E6; docs/architecture/easm.md "Verified domains").

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMDomainVerifier is the tenant side of domain verification
// (*domainverify.Service).
type EASMDomainVerifier interface {
	List(ctx context.Context, tenantID shared.ID) ([]*verifieddomain.VerifiedDomain, error)
	AddEASMDomain(ctx context.Context, tenantID shared.ID, rawDomain string) (*verifieddomain.VerifiedDomain, domainverify.TXTRecord, error)
	VerifyEASM(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error)
	DeleteEASM(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error)
}

// EASMVerifiedDomainHandler serves /api/v1/easm/verified-domains.
type EASMVerifiedDomainHandler struct {
	svc    EASMDomainVerifier
	audit  AttributionAuditor
	logger *logger.Logger
}

// NewEASMVerifiedDomainHandler creates the handler. A nil auditor skips
// audit records (tests only).
func NewEASMVerifiedDomainHandler(svc EASMDomainVerifier, audit AttributionAuditor, log *logger.Logger) *EASMVerifiedDomainHandler {
	return &EASMVerifiedDomainHandler{svc: svc, audit: audit, logger: log.With("handler", "easm-verified-domain")}
}

// EASMVerifiedDomain is one of the organization's verified domains.
type EASMVerifiedDomain struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// Status: pending (TXT not seen yet), verified, or failed (it was
	// verified and the record is gone; names under it stop auto-confirming).
	Status string `json:"status"`
	// Purpose: easm (added by the organization, attribution only) or sso
	// (set up by a platform administrator; admits SSO users, read-only here).
	Purpose string `json:"purpose"`
	// Managed is true for an sso row: the organization cannot re-check or
	// delete it here.
	Managed bool `json:"managed"`
	// Instructions is the TXT record to publish (easm rows only).
	Instructions  *domainverify.TXTRecord `json:"instructions,omitempty"`
	VerifiedAt    *string                 `json:"verified_at,omitempty"`
	LastCheckedAt *string                 `json:"last_checked_at,omitempty"`
	CreatedAt     string                  `json:"created_at"`
}

// EASMVerifiedDomainList is the list response.
type EASMVerifiedDomainList struct {
	Data []EASMVerifiedDomain `json:"data"`
}

// EASMVerifiedDomainCreateRequest adds a domain to verify.
type EASMVerifiedDomainCreateRequest struct {
	Domain string `json:"domain"`
}

func toEASMVerifiedDomain(vd *verifieddomain.VerifiedDomain) EASMVerifiedDomain {
	out := EASMVerifiedDomain{
		ID: vd.ID().String(), Domain: vd.Domain(), Status: string(vd.Status()), Purpose: string(vd.Purpose()),
		Managed: vd.Purpose() != verifieddomain.PurposeEASM, CreatedAt: vd.CreatedAt().UTC().Format(rfc3339),
	}
	if !out.Managed {
		txt := domainverify.Instructions(vd.Domain(), vd.VerificationToken())
		out.Instructions = &txt
	}
	if t := vd.VerifiedAt(); t != nil {
		s := t.UTC().Format(rfc3339)
		out.VerifiedAt = &s
	}
	if t := vd.LastCheckedAt(); t != nil {
		s := t.UTC().Format(rfc3339)
		out.LastCheckedAt = &s
	}
	return out
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

func (h *EASMVerifiedDomainHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *EASMVerifiedDomainHandler) pathID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Verified domain").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *EASMVerifiedDomainHandler) writeErr(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, domainverify.ErrVerifyRateLimited):
		w.Header().Set("Retry-After", "3600")
		apierror.TooManyRequests("Too many verification checks; at most 10 per hour").WriteJSON(w)
	case errors.Is(err, domainverify.ErrTooManyDomains):
		apierror.BadRequest("Domain limit reached for this organization").WriteJSON(w)
	case errors.Is(err, verifieddomain.ErrBlockedDomain):
		apierror.BadRequest("A shared or public domain cannot be verified").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Enter a domain name such as example.com").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("This domain is already listed for your organization").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Verified domain").WriteJSON(w)
	default:
		h.logger.Error("easm verified domain: "+what, "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to " + what).WriteJSON(w)
	}
}

func (h *EASMVerifiedDomainHandler) auditEvent(r *http.Request, action auditdom.Action, vd *verifieddomain.VerifiedDomain, ok bool, msg string) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	var ev auditapp.AuditEvent
	id, name := "", ""
	if vd != nil {
		id, name = vd.ID().String(), vd.Domain()
	}
	if ok {
		ev = auditapp.NewSuccessEvent(action, auditdom.ResourceTypeVerifiedDomain, id)
	} else {
		ev = auditapp.NewFailureEvent(action, auditdom.ResourceTypeVerifiedDomain, id, errors.New(msg))
	}
	ev = ev.WithResourceName(name).WithMessage(msg).WithMetadata("purpose", string(verifieddomain.PurposeEASM))
	if vd != nil {
		ev = ev.WithMetadata("domain", vd.Domain()).WithMetadata("status", string(vd.Status()))
	}
	_ = h.audit.LogEvent(ctx, auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}, ev)
}

// List handles GET /api/v1/easm/verified-domains
// @Summary      List the organization's verified domains
// @Description  Domains the organization proved it controls with a DNS TXT record. Names under a verified domain are attributed with the strong rule fqdn_under_verified_root. Rows a platform administrator set up for SSO are listed read-only (managed=true).
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  EASMVerifiedDomainList
// @Failure      401  {object}  apierror.Error
// @Router       /easm/verified-domains [get]
func (h *EASMVerifiedDomainHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	rows, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list verified domains")
		return
	}
	out := EASMVerifiedDomainList{Data: make([]EASMVerifiedDomain, 0, len(rows))}
	for _, vd := range rows {
		out.Data = append(out.Data, toEASMVerifiedDomain(vd))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// Create handles POST /api/v1/easm/verified-domains
// @Summary      Add a domain to verify for EASM
// @Description  Returns the DNS TXT record to publish. The domain is verified for EASM only: it never admits SSO users (SSO domains are set up by a platform administrator). Public suffixes and shared consumer domains are refused. Audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMVerifiedDomainCreateRequest true "Domain"
// @Success      201  {object}  EASMVerifiedDomain
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /easm/verified-domains [post]
func (h *EASMVerifiedDomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req EASMVerifiedDomainCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	vd, _, err := h.svc.AddEASMDomain(r.Context(), tenantID, req.Domain)
	if err != nil {
		h.writeErr(w, err, "add the domain")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMVerifiedDomainAdded, vd, true, "Domain '"+vd.Domain()+"' added for EASM verification")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toEASMVerifiedDomain(vd))
}

// Verify handles POST /api/v1/easm/verified-domains/{id}/verify
// @Summary      Check a domain's TXT record now
// @Description  Looks up the TXT record and marks the domain verified when the exact token is present. At most 10 checks per organization per hour (429 with Retry-After). Audited.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Verified domain ID"
// @Success      200  {object}  EASMVerifiedDomain
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /easm/verified-domains/{id}/verify [post]
func (h *EASMVerifiedDomainHandler) Verify(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := h.pathID(w, r)
	if !ok {
		return
	}
	vd, err := h.svc.VerifyEASM(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, domainverify.ErrVerifyRateLimited) {
			h.auditEvent(r, auditdom.ActionEASMVerifiedDomainThrottle, nil, false, "Domain verification check refused: hourly limit")
		}
		h.writeErr(w, err, "verify the domain")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMVerifiedDomainChecked, vd, true, "Domain '"+vd.Domain()+"' checked: "+string(vd.Status()))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toEASMVerifiedDomain(vd))
}

// Delete handles DELETE /api/v1/easm/verified-domains/{id}
// @Summary      Remove a domain the organization verified for EASM
// @Description  Names under it stop auto-confirming. SSO domains cannot be removed here. Audited.
// @Tags         Attack Surface
// @Security     BearerAuth
// @Param        id path string true "Verified domain ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /easm/verified-domains/{id} [delete]
func (h *EASMVerifiedDomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := h.pathID(w, r)
	if !ok {
		return
	}
	vd, err := h.svc.DeleteEASM(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "remove the domain")
		return
	}
	h.auditEvent(r, auditdom.ActionEASMVerifiedDomainDeleted, vd, true, "Domain '"+vd.Domain()+"' removed from EASM verification")
	w.WriteHeader(http.StatusNoContent)
}
