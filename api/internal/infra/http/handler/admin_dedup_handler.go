package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminDedupHandler handles asset dedup review endpoints.
type AdminDedupHandler struct {
	repo      *postgres.AssetDedupRepository
	logger    *logger.Logger
	dataScope DataScopeEnforcer
}

// SetDataScope wires the Layer 2 data scope: a scoped member sees and acts
// only on reviews whose assets are all in their scope (a merge deletes
// assets, so a review that touches one they cannot see is not theirs to
// approve). Returns h for chaining.
func (h *AdminDedupHandler) SetDataScope(e DataScopeEnforcer) *AdminDedupHandler {
	h.dataScope = e
	return h
}

// scope resolves the caller's data scope, writing the error response itself.
func (h *AdminDedupHandler) scope(w http.ResponseWriter, r *http.Request, tenantID string) (*shared.DataScope, bool) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return nil, false
	}
	scope, err := resolveDataScope(r.Context(), h.dataScope, tid)
	if err != nil {
		h.logger.Error("failed to resolve data scope", "error", err)
		apierror.InternalServerError("failed to resolve data scope").WriteJSON(w)
		return nil, false
	}
	return scope, true
}

// NewAdminDedupHandler creates a new AdminDedupHandler.
func NewAdminDedupHandler(repo *postgres.AssetDedupRepository, log *logger.Logger) *AdminDedupHandler {
	return &AdminDedupHandler{
		repo:   repo,
		logger: log.With("handler", "admin-dedup"),
	}
}

// ListPending handles GET /api/v1/admin/assets/dedup-review
func (h *AdminDedupHandler) ListPending(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	scope, ok := h.scope(w, r, tenantID)
	if !ok {
		return
	}
	reviews, err := h.repo.ListPendingReviews(r.Context(), tenantID, scope)
	if err != nil {
		h.logger.Error("failed to list dedup reviews", "error", err)
		apierror.InternalServerError("failed to list reviews").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  reviews,
		"total": len(reviews),
	})
}

// Approve handles POST /api/v1/admin/assets/dedup-review/{id}/approve
func (h *AdminDedupHandler) Approve(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	reviewID := r.PathValue("id")
	userID := middleware.GetUserID(r.Context())

	scope, ok := h.scope(w, r, tenantID)
	if !ok {
		return
	}
	if err := h.repo.ApproveAndMerge(r.Context(), tenantID, reviewID, userID, scope); err != nil {
		if writeDedupReviewError(w, err) {
			return
		}
		h.logger.Error("failed to approve merge", "review_id", reviewID, "error", err)
		apierror.InternalServerError("failed to execute merge").WriteJSON(w)
		return
	}

	h.logger.Info("dedup merge approved", "review_id", reviewID, "user_id", userID)

	// Findings moved by the merge were re-keyed for the kept asset inside the
	// merge transaction; duplicates became tombstones of one survivor
	// (postgres/asset_merge_findings.go). Nothing is left to do after commit.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "merged"})
}

// Reject handles POST /api/v1/admin/assets/dedup-review/{id}/reject
func (h *AdminDedupHandler) Reject(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	reviewID := r.PathValue("id")
	userID := middleware.GetUserID(r.Context())

	scope, ok := h.scope(w, r, tenantID)
	if !ok {
		return
	}
	if err := h.repo.RejectReview(r.Context(), tenantID, reviewID, userID, scope); err != nil {
		if writeDedupReviewError(w, err) {
			return
		}
		h.logger.Error("failed to reject review", "review_id", reviewID, "error", err)
		apierror.InternalServerError("failed to reject review").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "rejected"})
}

// writeDedupReviewError answers the caller-caused review errors — an unknown
// (or other tenant's) review, or one that is no longer pending — and reports
// whether it wrote a response.
func writeDedupReviewError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Dedup review").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("Dedup review is no longer pending").WriteJSON(w)
	default:
		return false
	}
	return true
}

// MergeLog handles GET /api/v1/admin/assets/merge-log
func (h *AdminDedupHandler) MergeLog(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	limit, ok := listLimit(w, r, 50, 100)
	if !ok {
		return
	}

	scope, ok := h.scope(w, r, tenantID)
	if !ok {
		return
	}
	log, err := h.repo.GetMergeLog(r.Context(), tenantID, limit, scope)
	if err != nil {
		h.logger.Error("failed to get merge log", "error", err)
		apierror.InternalServerError("failed to get merge log").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  log,
		"total": len(log),
	})
}
