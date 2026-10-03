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
	repo   *postgres.AssetDedupRepository
	logger *logger.Logger
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

	reviews, err := h.repo.ListPendingReviews(r.Context(), tenantID)
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

	if err := h.repo.ApproveAndMerge(r.Context(), tenantID, reviewID, userID); err != nil {
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

	if err := h.repo.RejectReview(r.Context(), tenantID, reviewID, userID); err != nil {
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
	limit := parseQueryInt(r.URL.Query().Get("limit"), 50)

	log, err := h.repo.GetMergeLog(r.Context(), tenantID, limit)
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
