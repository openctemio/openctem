package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AdminDedupHandler handles asset dedup review endpoints.
type AdminDedupHandler struct {
	repo     *postgres.AssetDedupRepository
	findings *postgres.FindingRepository
	logger   *logger.Logger
}

// NewAdminDedupHandler creates a new AdminDedupHandler.
func NewAdminDedupHandler(repo *postgres.AssetDedupRepository, findings *postgres.FindingRepository, log *logger.Logger) *AdminDedupHandler {
	return &AdminDedupHandler{
		repo:     repo,
		findings: findings,
		logger:   log.With("handler", "admin-dedup"),
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

	// Capture the surviving asset before the merge (its ID doesn't change) so we
	// can recompute finding fingerprints on it afterwards.
	keepID, keepErr := h.repo.ReviewKeepAssetID(r.Context(), tenantID, reviewID)
	if keepErr != nil {
		h.logger.Warn("could not resolve keep asset id before merge", "review_id", reviewID, "error", keepErr)
	}

	if err := h.repo.ApproveAndMerge(r.Context(), tenantID, reviewID, userID); err != nil {
		h.logger.Error("failed to approve merge", "review_id", reviewID, "error", err)
		apierror.InternalServerError("failed to execute merge").WriteJSON(w)
		return
	}

	h.logger.Info("dedup merge approved", "review_id", reviewID, "user_id", userID)

	// The merge repoints findings to the keep asset with a raw UPDATE that leaves
	// a stale fingerprint (fingerprints embed the asset_id). Recompute them so
	// future scans dedupe correctly and any moved-in duplicates are collapsed.
	// Best-effort and idempotent: a failure here does not undo the committed
	// merge and can be safely re-run.
	h.recomputeFingerprintsAfterMerge(r.Context(), tenantID, keepID, reviewID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "merged"})
}

// recomputeFingerprintsAfterMerge recomputes finding fingerprints on the keep
// asset following a merge. Best-effort: logs on failure, never fails the request.
func (h *AdminDedupHandler) recomputeFingerprintsAfterMerge(ctx context.Context, tenantID, keepID, reviewID string) {
	if h.findings == nil || keepID == "" {
		return
	}
	tID, e1 := shared.IDFromString(tenantID)
	kID, e2 := shared.IDFromString(keepID)
	if e1 != nil || e2 != nil {
		h.logger.Warn("skipping fingerprint recompute: invalid id", "review_id", reviewID)
		return
	}
	updated, deduped, err := h.findings.RecomputeFingerprintsForAsset(ctx, tID, kID)
	if err != nil {
		h.logger.Error("merge committed but finding fingerprint recompute failed (safe to re-run)",
			"review_id", reviewID, "keep_asset_id", keepID, "error", err)
		return
	}
	if updated > 0 || deduped > 0 {
		h.logger.Info("recomputed finding fingerprints after merge",
			"keep_asset_id", keepID, "updated", updated, "deduped", deduped)
	}
}

// Reject handles POST /api/v1/admin/assets/dedup-review/{id}/reject
func (h *AdminDedupHandler) Reject(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	reviewID := r.PathValue("id")
	userID := middleware.GetUserID(r.Context())

	if err := h.repo.RejectReview(r.Context(), tenantID, reviewID, userID); err != nil {
		h.logger.Error("failed to reject review", "review_id", reviewID, "error", err)
		apierror.InternalServerError("failed to reject review").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "rejected"})
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
