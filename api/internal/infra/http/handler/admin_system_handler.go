package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/systemstatus"
)

// AdminSystemHandler serves Console > System (RFC-114): service health, free
// space, backup age, certificate expiry and version. Any admin role reads it;
// it is read-only, aggregate-only (no tenant data, no secrets, no paths).
type AdminSystemHandler struct {
	collect func(ctx context.Context) systemstatus.Snapshot
}

// NewAdminSystemHandler creates the handler over a snapshot source.
func NewAdminSystemHandler(collect func(ctx context.Context) systemstatus.Snapshot) *AdminSystemHandler {
	return &AdminSystemHandler{collect: collect}
}

// Get handles GET /api/v1/admin/system.
//
// @Summary      System status (platform admin)
// @Description  Health of api, postgres, redis, web, gateway and connected sensors; free space of the configured data volumes and the database size; last successful backup; sensor CA and TLS certificate expiry; running version and the version-check result. Any admin role; read-only; no tenant content, secrets or paths.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  systemstatus.Snapshot
// @Router       /admin/system [get]
func (h *AdminSystemHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, h.collect(ctx))
}
