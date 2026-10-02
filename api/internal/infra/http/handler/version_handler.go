package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/version"
)

// Version serves the running API build's identity (Help > About).
//
// Signed-in callers only: the version is not on the public /health, so an
// unauthenticated client cannot fingerprint the exact build. The admin console
// reads the same document at /admin/version with its console session.
//
// @Summary      API version
// @Description  The running API build: release tag (or "<tag>-dev" on a development build), short commit, build time and channel.
// @Tags         System
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  version.Info
// @Router       /version [get]
// @Router       /admin/version [get]
func Version(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(version.Get())
}
