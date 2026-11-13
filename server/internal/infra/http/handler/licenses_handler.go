package handler

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/notices"
)

// LicensesHandler serves the API's third-party notices (About > Open-source
// licenses), read once from a fixed file in the image
// (docs/architecture/third-party-notices.md).
//
// Signed-in callers only, like /version: the exact dependency versions are
// not given to anonymous clients. No tenant data. A build without the file (a
// development build) answers an empty list with generated=false, never an
// error.
type LicensesHandler struct {
	path   string
	logger *logger.Logger

	once sync.Once
	body []byte
}

// NewLicensesHandler serves the notices file at path (notices.DefaultPath in
// the server). The path is chosen by the binary, never by a request.
func NewLicensesHandler(path string, log *logger.Logger) *LicensesHandler {
	return &LicensesHandler{path: path, logger: log}
}

func (h *LicensesHandler) load() []byte {
	h.once.Do(func() {
		doc, err := notices.Load(h.path, "api")
		if err != nil && h.logger != nil {
			h.logger.Warn("third-party notices not served", "error", err)
		}
		body, err := json.Marshal(doc)
		if err != nil {
			body = []byte(`{"generated":false,"component":"api","packages":[]}`)
		}
		h.body = body
	})
	return h.body
}

// List serves the notices document.
//
// @Summary      Open-source licenses
// @Description  The third-party components linked into the API build, with their versions, license identifiers and license texts. generated is false (and the list empty) for a build without a notices file.
// @Tags         System
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  notices.Document
// @Router       /licenses [get]
// @Router       /admin/licenses [get]
func (h *LicensesHandler) List(w http.ResponseWriter, _ *http.Request) {
	body := h.load()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
