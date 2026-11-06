package handler

// GET /api/v1/sensors/platform-ca: the platform's private CA bundle
// (PLATFORM_CA_CERT_FILE), docs/how-to/sensors-behind-a-private-ca.md.
//
// Public and tenant-agnostic: the bundle is the public certificates of the
// CA that signs the platform's TLS certificate, the same for every
// organization. A sensor that does not trust the platform's chain fetches it
// with chain verification off and trusts only a certificate that matches the
// SHA-256 pin from the console's install command (SENSOR_CA_SHA256), so a
// path attacker who answers this request gains nothing without the pin. The
// answer holds CERTIFICATE blocks only: a CA file with a private key is
// refused at load (sensorapp.ParsePlatformCA) and the route answers 404.
// Rate limited per IP like the other public install files.

import (
	"errors"
	"io/fs"
	"net/http"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PlatformCAHandler serves the platform's CA bundle.
type PlatformCAHandler struct {
	src    *sensorapp.PlatformCASource
	logger *logger.Logger
}

// NewPlatformCAHandler returns the handler; a nil or unset source answers 404.
func NewPlatformCAHandler(src *sensorapp.PlatformCASource, log *logger.Logger) *PlatformCAHandler {
	return &PlatformCAHandler{src: src, logger: log}
}

// Serve handles GET /api/v1/sensors/platform-ca
// @Summary      The platform's private CA bundle
// @Description  The PEM bundle of the CA certificate(s) that sign the platform's TLS certificate, when it uses a private CA (PLATFORM_CA_CERT_FILE). Public and the same for every organization; certificates only, never a key. A sensor started with SENSOR_CA_SHA256 fetches it when it does not trust the platform's chain and trusts only a certificate that matches the pin. 404 when no private CA is configured.
// @Tags         Sensors
// @Produce      application/x-pem-file
// @Success      200  {string}  string  "PEM bundle"
// @Failure      404  {object}  apierror.Error  "No private CA configured"
// @Failure      429  {object}  apierror.Error
// @Router       /sensors/platform-ca [get]
func (h *PlatformCAHandler) Serve(w http.ResponseWriter, _ *http.Request) {
	ca, err := h.src.Get()
	if err != nil && h.logger != nil && !errors.Is(err, fs.ErrNotExist) {
		h.logger.Warn("platform CA certificate not usable; GET platform-ca answers 404",
			"path", logger.SanitizeValue(h.src.Path()), "error", logger.SanitizeError(err))
	}
	if ca == nil || ca.PEM == "" {
		apierror.NotFound("platform CA").WriteJSON(w)
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "application/x-pem-file")
	hd.Set("Content-Disposition", `attachment; filename="openctem-platform-ca.pem"`)
	hd.Set("Cache-Control", "public, max-age=300")
	hd.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(ca.PEM))
}
