package handler

// Install commands for a sensor that does not exist yet (the "Add sensor"
// panel, docs/architecture/sensor-pairing.md "Onboarding"): the same
// hardened templates as a sensor's own install, rendered without any key.
// The sensor makes its own key on first start and pairs (RFC-052); a code
// the console created first is passed as SENSOR_PAIRING_CODE.
//
// The code travels in the request body, never the URL (access logs). The
// route renders text only: it neither checks nor spends the code, and the
// approval still needs the fingerprint compare and step-up.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
)

// installSensorName is the name the onboarding snippets give the container,
// service and volume; the administrator names the sensor when approving it.
const installSensorName = "openctem-sensor"

// maxInstallTemplatesBody bounds the request body.
const maxInstallTemplatesBody = 4 << 10

// jobSigningRootRegexp is the shape of a job-signing root id the snippets
// may carry (it is shell- and YAML-quoted as well).
var jobSigningRootRegexp = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// SensorInstallTemplatesRequest is the body of POST /sensors/install-templates.
type SensorInstallTemplatesRequest struct {
	// PairingCode is a code from POST /sensor-pairings/expectations
	// (XXXX-XXXX). Empty: the snippets start the sensor without one and it
	// prints a code to enter.
	PairingCode string `json:"pairing_code"`
	// Product is a sensor product id (GET /sensors/stats products) whose
	// image to install; empty: the scanning sensor. Only products that use
	// the scanning sensor's snippets can pair from these commands.
	Product string `json:"product"`
}

// SetJobSigningRoot sets where the onboarding snippets read the job-signing
// root from (signerclient.Client.RootKeyID). Optional.
func (h *SensorHandler) SetJobSigningRoot(f func(ctx context.Context) string) { h.jobRoot = f }

// InstallTemplates handles POST /api/v1/sensors/install-templates.
//
// @Summary Install commands for a new sensor that pairs
// @Description Renders the docker run, Compose, Kubernetes and Linux (binary and systemd) install commands, and the sensor-local policy, for a sensor that does not exist yet: no API key; the sensor makes its own key on first start and pairs. With pairing_code (a code the console created) the commands pass it as SENSOR_PAIRING_CODE. The code is never checked or spent here.
// @Tags Sensors
// @Accept json
// @Produce json
// @Param body body SensorInstallTemplatesRequest true "Pairing code and product"
// @Success 200 {object} SensorConfigTemplatesResponse
// @Failure 400 {object} apierror.Error
// @Failure 503 {object} apierror.Error "Template service not configured"
// @Security BearerAuth
// @Router /sensors/install-templates [post]
func (h *SensorHandler) InstallTemplates(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		apierror.New(http.StatusServiceUnavailable, "TEMPLATE_SERVICE_DISABLED",
			"Sensor config template service is not configured").WriteJSON(w)
		return
	}
	var req SensorInstallTemplatesRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxInstallTemplatesBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	code := ""
	if req.PairingCode != "" {
		norm, err := pairing.NormalizeCode(req.PairingCode)
		if err != nil {
			apierror.BadRequest("pairing_code is not a pairing code").WriteJSON(w)
			return
		}
		code = pairing.FormatCode(norm)
	}
	s := &sensor.Sensor{Name: installSensorName, Type: sensor.SensorTypeWorker, ExecutionMode: sensor.ExecutionModeDaemon}
	product, ok := h.installProduct(req.Product, s)
	if !ok || (product.Install != "" && product.Install != sensorapp.InstallSensor) {
		apierror.BadRequest("product is not a sensor product that pairs from these commands").WriteJSON(w)
		return
	}
	baseURL := h.publicAPIURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	caPEM, caFingerprint, caErr := sensorapp.LoadCACertificate(h.caCertFile)
	if caErr != nil {
		h.logger.Warn("sensor CA certificate not usable; install snippets omit it",
			"path", h.caCertFile, "error", caErr)
	}
	root := ""
	if h.jobRoot != nil {
		if v := h.jobRoot(r.Context()); jobSigningRootRegexp.MatchString(v) {
			root = v
		}
	}
	rendered, err := h.templateService.Render(sensorapp.SensorTemplateData{
		Sensor: s, BaseURL: baseURL, Image: product.Image, CACert: caPEM, Install: product.Install,
		ReleaseIdentity: product.ReleaseIdentity, Auth: sensorapp.AuthPair, PairingCode: code, JobSigningRoot: root,
	})
	if err != nil {
		h.logger.Error("failed to render sensor install templates", "error", logger.SanitizeError(err))
		apierror.InternalServerError("rendering the install commands failed").WriteJSON(w)
		return
	}
	// A pairing install has no Helm variant (the chart's bundled sensor is
	// installed with the platform), no config file and no env file: the
	// panel shows the four ways a remote sensor runs, and the policy.
	resp := SensorConfigTemplatesResponse{
		Docker: rendered.Docker, Compose: rendered.Compose, Kubernetes: rendered.Kubernetes, CLI: rendered.CLI,
		Policy: rendered.Policy, Image: product.Image, Product: product.ID, APIURL: baseURL,
		CACertificate: caPEM, CAFingerprintSHA256: caFingerprint,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
