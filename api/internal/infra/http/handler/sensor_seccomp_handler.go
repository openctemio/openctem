package handler

// GET /api/v1/sensors/install/seccomp.json: the sensor's seccomp profile,
// which every install command downloads and checks by its SHA-256
// (docs/architecture/sensors.md, "Hardened installs"). Public: the file is
// part of the open-source sensor release, the same for every organization,
// and holds no tenant data; the route is rate limited per IP.

import (
	"net/http"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
)

// ServeSensorSeccompProfile handles GET /api/v1/sensors/install/seccomp.json
// @Summary      The sensor's seccomp profile
// @Description  The seccomp profile the sensor container runs with so each tool task can run network-confined: the container runtime's default profile plus clone/unshare of new namespaces. Public and the same for every organization. The X-Content-SHA256 header carries the digest the install commands check.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  object
// @Router       /sensors/install/seccomp.json [get]
func ServeSensorSeccompProfile(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Disposition", `attachment; filename="openctem-sensor-seccomp.json"`)
	h.Set("X-Content-SHA256", sensorapp.SeccompProfileSHA256)
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(sensorapp.SeccompProfile())
}
