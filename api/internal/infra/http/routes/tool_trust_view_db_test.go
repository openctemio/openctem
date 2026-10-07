package routes

// The tool view's trust and platform-assigned tier come from the tenant's
// own sensors' manifests (RFC-055 §5): an operator-installed copy makes a
// tool unverified and T2, and another tenant's manifests never count.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// saveContractManifest stores a manifest for the sensor whose naabu tool
// reports a contract of origin.
func (h *authzPolicyHarness) saveContractManifest(tenantID, sensorID, origin string) {
	h.t.Helper()
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		h.t.Fatal(err)
	}
	sid, err := shared.IDFromString(sensorID)
	if err != nil {
		h.t.Fatal(err)
	}
	m := sensor.Manifest{Tools: []sensor.ManifestTool{{Name: "naabu", Installed: true, Contract: &sensor.ToolContract{
		APIVersion: sensor.ToolContractAPIVersion, Tier: "T1", Class: "target-scan", Origin: origin,
		Implements: []string{"scan.ports@1"}}}}}
	sum := sha256.Sum256([]byte(origin + sensorID))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := postgres.NewSensorRepository(&postgres.DB{DB: h.db}).SaveManifest(context.Background(),
		sensor.ManifestVersion{SensorID: sid, TenantID: &tid, Digest: digest, Source: sensor.ManifestSourceSensor, Manifest: m}, nil, time.Now()); err != nil {
		h.t.Fatal(err)
	}
	h.exec(`UPDATE sensors SET manifest_digest = $2 WHERE id = $1`, sensorID, digest)
}

func TestToolAvailability_TrustAndTier_DB(t *testing.T) {
	h := newToolAvailabilityHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, outsider := h.member(tid, "admin"), h.member(other, "admin")
	naabu := `[{"name":"naabu","version":"2.3.0","installed":true}]`

	ours := h.availabilitySensor(tid, "edge-ours", 5*time.Second, "online", naabu, []string{"naabu"})
	h.saveContractManifest(tid, ours, sensor.ToolOriginAdapter)
	theirs := h.availabilitySensor(other, "edge-theirs", 5*time.Second, "online", naabu, []string{"naabu"})
	h.saveContractManifest(other, theirs, sensor.ToolOriginBuiltin)

	const path = "/api/v1/tools?include=availability&per_page=50"
	got, _ := availabilityByName(t, h.expect(admin, http.MethodGet, path, "", http.StatusOK))
	// SECURITY: our operator-installed naabu is unverified and T2.
	if n := got["naabu"]; n.Trust != sensor.ToolTrustUnverified || n.Tier != "T2" ||
		len(n.Sensors) != 1 || n.Sensors[0].Trust != sensor.ToolTrustUnverified || n.Sensors[0].Tier != "T2" {
		t.Fatalf("our naabu = %+v", n)
	}
	// SECURITY: the other tenant sees its own built-in copy, never ours.
	got, _ = availabilityByName(t, h.expect(outsider, http.MethodGet, path, "", http.StatusOK))
	if n := got["naabu"]; n.Trust != sensor.ToolTrustBuiltin || n.Tier != "T1" {
		t.Fatalf("their naabu = %+v", n)
	}
}
