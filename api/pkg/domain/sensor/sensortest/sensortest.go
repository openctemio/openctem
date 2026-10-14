// Package sensortest is test support for sensors: the manifest a released
// sensor reports for its built-in tools (their tool contracts, from
// stagetest.Builtins), so tests of tier, grant and dispatch rules see the
// contracts a real sensor sends. Production code must never import it.
package sensortest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"
)

// ReleasedContract is the contract a released sensor reports for a
// built-in tool, nil for any other tool. It declares no produces.
func ReleasedContract(tool string) *sensor.ToolContract {
	tool = strings.ToLower(strings.TrimSpace(sensor.CanonicalTool(tool)))
	for _, f := range stagetest.Builtins() {
		if f.Name != tool {
			continue
		}
		tier := 0
		refs := make([]string, 0, len(f.Implements))
		for _, k := range f.Implements {
			ref := fmt.Sprintf("%s@1", k)
			if cp, ok := capability.Lookup(ref); ok {
				tier = max(tier, cp.TierFloor)
				refs = append(refs, ref)
			}
		}
		sum := sha256.Sum256([]byte("released:" + tool))
		return &sensor.ToolContract{APIVersion: sensor.ToolContractAPIVersion, Digest: "sha256:" + hex.EncodeToString(sum[:]),
			Version: "1.0.0", Class: "target-scan", Tier: fmt.Sprintf("T%d", tier), Origin: sensor.ToolOriginBuiltin,
			Implements: refs, Batch: f.Batch, Produces: []string{}}
	}
	return nil
}

// ReleasedManifest is the manifest of a released sensor that has the tools
// installed (a built-in tool with its contract) and reports caps.
func ReleasedManifest(tools, caps []string) sensor.Manifest {
	m := sensor.Manifest{Schema: 1, Capabilities: caps, Tools: make([]sensor.ManifestTool, 0, len(tools))}
	for _, t := range tools {
		m.Tools = append(m.Tools, sensor.ManifestTool{Name: t, Installed: true, Contract: ReleasedContract(t)})
	}
	return m
}

// ManifestSaver stores a sensor's manifest (sensor.ManifestStore).
type ManifestSaver interface {
	SaveManifest(ctx context.Context, v sensor.ManifestVersion, report *sensor.CapabilityReport, at time.Time) (bool, error)
}

// SaveReleased stores ReleasedManifest as the sensor's current manifest.
func SaveReleased(ctx context.Context, store ManifestSaver, tenantID *shared.ID, sensorID shared.ID, tools, caps []string) error {
	sorted := append([]string(nil), tools...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(sensorID.String() + strings.Join(sorted, ",")))
	_, err := store.SaveManifest(ctx, sensor.ManifestVersion{SensorID: sensorID, TenantID: tenantID,
		Digest: "sha256:" + hex.EncodeToString(sum[:]), Source: sensor.ManifestSourceSensor,
		Manifest: ReleasedManifest(tools, caps)}, nil, time.Now())
	return err
}
