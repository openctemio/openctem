package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	toolapp "github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// readinessSources builds the sources of workflow readiness from the same
// services the dispatch gate and the platform scanning view read.
func readinessSources(tools *toolapp.Service, sensors *postgres.SensorRepository) (scanapp.ToolStatuses, scanapp.PlatformOffer) {
	statuses := func(ctx context.Context, tenantID shared.ID) (map[string]sensordom.ToolStatus, error) {
		res, err := tools.ToolAvailability(ctx, tenantID.String(), "")
		if err != nil || res == nil {
			return nil, err
		}
		out := make(map[string]sensordom.ToolStatus, len(res.Tools))
		for _, t := range res.Tools {
			if t.InCatalog {
				out[t.Name] = t.Status
			}
		}
		return out, nil
	}
	platform := sensorapp.NewPlatformScanningService(sensors, app.PlatformSensorsAllowed)
	offer := func(ctx context.Context, tenantID shared.ID) (bool, bool, []string, error) {
		pf, err := platform.Get(ctx, tenantID)
		if err != nil || pf == nil {
			return false, false, nil, err
		}
		return pf.Offered, pf.Status != "" && pf.Status != sensorapp.PlatformScanningUnavailable, pf.Tools, nil
	}
	return statuses, offer
}
