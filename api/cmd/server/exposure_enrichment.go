package main

import (
	"context"

	"github.com/openctemio/api/internal/app/exposure"
	"github.com/openctemio/api/internal/infra/postgres"
)

// exposureEPSSShim adapts the shared EPSS adapter (which speaks the finding
// package's EPSSData) to the exposure enricher's EPSSData shape, so exposure
// enrichment reuses the exact same EPSS threat-intel source as finding
// prioritization without coupling the exposure package to the finding package.
type exposureEPSSShim struct{ inner *postgres.EPSSAdapter }

func (s exposureEPSSShim) GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]exposure.EPSSData, error) {
	m, err := s.inner.GetByCVEIDs(ctx, cveIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string]exposure.EPSSData, len(m))
	for k, v := range m {
		out[k] = exposure.EPSSData{Score: v.Score, Percentile: v.Percentile}
	}
	return out, nil
}

// exposureKEVShim adapts the shared KEV adapter to the exposure enricher's
// KEVData shape (same catalog, same source as finding prioritization).
type exposureKEVShim struct{ inner *postgres.KEVAdapter }

func (s exposureKEVShim) GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]exposure.KEVData, error) {
	m, err := s.inner.GetByCVEIDs(ctx, cveIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string]exposure.KEVData, len(m))
	for k, v := range m {
		out[k] = exposure.KEVData{DueDate: v.DueDate}
	}
	return out, nil
}
