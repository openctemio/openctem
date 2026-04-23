package template

import (
	"context"

	"github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/pkg/domain/templatesource"
)

// Scan adapter — moved from internal/app/adapters.go so the template
// package can own its own outward conversion. Placed here (not in
// `app`) because `template` already imports `app` for
// SecretStoreService and Prometheus metrics; re-adding the adapter
// there would create a cycle.

type scanSyncerAdapter struct {
	syncer *Syncer
}

// NewScanAdapter wires a template.Syncer into the scan package's
// narrow TemplateSyncer interface. Used by cmd/server/services.go.
func NewScanAdapter(syncer *Syncer) scan.TemplateSyncer {
	return &scanSyncerAdapter{syncer: syncer}
}

// SyncSource implements scan.TemplateSyncer.
func (a *scanSyncerAdapter) SyncSource(ctx context.Context, source *templatesource.TemplateSource) (*scan.TemplateSyncResult, error) {
	result, err := a.syncer.SyncSource(ctx, source)
	if err != nil {
		return nil, err
	}
	return &scan.TemplateSyncResult{
		Success:        result.Success,
		TemplatesFound: result.TemplatesFound,
		TemplatesAdded: result.TemplatesAdded,
	}, nil
}
