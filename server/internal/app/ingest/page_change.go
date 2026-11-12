package ingest

// A web service whose page changed is captured again (docs/rfcs/RFC-081-web-evidence-screenshots.md):
// when a probe changes the title, status code, redirect target or favicon
// hash a stored web service already had, the service's screenshot pair is
// handed to the coverage ledger as due now (at most once a day per asset,
// decided by the ledger). Best effort: it never fails an ingest.

import (
	"context"
	"encoding/json"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// PageChangeNotifier takes the web services (of one tenant) whose page
// changed.
type PageChangeNotifier interface {
	PagesChanged(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error
}

// SetPageChangeNotifier enables re-capture on change (nil = cadence only).
func (p *AssetProcessor) SetPageChangeNotifier(n PageChangeNotifier) { p.pageChange = n }

// pageWatchedKeys are the stored http_service properties whose change means
// the page looks different.
const (
	propPageTitle    = "title"
	propPageStatus   = "status_code"
	propPageRedirect = "redirect_url"
	propFaviconMMH3  = "favicon_mmh3"
)

var pageWatchedKeys = []string{propPageTitle, propPageStatus, propPageRedirect, propFaviconMMH3}

// pageSignature is the watched values of a web service ("" for any other
// asset, and for a service with none of them yet).
func pageSignature(a *asset.Asset) string {
	if a.Type() != asset.AssetTypeService || a.SubType() != "http" {
		return ""
	}
	props := a.Properties()
	vals := make(map[string]any, len(pageWatchedKeys))
	for _, k := range pageWatchedKeys {
		if v, ok := props[k]; ok && v != nil && v != "" {
			vals[k] = v
		}
	}
	if len(vals) == 0 {
		return ""
	}
	b, err := json.Marshal(vals) // map keys are sorted: stable
	if err != nil {
		return ""
	}
	return string(b)
}

// notifyPagesChanged hands the changed services to the notifier.
func (p *AssetProcessor) notifyPagesChanged(ctx context.Context, tenantID shared.ID, ids []shared.ID) {
	if p.pageChange == nil || len(ids) == 0 {
		return
	}
	if err := p.pageChange.PagesChanged(ctx, tenantID, ids); err != nil {
		p.logger.Warn("web pages changed: recapture not scheduled", "tenant_id", tenantID.String(), "error", err)
	}
}
