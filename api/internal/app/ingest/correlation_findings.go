package ingest

// Cross-rule correlation of DAST findings at ingest (research/134 section
// 12; pkg/domain/correlation). After a report's findings are stored, each
// DAST finding's injection point is recorded, and the correlation of the
// touched assets is re-derived: two detections of one issue (same asset,
// CWE and injection point; generic + CVE, or the same CVE) become a primary
// and a duplicate; a duplicate whose primary was not seen, or left the open
// statuses, is released and treated as a new finding. Correlation may
// reduce noise, never coverage: when unsure it only suggests.

import (
	"context"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/correlation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// InjectionPointRow is one DAST finding's injection point, keyed by its
// stored fingerprint.
type InjectionPointRow struct {
	Fingerprint string
	AssetID     shared.ID
	Point       correlation.InjectionPoint
	MatchedURL  string
}

// CorrelationStore stores injection points and re-derives correlations
// (the postgres finding correlation repository).
type CorrelationStore interface {
	UpsertInjectionPoints(ctx context.Context, tenantID shared.ID, rows []InjectionPointRow) error
	// Correlate re-derives the correlations of the assets and returns the
	// ids of findings released from a correlation (to be treated as new).
	Correlate(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, sighted []string, opt correlation.Options) ([]shared.ID, error)
	// Options is the tenant's correlation switches.
	Options(ctx context.Context, tenantID shared.ID) (correlation.Options, error)
}

// ReleasedLoader loads the released findings for the created callback.
type ReleasedLoader interface {
	GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error)
}

// SetCorrelationStore wires cross-rule correlation (nil: off).
func (p *FindingProcessor) SetCorrelationStore(s CorrelationStore) { p.correlations = s }

// dastPoint is the injection point of a DAST result, with the payloads its
// own evidence shows (a redirect target) removed.
func dastPoint(f *ctis.Finding) (correlation.InjectionPoint, string, bool) {
	if identityKind(f) != vulnerability.IdentityKindDAST {
		return correlation.InjectionPoint{}, "", false
	}
	matched := locationPath(f)
	var params []string
	if f.Web != nil && f.Web.Parameter != nil && strings.TrimSpace(f.Web.Parameter.Name) != "" {
		params = append(params, string(f.Web.Parameter.Location)+":"+strings.TrimSpace(f.Web.Parameter.Name))
	}
	for _, key := range []string{"parameter", "param"} {
		if v, ok := f.Properties[key].(string); ok && strings.TrimSpace(v) != "" {
			params = append(params, "unknown:"+strings.TrimSpace(v))
		}
	}
	p, ok := correlation.Point(correlation.PointInput{MatchedURL: matched, Method: dastMethod(f), Params: params,
		Payloads: evidencePayloads(f.EvidenceItems)})
	return p, matched, ok
}

// evidencePayloads are the redirect targets the detection's own responses
// name (Location headers): the values a template inserted and the target
// echoed.
func evidencePayloads(items []ctis.EvidenceItem) []string {
	var out []string
	for _, it := range items {
		if it.HTTP == nil || it.HTTP.Response == nil {
			continue
		}
		for _, h := range it.HTTP.Response.Headers {
			if strings.EqualFold(h.Name, "Location") && strings.TrimSpace(h.Value) != "" {
				out = append(out, h.Value)
			}
		}
	}
	return out
}

// correlateFindings records the batch's DAST injection points and re-derives
// the correlations of the assets they are on. Best-effort: a failure is
// logged and leaves findings as they are.
// correlationItem is one stored finding of the batch.
type correlationItem struct {
	fingerprint string
	assetID     shared.ID
	finding     *ctis.Finding
}

func (p *FindingProcessor) correlateFindings(ctx context.Context, tenantID shared.ID, findings []correlationItem, sighted []string) {
	if p.correlations == nil || len(findings) == 0 {
		return
	}
	rows := make([]InjectionPointRow, 0)
	assets := map[shared.ID]bool{}
	for i := range findings {
		pt, matched, ok := dastPoint(findings[i].finding)
		if !ok {
			continue
		}
		rows = append(rows, InjectionPointRow{Fingerprint: findings[i].fingerprint, AssetID: findings[i].assetID, Point: pt, MatchedURL: matched})
		assets[findings[i].assetID] = true
	}
	if len(rows) == 0 {
		return
	}
	if err := p.correlations.UpsertInjectionPoints(ctx, tenantID, rows); err != nil {
		p.logger.Warn("injection points not stored", "error", err)
		return
	}
	opt, err := p.correlations.Options(ctx, tenantID)
	if err != nil {
		p.logger.Warn("correlation settings not read", "error", err)
		return
	}
	opt.SightingAware = true
	ids := make([]shared.ID, 0, len(assets))
	for a := range assets {
		ids = append(ids, a)
	}
	released, err := p.correlations.Correlate(ctx, tenantID, ids, sighted, opt)
	if err != nil {
		p.logger.Warn("findings not correlated", "error", err)
		return
	}
	// A released duplicate is a finding of its own again: it takes the
	// new-finding path (notifications, tickets).
	if len(released) > 0 && p.findingCreatedCallback != nil {
		if loader, ok := p.repo.(ReleasedLoader); ok {
			if fs, err := loader.GetByIDs(ctx, tenantID, released); err == nil && len(fs) > 0 {
				p.findingCreatedCallback(ctx, tenantID, fs)
			}
		}
	}
}
