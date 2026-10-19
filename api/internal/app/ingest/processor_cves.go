package ingest

import (
	"context"
	"fmt"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CVEProcessor materializes the global vulnerability catalog from CTIS
// findings.  It is intentionally decoupled from FindingProcessor: its only
// output is a cveID -> shared.ID map, which the FindingProcessor uses to
// stamp Finding.VulnerabilityID.
type CVEProcessor struct {
	repo   vulnerability.VulnerabilityRepository
	logger *logger.Logger
}

// NewCVEProcessor creates a processor bound to the given repository.
func NewCVEProcessor(repo vulnerability.VulnerabilityRepository, log *logger.Logger) *CVEProcessor {
	return &CVEProcessor{
		repo:   repo,
		logger: log.With("processor", "cves"),
	}
}

// ProcessBatch walks report.Findings, deduplicates by CVE ID, and makes sure
// the shared catalog has an entry for each (an identity stub when the feeds
// do not know the CVE yet). It returns a map from CVE ID to the catalog row's
// shared.ID.
//
// Errors are returned to the caller but the caller is expected to treat CVE
// upsert failures as non-fatal for ingestion (see ingest.Service wiring).
func (p *CVEProcessor) ProcessBatch(
	ctx context.Context,
	report *ctis.Report,
	output *Output,
) (map[string]shared.ID, error) {
	if report == nil || len(report.Findings) == 0 {
		return map[string]shared.ID{}, nil
	}

	// Only the CVE id leaves the report: the shared catalog takes its content
	// from public feeds (docs/architecture/global-catalog-trust.md), and the
	// report's title, description, CVSS and references stay on the tenant's
	// own findings.
	merged := make(map[string]*vulnerability.Vulnerability)

	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Vulnerability == nil {
			continue
		}
		cveID := vulnerability.NormalizeCVEID(f.Vulnerability.CVEID)
		if cveID == "" || !vulnerability.IsValidCVE(cveID) {
			continue
		}
		if _, ok := merged[cveID]; ok {
			continue
		}
		v, err := vulnerability.NewVulnerability(cveID, cveID, vulnerability.SeverityNone)
		if err != nil {
			p.logger.Debug("skip CVE (cannot construct)", "cve_id", cveID, "error", err)
			continue
		}
		merged[cveID] = v
	}

	if len(merged) == 0 {
		return map[string]shared.ID{}, nil
	}

	batch := make([]*vulnerability.Vulnerability, 0, len(merged))
	for _, v := range merged {
		batch = append(batch, v)
	}

	if err := p.repo.UpsertBatchByCVE(ctx, batch); err != nil {
		return map[string]shared.ID{}, fmt.Errorf("upsert CVE batch: %w", err)
	}

	result := make(map[string]shared.ID, len(batch))
	for _, v := range batch {
		if v.ID().IsZero() {
			p.logger.Warn("upsert returned zero id", "cve_id", logger.SanitizeValue(v.CVEID()))
			continue
		}
		result[v.CVEID()] = v.ID()
	}

	p.linkUnlinkedFindings(ctx, result)

	// Best-effort counter: without per-row insert/update distinction from
	// RETURNING (xmax=0), count all as updates. A future improvement can
	// plumb the insert bit through the repo.
	output.CVEsUpdated += len(result)

	return result, nil
}

// findingCatalogLinker links stored findings to catalog entries by CVE.
// Optional, like cveIDLookup, so repository fakes need not implement it.
type findingCatalogLinker interface {
	LinkUnlinkedFindings(ctx context.Context, cveIDs []string) (int64, error)
}

// linkUnlinkedFindings links findings stored before their CVE had a catalog
// entry (a protocol v2 report reads the catalog and never creates entries; a
// manual or pentest finding never looked one up) to the entries this batch
// found or created. Failures are logged: the link is repaired by the next
// batch that names the CVE.
func (p *CVEProcessor) linkUnlinkedFindings(ctx context.Context, ids map[string]shared.ID) {
	l, ok := p.repo.(findingCatalogLinker)
	if !ok || len(ids) == 0 {
		return
	}
	cves := make([]string, 0, len(ids))
	for cve := range ids {
		cves = append(cves, cve)
	}
	n, err := l.LinkUnlinkedFindings(ctx, cves)
	if err != nil {
		p.logger.Warn("failed to link stored findings to the CVE catalog", "error", err)
		return
	}
	if n > 0 {
		p.logger.Info("linked stored findings to the CVE catalog", "findings", n)
	}
}

// cveIDLookup is the read-only batch lookup the catalog repository offers.
// Kept optional so repository fakes without it fall back to GetByCVE.
type cveIDLookup interface {
	IDsByCVE(ctx context.Context, cveIDs []string) (map[string]shared.ID, error)
}

// LookupBatch links findings to catalog entries that already exist and
// writes nothing (protocol v2, RFC-026 §5.3: a sensor never writes the global
// vulnerability catalog). It returns CVE ID -> catalog id for the CVEs found.
func (p *CVEProcessor) LookupBatch(ctx context.Context, report *ctis.Report) (map[string]shared.ID, error) {
	if report == nil || len(report.Findings) == 0 {
		return map[string]shared.ID{}, nil
	}
	seen := map[string]bool{}
	ids := make([]string, 0)
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Vulnerability == nil {
			continue
		}
		cveID := vulnerability.NormalizeCVEID(f.Vulnerability.CVEID)
		if cveID == "" || seen[cveID] || !vulnerability.IsValidCVE(cveID) {
			continue
		}
		seen[cveID] = true
		ids = append(ids, cveID)
	}
	if len(ids) == 0 {
		return map[string]shared.ID{}, nil
	}
	if l, ok := p.repo.(cveIDLookup); ok {
		m, err := l.IDsByCVE(ctx, ids)
		if err != nil {
			return map[string]shared.ID{}, fmt.Errorf("look up CVE batch: %w", err)
		}
		p.linkUnlinkedFindings(ctx, m)
		return m, nil
	}
	out := make(map[string]shared.ID, len(ids))
	for _, id := range ids {
		v, err := p.repo.GetByCVE(ctx, id)
		if err != nil || v == nil {
			continue // not in the catalog: the finding keeps its reported text
		}
		out[id] = v.ID()
	}
	return out, nil
}

// truncateString limits s to n chars (rune-safe truncation, trailing "...").
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
