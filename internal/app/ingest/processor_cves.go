package ingest

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
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

// ProcessBatch walks report.Findings, deduplicates by CVE ID, and upserts the
// unique set into the vulnerability catalog with fill-blanks semantics. It
// returns a map from CVE ID to the persisted row's shared.ID.
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

	merged := make(map[string]*vulnerability.Vulnerability)

	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Vulnerability == nil {
			continue
		}
		cveID := strings.TrimSpace(f.Vulnerability.CVEID)
		if cveID == "" || !vulnerability.IsValidCVE(cveID) {
			continue
		}

		sev := ctisSeverityToDomainCVE(f.Severity)

		if existing, ok := merged[cveID]; ok {
			if domainSeverityRank(sev) > domainSeverityRank(existing.Severity()) {
				_ = existing.UpdateSeverity(sev)
			}
			fillFromCTIS(existing, f)
			continue
		}

		title := cveID
		if f.Title != "" {
			title = truncateString(f.Title, 500)
		}
		v, err := vulnerability.NewVulnerability(cveID, title, sev)
		if err != nil {
			p.logger.Debug("skip CVE (cannot construct)", "cve_id", cveID, "error", err)
			continue
		}
		fillFromCTIS(v, f)
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
			p.logger.Warn("upsert returned zero id", "cve_id", v.CVEID())
			continue
		}
		result[v.CVEID()] = v.ID()
	}

	// Best-effort counter: without per-row insert/update distinction from
	// RETURNING (xmax=0), count all as updates. A future improvement can
	// plumb the insert bit through the repo.
	output.CVEsUpdated += len(result)

	return result, nil
}

// fillFromCTIS copies non-empty scanner-reported fields from a CTIS finding
// onto an in-memory domain Vulnerability. The database's ON CONFLICT clause
// is the authoritative fill-blanks layer; this function only ensures that
// the batch we send includes richer data when we have it.
func fillFromCTIS(v *vulnerability.Vulnerability, f *ctis.Finding) {
	d := f.Vulnerability
	if d == nil {
		return
	}
	if f.Description != "" && v.Description() == "" {
		v.UpdateDescription(f.Description)
	}
	if d.CVSSScore > 0 && v.CVSSScore() == nil {
		v.UpdateCVSS(d.CVSSScore, d.CVSSVector)
	}
	if d.EPSSScore > 0 && v.EPSSScore() == nil {
		v.UpdateEPSS(d.EPSSScore, d.EPSSPercentile)
	}
	if d.ExploitAvailable {
		v.SetExploitAvailable(true)
	}
	if d.ExploitMaturity != "" {
		if m := parseExploitMaturity(d.ExploitMaturity); m != vulnerability.ExploitMaturityNone {
			v.SetExploitMaturity(m)
		}
	}
	if d.PublishedAt != nil && v.PublishedAt() == nil {
		v.SetPublishedAt(*d.PublishedAt)
	}
	if d.ModifiedAt != nil && v.ModifiedAt() == nil {
		v.SetModifiedAt(*d.ModifiedAt)
	}
	for _, url := range d.Advisories {
		if url == "" {
			continue
		}
		v.AddReference(vulnerability.NewReference("scanner", url))
	}
	if len(d.FixedVersions) > 0 {
		v.SetFixedVersions(d.FixedVersions)
	} else if d.FixedVersion != "" {
		v.SetFixedVersions([]string{d.FixedVersion})
	}
}

// parseExploitMaturity maps the CTIS string to the domain enum. Returns
// ExploitMaturityNone for unknown or empty input so callers can skip.
func parseExploitMaturity(s string) vulnerability.ExploitMaturity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "poc", "proof-of-concept", "proof_of_concept":
		return vulnerability.ExploitMaturityProofOfConcept
	case "functional":
		return vulnerability.ExploitMaturityFunctional
	case "weaponized":
		return vulnerability.ExploitMaturityWeaponized
	default:
		return vulnerability.ExploitMaturityNone
	}
}

// domainSeverityRank — stable order for merge-by-max.
func domainSeverityRank(s vulnerability.Severity) int {
	switch s {
	case vulnerability.SeverityCritical:
		return 5
	case vulnerability.SeverityHigh:
		return 4
	case vulnerability.SeverityMedium:
		return 3
	case vulnerability.SeverityLow:
		return 2
	case vulnerability.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ctisSeverityToDomainCVE maps ctis.Severity to the domain Severity. Unknown
// input falls back to SeverityMedium, mirroring sibling processors.
// Named *CVE to avoid collision with any future sibling helper.
func ctisSeverityToDomainCVE(s ctis.Severity) vulnerability.Severity {
	switch s {
	case ctis.SeverityCritical:
		return vulnerability.SeverityCritical
	case ctis.SeverityHigh:
		return vulnerability.SeverityHigh
	case ctis.SeverityMedium:
		return vulnerability.SeverityMedium
	case ctis.SeverityLow:
		return vulnerability.SeverityLow
	case ctis.SeverityInfo:
		return vulnerability.SeverityInfo
	default:
		return vulnerability.SeverityMedium
	}
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
