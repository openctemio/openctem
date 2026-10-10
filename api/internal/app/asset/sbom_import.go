package asset

// SBOM upload into the software components inventory. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/openctemio/openctem/api/internal/app/licensepolicy"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	componentdom "github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// assetTenantChecker resolves an asset of the tenant (ErrNotFound otherwise).
type assetTenantChecker interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*assetdom.Asset, error)
}

// MaxSBOMBytes is the largest SBOM accepted.
const MaxSBOMBytes = 50 << 20

// SBOMLicenseEvaluator re-evaluates the license policy on an asset's
// packages (internal/app/licensepolicy).
type SBOMLicenseEvaluator interface {
	EvaluateAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (licensepolicy.Result, error)
}

// SetLicenseEvaluator wires the license policy evaluation after an import.
func (s *SBOMImportService) SetLicenseEvaluator(e SBOMLicenseEvaluator) { s.license = e }

// SBOMStore writes packages and reads the current inventory for the diff.
type SBOMStore interface {
	software.PackageWriter
	ListSBOMEntries(ctx context.Context, tenantID shared.ID, assetID *shared.ID, scope *shared.DataScope, limit int) ([]componentdom.SBOMEntry, error)
}

// SBOMImportService imports CycloneDX and SPDX documents.
type SBOMImportService struct {
	license      SBOMLicenseEvaluator
	store        SBOMStore
	assetChecker assetTenantChecker
	dataScope    *datascope.Enforcer
	logger       *logger.Logger
}

// SetDataScope limits imports to assets in the caller's data scope.
func (s *SBOMImportService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// NewSBOMImportService creates an SBOMImportService.
func NewSBOMImportService(store SBOMStore, assetChecker assetTenantChecker, log *logger.Logger) *SBOMImportService {
	return &SBOMImportService{store: store, assetChecker: assetChecker, logger: log.With("service", "sbom-import")}
}

// SBOMDiff compares the document with the asset's current inventory.
type SBOMDiff struct {
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

// SBOMImportResult is the preview, or the outcome, of an import.
type SBOMImportResult struct {
	DryRun             bool                         `json:"dry_run"`
	Format             string                       `json:"format"`
	SpecVersion        string                       `json:"spec_version"`
	ComponentsTotal    int                          `json:"components_total"`
	ComponentsImported int                          `json:"components_imported"`
	ComponentsSkipped  int                          `json:"components_skipped"`
	Direct             int                          `json:"direct"`
	Transitive         int                          `json:"transitive"`
	Edges              int                          `json:"edges"`
	LicensesFound      int                          `json:"licenses_found"`
	Ecosystems         []componentdom.FacetValue    `json:"ecosystems"`
	Issues             []SBOMIssue                  `json:"issues"`
	Diff               *SBOMDiff                    `json:"diff,omitempty"`
	Written            *software.PackageWriteResult `json:"written,omitempty"`
}

// ImportSBOM parses the document and, unless dryRun, replaces the asset's
// packages at the locations the document names. The asset must be the
// tenant's and in the caller's scope (404 otherwise).
func (s *SBOMImportService) ImportSBOM(ctx context.Context, tenantID, assetID string, reader io.Reader, dryRun bool) (*SBOMImportResult, error) {
	tid, err := parseID(tenantID, "tenant")
	if err != nil {
		return nil, err
	}
	aid, err := parseID(assetID, "asset")
	if err != nil {
		return nil, err
	}
	if s.assetChecker != nil {
		if _, err := s.assetChecker.GetByID(ctx, tid, aid); err != nil {
			return nil, err
		}
	}
	if s.dataScope != nil {
		if err := s.dataScope.AssertAsset(ctx, tid, aid); err != nil {
			return nil, err
		}
	}
	data, err := httpsec.ReadLimited(reader, MaxSBOMBytes)
	if errors.Is(err, httpsec.ErrBodyTooLarge) {
		return nil, fmt.Errorf("%w: SBOM exceeds 50 MB", shared.ErrValidation)
	}
	if err != nil {
		return nil, fmt.Errorf("read SBOM: %w", err)
	}
	parsed, err := ParseSBOM(data)
	if err != nil {
		return nil, err
	}
	res := summarizeSBOM(parsed)
	res.DryRun = dryRun

	current, err := s.store.ListSBOMEntries(ctx, tid, &aid, nil, software.MaxSnapshotPackages+1)
	if err != nil {
		return nil, err
	}
	res.Diff = diffSBOM(parsed.Nodes, current)
	if dryRun {
		return res, nil
	}
	written, err := s.store.WritePackages(ctx, tid, software.PackageSnapshot{
		AssetID: aid, Channel: software.ChannelSBOMUpload, Packages: parsed.Nodes, Replace: true,
	})
	if err != nil {
		return nil, err
	}
	res.Written = &written
	if s.license != nil {
		if _, err := s.license.EvaluateAssets(ctx, tid, []shared.ID{aid}); err != nil {
			s.logger.Warn("license policy evaluation failed", "tenant_id", tid.String(), "error", err)
		}
	}
	res.ComponentsImported = written.Links
	s.logger.Info("sbom imported", "tenant_id", tid.String(), "asset_id", aid.String(),
		"format", parsed.Format, "packages", len(parsed.Nodes), "links", written.Links, "removed", written.Removed)
	return res, nil
}

func summarizeSBOM(p *ParsedSBOM) *SBOMImportResult {
	res := &SBOMImportResult{
		Format: p.Format, SpecVersion: p.SpecVersion, ComponentsTotal: p.Total,
		ComponentsImported: len(p.Nodes), ComponentsSkipped: p.Skipped, Edges: p.Edges,
		Issues: p.Issues, Ecosystems: []componentdom.FacetValue{},
	}
	if res.Issues == nil {
		res.Issues = []SBOMIssue{}
	}
	licenses := map[string]bool{}
	ecos := map[string]int{}
	for _, n := range p.Nodes {
		switch n.Relationship {
		case software.RelationshipDirect:
			res.Direct++
		case software.RelationshipTransitive:
			res.Transitive++
		}
		for _, l := range n.Licenses {
			licenses[l] = true
		}
		ecos[software.EcosystemForType(n.PURL.Type)]++
	}
	res.LicensesFound = len(licenses)
	for e, c := range ecos {
		res.Ecosystems = append(res.Ecosystems, componentdom.FacetValue{Value: e, Count: c})
	}
	sort.Slice(res.Ecosystems, func(i, j int) bool {
		if res.Ecosystems[i].Count != res.Ecosystems[j].Count {
			return res.Ecosystems[i].Count > res.Ecosystems[j].Count
		}
		return res.Ecosystems[i].Value < res.Ecosystems[j].Value
	})
	return res
}

func diffSBOM(nodes []software.PackageNode, current []componentdom.SBOMEntry) *SBOMDiff {
	incoming := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		incoming[n.PURL.String()] = true
	}
	d := &SBOMDiff{}
	existing := make(map[string]bool, len(current))
	for _, e := range current {
		existing[e.PURL] = true
		if incoming[e.PURL] {
			d.Unchanged++
		} else {
			d.Removed++
		}
	}
	for k := range incoming {
		if !existing[k] {
			d.Added++
		}
	}
	return d
}
