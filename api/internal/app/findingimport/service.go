// Package findingimport imports the files other security tools export
// (Nessus, Qualys, CycloneDX, SPDX, OSV, CSAF, OpenVEX, DefectDojo, ...)
// uploaded by a person: it converts each file with the ctis importer
// package, ingests the report with the uploader's rights, and applies the
// statements of VEX documents to the tenant's matching findings.
//
// Design: docs/architecture/finding-import.md.
package findingimport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Ingester ingests a CTIS report (ingest.Service).
type Ingester interface {
	Ingest(ctx context.Context, agt *sensor.Sensor, input ingest.Input) (*ingest.Output, error)
}

// VEXRepository matches and updates the tenant's findings for a VEX
// document (postgres.FindingRepository).
type VEXRepository interface {
	MatchVEXDocument(ctx context.Context, tenantID shared.ID, q vulnerability.VEXDocumentQuery, limit int) ([]vulnerability.VEXCandidate, error)
	ApplyVEXDocument(ctx context.Context, tenantID shared.ID, ids []shared.ID, v vulnerability.InteropVEX, closeNotAffected bool, reason string) (stored, closed []shared.ID, err error)
}

// Limits of one upload. The handler enforces the body size; these bound
// what the parser accepts from each file.
var (
	FileLimits = importer.Limits{
		MaxInputBytes: 100 << 20,
		MaxFindings:   100_000,
		MaxAssets:     100_000,
		MaxComponents: 200_000,
		MaxStatements: 20_000,
		MaxIssues:     100,
	}
	ArchiveLimits = importer.ArchiveLimits{
		MaxEntries:    50,
		MaxEntryBytes: 100 << 20,
		MaxTotalBytes: 400 << 20,
		MaxRatio:      200,
	}
)

// MaxUnmappedListed bounds the unmapped field paths returned per file.
const MaxUnmappedListed = 100

// Request is one upload.
type Request struct {
	TenantID shared.ID
	// Actor is the uploader's data scope; nil is unrestricted (owner,
	// admin, full data access).
	Actor ingest.ActorScope
	// DryRun parses and counts; nothing is written.
	DryRun bool
	// CanApprove: the uploader may set findings to false_positive
	// (findings:approve). Without it a VEX document never closes a finding.
	CanApprove bool
	// Format forces the format of a single file (empty: detected).
	Format importer.Format
	// MinSeverity drops findings below it (empty keeps all).
	MinSeverity ctis.Severity
	// SessionID names the import; report ids derive from it.
	SessionID string
}

// FileError is why a file could not be imported, with its place in the file.
type FileError struct {
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	// Kind: unknown_format, too_large, unsafe, malformed, failed.
	Kind string `json:"kind"`
}

// VEXSummary is what a VEX document did (or, in a preview, would do).
type VEXSummary struct {
	Statements int `json:"statements"`
	// Statements without a vulnerability id or a package URL product the
	// platform can match (CPE-only or name-only products).
	Unmatchable int `json:"unmatchable"`
	// Findings of the tenant, within the uploader's scope, that a statement
	// matched.
	Matched int `json:"matched"`
	// Findings the statement was stored on (commit only).
	Stored int `json:"stored"`
	// Open findings a not_affected statement closed (enforce), or would
	// close (dry_run mode, a preview, or an uploader without
	// findings:approve).
	Closed     int    `json:"closed"`
	WouldClose int    `json:"would_close"`
	Mode       string `json:"mode"`
	// Ids of the findings closed or that would be, for the audit record.
	FindingIDs []shared.ID `json:"-"`
}

// FileResult is the outcome of one file.
type FileResult struct {
	Name     string           `json:"name"`
	Format   importer.Format  `json:"format,omitempty"`
	Error    *FileError       `json:"error,omitempty"`
	Stats    importer.Stats   `json:"stats"`
	Issues   []importer.Issue `json:"issues,omitempty"`
	Unmapped []string         `json:"unmapped,omitempty"`
	VEX      *VEXSummary      `json:"vex,omitempty"`
	Ingest   *ingest.Output   `json:"ingest,omitempty"`
}

// Service imports uploaded files.
type Service struct {
	ingest  Ingester
	repo    VEXRepository
	vexMode ingest.VEXMode
	logger  *logger.Logger
}

// NewService creates the import service. vexMode is INGEST_VEX.
func NewService(ing Ingester, repo VEXRepository, vexMode ingest.VEXMode, log *logger.Logger) *Service {
	if vexMode == "" {
		vexMode = ingest.SourceResolveDryRun
	}
	return &Service{ingest: ing, repo: repo, vexMode: vexMode, logger: log}
}

// VEXMode returns the mode VEX documents are applied in.
func (s *Service) VEXMode() ingest.VEXMode { return s.vexMode }

// ImportFile converts one file and, unless req.DryRun, ingests it and
// applies its VEX statements. kb is the Qualys KnowledgeBase companion (may
// be nil). index numbers the file within the upload.
func (s *Service) ImportFile(ctx context.Context, req Request, index int, name string, r io.Reader, kb io.Reader) FileResult {
	fr := FileResult{Name: name}
	res, err := importer.Parse(ctx, r, importer.Options{
		Format:              req.Format,
		Limits:              FileLimits,
		ReportID:            fmt.Sprintf("%s-%d", req.SessionID, index),
		MinSeverity:         req.MinSeverity,
		QualysKnowledgeBase: kb,
	})
	if err != nil {
		fr.Error = fileError(err)
		return fr
	}
	fr.Format = res.Format
	fr.Stats = res.Stats
	fr.Issues = res.Issues
	fr.Unmapped = res.Unmapped
	if len(fr.Unmapped) > MaxUnmappedListed {
		fr.Unmapped = fr.Unmapped[:MaxUnmappedListed]
	}

	if !req.DryRun && hasContent(res.Report) {
		out, err := s.ingestReport(ctx, req, res.Report)
		if err != nil {
			fr.Error = &FileError{Message: err.Error(), Kind: "failed"}
			return fr
		}
		fr.Ingest = out
	}
	if len(res.VEX) > 0 {
		sum, err := s.applyVEX(ctx, req, res.VEX)
		if err != nil {
			s.logger.Error("finding import: vex", "tenant_id", req.TenantID.String(), "error", err)
			fr.Error = &FileError{Message: "applying the VEX statements failed", Kind: "failed"}
		}
		fr.VEX = sum
	}
	return fr
}

func hasContent(r *ctis.Report) bool {
	return r != nil && (len(r.Assets) > 0 || len(r.Findings) > 0 || len(r.Dependencies) > 0)
}

// ingestReport runs the report through ingest with the uploader's rights.
// An upload never auto-resolves: its coverage is partial whatever the file
// says.
func (s *Service) ingestReport(ctx context.Context, req Request, report *ctis.Report) (*ingest.Output, error) {
	report.Metadata.CoverageType = string(ingest.CoverageTypePartial)
	report.Metadata.Branch = nil
	in := ingest.Input{Report: report, CoverageType: ingest.CoverageTypePartial}
	in.Options.Actor = req.Actor
	// The ingest service takes its tenant from a sensor record; this one
	// carries only the tenant. The uploader's rights come from Actor.
	tid := req.TenantID
	agt := &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}
	out, err := s.ingest.Ingest(ctx, agt, in)
	if err != nil {
		if strings.Contains(err.Error(), "validation") || strings.Contains(err.Error(), "INVALID") {
			return nil, fmt.Errorf("the converted report was refused: %w", err)
		}
		s.logger.Error("finding import: ingest", "tenant_id", req.TenantID.String(), "error", err)
		return nil, errors.New("ingest failed")
	}
	return out, nil
}

// Finding statuses a VEX document may close, and sources it never closes
// (the same sets as the repository's guard; the repository re-checks).
var (
	openStatuses     = map[string]bool{"new": true, "open": true, "confirmed": true, "in_progress": true, "fix_applied": true}
	protectedSources = map[string]bool{"pentest": true, "manual": true, "bug_bounty": true, "red_team": true}
)

// applyVEX matches each statement against the tenant's findings within the
// uploader's scope and, outside a preview, stores it on them; a not_affected
// statement closes them only under INGEST_VEX=enforce and only for an
// uploader allowed to approve false positives.
func (s *Service) applyVEX(ctx context.Context, req Request, stmts []importer.VEXStatement) (*VEXSummary, error) {
	sum := &VEXSummary{Statements: len(stmts), Mode: string(s.vexMode)}
	closeAllowed := s.vexMode == ingest.SourceResolveEnforce && req.CanApprove
	for i := range stmts {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		st := &stmts[i]
		queries, ok := documentQueries(st)
		if !ok {
			sum.Unmatchable++
			continue
		}
		var cands []vulnerability.VEXCandidate
		got := map[shared.ID]bool{}
		for _, q := range queries {
			found, err := s.repo.MatchVEXDocument(ctx, req.TenantID, q, vulnerability.MaxVEXMatchFindings)
			if err != nil {
				return sum, err
			}
			for _, c := range found {
				if !got[c.ID] {
					got[c.ID] = true
					cands = append(cands, c)
				}
			}
		}
		cands, err := inScope(ctx, req.Actor, cands)
		if err != nil {
			return sum, err
		}
		if len(cands) == 0 {
			continue
		}
		sum.Matched += len(cands)
		notAffected := st.VEX.Status == ctis.VEXStatusNotAffected
		var closable []shared.ID
		if notAffected {
			for _, c := range cands {
				if openStatuses[c.Status] && !protectedSources[c.Source] {
					closable = append(closable, c.ID)
				}
			}
		}
		if req.DryRun {
			sum.WouldClose += len(closable)
			sum.FindingIDs = append(sum.FindingIDs, closable...)
			continue
		}
		v := interopVEX(st.VEX)
		ids := make([]shared.ID, len(cands))
		for j, c := range cands {
			ids[j] = c.ID
		}
		reason := vulnerability.VEXResolutionText(&v)
		stored, closed, err := s.repo.ApplyVEXDocument(ctx, req.TenantID, ids, v, closeAllowed && notAffected, reason)
		if err != nil {
			return sum, err
		}
		sum.Stored += len(stored)
		if closeAllowed {
			sum.Closed += len(closed)
			sum.FindingIDs = append(sum.FindingIDs, closed...)
		} else if s.vexMode != ingest.SourceResolveOff {
			sum.WouldClose += len(closable)
			sum.FindingIDs = append(sum.FindingIDs, closable...)
		}
	}
	return sum, nil
}

// documentQueries are the match queries of a statement: its vulnerability
// ids with the package URL products it names directly, and, for each
// product it names with subcomponents, those subcomponents restricted to
// findings on that product's asset. A subcomponent statement is never
// product-wide: a product without a name or package URL to find its asset
// by makes its subcomponents unmatchable. ok is false when nothing can be
// matched.
func documentQueries(st *importer.VEXStatement) ([]vulnerability.VEXDocumentQuery, bool) {
	ids := make([]string, 0, len(st.VulnerabilityIDs))
	seen := map[string]bool{}
	for _, id := range st.VulnerabilityIDs {
		v := strings.ToUpper(strings.TrimSpace(id.ID))
		if v == "" || len(v) > 128 || seen[v] || len(ids) >= vulnerability.MaxVEXMatchIDs {
			continue
		}
		seen[v] = true
		ids = append(ids, v)
	}
	if len(ids) == 0 {
		return nil, false
	}
	out := make([]vulnerability.VEXDocumentQuery, 0, 1+len(st.Products))
	direct := vulnerability.VEXDocumentQuery{IDs: ids, Products: purlProducts(st.Products, true)}
	if len(direct.Products) > 0 {
		out = append(out, direct)
	}
	for _, p := range st.Products {
		if len(p.Subcomponents) == 0 {
			continue
		}
		names := productAssetNames(p)
		subs := purlProducts(p.Subcomponents, false)
		if len(names) == 0 || len(subs) == 0 {
			continue
		}
		out = append(out, vulnerability.VEXDocumentQuery{IDs: ids, Products: subs, AssetNames: names})
	}
	return out, len(out) > 0
}

// purlProducts returns the distinct package URL products; with topLevel,
// products that carry subcomponents are left out (they are matched through
// their subcomponents only).
func purlProducts(ps []importer.Product, topLevel bool) []vulnerability.VEXProduct {
	out := make([]vulnerability.VEXProduct, 0, len(ps))
	seen := map[vulnerability.VEXProduct]bool{}
	for _, p := range ps {
		if topLevel && len(p.Subcomponents) > 0 {
			continue
		}
		base, version, ok := vulnerability.SplitPURL(p.PURL)
		if !ok {
			continue
		}
		vp := vulnerability.VEXProduct{Base: base, Version: version}
		if seen[vp] || len(out) >= vulnerability.MaxVEXMatchProducts {
			continue
		}
		seen[vp] = true
		out = append(out, vp)
	}
	return out
}

// productAssetNames are the asset names a product is known by: its name
// (with and without the version), its package URL (as given and without
// qualifiers) and, for a container image, its repository_url qualifier;
// lower case.
func productAssetNames(p importer.Product) []string {
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || len(s) > 255 || len(out) >= vulnerability.MaxVEXMatchAssetNames {
			return
		}
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	add(p.Name)
	if p.Name != "" && p.Version != "" {
		add(p.Name + ":" + p.Version)
	}
	if p.PURL != "" {
		add(p.PURL)
		if base, version, ok := vulnerability.SplitPURL(p.PURL); ok {
			add(base)
			if version != "" {
				add(base + "@" + version)
			}
		}
		if i := strings.IndexByte(p.PURL, '?'); i >= 0 {
			if qs, err := url.ParseQuery(p.PURL[i+1:]); err == nil {
				add(qs.Get("repository_url"))
			}
		}
	}
	return out
}

// inScope keeps the candidates on assets the actor may change.
func inScope(ctx context.Context, actor ingest.ActorScope, cands []vulnerability.VEXCandidate) ([]vulnerability.VEXCandidate, error) {
	if actor == nil || len(cands) == 0 {
		return cands, nil
	}
	seen := map[shared.ID]bool{}
	assets := make([]shared.ID, 0, len(cands))
	for _, c := range cands {
		if !seen[c.AssetID] {
			seen[c.AssetID] = true
			assets = append(assets, c.AssetID)
		}
	}
	allowed, err := actor.AssetsInScope(ctx, assets)
	if err != nil {
		return nil, err
	}
	ok := make(map[shared.ID]bool, len(allowed))
	for _, a := range allowed {
		ok[a] = true
	}
	out := cands[:0]
	for _, c := range cands {
		if ok[c.AssetID] {
			out = append(out, c)
		}
	}
	return out, nil
}

func interopVEX(v ctis.VEX) vulnerability.InteropVEX {
	return vulnerability.InteropVEX{
		Status:              string(v.Status),
		Justification:       string(v.Justification),
		NativeJustification: v.NativeJustification,
		Statement:           v.Statement,
		Source:              v.Source,
		AsOf:                v.AsOf,
	}
}

// fileError maps a parse error to its public form. The message of an
// importer.ParseError describes the input only (format, place, rule).
func fileError(err error) *FileError {
	fe := &FileError{Kind: "malformed", Message: "the file could not be read"}
	var pe *importer.ParseError
	if errors.As(err, &pe) {
		fe.Message = pe.Error()
		fe.Line, fe.Column = pe.Line, pe.Column
	}
	switch {
	case errors.Is(err, importer.ErrUnknownFormat):
		fe.Kind = "unknown_format"
	case errors.Is(err, importer.ErrTooLarge):
		fe.Kind = "too_large"
	case errors.Is(err, importer.ErrUnsafe):
		fe.Kind = "unsafe"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		fe.Kind = "failed"
		fe.Message = "the import took too long"
	}
	return fe
}
