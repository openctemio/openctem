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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Ingester ingests a CTIS report (ingest.Service).
type Ingester interface {
	Ingest(ctx context.Context, agt *sensor.Sensor, input ingest.Input) (*ingest.Output, error)
}

// Repository records imports and matches and updates the tenant's findings
// for a VEX document (postgres.FindingRepository).
type Repository interface {
	StampAssetsImport(ctx context.Context, tenantID, importID shared.ID, ids []shared.ID) (int64, error)
	MatchVEXDocument(ctx context.Context, tenantID shared.ID, q vulnerability.VEXDocumentQuery, limit int) ([]vulnerability.VEXCandidate, error)
	ApplyVEXDocument(ctx context.Context, tenantID shared.ID, ids []shared.ID, v vulnerability.InteropVEX, requestNotAffected bool, reason string) (stored, requested []shared.ID, err error)
}

// ReceiptStore records the receipt of an upload
// (postgres.IngestReceiptRepository): created before anything is written,
// finished with the file-level counts once every file is done. The findings
// counts are recorded by each file's ingest.
type ReceiptStore interface {
	CreateUpload(ctx context.Context, u *ingestreceipt.Upload) error
	FinishUpload(ctx context.Context, tenantID, id shared.ID, r *ingestreceipt.UploadResult) error
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
	// ActorUserID is the uploader, recorded as the producer of the import.
	ActorUserID *shared.ID
	// DryRun parses and counts; nothing is written.
	DryRun bool
	// CanApprove: the uploader holds findings:approve. Without it a VEX
	// document never requests a false positive.
	CanApprove bool
	// Format forces the format of a single file (empty: detected).
	Format importer.Format
	// Mapping converts the file through an organization's import mapping
	// (Format is then "mapping:<name>@<n>"). Such an upload is always
	// partial coverage.
	Mapping *appimportmapping.Resolved
	// MinSeverity drops findings below it (empty keeps all).
	MinSeverity ctis.Severity
	// SessionID names the import; report ids derive from it.
	SessionID string
	// Coverage is what the upload declares it covered (§ coverage.go);
	// the zero value is partial and closes nothing.
	Coverage Coverage
	// CoverageScope is the uploader's visibility for a full-coverage
	// declaration (nil: fall back to Actor); see Request.coverageScope.
	CoverageScope ingest.ActorScope
	// ReceiptID is the upload's receipt (BeginUpload); zero in a preview.
	// Every file of the upload is ingested under it: it is the report id,
	// so the findings' scan_id, and the assets' import_id.
	ReceiptID shared.ID
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
	// Requested counts the pending false-positive requests the statements
	// created (enforce mode); a person decides, nothing is closed here.
	Requested  int    `json:"requested"`
	WouldClose int    `json:"would_close"`
	Mode       string `json:"mode"`
	// Ids of the findings closed or that would be, for the audit record.
	FindingIDs []shared.ID `json:"-"`
}

// FileResult is the outcome of one file.
type FileResult struct {
	// ImportID is the receipt of the upload the file was committed in: the
	// producer of what it wrote (findings.scan_id, assets.import_id). Empty
	// in a preview.
	ImportID string          `json:"import_id,omitempty"`
	Name     string          `json:"name"`
	Format   importer.Format `json:"format,omitempty"`
	// Tool is the scanner the file's report names (canonical), the tool of
	// a full-coverage scope.
	Tool     string           `json:"-"`
	Error    *FileError       `json:"error,omitempty"`
	Stats    importer.Stats   `json:"stats"`
	Issues   []importer.Issue `json:"issues,omitempty"`
	Unmapped []string         `json:"unmapped,omitempty"`
	VEX      *VEXSummary      `json:"vex,omitempty"`
	Ingest   *ingest.Output   `json:"ingest,omitempty"`
}

// Service imports uploaded files.
type Service struct {
	ingest   Ingester
	repo     Repository
	receipts ReceiptStore
	vexMode  ingest.VEXMode
	logger   *logger.Logger
}

// NewService creates the import service. vexMode is INGEST_VEX.
func NewService(ing Ingester, repo Repository, receipts ReceiptStore, vexMode ingest.VEXMode, log *logger.Logger) *Service {
	if vexMode == "" {
		vexMode = ingest.SourceResolveDryRun
	}
	return &Service{ingest: ing, repo: repo, receipts: receipts, vexMode: vexMode, logger: log}
}

// ErrReceiptUnavailable is returned by BeginUpload when the receipt cannot
// be recorded: nothing is imported without a producer record.
var ErrReceiptUnavailable = errors.New("recording the import failed")

// BeginUpload records the receipt of an upload before anything is written,
// so every finding and asset it writes names an existing producer. name is
// the first file's name (only its hash is stored).
func (s *Service) BeginUpload(ctx context.Context, req Request, name string) (shared.ID, error) {
	if s.receipts == nil {
		return shared.ID{}, ErrReceiptUnavailable
	}
	u := &ingestreceipt.Upload{
		ID:             shared.NewID(),
		TenantID:       req.TenantID,
		ActorUserID:    req.ActorUserID,
		Format:         string(req.Format),
		FilenameSHA256: nameHash(name),
	}
	if err := s.receipts.CreateUpload(ctx, u); err != nil {
		s.logger.Error("finding import: receipt", "tenant_id", req.TenantID.String(), "error", err)
		return shared.ID{}, ErrReceiptUnavailable
	}
	return u.ID, nil
}

// FinishUpload stores the file-level counts of an upload on its receipt:
// components, VEX statements, what the parsers skipped, the files that
// failed (by index and a fixed code). The upload failed when no file was
// imported. complete says the request read every part; only a complete
// full-coverage upload closes what it did not report (closeUncovered).
// Best-effort: what the files wrote is already stored.
func (s *Service) FinishUpload(ctx context.Context, req Request, results []FileResult, complete bool) {
	if s.receipts == nil || req.ReceiptID.IsZero() {
		return
	}
	res := &ingestreceipt.UploadResult{Status: ingestreceipt.StatusCompleted}
	if req.Coverage.Full {
		note := noteIncomplete
		var untouched *int
		if complete {
			note, untouched = s.closeUncovered(ctx, req, results)
		}
		res.Coverage, res.CoverageNote, res.Untouched = ingestreceipt.CoverageFull, note, untouched
		if untouched == nil {
			// Coverage was declared but not proven: the receipt stays
			// partial and says why.
			res.Coverage = ingestreceipt.CoveragePartial
		}
	}
	formats := map[importer.Format]bool{}
	ok := 0
	for i, fr := range results {
		if fr.Format != "" {
			formats[fr.Format] = true
		}
		if fr.Error != nil {
			if len(res.Errors) < ingestreceipt.MaxErrors {
				res.Errors = append(res.Errors, ingestreceipt.ErrorEntry{Index: i, Code: "file_" + fr.Error.Kind})
			}
			continue
		}
		ok++
		res.Components += fr.Stats.Components
		res.Statements += fr.Stats.Statements
		res.Skipped += fr.Stats.Skipped
		if v := fr.VEX; v != nil {
			res.VEXStored += v.Stored
			res.VEXRequested += v.Requested
		}
	}
	if ok == 0 {
		res.Status = ingestreceipt.StatusFailed
	}
	switch len(formats) {
	case 0:
	case 1:
		for f := range formats {
			res.Format = string(f)
		}
	default:
		res.Format = "mixed"
	}
	if err := s.receipts.FinishUpload(ctx, req.TenantID, req.ReceiptID, res); err != nil {
		metrics.IngestReceiptWriteFailures.WithLabelValues("upload").Inc()
		s.logger.Warn("finding import: finish receipt", "tenant_id", req.TenantID.String(), "error", err)
	}
}

// VEXMode returns the mode VEX documents are applied in.
func (s *Service) VEXMode() ingest.VEXMode { return s.vexMode }

// ImportUpload converts an upload (Convert) and, unless req.DryRun, stores
// each file: an import record, the ingest of its report with the uploader's
// rights, its VEX statements. refused is set when the upload as a whole
// cannot be read; archive tells a ZIP from a single file.
func (s *Service) ImportUpload(ctx context.Context, req Request, up Upload) (results []FileResult, archive bool, refused *FileError) {
	up.Format = req.Format
	up.Mapping = req.Mapping
	up.MinSeverity = req.MinSeverity
	if up.ReportIDPrefix == "" {
		up.ReportIDPrefix = req.SessionID
	}
	archive, refused = Convert(ctx, up, func(c Converted) {
		results = append(results, s.store(ctx, req, c))
	})
	return results, archive, refused
}

// ImportFile imports one file (not an archive); kb is the Qualys
// KnowledgeBase companion, may be nil. index numbers the file within the
// request.
//
// Outside a preview, a request without a receipt gets one of its own: the
// file is a one-file upload.
func (s *Service) ImportFile(ctx context.Context, req Request, index int, name string, r io.Reader, kb io.Reader) (fr FileResult) {
	if !req.DryRun && req.ReceiptID.IsZero() {
		id, err := s.BeginUpload(ctx, req, name)
		if err != nil {
			return FileResult{Name: SafeName(name), Error: &FileError{Kind: KindFailed, Message: err.Error()}}
		}
		req.ReceiptID = id
		defer func() { s.FinishUpload(context.WithoutCancel(ctx), req, []FileResult{fr}, true) }()
	}
	up := Upload{Name: name, Body: r, ReportIDPrefix: fmt.Sprintf("%s-%d", req.SessionID, index)}
	if kb != nil {
		b, err := io.ReadAll(io.LimitReader(kb, MaxKnowledgeBase+1))
		if err != nil || len(b) > MaxKnowledgeBase {
			return FileResult{Name: name, Error: &FileError{Kind: KindTooLarge, Message: "the knowledge base is too large"}}
		}
		up.KnowledgeBase = b
	}
	results, _, refused := s.ImportUpload(ctx, req, up)
	if refused != nil {
		return FileResult{Name: SafeName(name), Error: refused}
	}
	if len(results) == 0 {
		return FileResult{Name: SafeName(name), Error: &FileError{Kind: KindMalformed, Message: "the file holds nothing to import"}}
	}
	return results[0]
}

// store ingests one converted file under the upload's receipt.
func (s *Service) store(ctx context.Context, req Request, c Converted) FileResult {
	fr := FileResult{Name: c.Name}
	if c.Error != nil {
		fr.Error = c.Error
		return fr
	}
	res := c.Result
	fr.Format = res.Format
	if res.Report != nil && res.Report.Tool != nil {
		fr.Tool = tooldom.CanonicalName(res.Report.Tool.Name)
	}
	fr.Stats = res.Stats
	fr.Issues = res.Issues
	fr.Unmapped = res.Unmapped
	if len(fr.Unmapped) > MaxUnmappedListed {
		fr.Unmapped = fr.Unmapped[:MaxUnmappedListed]
	}

	if !req.DryRun {
		if req.ReceiptID.IsZero() {
			fr.Error = &FileError{Message: ErrReceiptUnavailable.Error(), Kind: KindFailed}
			return fr
		}
		fr.ImportID = req.ReceiptID.String()
		// The report id becomes the findings' scan_id: the upload is their
		// producer, as a scan is.
		res.Report.Metadata.ID = req.ReceiptID.String()
	}

	if !req.DryRun && hasContent(res.Report) {
		out, err := s.ingestReport(ctx, req, res.Report)
		if err != nil {
			fr.Error = &FileError{Message: err.Error(), Kind: KindFailed}
			return fr
		}
		fr.Ingest = out
	}
	if len(res.VEX) > 0 {
		sum, err := s.applyVEX(ctx, req, res.VEX)
		if err != nil {
			s.logger.Error("finding import: vex", "tenant_id", req.TenantID.String(), "error", err)
			fr.Error = &FileError{Message: "applying the VEX statements failed", Kind: KindFailed}
		}
		fr.VEX = sum
	}
	s.stampAssets(ctx, req, &fr)
	return fr
}

// nameHash is the hex SHA-256 of a file name label.
func nameHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// stampAssets stamps the assets a committed file wrote with the upload's
// receipt id. Best-effort: the results are already stored.
func (s *Service) stampAssets(ctx context.Context, req Request, fr *FileResult) {
	if req.DryRun || req.ReceiptID.IsZero() || fr.Ingest == nil {
		return
	}
	if ids := s.writtenAssets(ctx, req, fr.Ingest.AssetMap); len(ids) > 0 {
		if _, err := s.repo.StampAssetsImport(ctx, req.TenantID, req.ReceiptID, ids); err != nil {
			s.logger.Warn("finding import: stamp assets", "tenant_id", req.TenantID.String(), "error", err)
		}
	}
}

// writtenAssets are the persisted assets of the report the uploader may
// change: ingest maps every report asset, and a restricted uploader's
// out-of-scope ones were not written.
func (s *Service) writtenAssets(ctx context.Context, req Request, assetMap map[string]shared.ID) []shared.ID {
	seen := map[shared.ID]bool{}
	ids := make([]shared.ID, 0, len(assetMap))
	for _, id := range assetMap {
		if !id.IsZero() && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if req.Actor == nil || len(ids) == 0 {
		return ids
	}
	allowed, err := req.Actor.AssetsInScope(ctx, ids)
	if err != nil {
		s.logger.Warn("finding import: scope of written assets", "tenant_id", req.TenantID.String(), "error", err)
		return nil
	}
	return allowed
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
	in.Options.Receipt = &ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: req.ReceiptID.String()}
	// A person's file: an import for attribute reconciliation (RFC-069).
	in.Options.SourceKind, in.Options.SourceName = asset.SourceKindImport, importSourceName(req.Format)
	if req.Mapping != nil {
		in.Options.SourceName = req.Mapping.SourceName()
	}
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

// ApplyVEXStatements applies the statements of a converted VEX document
// with the rights of req (Actor limits the findings it may touch). Another
// caller that converts files itself (a CI run's upload) uses it.
func (s *Service) ApplyVEXStatements(ctx context.Context, req Request, stmts []importer.VEXStatement) (*VEXSummary, error) {
	return s.applyVEX(ctx, req, stmts)
}

// applyVEX matches each statement against the tenant's findings within the
// uploader's scope and, outside a preview, stores it on them; a not_affected
// statement requests a false positive for them (a pending request by the
// actor "vex", decided by a person under the approval policy) only under
// INGEST_VEX=enforce and only for an uploader allowed to approve false
// positives. It never sets a status itself.
func (s *Service) applyVEX(ctx context.Context, req Request, stmts []importer.VEXStatement) (*VEXSummary, error) {
	sum := &VEXSummary{Statements: len(stmts), Mode: string(s.vexMode)}
	requestAllowed := s.vexMode == ingest.SourceResolveEnforce && req.CanApprove
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
		stored, requested, err := s.repo.ApplyVEXDocument(ctx, req.TenantID, ids, v, requestAllowed && notAffected, reason)
		if err != nil {
			return sum, err
		}
		sum.Stored += len(stored)
		if requestAllowed {
			sum.Requested += len(requested)
			sum.FindingIDs = append(sum.FindingIDs, requested...)
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
	fe := &FileError{Kind: KindMalformed, Message: "the file could not be read"}
	var pe *importer.ParseError
	if errors.As(err, &pe) {
		fe.Message = pe.Error()
		fe.Line, fe.Column = pe.Line, pe.Column
	}
	switch {
	case errors.Is(err, importer.ErrUnknownFormat):
		fe.Kind = KindUnknownFormat
	case errors.Is(err, importer.ErrTooLarge):
		fe.Kind = KindTooLarge
	case errors.Is(err, importer.ErrUnsafe):
		fe.Kind = KindUnsafe
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		fe.Kind = KindFailed
		fe.Message = "the import took too long"
	}
	return fe
}

// importSourceName names an upload for attribute reconciliation: its format,
// or "file" when it was detected per file.
func importSourceName(f importer.Format) string {
	if f == "" {
		return "file"
	}
	return string(f)
}
