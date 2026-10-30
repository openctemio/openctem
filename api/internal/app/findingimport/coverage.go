package findingimport

// Full-coverage uploads (docs/rfcs/RFC-122-ingest-receipts.md §5). An upload
// closes findings only when it declares full coverage of an explicit scope:
// the asset ids it names, for the tool of each of its files. Then the open
// findings of that scope the upload did not report are closed through the
// same guards as a covered scan (human sources, leaked secrets and branch
// occurrences never; the blinding guard holds a mass close), and further:
// the uploader must hold findings:verify, a critical or known-exploited
// finding stays open, and only a finding whose latest sighting was itself an
// upload closes (a platform sensor's sighting is not overruled by a file). Nothing closes
// when any file failed or a finding could not be stored: an incomplete
// upload proves nothing about what it left out.

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/internal/app/closuremode"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// MaxCoverageAssets bounds the asset ids one full-coverage upload names.
const MaxCoverageAssets = 100

// Coverage is what an upload declares it covered.
type Coverage struct {
	// Full: the upload is a complete scan of AssetIDs by the tool of each
	// of its files. False (the default) never closes anything.
	Full     bool
	AssetIDs []shared.ID
	// CanVerify: the uploader holds findings:verify. Closing a finding as
	// fixed is a verification, so an upload without it still imports but
	// closes nothing (noteNeedsVerify).
	CanVerify bool
}

// Errors of a coverage declaration (the handler answers 400 or 403).
var (
	ErrCoverageScope       = errors.New("coverage=full needs 1 to 100 asset_id values, each an asset of the organization in your data scope")
	ErrCoverageUnsupported = errors.New("full-coverage uploads are not available")
)

// coverageRepo is implemented by the postgres finding repository.
type coverageRepo interface {
	CountTenantAssets(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error)
	ImportCoverageCandidates(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string, receiptID shared.ID) ([]shared.ID, int, error)
	ResolveImportCoverage(ctx context.Context, tenantID shared.ID, assets, ids []shared.ID, tool string, receiptID shared.ID) ([]shared.ID, error)
	ImportCoverageUntouched(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string, receiptID shared.ID) (int, error)
}

// noteIncomplete: a declared full coverage that closed nothing because the
// upload was not complete (a failed file, a finding not stored, a record the
// parser skipped, a request cut short). noteScopeChanged: the declared scope
// was no longer the uploader's when the close was due.
const (
	noteIncomplete   = "incomplete"
	noteScopeChanged = "scope_changed"
	// noteNeedsVerify: the uploader may not verify a fix, so nothing closed.
	noteNeedsVerify = "needs_verify"
	// noteProposed: the organization's closing mode asked a person to confirm
	// the closes (Ready to close); the upload closed nothing itself.
	noteProposed = "proposed"
)

// receiptRecorder records the findings an upload closed on its receipt.
type receiptRecorder interface {
	Record(ctx context.Context, d *ingestreceipt.Delta) (shared.ID, error)
}

// CheckCoverage validates a declaration before anything is imported: 1 to
// MaxCoverageAssets distinct assets, every one an asset of the tenant and
// in the uploader's data scope. The answer does not tell a missing asset
// from a hidden one.
func (s *Service) CheckCoverage(ctx context.Context, req Request) error {
	if !req.Coverage.Full {
		if len(req.Coverage.AssetIDs) > 0 {
			return ErrCoverageScope
		}
		return nil
	}
	repo, ok := s.repo.(coverageRepo)
	if !ok {
		return ErrCoverageUnsupported
	}
	if _, ok := s.receipts.(receiptRecorder); !ok {
		return ErrCoverageUnsupported
	}
	ids := uniqueIDs(req.Coverage.AssetIDs)
	if len(ids) == 0 || len(ids) > MaxCoverageAssets {
		return ErrCoverageScope
	}
	n, err := repo.CountTenantAssets(ctx, req.TenantID, ids)
	if err != nil {
		return err
	}
	if n != len(ids) {
		return ErrCoverageScope
	}
	if scope := req.coverageScope(); scope != nil {
		in, err := scope.AssetsInScope(ctx, ids)
		if err != nil {
			return err
		}
		if len(uniqueIDs(in)) != len(ids) {
			return ErrCoverageScope
		}
	}
	return nil
}

// coverageScope is who must be able to see every declared asset: the
// uploader's visibility (CoverageScope), which also hides the private
// program assets an unrestricted member is not part of, else their write
// scope (Actor). nil: every asset of the organization (an administrator).
func (r Request) coverageScope() ingest.ActorScope {
	if r.CoverageScope != nil {
		return r.CoverageScope
	}
	return r.Actor
}

// closeUncovered closes, for a complete full-coverage upload, the open
// findings of its scope it did not report, records them on the receipt,
// and returns the coverage note and the untouched count for the receipt.
// note "incomplete" means nothing was closed because a file or a finding
// failed.
func (s *Service) closeUncovered(ctx context.Context, req Request, results []FileResult) (note string, untouched *int) {
	// A file read through an import mapping never proves what it did not
	// report (the handler refuses coverage=full with a mapping already).
	if req.Mapping != nil {
		return noteIncomplete, nil
	}
	// A recon directory is partial by nature: a host missing from it says
	// nothing about whether it still exists.
	for _, fr := range results {
		if bundleFormat(fr.Format) {
			return noteIncomplete, nil
		}
	}
	repo, ok := s.repo.(coverageRepo)
	rec, rok := s.receipts.(receiptRecorder)
	if !ok || !rok {
		return "", nil
	}
	// Closing by absence is a verification of a fix, as POST
	// /findings/{id}/verify: it needs findings:verify, else the upload is
	// ingested and closes nothing.
	if !req.Coverage.CanVerify {
		return noteNeedsVerify, nil
	}
	tools := map[string]bool{}
	for _, fr := range results {
		// A skipped record (below min_severity, or unusable) is a finding
		// the file may hold but the upload did not report: closing on its
		// absence would close what is still there.
		// A file whose receipt write failed left its findings off the
		// receipt that decides what the upload did not report.
		if fr.Error != nil || fr.Stats.Skipped > 0 || fr.Ingest != nil && (len(fr.Ingest.FailedFindings) > 0 || fr.Ingest.ReceiptFailed) {
			return noteIncomplete, nil
		}
		if fr.Ingest != nil && fr.Tool != "" {
			tools[fr.Tool] = true
		}
	}
	if len(tools) == 0 {
		return noteIncomplete, nil
	}
	names := make([]string, 0, len(tools))
	for t := range tools {
		names = append(names, t)
	}
	sort.Strings(names)
	// The declaration was checked when the request started; an upload can
	// run for minutes. Check it again right before closing, so an asset that
	// left the uploader's scope (or the organization) meanwhile closes
	// nothing.
	if err := s.CheckCoverage(ctx, req); err != nil {
		s.logger.Warn("finding import: coverage scope changed", "tenant_id", req.TenantID.String(), "error", err)
		return noteScopeChanged, nil
	}
	assets := uniqueIDs(req.Coverage.AssetIDs)
	note = "resolved"
	total, proposals, resolvedAny := 0, 0, false
	for _, tool := range names {
		stale, open, err := repo.ImportCoverageCandidates(ctx, req.TenantID, assets, tool, req.ReceiptID)
		if errors.Is(err, ingestreport.ErrReceiptIncomplete) {
			// Past the action cap the receipt no longer lists everything
			// the upload reported: absence cannot be decided.
			return noteIncomplete, nil
		}
		if err != nil {
			s.logger.Warn("finding import: coverage candidates", "tenant_id", req.TenantID.String(), "error", err)
			return "error", nil
		}
		var proposed []shared.ID
		// The organization's closing mode decides per finding: close,
		// propose to a person, or keep (off keeps and proposes nothing).
		toClose, proposed, _ := s.closureDecider().Split(ctx, req.TenantID, stale, vulnerability.ClosureMethodCoveredScan)
		held := len(stale) > 0 && ingest.DefaultBlindingGuard().Holds(len(stale), open)
		if held {
			// A held run closes nothing; a person decides in Ready to close.
			proposed = append(proposed, toClose...)
			toClose = nil
			note = "held"
		}
		if len(proposed) > 0 {
			s.proposeClosures(ctx, req, tool, proposed)
			proposals += len(proposed)
		}
		if len(toClose) > 0 {
			closed, err := repo.ResolveImportCoverage(ctx, req.TenantID, assets, toClose, tool, req.ReceiptID)
			if err != nil {
				s.logger.Warn("finding import: coverage resolve", "tenant_id", req.TenantID.String(), "error", err)
				return "error", nil
			}
			resolvedAny = resolvedAny || len(closed) > 0
			if len(closed) > 0 {
				if _, err := rec.Record(ctx, &ingestreceipt.Delta{TenantID: req.TenantID, Tool: tool, Closed: closed,
					Source: ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: req.ReceiptID.String()}}); err != nil {
					s.logger.Warn("finding import: record closed findings", "tenant_id", req.TenantID.String(), "error", err)
				}
			}
		}
		n, err := repo.ImportCoverageUntouched(ctx, req.TenantID, assets, tool, req.ReceiptID)
		if err != nil {
			s.logger.Warn("finding import: coverage untouched", "tenant_id", req.TenantID.String(), "error", err)
			return note, nil
		}
		total += n
	}
	if note == "resolved" && proposals > 0 && !resolvedAny {
		note = noteProposed
	}
	return note, &total
}

// closureDecider is the shared closing-mode rule over this service's
// settings reader and finding repository.
func (s *Service) closureDecider() closuremode.Decider {
	return closuremode.Decider{Settings: s.closure, Repo: s.repo, Log: s.logger}
}

// SetClosureSettings wires the organization closing policy. Without it every
// organization is in review: a full-coverage upload proposes and closes
// nothing.
func (s *Service) SetClosureSettings(r closuremode.SettingsReader) { s.closure = r }

// proposeClosures records a Ready to close proposal (method covered_scan)
// for each finding the upload did not report, with the upload as evidence.
func (s *Service) proposeClosures(ctx context.Context, req Request, tool string, ids []shared.ID) {
	at := time.Now().UTC()
	evidence := map[string]any{
		"source": "full_coverage_upload", "receipt_id": req.ReceiptID.String(), "tool": tool,
		"covered_assets": len(uniqueIDs(req.Coverage.AssetIDs)), "observed_at": at.Format(time.RFC3339),
	}
	recs := make([]vulnerability.ClosureProposalRecord, len(ids))
	for i, id := range ids {
		recs[i] = vulnerability.ClosureProposalRecord{FindingID: id, Method: vulnerability.ClosureMethodCoveredScan, Evidence: evidence, EvidenceAt: at}
	}
	s.closureDecider().Record(ctx, req.TenantID, recs)
}

func uniqueIDs(in []shared.ID) []shared.ID {
	seen := map[shared.ID]bool{}
	out := make([]shared.ID, 0, len(in))
	for _, id := range in {
		if !id.IsZero() && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
