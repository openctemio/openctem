package ingest

// Ingest semantics of sensor protocol v2 results (RFC-026 §5,
// docs/rfcs/RFC-026-sensor-results-ingest.md).
//
// A v2 segment runs through the same ingest path as v1 (Service.Ingest) with the
// v2 Options on: no fallback asset, no writes to the global vulnerability
// catalog, no auto-resolve. Findings whose asset cannot be resolved inside
// their own segment are rejected per item before the scan runs, and every
// finding and asset ends up either accepted or rejected with a pointer and a
// fixed reason. Auto-resolve runs once, at commit, over the union of the
// assets the report's segments touched, behind the blinding guard.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// V2Options are the ingest rules every v2 segment runs with.
func V2Options() Options {
	return Options{RequireAssetForFindings: true, NoCatalogWrites: true, DeferAutoResolve: true, DeferSensorStats: true}
}

// Provenance is what the server stamps on a v2 segment (RFC-026 §5.1). None
// of it is read from the CTIS body.
type Provenance struct {
	TenantID      shared.ID
	SensorID      shared.ID
	SensorType    string
	CommandID     *shared.ID
	ScanZoneID    *shared.ID
	ReportRef     shared.ID
	ReportID      string
	SegmentSeq    int
	ContentDigest string
	MediaType     string
}

// V2Header is the part every segment of a report repeats: the tool and the
// report metadata. Its canonical JSON is stored on the report and its digest
// is how segments are checked to belong together.
type V2Header struct {
	Tool     *ctis.Tool          `json:"tool"`
	Metadata ctis.ReportMetadata `json:"metadata"`
}

// MaxV2HeaderBytes caps the header of a report (its tool and metadata,
// without the items), which is stored with the report.
const MaxV2HeaderBytes = 64 << 10

// V2HeaderOf returns the canonical header JSON of a segment and its digest.
// The report id is not part of it: metadata.id is either empty or the report
// id, and both spellings describe the same report.
//
// The header is stored with the report and kept as long as the report, so
// it is capped (MaxV2HeaderBytes): over it the segment is report-too-large.
func V2HeaderOf(r *ctis.Report) (canonical []byte, digest string, err error) {
	md := r.Metadata
	md.ID = ""
	canonical, err = json.Marshal(V2Header{Tool: r.Tool, Metadata: md})
	if err != nil {
		return nil, "", fmt.Errorf("encode v2 header: %w", err)
	}
	if len(canonical) > MaxV2HeaderBytes {
		return nil, "", &V2ReportError{Problem: protov2.ProblemReportTooLarge, Errors: []protov2.ItemError{
			item("/metadata", protov2.CodeTooMany, protov2.DetailTooMany)}}
	}
	sum := sha256.Sum256(canonical)
	return canonical, protov2.FormatSHA256(sum[:]), nil
}

// SegmentResult is what ingesting one v2 segment produced.
type SegmentResult struct {
	Outcome ingestreport.SegmentOutcome
	// Touched are the persisted assets the segment upserted: the scope of
	// the report's commit-time auto-resolve.
	Touched []shared.ID
}

// IngestV2Segment ingests one validated v2 segment under the server-stamped
// provenance. Item problems are returned in the outcome, never as an error;
// an error means the segment could not be processed and is retried.
func (s *Service) IngestV2Segment(ctx context.Context, prov Provenance, report *ctis.Report) (*SegmentResult, error) {
	if report == nil {
		return nil, shared.NewDomainError("INVALID_INPUT", "report is required", nil)
	}
	// The report id is the scan identity of every finding of every segment,
	// which is what lets the commit tell seen from stale.
	report.Metadata.ID = prov.ReportID

	kept, keptIdx, assetIdx, itemErrs := resolveV2Assets(report)
	filtered := *report
	filtered.Findings = kept

	agt := &sensor.Sensor{ID: prov.SensorID, TenantID: &prov.TenantID, Type: sensor.SensorType(prov.SensorType), Status: sensor.SensorStatusActive}
	opts := V2Options()
	// The job processor ran the unsolicited gate for a report without a
	// command (V2JobProcessor.processSegment); a bound one changes only what
	// its command covers.
	opts.Binding = s.bindingFromCommandID(ctx, prov.TenantID, prov.CommandID)
	opts.Admitted = true
	out, err := s.Ingest(ctx, agt, Input{Report: &filtered, Options: opts})
	if err != nil {
		return nil, err
	}

	res := &SegmentResult{}
	o := &res.Outcome
	o.RejectedFindings = len(report.Findings) - len(kept)
	o.Errors = itemErrs

	// Assets: accepted when persisted, rejected otherwise.
	seen := map[shared.ID]bool{}
	for i := range filtered.Assets {
		id, ok := out.AssetMap[filtered.Assets[i].ID]
		if !ok || id.IsZero() {
			o.RejectedAssets++
			addItemError(o, protov2.ItemError{Pointer: "/assets/" + strconv.Itoa(assetIdx[i]),
				Code: protov2.CodeAssetInvalid, Detail: protov2.DetailAssetInvalid})
			continue
		}
		if !seen[id] {
			seen[id] = true
			res.Touched = append(res.Touched, id)
		}
	}
	o.AcceptedAssets = len(filtered.Assets) - o.RejectedAssets

	// Findings: rejected when their asset was not stored or the store failed.
	failed := map[int]bool{}
	for i := range kept {
		if id, ok := out.AssetMap[kept[i].AssetRef]; !ok || id.IsZero() {
			failed[i] = true
			addItemError(o, protov2.ItemError{Pointer: "/findings/" + strconv.Itoa(keptIdx[i]) + "/asset_ref",
				Code: protov2.CodeAssetUnresolved, Detail: protov2.DetailAssetNotStored})
		}
	}
	for _, ff := range out.FailedFindings {
		if ff.Index < 0 || ff.Index >= len(kept) || failed[ff.Index] {
			continue
		}
		failed[ff.Index] = true
		addItemError(o, protov2.ItemError{Pointer: "/findings/" + strconv.Itoa(keptIdx[ff.Index]),
			Code: protov2.CodeFindingNotStored, Detail: protov2.DetailFindingNotStored})
	}
	o.RejectedFindings += len(failed)
	o.AcceptedFindings = len(kept) - len(failed)
	return res, nil
}

// addItemError appends an item error, capped at protov2.MaxItemErrors.
func addItemError(o *ingestreport.SegmentOutcome, e protov2.ItemError) {
	if len(o.Errors) >= protov2.MaxItemErrors {
		o.ErrorsTruncated = true
		return
	}
	o.Errors = append(o.Errors, e)
}

// resolveV2Assets binds every finding to an asset of its own segment
// (RFC-026 §5.2) before the scan runs. A finding with an asset_ref keeps
// it when the segment has that asset; a finding without one is bound to the
// segment's asset when there is exactly one. Anything else is rejected:
// v2 never falls back to a made-up or shared asset. Assets without an id get
// a server-generated one so the binding is exact. It returns the kept
// findings, their original indices, each asset's original index and the
// item errors of the rejected findings.
func resolveV2Assets(r *ctis.Report) (kept []ctis.Finding, keptIdx, assetIdx []int, errs []protov2.ItemError) {
	ids := make(map[string]bool, len(r.Assets))
	for i := range r.Assets {
		if r.Assets[i].ID != "" {
			ids[r.Assets[i].ID] = true
		}
	}
	assetIdx = make([]int, len(r.Assets))
	for i := range r.Assets {
		assetIdx[i] = i
		if r.Assets[i].ID == "" {
			gen := "_server_asset_" + strconv.Itoa(i)
			for ids[gen] {
				gen += "_"
			}
			ids[gen] = true
			r.Assets[i].ID = gen
		}
	}

	kept = make([]ctis.Finding, 0, len(r.Findings))
	keptIdx = make([]int, 0, len(r.Findings))
	for i := range r.Findings {
		f := r.Findings[i]
		switch {
		case f.AssetRef != "" && ids[f.AssetRef]:
		case f.AssetRef == "" && len(r.Assets) == 1:
			f.AssetRef = r.Assets[0].ID
		default:
			detail := protov2.DetailAssetUnresolved
			if f.AssetRef == "" && len(r.Assets) > 1 {
				detail = protov2.DetailAssetAmbiguous
			}
			if len(errs) < protov2.MaxItemErrors {
				errs = append(errs, protov2.ItemError{Pointer: "/findings/" + strconv.Itoa(i) + "/asset_ref",
					Code: protov2.CodeAssetUnresolved, Detail: detail})
			}
			continue
		}
		kept = append(kept, f)
		keptIdx = append(keptIdx, i)
	}
	return kept, keptIdx, assetIdx, errs
}

// BlindingGuard holds back a commit-time auto-resolve that would close too
// much at once (RFC-023 C-4, RFC-026 §5.4): more than MinFindings findings
// and more than Ratio of the open findings of that tool on those assets.
type BlindingGuard struct {
	Ratio       float64
	MinFindings int
}

// DefaultBlindingGuard is 50 % and more than 100 findings (RFC-026 §10.1).
func DefaultBlindingGuard() BlindingGuard { return BlindingGuard{Ratio: 0.5, MinFindings: 100} }

// Holds reports whether resolving stale of open findings must be held.
func (g BlindingGuard) Holds(stale, open int) bool {
	return stale > g.MinFindings && float64(stale) > g.Ratio*float64(open)
}

// CommitResult is what the commit-time steps did.
type CommitResult struct {
	AutoResolved int
	// AutoResolve is protov2.AutoResolveApplied, AutoResolveHeld or
	// AutoResolveSkipped.
	AutoResolve string
}

// ErrV2ToolNotDeclared: the report's tool is not among the sensor's effective
// tools, the ones it reported installed (strict: a sensor that reported no
// tool may report no result).
var ErrV2ToolNotDeclared = errors.New("tool not declared by the sensor")

// SensorDeclaresTool is the v2 tool gate (RFC-026 §5.2): the tool must be one
// the sensor reported installed, and never a name reserved for non-sensor sources.
// There is no allow-all for a sensor that reported nothing.
func SensorDeclaresTool(tools []string, toolName string) bool {
	name := strings.TrimSpace(toolName)
	if name == "" {
		return false
	}
	if _, reserved := reservedAutoResolveTools[strings.ToLower(name)]; reserved {
		return false
	}
	for _, t := range tools {
		if tooldom.SameTool(t, name) {
			return true
		}
	}
	return false
}

// CommitV2Report runs the report-level steps once, after every segment of a
// committed report was processed: auto-resolve over the assets the report
// touched (full coverage on a default branch, a tool the sensor declares,
// behind the blinding guard), the per-branch occurrence sweep and the asset
// finding counts. Failures are logged; they never fail the report, as in v1.
//
//nolint:cyclop // a sequence of guarded, independent steps
func (s *Service) CommitV2Report(ctx context.Context, prov Provenance, header V2Header, touched []shared.ID, guard BlindingGuard) CommitResult {
	res := CommitResult{AutoResolve: protov2.AutoResolveSkipped}
	tenantID := prov.TenantID
	defer func() {
		if len(touched) > 0 {
			if err := s.assetProcessor.UpdateFindingCounts(ctx, tenantID, touched); err != nil {
				s.logger.Warn("failed to update finding counts", "error", err)
			}
		}
	}()

	if header.Tool == nil || s.findingRepo == nil || len(touched) == 0 {
		return res
	}
	// RFC-040 §5.3: a report without a command never auto-resolves in a
	// tenant whose mode is quarantine; a bound one resolves only on the
	// assets its command covers. finding counts still cover every touched
	// asset (deferred above).
	scoped := touched
	if prov.CommandID == nil {
		if s.ResultPolicy(ctx, tenantID).Mode != sensorresult.ModeWarn {
			s.logger.Info("v2 commit: auto-resolve skipped, the report names no command (tenant mode quarantine)",
				"sensor_id", prov.SensorID.String(), "report_id", prov.ReportID)
			return res
		}
		// Warn mode: the per-branch occurrence sweep still runs, but a report
		// without a command never closes a finding (owner decision O11).
	} else {
		scoped = s.coveredByCommand(ctx, tenantID, prov.CommandID, touched)
		if len(scoped) == 0 {
			return res
		}
	}
	toolName := header.Tool.Name
	md := header.Metadata
	md.ID = prov.ReportID
	input := Input{Report: &ctis.Report{Metadata: md, Tool: header.Tool}}

	var tools []string
	if s.sensorRepo != nil {
		if stored, err := s.sensorRepo.GetByID(ctx, prov.SensorID); err == nil && stored != nil {
			tools = stored.EffectiveTools()
		}
	}
	if !SensorDeclaresTool(tools, toolName) {
		s.logger.Warn("v2 commit: auto-resolve skipped, tool not declared by the sensor",
			"sensor_id", prov.SensorID.String(), "tool_name", sanitizeIngestLogField(toolName))
		return res
	}

	// Default-branch findings close only through the per-command evaluation
	// (evaluateRepoCoverage): it needs the command completed with exit 0 and
	// every report of the run clean, so it runs here when the command already
	// finished, and again when it does (command completion, finalize).
	if input.ShouldAutoResolve() && prov.CommandID != nil {
		if repo, ok := s.findingRepo.(coverageRepo); ok {
			if cov, err := repo.CommandCoverage(ctx, tenantID, *prov.CommandID); err == nil {
				// This report is being finalized: committed, with every
				// segment's outcome recorded (ClaimFinalize). Its row says
				// so only after Finish, so count it as completed here.
				for i := range cov.Reports {
					if cov.Reports[i].ReportID == prov.ReportID {
						cov.Reports[i].State = protov2.StateCompleted
					}
				}
				out := s.evaluateRepoCoverage(ctx, tenantID, *prov.CommandID, cov, guard)
				switch {
				case out.Held:
					res.AutoResolve = protov2.AutoResolveHeld
				case out.Reason == coverageEligible:
					res.AutoResolve = protov2.AutoResolveApplied
					res.AutoResolved = len(out.Resolved)
				}
			}
		}
	}

	// Per-branch occurrences: any full scan, on the branch it scanned.
	if input.IsFullCoverage() && s.branchRepo != nil && md.Branch != nil && md.Branch.Name != "" {
		for _, assetID := range scoped {
			br, err := s.branchRepo.GetByName(ctx, assetID, md.Branch.Name)
			if err != nil || br == nil {
				continue
			}
			if _, err := s.findingRepo.AutoResolveStaleBranchOccurrences(ctx, tenantID, br.ID(), toolName, prov.ReportID); err != nil {
				s.logger.Warn("v2 commit: branch occurrence auto-resolve failed", "asset_id", assetID.String(), "error", err)
			}
		}
	}
	return res
}

// coveredByCommand keeps the assets among ids that the bound command's
// targets cover (RFC-040 §5.3): the scope of a bound report's auto-resolve.
func (s *Service) coveredByCommand(ctx context.Context, tenantID shared.ID, commandID *shared.ID, ids []shared.ID) []shared.ID {
	scope := newAlterScope(s.bindingFromCommandID(ctx, tenantID, commandID))
	if s.assetRepo == nil {
		return nil
	}
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		a, err := s.assetRepo.GetByID(ctx, tenantID, id)
		if err != nil || a == nil {
			continue
		}
		if scope.mayAlter(a) {
			out = append(out, id)
		}
	}
	return out
}
