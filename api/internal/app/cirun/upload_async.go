package cirun

// A CI run's results are accepted fast and applied by the ingest worker
// (docs/rfcs/RFC-122-ingest-receipts.md, "Accept fast, apply async";
// docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).
//
// POST /ci/runs/{id}/results checks what it can cheaply (a CTIS report is
// decoded and must name only the run's repository; a tool export is only
// recognized), takes one of the run's report slots, stores the raw body
// sealed and enqueues one ci_results job, then answers 202 with the upload
// id. The worker applies the job exactly as the request used to, records
// the run's sightings and the decided results the job may hide, and deletes
// the raw body. The gate waits for the run's jobs (Evaluate) and fails a
// run whose upload could not be applied.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// UploadQueue is the ingest queue (ingestqueue.Queue).
type UploadQueue interface {
	StagePart(ctx context.Context, tenantID, jobID shared.ID, part int, name string, body []byte) error
	Commit(ctx context.Context, job *ingestjob.Job, admit func() error) (*ingestjob.Job, bool, error)
	Get(ctx context.Context, tenantID, id shared.ID, kind ingestjob.Kind) (*ingestjob.Job, error)
	Wait(ctx context.Context, tenantID, id shared.ID, kind ingestjob.Kind, wait time.Duration) (*ingestjob.Job, error)
	SourceState(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, sourceRef string) (pending, dead int, err error)
	Parts(ctx context.Context, job *ingestjob.Job) ([]ingestqueue.OpenedPart, error)
	Done(ctx context.Context, job *ingestjob.Job) error
}

// VEXApplier applies the statements of a VEX document a run uploaded
// (findingimport.Service).
type VEXApplier interface {
	ApplyVEXStatements(ctx context.Context, req findingimport.Request, stmts []importer.VEXStatement) (*findingimport.VEXSummary, error)
}

// SetUploadQueue enables CI result uploads: without a queue every upload is
// refused (nothing is applied in the request any more). vex applies VEX
// documents (nil refuses them).
func (s *Service) SetUploadQueue(q UploadQueue, vex VEXApplier) { s.uploads, s.vex = q, vex }

// Errors of an upload.
var (
	// ErrUploadsUnavailable: no upload queue is wired.
	ErrUploadsUnavailable = errors.New("CI result uploads are not available")
	// ErrInvalidReport: the body is neither a CTIS report nor a tool export.
	ErrInvalidReport = fmt.Errorf("%w: invalid CTIS report", shared.ErrValidation)
	// ErrUploadsPending: the run still has uploads being applied; ask for
	// the verdict again shortly.
	ErrUploadsPending = errors.New("the run's uploads are still being applied")
)

// Public error codes of a CI upload that failed for good.
const (
	UploadErrorUnreadable   = "unreadable"
	UploadErrorTooLarge     = "too_large"
	UploadErrorOutOfScope   = "report_out_of_scope"
	UploadErrorRunEvaluated = "run_evaluated"
	UploadErrorRunGone      = "run_not_found"
	UploadErrorVEXRefused   = "vex_not_accepted"
)

// uploadEnvelope is what the worker needs besides the raw body.
type uploadEnvelope struct {
	// Export: the body is a tool export (SARIF, an SBOM, a ZIP ...), not a
	// CTIS report.
	Export bool `json:"export"`
}

// UploadResult is what an applied upload did, as the status read returns
// it (the same fields the upload answered with when it was applied in the
// request).
type UploadResult struct {
	ScanID            string   `json:"scan_id"`
	AssetsCreated     int      `json:"assets_created"`
	AssetsUpdated     int      `json:"assets_updated"`
	FindingsCreated   int      `json:"findings_created"`
	FindingsUpdated   int      `json:"findings_updated"`
	FindingsSkipped   int      `json:"findings_skipped"`
	CVEsCreated       int      `json:"cves_created"`
	CVEsUpdated       int      `json:"cves_updated"`
	Errors            []string `json:"errors,omitempty"`
	AssetsLimited     int      `json:"assets_limited,omitempty"`
	ReopensWithheld   int      `json:"reopens_withheld,omitempty"`
	AssetsSkippedExcl int      `json:"assets_skipped_excluded,omitempty"`
	// Known lists the uploaded results that carry a decision the gate
	// honors, by index in the CTIS report (a CTIS upload only).
	Known          []cirun.KnownFinding `json:"known"`
	KnownTotal     int                  `json:"known_total"`
	KnownTruncated bool                 `json:"known_truncated,omitempty"`
	// Files of a tool export with their format or error.
	Files []ExportFile `json:"files,omitempty"`
	// FindingsDroppedOutOfScope counts an export's findings filed on an
	// asset other than the run's repository.
	FindingsDroppedOutOfScope int `json:"findings_dropped_out_of_scope,omitempty"`
	// VEXStored counts findings a VEX statement was stored on.
	VEXStored int `json:"vex_stored,omitempty"`
}

// ExportFile is one converted file of a run's tool export.
type ExportFile struct {
	Name   string `json:"name"`
	Format string `json:"format,omitempty"`
	Error  *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
		Line    int    `json:"line,omitempty"`
		Column  int    `json:"column,omitempty"`
	} `json:"error,omitempty"`
}

// UploadReceipt is the state of one upload of a run.
type UploadReceipt struct {
	UploadID  shared.ID
	Status    ingestqueue.Status
	ErrorCode string
	// Replayed: the same body was already uploaded to this run; this is
	// that upload.
	Replayed bool
	// Result is set once the upload was applied.
	Result *UploadResult
}

// DecodeReport accepts {"report": {...}} or a bare CTIS report, refusing
// fields outside the contract. The bounded I-JSON pre-pass runs first:
// nothing is decoded until the document's item counts are within
// ingest.CIReportBounds.
func DecodeReport(body []byte) (*ctis.Report, bool) {
	if ingest.CheckIJSONBounded(body, protov2.DefaultMaxJSONDepth, ingest.CIReportBounds) != nil {
		return nil, false
	}
	var wrapped struct {
		Report ctis.Report `json:"report"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wrapped); err == nil && wrapped.Report.Version != "" {
		return &wrapped.Report, true
	}
	var report ctis.Report
	dec = json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		return nil, false
	}
	if report.Version == "" {
		report.Version = "1.0"
	}
	return &report, true
}

// uploadPrincipal names a run as the submitter of its uploads.
func uploadPrincipal(runID shared.ID) string { return "run:" + runID.String() }

// AcceptUpload stores a run's upload and enqueues it. A CTIS report is
// decoded and scoped first, so a malformed report (ErrInvalidReport) or one
// naming another asset (ErrReportOutOfScope) is refused at once; a tool
// export is converted by the worker. The same body uploaded to the run
// again is the same upload (Replayed).
func (s *Service) AcceptUpload(ctx context.Context, run *cirun.Run, body []byte, export bool) (*UploadReceipt, error) {
	if s.uploads == nil {
		return nil, ErrUploadsUnavailable
	}
	if run == nil {
		return nil, cirun.ErrRunNotFound
	}
	// A tool export is converted by the worker; a gate waits on it.
	lane := ingestjob.LaneInteractive
	if !export {
		report, ok := DecodeReport(body)
		if !ok {
			return nil, ErrInvalidReport
		}
		if err := ScopeReport(report, run); err != nil {
			return nil, err
		}
		lane = s.uploadLane(ctx, report)
	}
	env, err := json.Marshal(uploadEnvelope{Export: export})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	job := ingestjob.NewUploadJob(shared.NewID(), run.TenantID, ingestjob.KindCIResults, run.ID.String(),
		uploadPrincipal(run.ID), "ci:"+run.ID.String(), env, digest[:])
	// The uploads of one repository are applied one at a time: concurrent
	// jobs of a CI matrix never write the same rows together.
	job.Route(lane, ingestjob.ScopeKey(run.TenantID, "repo", run.RepositoryAssetID.String()))
	if err := s.uploads.StagePart(ctx, run.TenantID, job.ID(), 0, "results", body); err != nil {
		return nil, fmt.Errorf("store CI upload: %w", err)
	}
	// The run status and report count on run are the snapshot of the token
	// lookup; the slot is taken atomically against the stored run, so
	// concurrent uploads cannot pass the cap or land after the verdict.
	stored, created, err := s.uploads.Commit(ctx, job, func() error {
		return s.repo.ReserveRunReport(ctx, run.TenantID, run.ID)
	})
	if err != nil {
		return nil, err
	}
	return &UploadReceipt{UploadID: stored.ID(), Status: ingestqueue.StatusOf(stored), ErrorCode: stored.PublicError(),
		Replayed: !created, Result: uploadResultOf(stored)}, nil
}

// UploadStatus returns the state of one of the run's uploads, waiting up to
// wait (bounded by ingestqueue.MaxWait) for it to finish. An upload of
// another run or tenant is cirun.ErrRunNotFound.
func (s *Service) UploadStatus(ctx context.Context, run *cirun.Run, uploadID shared.ID, wait time.Duration) (*UploadReceipt, error) {
	if s.uploads == nil {
		return nil, ErrUploadsUnavailable
	}
	job, err := s.uploads.Wait(ctx, run.TenantID, uploadID, ingestjob.KindCIResults, min(wait, ingestqueue.MaxWait))
	if errors.Is(err, shared.ErrNotFound) {
		return nil, cirun.ErrRunNotFound
	}
	if err != nil {
		return nil, err
	}
	if job.SourceRef() != run.ID.String() {
		return nil, cirun.ErrRunNotFound
	}
	return &UploadReceipt{UploadID: job.ID(), Status: ingestqueue.StatusOf(job), ErrorCode: job.PublicError(),
		Result: uploadResultOf(job)}, nil
}

func uploadResultOf(job *ingestjob.Job) *UploadResult {
	if job.Status() != ingestjob.StatusCompleted || len(job.Result()) == 0 {
		return nil
	}
	var r UploadResult
	if json.Unmarshal(job.Result(), &r) != nil {
		return nil
	}
	return &r
}

// uploadWaitStep is how often the gate reads the run's upload state.
var uploadWaitStep = 250 * time.Millisecond

// waitForUploads waits up to the configured bound for the run's uploads to
// be applied and returns how many failed for good. Uploads still pending
// after the wait are ErrUploadsPending: the verdict is never computed over
// part of the run's results.
func (s *Service) waitForUploads(ctx context.Context, run *cirun.Run) (int, error) {
	if s.uploads == nil {
		return 0, nil
	}
	deadline := s.now().Add(s.cfg.gateUploadWait())
	if dl, ok := ctx.Deadline(); ok && dl.Add(-2*time.Second).Before(deadline) {
		deadline = dl.Add(-2 * time.Second)
	}
	for {
		pending, dead, err := s.uploads.SourceState(ctx, run.TenantID, ingestjob.KindCIResults, run.ID.String())
		if err != nil {
			return 0, fmt.Errorf("read the run's uploads: %w", err)
		}
		if pending == 0 {
			return dead, nil
		}
		if !s.now().Before(deadline) {
			return 0, ErrUploadsPending
		}
		t := time.NewTimer(uploadWaitStep)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0, ErrUploadsPending
		case <-t.C:
		}
	}
}

// ProcessUploadJob applies a queued upload (the ingest worker, kind
// ci_results).
func (s *Service) ProcessUploadJob(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	if s.uploads == nil {
		return nil, ErrUploadsUnavailable
	}
	runID, err := shared.IDFromString(job.SourceRef())
	if err != nil {
		return nil, ingestjob.Permanent(UploadErrorRunGone, err)
	}
	run, err := s.repo.GetRun(ctx, job.TenantID(), runID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, ingestjob.Permanent(UploadErrorRunGone, err)
	}
	if err != nil {
		return nil, err
	}
	var env uploadEnvelope
	if err := json.Unmarshal(job.Payload(), &env); err != nil {
		return nil, ingestjob.Permanent(UploadErrorUnreadable, err)
	}
	parts, err := s.uploads.Parts(ctx, job)
	if err != nil {
		return nil, err
	}
	body := parts[0].Body
	var res *UploadResult
	if env.Export {
		res, err = s.applyExport(ctx, run, body)
	} else {
		res, err = s.applyCTIS(ctx, run, body)
	}
	if err != nil {
		return nil, classifyUploadError(err)
	}
	out, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	// The raw report is deleted when the worker records the job completed
	// (IngestJobRepository.Complete), not here: a crash before that
	// re-applies the upload instead of failing an applied one.
	return out, nil
}

// DeadLetter records an upload that failed for good on the run: the gate
// reads it from the queue (waitForUploads) and fails the run.
func (s *Service) DeadLetter(ctx context.Context, job *ingestjob.Job, publicErr string) {
	s.log.Warn("ci upload failed for good", "job_id", job.ID().String(), "run_id", job.SourceRef(), "code", publicErr)
}

// classifyUploadError turns an apply error a retry cannot fix into a
// permanent job error with a fixed code.
func classifyUploadError(err error) error {
	var perm *ingestjob.PermanentError
	var de *shared.DomainError
	switch {
	case errors.As(err, &perm):
		return err
	case errors.Is(err, ErrReportOutOfScope):
		return ingestjob.Permanent(UploadErrorOutOfScope, err)
	case errors.Is(err, cirun.ErrRunEvaluated):
		return ingestjob.Permanent(UploadErrorRunEvaluated, err)
	case errors.Is(err, cirun.ErrRunNotFound):
		return ingestjob.Permanent(UploadErrorRunGone, err)
	case errors.Is(err, ErrInvalidReport):
		return ingestjob.Permanent(UploadErrorUnreadable, err)
	case errors.As(err, &de) && de.Code == ingest.CodePayloadTooLarge:
		return ingestjob.Permanent(UploadErrorTooLarge, err)
	case errors.Is(err, shared.ErrValidation):
		return ingestjob.Permanent(UploadErrorUnreadable, err)
	}
	return err
}

// applyCTIS applies a CTIS report of the run (its slot was reserved when
// it was accepted).
func (s *Service) applyCTIS(ctx context.Context, run *cirun.Run, body []byte) (*UploadResult, error) {
	report, ok := DecodeReport(body)
	if !ok {
		return nil, ErrInvalidReport
	}
	out, err := s.applyReport(ctx, run, report)
	if err != nil {
		return nil, err
	}
	res := resultOf(out)
	known, total := s.KnownFindings(ctx, run, out)
	if known == nil {
		known = []cirun.KnownFinding{}
	}
	res.Known, res.KnownTotal, res.KnownTruncated = known, total, total > len(known)
	return res, nil
}

// applyExport converts a run's tool export (the same content sniffing,
// limits and archive checks as the import endpoint) and applies each
// converted report on the run's repository. The first report uses the slot
// reserved at accept; each further one takes its own.
func (s *Service) applyExport(ctx context.Context, run *cirun.Run, body []byte) (*UploadResult, error) {
	res := &UploadResult{Files: []ExportFile{}, Known: []cirun.KnownFinding{}}
	total := &ingest.Output{}
	var firstErr error
	var refusedFile *findingimport.FileError
	reports := 0
	_, refused := findingimport.Convert(ctx, findingimport.Upload{
		Name: "results", Body: bytes.NewReader(body), ReportIDPrefix: run.ID.String(),
		// Code reports are filed on the run's repository, whatever the file
		// names; ScopeImported then drops anything still elsewhere.
		Repository: run.Repository, Branch: run.Branch, CommitSHA: run.CommitSHA,
	}, func(c findingimport.Converted) {
		f := ExportFile{Name: c.Name}
		if c.Error != nil {
			f.Error = &struct {
				Kind    string `json:"kind"`
				Message string `json:"message"`
				Line    int    `json:"line,omitempty"`
				Column  int    `json:"column,omitempty"`
			}{Kind: c.Error.Kind, Message: c.Error.Message, Line: c.Error.Line, Column: c.Error.Column}
			if refusedFile == nil {
				refusedFile = c.Error
			}
			res.Files = append(res.Files, f)
			return
		}
		f.Format = string(c.Result.Format)
		res.Files = append(res.Files, f)
		if firstErr != nil {
			return
		}
		rep := c.Result.Report
		if len(rep.Findings) > 0 || len(rep.Dependencies) > 0 {
			dropped, err := ScopeImported(rep, run)
			res.FindingsDroppedOutOfScope += dropped
			if err == nil && reports > 0 {
				err = s.repo.ReserveRunReport(ctx, run.TenantID, run.ID)
			}
			if err != nil {
				firstErr = err
				return
			}
			reports++
			out, err := s.applyReport(ctx, run, rep)
			if err != nil {
				firstErr = err
				return
			}
			addOutput(total, out)
		}
		if len(c.Result.VEX) > 0 {
			if s.vex == nil {
				return
			}
			// Like findings, statements belong to a run that is still being
			// judged; VEX never closes a finding.
			if run.Status == cirun.StatusEvaluated {
				firstErr = cirun.ErrRunEvaluated
				return
			}
			sum, err := s.vex.ApplyVEXStatements(ctx, findingimport.Request{
				TenantID: run.TenantID, Actor: onlyAsset(run.RepositoryAssetID), SessionID: run.ID.String(),
			}, c.Result.VEX)
			if err != nil {
				firstErr = err
				return
			}
			res.VEXStored += sum.Stored
		}
	})
	if refused != nil {
		if refused.Kind == findingimport.KindTooLarge {
			return nil, ingestjob.Permanent(UploadErrorTooLarge, errors.New(refused.Message))
		}
		return nil, ingestjob.Permanent(UploadErrorUnreadable, errors.New(refused.Message))
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if len(res.Files) == 1 && refusedFile != nil {
		if refusedFile.Kind == findingimport.KindTooLarge {
			return nil, ingestjob.Permanent(UploadErrorTooLarge, errors.New(refusedFile.Message))
		}
		return nil, ingestjob.Permanent(UploadErrorUnreadable, errors.New(refusedFile.Message))
	}
	total.ReportID = run.ID.String()
	r := resultOf(total)
	r.Files, r.FindingsDroppedOutOfScope, r.VEXStored, r.Known = res.Files, res.FindingsDroppedOutOfScope, res.VEXStored, res.Known
	return r, nil
}

// onlyAsset is the data scope of a run: its repository asset only.
type onlyAsset shared.ID

func (o onlyAsset) AssetsInScope(_ context.Context, ids []shared.ID) ([]shared.ID, error) {
	out := make([]shared.ID, 0, 1)
	for _, id := range ids {
		if id == shared.ID(o) {
			out = append(out, id)
		}
	}
	return out, nil
}

func resultOf(o *ingest.Output) *UploadResult {
	return &UploadResult{
		ScanID: o.ReportID, AssetsCreated: o.AssetsCreated, AssetsUpdated: o.AssetsUpdated,
		FindingsCreated: o.FindingsCreated, FindingsUpdated: o.FindingsUpdated, FindingsSkipped: o.FindingsSkipped,
		CVEsCreated: o.CVEsCreated, CVEsUpdated: o.CVEsUpdated, Errors: o.Errors, AssetsLimited: o.AssetsLimited,
		ReopensWithheld: o.ReopensWithheld, AssetsSkippedExcl: o.AssetsSkippedExcluded,
	}
}

// addOutput sums the counts of one converted file's ingest.
func addOutput(t, o *ingest.Output) {
	if o == nil {
		return
	}
	t.AssetsCreated += o.AssetsCreated
	t.AssetsUpdated += o.AssetsUpdated
	t.FindingsCreated += o.FindingsCreated
	t.FindingsUpdated += o.FindingsUpdated
	t.FindingsSkipped += o.FindingsSkipped
	t.CVEsCreated += o.CVEsCreated
	t.CVEsUpdated += o.CVEsUpdated
	t.Errors = append(t.Errors, o.Errors...)
}
