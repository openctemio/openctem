package findingimport

// A committed upload is accepted fast and imported by the ingest worker
// (docs/rfcs/RFC-122-ingest-receipts.md, "Accept fast, apply async").
//
// POST /findings/imports stores each part sealed as it streams in, records
// the receipt (status queued) and enqueues one finding_import job, then
// answers 202 with the receipt. The worker re-resolves the uploader's data
// scope from the caller recorded at accept (a member whose scope shrank in
// the meantime imports with the smaller scope; a member gone is refused),
// imports every file exactly as the request used to, finishes the receipt
// and deletes the stored parts. A preview (dry_run) still runs in the
// request: it writes nothing.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Queue is the ingest queue (ingestqueue.Queue).
type Queue interface {
	StagePart(ctx context.Context, tenantID, jobID shared.ID, part int, name string, body []byte) error
	Commit(ctx context.Context, job *ingestjob.Job, admit func() error) (*ingestjob.Job, bool, error)
	Discard(ctx context.Context, tenantID, jobID shared.ID)
	Recent(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, principal string, digest []byte, window time.Duration) (*ingestjob.Job, error)
	Admit(ctx context.Context, tenantID shared.ID) error
	Get(ctx context.Context, tenantID, id shared.ID, kind ingestjob.Kind) (*ingestjob.Job, error)
	Wait(ctx context.Context, tenantID, id shared.ID, kind ingestjob.Kind, wait time.Duration) (*ingestjob.Job, error)
	BySource(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, sourceRef string) (*ingestjob.Job, error)
	Parts(ctx context.Context, job *ingestjob.Job) ([]ingestqueue.OpenedPart, error)
	Done(ctx context.Context, job *ingestjob.Job) error
}

// Caller is who uploaded, as recorded at accept: the worker resolves the
// data scope from it when the upload is imported.
type Caller struct {
	UserID  string `json:"user_id,omitempty"`
	IsAdmin bool   `json:"is_admin,omitempty"`
	IsOwner bool   `json:"is_owner,omitempty"`
	APIKey  bool   `json:"api_key,omitempty"`
}

// ScopeResolver resolves an uploader's data scope for importing (nil actor:
// unrestricted) and for a full-coverage declaration (nil: every asset).
type ScopeResolver func(ctx context.Context, tenantID shared.ID, c Caller) (actor, coverage ingest.ActorScope, err error)

// Auditor records the import (auditapp.AuditService).
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// SetQueue enables committed uploads: without a queue, a scope resolver
// and an auditor every committed upload is refused (fail closed).
func (s *Service) SetQueue(q Queue, resolve ScopeResolver, audit Auditor) {
	s.queue, s.resolveScope, s.audit = q, resolve, audit
}

// MemberReader reads a user's membership of a tenant (tenant.Repository).
type MemberReader interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenant.Membership, error)
}

// SetMembers makes the worker re-read the uploader's membership before it
// imports a committed upload: the rights recorded at accept time are only
// ever narrowed by it, never widened.
func (s *Service) SetMembers(m MemberReader) { s.members = m }

// currentCaller narrows the uploader recorded at accept time to the
// uploader's membership now: a member who left or was suspended meanwhile
// is shared.ErrNotFound (the upload is refused), a demoted administrator or
// owner imports with the member's data scope. Rights are never widened: a flag is kept only when both the record and
// the current role grant it.
func (s *Service) currentCaller(ctx context.Context, tenantID shared.ID, env *Envelope) error {
	if s.members == nil || env.Caller.UserID == "" {
		return nil
	}
	uid, err := shared.IDFromString(env.Caller.UserID)
	if err != nil {
		return fmt.Errorf("%w: invalid uploader", shared.ErrNotFound)
	}
	m, err := s.members.GetMembership(ctx, uid, tenantID)
	if errors.Is(err, shared.ErrNotFound) {
		return err
	}
	if err != nil {
		return fmt.Errorf("read the uploader's membership: %w", err)
	}
	if m == nil || !m.IsActive() {
		return fmt.Errorf("%w: the uploader is no longer an active member", shared.ErrNotFound)
	}
	env.Caller.IsOwner = env.Caller.IsOwner && m.IsOwner()
	env.Caller.IsAdmin = env.Caller.IsAdmin && (m.IsOwner() || m.IsAdmin())
	return nil
}

// ErrQueueUnavailable: committed uploads are not available.
var ErrQueueUnavailable = errors.New("imports are not available right now")

// DigestWindow is how long the same files from the same principal, sent
// again without an Idempotency-Key, are the same upload.
const DigestWindow = 10 * time.Minute

// EnvelopePart is one stored part of an upload.
type EnvelopePart struct {
	Part int    `json:"part"`
	KB   bool   `json:"kb,omitempty"`
	Name string `json:"name"`
}

// Envelope is what the worker needs besides the stored parts.
type Envelope struct {
	SessionID   string         `json:"session_id"`
	Format      string         `json:"format,omitempty"`
	MinSeverity string         `json:"min_severity,omitempty"`
	CanApprove  bool           `json:"can_approve,omitempty"`
	CoverageAll bool           `json:"coverage_full,omitempty"`
	CoverageIDs []string       `json:"coverage_asset_ids,omitempty"`
	Caller      Caller         `json:"caller"`
	Parts       []EnvelopePart `json:"parts"`
	// Audit is the request's audit context (who, from where), for the
	// record written when the upload is imported.
	Audit auditapp.AuditContext `json:"audit"`
}

// Accepted is a stored upload.
type Accepted struct {
	ReceiptID shared.ID
	// Status is the upload's state (queued for a new one).
	Status ingestqueue.Status
	// Replayed: the same files from the same principal were uploaded
	// within DigestWindow; this is that upload.
	Replayed bool
}

// AdmitUpload runs the tenant's queue back-pressure before an upload's
// parts are read and stored, so a tenant at its limit writes nothing
// (CommitUpload checks again against the stored queue).
func (s *Service) AdmitUpload(ctx context.Context, tenantID shared.ID) error {
	if s.queue == nil {
		return ErrQueueUnavailable
	}
	return s.queue.Admit(ctx, tenantID)
}

// StagePart stores one part of an upload that is still being received.
func (s *Service) StagePart(ctx context.Context, tenantID, jobID shared.ID, part int, name string, body []byte) error {
	if s.queue == nil {
		return ErrQueueUnavailable
	}
	return s.queue.StagePart(ctx, tenantID, jobID, part, name, body)
}

// DiscardParts drops the parts of an upload that will not be enqueued.
func (s *Service) DiscardParts(ctx context.Context, tenantID, jobID shared.ID) {
	if s.queue != nil {
		s.queue.Discard(ctx, tenantID, jobID)
	}
}

// CommitUpload records the receipt of a fully received upload (status
// queued) and enqueues it. digest is the request fingerprint; the same
// fingerprint from the same principal within DigestWindow returns that
// upload instead (Replayed), unless the caller holds an Idempotency-Key
// (keyed=true), which decides on its own.
func (s *Service) CommitUpload(ctx context.Context, tenantID shared.ID, actorUserID *shared.ID, jobID shared.ID,
	principal string, digest []byte, keyed bool, firstName string, env Envelope) (*Accepted, error) {
	if s.queue == nil || s.resolveScope == nil || s.receipts == nil {
		s.DiscardParts(context.WithoutCancel(ctx), tenantID, jobID)
		return nil, ErrQueueUnavailable
	}
	if !keyed {
		prev, err := s.queue.Recent(ctx, tenantID, ingestjob.KindFindingImport, principal, digest, DigestWindow)
		if err != nil {
			s.DiscardParts(context.WithoutCancel(ctx), tenantID, jobID)
			return nil, err
		}
		if prev != nil {
			if rid, perr := shared.IDFromString(prev.SourceRef()); perr == nil {
				s.DiscardParts(context.WithoutCancel(ctx), tenantID, jobID)
				return &Accepted{ReceiptID: rid, Status: ingestqueue.StatusOf(prev), Replayed: true}, nil
			}
		}
	}
	// Back-pressure before the receipt: a refused upload leaves no trace.
	if err := s.queue.Admit(ctx, tenantID); err != nil {
		s.DiscardParts(context.WithoutCancel(ctx), tenantID, jobID)
		return nil, err
	}
	receiptID := shared.NewID()
	if err := s.receipts.CreateUpload(ctx, &ingestreceipt.Upload{
		ID: receiptID, TenantID: tenantID, ActorUserID: actorUserID, Format: env.Format,
		FilenameSHA256: nameHash(firstName), Status: ingestreceipt.StatusQueued,
	}); err != nil {
		s.DiscardParts(context.WithoutCancel(ctx), tenantID, jobID)
		s.logger.Error("finding import: receipt", "tenant_id", tenantID.String(), "error", err)
		return nil, ErrReceiptUnavailable
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	job := ingestjob.NewUploadJob(jobID, tenantID, ingestjob.KindFindingImport, receiptID.String(), principal,
		"import:"+receiptID.String(), raw, digest)
	// A person waits on it; the imports of a tenant are applied one at a
	// time (an import may name any of its assets).
	job.Route(ingestjob.LaneInteractive, ingestjob.ScopeKey(tenantID, "import"))
	if _, _, err := s.queue.Commit(ctx, job, nil); err != nil {
		s.failReceipt(context.WithoutCancel(ctx), tenantID, receiptID, ingestreceipt.ErrorStoreFailed)
		return nil, err
	}
	return &Accepted{ReceiptID: receiptID, Status: ingestqueue.StatusQueued}, nil
}

// failReceipt marks an upload's receipt failed with a fixed code.
func (s *Service) failReceipt(ctx context.Context, tenantID, receiptID shared.ID, code string) {
	if err := s.receipts.FinishUpload(ctx, tenantID, receiptID, &ingestreceipt.UploadResult{
		Status: ingestreceipt.StatusFailed, Errors: []ingestreceipt.ErrorEntry{{Index: -1, Code: code}},
	}); err != nil {
		s.logger.Warn("finding import: fail receipt", "tenant_id", tenantID.String(), "error", err)
	}
}

// Public error codes of an import that failed for good.
const (
	ImportErrorUploaderGone = "uploader_not_permitted"
	ImportErrorUnreadable   = "unreadable"
)

// ProcessImportJob imports a queued upload (the ingest worker, kind
// finding_import). It returns the per-file results as stored on the job.
func (s *Service) ProcessImportJob(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	if s.queue == nil || s.resolveScope == nil {
		return nil, ErrQueueUnavailable
	}
	var env Envelope
	if err := json.Unmarshal(job.Payload(), &env); err != nil {
		return nil, ingestjob.Permanent(ImportErrorUnreadable, err)
	}
	receiptID, err := shared.IDFromString(job.SourceRef())
	if err != nil {
		return nil, ingestjob.Permanent(ImportErrorUnreadable, err)
	}
	tenantID := job.TenantID()
	// An upload is never imported with more than the uploader's rights: a
	// caller without a user is only an API key with no user (which reads
	// nothing scoped), never "internal".
	if env.Caller.UserID == "" && !env.Caller.APIKey {
		return nil, ingestjob.Permanent(ImportErrorUploaderGone, errors.New("no uploader recorded"))
	}
	if err := s.currentCaller(ctx, tenantID, &env); errors.Is(err, shared.ErrNotFound) {
		return nil, ingestjob.Permanent(ImportErrorUploaderGone, err)
	} else if err != nil {
		return nil, err
	}
	actor, coverage, err := s.resolveScope(ctx, tenantID, env.Caller)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, ingestjob.Permanent(ImportErrorUploaderGone, err)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve the uploader's scope: %w", err)
	}
	req, err := env.request(tenantID, receiptID, actor, coverage)
	if err != nil {
		return nil, ingestjob.Permanent(ImportErrorUnreadable, err)
	}
	parts, err := s.queue.Parts(ctx, job)
	if err != nil {
		return nil, err
	}
	s.markProcessing(ctx, tenantID, receiptID)

	byPart := map[int][]byte{}
	for _, p := range parts {
		byPart[p.Part] = p.Body
	}
	var kb []byte
	var results []FileResult
	for i, ep := range env.Parts {
		body, ok := byPart[ep.Part]
		if !ok {
			return nil, ingestjob.Permanent(ingestqueue.ErrorPayloadMissing, fmt.Errorf("part %d missing", ep.Part))
		}
		if ep.KB {
			kb = body
			continue
		}
		res, archive, refused := s.ImportUpload(ctx, req, Upload{
			Name: ep.Name, Body: bytes.NewReader(body), KnowledgeBase: kb,
			ReportIDPrefix: fmt.Sprintf("%s-%d", req.SessionID, i), TempDir: s.tempDir,
		})
		switch {
		case refused != nil:
			results = append(results, FileResult{Name: ep.Name, Error: refused})
		case !archive && len(res) == 0:
			results = append(results, FileResult{Name: ep.Name, Error: &FileError{Kind: KindMalformed, Message: "the file holds nothing to import"}})
		default:
			results = append(results, res...)
		}
	}
	s.FinishUpload(context.WithoutCancel(ctx), req, results, true)
	if s.audit != nil {
		actx := env.Audit
		actx.TenantID = tenantID.String()
		AuditImport(ctx, s.audit, actx, req, results, s.vexMode)
	}
	out, err := json.Marshal(QueuedResult{Files: results})
	if err != nil {
		return nil, err
	}
	// The stored parts are deleted when the worker records the job
	// completed (IngestJobRepository.Complete), not here: a crash before
	// that re-imports the upload instead of failing an applied one.
	return out, nil
}

// QueuedResult is what an imported upload stores on its job: the per-file
// results the upload used to answer with.
type QueuedResult struct {
	Files []FileResult `json:"files"`
}

// DeadLetter marks the receipt of an upload that failed for good, with the
// job's fixed code.
func (s *Service) DeadLetter(ctx context.Context, job *ingestjob.Job, publicErr string) {
	rid, err := shared.IDFromString(job.SourceRef())
	if err != nil || s.receipts == nil {
		return
	}
	if publicErr == "" {
		publicErr = ingestjob.ErrorApplyFailed
	}
	s.failReceipt(ctx, job.TenantID(), rid, publicErr)
}

// markProcessing moves a queued receipt to processing. Best effort.
func (s *Service) markProcessing(ctx context.Context, tenantID, receiptID shared.ID) {
	if m, ok := s.receipts.(interface {
		MarkUploadProcessing(ctx context.Context, tenantID, id shared.ID) error
	}); ok {
		if err := m.MarkUploadProcessing(ctx, tenantID, receiptID); err != nil {
			s.logger.Warn("finding import: mark receipt processing", "error", logger.SanitizeError(err))
		}
	}
}

// UploadState is the state of a committed upload's job.
type UploadState struct {
	Status    ingestqueue.Status
	ErrorCode string
	Files     []FileResult
}

// UploadResult returns the state of a committed upload, waiting up to wait
// for it to finish. An upload of another tenant is shared.ErrNotFound.
func (s *Service) UploadResult(ctx context.Context, tenantID, receiptID shared.ID, wait time.Duration) (*UploadState, error) {
	if s.queue == nil {
		return nil, ErrQueueUnavailable
	}
	job, err := s.findJob(ctx, tenantID, receiptID)
	if err != nil {
		return nil, err
	}
	if wait > 0 && !job.Status().IsTerminal() {
		if job, err = s.queue.Wait(ctx, tenantID, job.ID(), ingestjob.KindFindingImport, min(wait, ingestqueue.MaxWait)); err != nil {
			return nil, err
		}
	}
	st := &UploadState{Status: ingestqueue.StatusOf(job), ErrorCode: job.PublicError()}
	if job.Status() == ingestjob.StatusCompleted {
		var r QueuedResult
		if json.Unmarshal(job.Result(), &r) == nil {
			st.Files = r.Files
		}
	}
	return st, nil
}

// findJob finds the job of an upload receipt.
func (s *Service) findJob(ctx context.Context, tenantID, receiptID shared.ID) (*ingestjob.Job, error) {
	return s.queue.BySource(ctx, tenantID, ingestjob.KindFindingImport, receiptID.String())
}

// request rebuilds the import request from the envelope.
func (e Envelope) request(tenantID, receiptID shared.ID, actor, coverage ingest.ActorScope) (Request, error) {
	req := Request{
		TenantID: tenantID, Actor: actor, CanApprove: e.CanApprove, SessionID: e.SessionID,
		ReceiptID: receiptID, CoverageScope: coverage,
	}
	if e.Caller.UserID != "" {
		if uid, err := shared.IDFromString(e.Caller.UserID); err == nil {
			req.ActorUserID = &uid
		}
	}
	if e.Format != "" {
		f := importer.Format(e.Format)
		if !f.IsValid() {
			return req, fmt.Errorf("unknown format %q", e.Format)
		}
		req.Format = f
	}
	if e.MinSeverity != "" {
		sev := ctis.Severity(e.MinSeverity)
		if !sev.IsValid() {
			return req, fmt.Errorf("unknown severity %q", e.MinSeverity)
		}
		req.MinSeverity = sev
	}
	req.Coverage.Full = e.CoverageAll
	for _, raw := range e.CoverageIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			return req, err
		}
		req.Coverage.AssetIDs = append(req.Coverage.AssetIDs, id)
	}
	return req, nil
}

// DataScopeResolver resolves an uploader's scope through the data scope
// enforcer, the same decision the request made: an unrestricted uploader
// imports without a scope (it may create assets), a restricted one only on
// its scope rows; a full-coverage declaration always uses the scope (an
// administrator cannot close the findings of a private program asset
// hidden from them). A nil enforcer refuses (fail closed).
func DataScopeResolver(ds *datascope.Enforcer) ScopeResolver {
	return func(ctx context.Context, tenantID shared.ID, c Caller) (ingest.ActorScope, ingest.ActorScope, error) {
		if ds == nil {
			return nil, nil, errors.New("no data scope enforcer")
		}
		scope, err := ds.ResolveForStrict(ctx, tenantID, datascope.Caller{UserID: c.UserID, IsAdmin: c.IsAdmin,
			IsOwner: c.IsOwner, APIKey: c.APIKey})
		if err != nil {
			return nil, nil, err
		}
		if scope == nil {
			return nil, nil, nil
		}
		sc := ScopedActor{Enforcer: ds, Scope: scope}
		if !scope.Restricted() {
			return nil, sc, nil
		}
		return sc, sc, nil
	}
}

// ScopedActor is the data scope of a person uploading a report, as the
// ingest service consumes it.
type ScopedActor struct {
	Enforcer *datascope.Enforcer
	Scope    *shared.DataScope
}

// AssetsInScope implements ingest.ActorScope.
func (u ScopedActor) AssetsInScope(ctx context.Context, ids []shared.ID) ([]shared.ID, error) {
	admit, err := u.Enforcer.Filter(ctx, u.Scope, ids)
	if err != nil {
		return nil, err
	}
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if admit(id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// maxAuditedImportIDs bounds the finding ids one audit record lists.
const maxAuditedImportIDs = 100

// AuditImport records an import (or a preview): counts, formats and file
// names, never file content. A VEX document that closed findings, or would
// have, gets its own record listing them.
func AuditImport(ctx context.Context, audit Auditor, actx auditapp.AuditContext, req Request, results []FileResult, vexMode ingest.VEXMode) {
	if audit == nil {
		return
	}
	importIDs := make([]string, 0, len(results))
	names := make([]string, 0, len(results))
	formats := make([]string, 0, len(results))
	var assetsC, assetsU, skipped, findC, findU, failed, vexStored, vexRequested, vexWould int
	var vexIDs []string
	for i := range results {
		fr := &results[i]
		names = append(names, fr.Name)
		if fr.ImportID != "" {
			importIDs = append(importIDs, fr.ImportID)
		}
		formats = append(formats, string(fr.Format))
		if fr.Error != nil {
			failed++
		}
		if o := fr.Ingest; o != nil {
			assetsC += o.AssetsCreated
			assetsU += o.AssetsUpdated
			skipped += o.AssetsSkippedOutOfScope
			findC += o.FindingsCreated
			findU += o.FindingsUpdated
		}
		if v := fr.VEX; v != nil {
			vexStored += v.Stored
			vexRequested += v.Requested
			vexWould += v.WouldClose
			for _, id := range v.FindingIDs {
				if len(vexIDs) < maxAuditedImportIDs {
					vexIDs = append(vexIDs, id.String())
				}
			}
		}
	}
	msg := "Findings imported from files"
	if req.DryRun {
		msg = "Finding import previewed"
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAssetImported, auditdom.ResourceTypeFinding, req.SessionID).
		WithMessage(msg).
		WithSeverity(auditdom.SeverityForAction(auditdom.ActionAssetImported)).
		WithMetadata("source", "finding_import").
		WithMetadata("dry_run", req.DryRun).
		WithMetadata("restricted_uploader", req.Actor != nil).
		WithMetadata("import_ids", importIDs).
		WithMetadata("files", names).
		WithMetadata("formats", formats).
		WithMetadata("files_failed", failed).
		WithMetadata("assets_created", assetsC).
		WithMetadata("assets_updated", assetsU).
		WithMetadata("assets_skipped_out_of_scope", skipped).
		WithMetadata("findings_created", findC).
		WithMetadata("findings_updated", findU).
		WithMetadata("vex_stored", vexStored).
		WithMetadata("vex_requested", vexRequested).
		WithMetadata("vex_would_close", vexWould)
	_ = audit.LogEvent(ctx, actx, event)

	if len(vexIDs) > 0 && !req.DryRun {
		action := auditdom.ActionIngestVEXDryRun
		if vexRequested > 0 {
			action = auditdom.ActionIngestVEXApplied
		}
		ve := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeIngest, req.SessionID).
			WithMessage("VEX not_affected from an imported document").
			WithSeverity(auditdom.SeverityForAction(action)).
			WithMetadata("source", "finding_import").
			WithMetadata("import_ids", importIDs).
			WithMetadata("mode", string(vexMode)).
			WithMetadata("requested", vexRequested).
			WithMetadata("would_close", vexWould).
			WithMetadata("finding_ids", vexIDs).
			WithMetadata("finding_ids_truncated", vexRequested+vexWould > len(vexIDs))
		_ = audit.LogEvent(ctx, actx, ve)
	}
}
