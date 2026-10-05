// Package audit implements the application service for the audit bounded context — orchestrates pkg/domain/audit entities and cross-cutting concerns (audit, notifications, RBAC).
package audit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify"
	cryptopkg "github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AuditService handles audit logging operations.
type AuditService struct {
	auditRepo auditdom.Repository
	logger    *logger.Logger
	// Buffer for batch operations (optional async processing)
	asyncEnabled bool
	// chainMu serialises hash-chain extension so two concurrent
	// LogEvent calls for the same tenant cannot both see the same
	// prev_hash and write sibling rows. Single-replica safe; scaling
	// beyond one API replica requires a postgres advisory lock.
	chainMu sync.Mutex
}

// NewAuditService creates a new AuditService.
func NewAuditService(repo auditdom.Repository, log *logger.Logger) *AuditService {
	return &AuditService{
		auditRepo:    repo,
		logger:       log.With("service", "audit"),
		asyncEnabled: false,
	}
}

// AuditContext holds contextual information for audit logging.
type AuditContext struct {
	TenantID   string
	ActorID    string
	ActorEmail string
	ActorIP    string
	UserAgent  string
	RequestID  string
	SessionID  string
	// ActorRole captures the caller's role at the moment of the action.
	// Used by pentest module to distinguish reviewer QA edits from creator
	// self-edits in audit forensics. Optional — empty for non-pentest paths.
	ActorRole string
}

// LogEvent creates and persists an audit log entry.
func (s *AuditService) LogEvent(ctx context.Context, actx AuditContext, event AuditEvent) error {
	log, err := auditdom.NewAuditLog(
		event.Action,
		event.ResourceType,
		event.ResourceID,
		event.Result,
	)
	if err != nil {
		s.logger.Error("failed to create audit log", "error", err)
		return err
	}

	// Set tenant context
	if actx.TenantID != "" {
		tenantID, err := shared.IDFromString(actx.TenantID)
		if err == nil {
			log.WithTenantID(tenantID)
		}
	}

	// Set actor information
	if actx.ActorID != "" {
		actorID, err := shared.IDFromString(actx.ActorID)
		if err == nil {
			log.WithActor(actorID, actx.ActorEmail)
		}
	} else if actx.ActorEmail != "" {
		// System action with email only
		log.WithActor(shared.ID{}, actx.ActorEmail)
	}

	// Set request context
	if actx.ActorIP != "" {
		log.WithActorIP(actx.ActorIP)
	}
	if actx.UserAgent != "" {
		log.WithActorUserAgent(actx.UserAgent)
	}
	if actx.RequestID != "" {
		log.WithRequestID(actx.RequestID)
	}
	if actx.SessionID != "" {
		log.WithSessionID(actx.SessionID)
	}
	// Stamp the actor's role into metadata so audit reviewers can distinguish
	// reviewer QA actions from creator self-edits without joining other tables.
	if actx.ActorRole != "" {
		log.WithMetadata("actor_role", actx.ActorRole)
	}

	// Set event details
	if event.ResourceName != "" {
		log.WithResourceName(event.ResourceName)
	}
	if event.Changes != nil {
		log.WithChanges(event.Changes)
	}
	if event.Message != "" {
		log.WithMessage(event.Message)
	}
	if event.Severity != "" {
		log.WithSeverity(event.Severity)
	}
	for k, v := range event.Metadata {
		log.WithMetadata(k, v)
	}
	// Attribute the action to the API key that performed it (the actor is the
	// key's user). Stamped after the event metadata so it cannot be overwritten.
	if k, ok := apiKeyActorFrom(ctx); ok {
		log.WithMetadata("auth_method", "api_key")
		log.WithMetadata("api_key_id", k.id)
		log.WithMetadata("api_key_prefix", k.prefix)
	}

	// Persist
	if err := s.auditRepo.Create(ctx, log); err != nil {
		s.logger.Error("failed to persist audit log",
			"error", err,
			"action", event.Action,
			"resource_type", event.ResourceType,
			"resource_id", event.ResourceID,
		)
		return err
	}

	// Append to the tamper-evident hash-chain (migration 000154).
	// Best-effort: a chain failure does not roll back the audit log.
	// Verification would detect the missing row as a chain gap, which
	// is strictly better than dropping the audit entry altogether.
	s.appendChainEntry(ctx, log)

	// Log to structured logger as well for immediate visibility
	s.logger.Info("audit event",
		"action", event.Action.String(),
		"resource_type", event.ResourceType.String(),
		"resource_id", event.ResourceID,
		"result", event.Result.String(),
		"actor_email", actx.ActorEmail,
		"tenant_id", actx.TenantID,
	)

	return nil
}

// ChainBreak describes a single inconsistency discovered while
// walking the audit hash-chain for a tenant.
type ChainBreak struct {
	AuditLogID    string
	ChainPosition int64
	ExpectedHash  string // hash recomputed from the audit_log row
	ActualHash    string // hash stored in audit_log_chain
	Reason        string // "hash_mismatch" | "prev_hash_mismatch" | "audit_log_missing"
}

// ChainVerifyResult is the outcome of a VerifyChain call.
// OK is true iff Breaks is empty.
type ChainVerifyResult struct {
	TenantID string
	Total    int
	Verified int
	Breaks   []ChainBreak
	OK       bool
}

// chainPageSize is how many chain rows are loaded per keyset page while
// walking a chain. It bounds memory per page; it does NOT bound how much of the
// chain is walked.
const chainPageSize = 1000

// walkChain calls fn for every chain entry of tenantID in chain_position order,
// loading the chain one keyset page at a time. maxEntries <= 0 walks the whole
// chain; a positive value stops after that many entries.
//
// The chain used to be read with a single LIMIT 10000 query ordered oldest
// first. Once a tenant (or the system chain, which takes every login) passed
// 10,000 entries, everything written after that was never verified again — the
// oldest rows were re-checked every hour while the newest, the ones an intruder
// would edit, were never looked at. Rebaseline had the same cap, so re-signing
// a long chain rewrote the first 10,000 rows and left the 10,001st pointing at
// a hash that no longer existed.
func (s *AuditService) walkChain(ctx context.Context, tenantID shared.ID, maxEntries int, fn func(auditdom.ChainEntry) error) error {
	var after int64
	seen := 0
	for {
		page := chainPageSize
		if maxEntries > 0 && maxEntries-seen < page {
			page = maxEntries - seen
		}
		if page <= 0 {
			return nil
		}
		entries, err := s.auditRepo.ListChainEntries(ctx, tenantID, after, page)
		if err != nil {
			return fmt.Errorf("list chain entries: %w", err)
		}
		for _, e := range entries {
			if err := fn(e); err != nil {
				return err
			}
			after = e.ChainPosition
			seen++
		}
		if len(entries) < page {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// VerifyChain walks the audit_log_chain entries for a tenant in
// chain_position order and confirms each stored hash matches the hash
// recomputed from the original audit_logs row. A single tampered audit
// row surfaces as (at least) one break; downstream entries typically
// break too because prev_hash no longer links.
//
// limit <= 0 walks the whole chain (what the periodic verifier does); a
// positive limit verifies only the first limit entries. The chain is read in
// keyset pages, so memory is bounded by the page size, not the chain length.
func (s *AuditService) VerifyChain(ctx context.Context, tenantID shared.ID, limit int) (*ChainVerifyResult, error) {
	res := &ChainVerifyResult{
		TenantID: tenantID.String(),
	}
	prevStored, err := s.chainStart(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	err = s.walkChain(ctx, tenantID, limit, func(e auditdom.ChainEntry) error {
		res.Total++
		// 1. Fetch the original audit_log. If it's gone, flag it — a
		//    deleted row is a tamper signal (FK ON DELETE RESTRICT
		//    blocks it in production but not in every path).
		// System-chain entries point at audit_logs rows with tenant_id IS NULL,
		// which the tenant-scoped getter cannot see — using it here would
		// report every one of them as audit_log_missing, i.e. a fabricated
		// tamper signal on the chain that exists to detect real ones.
		var log *auditdom.AuditLog
		var err error
		if tenantID == auditdom.SystemChainTenantID {
			log, err = s.auditRepo.GetSystemByID(ctx, e.AuditLogID)
		} else {
			log, err = s.auditRepo.GetByTenantAndID(ctx, tenantID, e.AuditLogID)
		}
		if err != nil {
			res.Breaks = append(res.Breaks, ChainBreak{
				AuditLogID:    e.AuditLogID.String(),
				ChainPosition: e.ChainPosition,
				ExpectedHash:  "",
				ActualHash:    e.Hash,
				Reason:        "audit_log_missing",
			})
			prevStored = e.Hash
			return nil //nolint:nilerr // a missing source row is reported as a break, and the walk continues
		}

		// 2. Recompute hash from the audit_log fields + stored prev_hash.
		payload := fmt.Sprintf("%s|%s|%s|%s",
			log.Action().String(),
			log.ResourceType().String(),
			log.ResourceID(),
			log.Result().String(),
		)
		expected := cryptopkg.ComputeAuditChainHash(e.PrevHash, log.ID().String(), payload, log.Timestamp())

		if expected != e.Hash {
			res.Breaks = append(res.Breaks, ChainBreak{
				AuditLogID:    e.AuditLogID.String(),
				ChainPosition: e.ChainPosition,
				ExpectedHash:  expected,
				ActualHash:    e.Hash,
				Reason:        "hash_mismatch",
			})
		} else if e.ChainPosition > 1 && e.PrevHash != prevStored {
			// 3. prev_hash link check. We intentionally do this ONLY
			//    when the hash itself was OK — a hash_mismatch already
			//    tells the whole story; prepending a prev-hash break
			//    would double-count.
			res.Breaks = append(res.Breaks, ChainBreak{
				AuditLogID:    e.AuditLogID.String(),
				ChainPosition: e.ChainPosition,
				ExpectedHash:  prevStored,
				ActualHash:    e.PrevHash,
				Reason:        "prev_hash_mismatch",
			})
		} else {
			res.Verified++
		}
		prevStored = e.Hash
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.OK = len(res.Breaks) == 0
	return res, nil
}

// chainStart is the prev_hash a tenant's oldest remaining chain entry links
// to: the newest retention anchor, or "" when the chain was never pruned.
func (s *AuditService) chainStart(ctx context.Context, tenantID shared.ID) (string, error) {
	ar, ok := s.auditRepo.(auditdom.ChainAnchorReader)
	if !ok {
		return "", nil
	}
	h, err := ar.ChainAnchorHash(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("read chain anchor: %w", err)
	}
	return h, nil
}

// RebaselineResult is the outcome of a RebaselineChain call.
type RebaselineResult struct {
	// RebaselineID identifies the archived record (audit_chain_rebaselines)
	// holding the hashes this rebaseline overwrote.
	RebaselineID     string `json:"rebaseline_id"`
	EntriesTotal     int    `json:"entries_total"`
	EntriesRewritten int    `json:"entries_rewritten"`
}

// RebaselineChain re-signs a tenant's entire audit hash-chain from the current
// audit_logs data, recomputing prev_hash + hash for every entry in position
// order. It exists to clear breaks caused by a known-benign hashing change (the
// timestamp-precision fix, migration-era rows whose sub-microsecond digits are
// unrecoverable) — NOT to dismiss tampering. Run `go run ./cmd/chainaudit`
// first; it should report 0 UNEXPLAINED breaks.
//
// SECURITY: this overwrites the tamper-evident chain, so it accepts the current
// DB state as authoritative. To keep that reviewable:
//   - the old and new hashes of every rewritten entry are archived in the same
//     transaction as the rewrite, which is all-or-nothing;
//   - the action is recorded as a critical audit.chain_rebaselined event (and
//     a failed attempt as a failure event);
//   - it refuses, changing nothing, if an underlying audit_log is missing,
//     since that is a genuine tamper signal it must not paper over.
func (s *AuditService) RebaselineChain(ctx context.Context, tenantID shared.ID, actx AuditContext) (*RebaselineResult, error) {
	res, _, err := s.rebaseline(ctx, tenantID, actx, actx.ActorID, nil)
	return res, err
}

// ErrChainUnexplained means a rebaseline was refused because the chain has a
// break no known defect explains (or a missing source row, or a broken link).
var ErrChainUnexplained = fmt.Errorf("%w: audit chain has unexplained breaks", shared.ErrConflict)

// ErrChainFingerprintMismatch means a rebaseline was refused because the chain
// is no longer the one the caller classified and reviewed.
var ErrChainFingerprintMismatch = fmt.Errorf("%w: audit chain changed since it was classified", shared.ErrConflict)

// ClassifyChain classifies every row of a tenant's chain (see chainclassify):
// how many verify, how many are explained by a known hashing defect, and how
// many are not. The report's fingerprint names the exact chain classified.
func (s *AuditService) ClassifyChain(ctx context.Context, tenantID shared.ID) (*chainclassify.Report, error) {
	start, err := s.chainStart(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	b := chainclassify.NewBuilderFrom(start)
	err = s.walkChain(ctx, tenantID, 0, func(e auditdom.ChainEntry) error {
		log, err := s.chainSource(ctx, tenantID, e)
		if err != nil || log == nil {
			b.AddMissing(e.ChainPosition, e.AuditLogID.String(), e.PrevHash, e.Hash)
			return nil //nolint:nilerr // a missing source row is classified, and the walk continues
		}
		b.Add(chainRow(e, log))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b.Report(), nil
}

// RebaselineChainIfExplained is RebaselineChain for the platform admin console:
// it re-runs the classification in the same locked walk that computes the new
// hashes and refuses, rewriting nothing, unless every break is explained by a
// known defect AND the chain is exactly the one the caller reviewed
// (expectedFingerprint, from ClassifyChain). The classification of that walk is
// returned with a refusal so the caller can show why.
//
// archiveActorID is recorded on the archive row (audit_chain_rebaselines, a
// plain UUID); actx attributes the tenant audit event.
func (s *AuditService) RebaselineChainIfExplained(ctx context.Context, tenantID shared.ID, expectedFingerprint string,
	actx AuditContext, archiveActorID string,
) (*RebaselineResult, *chainclassify.Report, error) {
	if expectedFingerprint == "" {
		return nil, nil, fmt.Errorf("%w: classification fingerprint is required", shared.ErrValidation)
	}
	return s.rebaseline(ctx, tenantID, actx, archiveActorID, func(rep *chainclassify.Report) error {
		if !rep.RebaselineAllowed() {
			return fmt.Errorf("cannot re-baseline: %w (%d unexplained, %d missing source, %d broken links)",
				ErrChainUnexplained, rep.Counts.Unexplained, rep.Counts.SourceMissing, rep.Counts.LinkBroken)
		}
		if rep.Fingerprint != expectedFingerprint {
			return fmt.Errorf("cannot re-baseline: %w", ErrChainFingerprintMismatch)
		}
		return nil
	})
}

// rebaseline runs a rebaseline and records it on the tenant's chain. guard,
// when set, sees the classification of the chain about to be re-signed and
// may refuse it.
func (s *AuditService) rebaseline(ctx context.Context, tenantID shared.ID, actx AuditContext, archiveActorID string,
	guard func(*chainclassify.Report) error,
) (*RebaselineResult, *chainclassify.Report, error) {
	// The event must land on the chain that was rebaselined.
	actx.TenantID = tenantID.String()

	// rebaselineLocked holds chainMu; it is released before the audit event
	// is written because LogEvent -> appendChainEntry takes chainMu itself.
	res, rep, err := s.rebaselineLocked(ctx, tenantID, archiveActorID, guard)
	if err != nil {
		event := NewFailureEvent(auditdom.ActionAuditChainRebaselined, auditdom.ResourceTypeAuditChain, tenantID.String(), err).
			WithSeverity(auditdom.SeverityCritical).
			WithMessage("Audit hash-chain rebaseline refused or failed; nothing was rewritten")
		if logErr := s.LogEvent(ctx, actx, event); logErr != nil {
			s.logger.Error("failed to audit a failed chain rebaseline",
				"tenant_id", tenantID.String(), "error", logErr)
		}
		return nil, rep, err
	}

	s.logger.Warn("audit chain re-baselined",
		"tenant_id", tenantID.String(),
		"actor_id", archiveActorID,
		"rebaseline_id", res.RebaselineID,
		"entries_total", res.EntriesTotal,
		"entries_rewritten", res.EntriesRewritten,
		"alert", "audit_chain_rebaselined",
	)

	event := NewSuccessEvent(auditdom.ActionAuditChainRebaselined, auditdom.ResourceTypeAuditChain, res.RebaselineID).
		WithSeverity(auditdom.SeverityCritical).
		WithMessage(fmt.Sprintf("Audit hash-chain rebaselined: %d of %d entries re-signed; old hashes archived",
			res.EntriesRewritten, res.EntriesTotal)).
		WithMetadata("rebaseline_id", res.RebaselineID).
		WithMetadata("entries_total", res.EntriesTotal).
		WithMetadata("entries_rewritten", res.EntriesRewritten).
		WithMetadata("actor_id", archiveActorID)
	if rep != nil {
		event = event.
			WithMetadata("classification_fingerprint", rep.Fingerprint).
			WithMetadata("legacy_truncate", rep.Counts.LegacyTruncate).
			WithMetadata("pre_79_nanosecond", rep.Counts.PreHashReduction)
	}
	if err := s.LogEvent(ctx, actx, event); err != nil {
		// The rewrite is committed and its archive row names the actor, so
		// the evidence survives; this only loses the audit_logs copy.
		s.logger.Error("chain rebaselined but its audit event was not written",
			"tenant_id", tenantID.String(), "rebaseline_id", res.RebaselineID, "error", err)
	}
	return res, rep, nil
}

func (s *AuditService) rebaselineLocked(ctx context.Context, tenantID shared.ID, actorID string,
	guard func(*chainclassify.Report) error,
) (*RebaselineResult, *chainclassify.Report, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	rb := auditdom.ChainRebaseline{
		ID:       shared.NewID(),
		TenantID: tenantID,
	}
	if id, err := shared.IDFromString(actorID); err == nil && !id.IsZero() {
		rb.ActorID = &id
	}

	start, err := s.chainStart(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	var classify *chainclassify.Builder
	if guard != nil {
		classify = chainclassify.NewBuilderFrom(start)
	}
	// A pruned chain is re-signed from its retention anchor, so it still
	// links to the archived prefix.
	prev := start
	err = s.walkChain(ctx, tenantID, 0, func(e auditdom.ChainEntry) error {
		rb.EntriesTotal++
		log, err := s.auditRepo.GetByTenantAndID(ctx, tenantID, e.AuditLogID)
		if err != nil || log == nil {
			// A missing source row is a real tamper signal — refuse to
			// re-baseline over it. Nothing has been written yet.
			return fmt.Errorf("cannot re-baseline: %w: audit log %s (position %d)",
				auditdom.ErrChainSourceMissing, e.AuditLogID.String(), e.ChainPosition)
		}
		if classify != nil {
			classify.Add(chainRow(e, log))
		}
		payload := chainclassify.Payload(
			log.Action().String(),
			log.ResourceType().String(),
			log.ResourceID(),
			log.Result().String(),
		)
		newHash := cryptopkg.ComputeAuditChainHash(prev, log.ID().String(), payload, log.Timestamp())
		if e.PrevHash != prev || e.Hash != newHash {
			rb.Rewrites = append(rb.Rewrites, auditdom.ChainRewrite{
				AuditLogID:    e.AuditLogID,
				ChainPosition: e.ChainPosition,
				OldPrevHash:   e.PrevHash,
				OldHash:       e.Hash,
				NewPrevHash:   prev,
				NewHash:       newHash,
			})
		}
		prev = newHash
		rb.LastChainPosition = e.ChainPosition
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	var rep *chainclassify.Report
	if classify != nil {
		rep = classify.Report()
		if err := guard(rep); err != nil {
			return nil, rep, err
		}
	}

	if err := s.auditRepo.ApplyChainRebaseline(ctx, rb); err != nil {
		return nil, rep, fmt.Errorf("apply rebaseline: %w", err)
	}
	return &RebaselineResult{
		RebaselineID:     rb.ID.String(),
		EntriesTotal:     rb.EntriesTotal,
		EntriesRewritten: len(rb.Rewrites),
	}, rep, nil
}

// chainSource loads the audit log behind a chain entry. System-chain entries
// point at rows with tenant_id IS NULL, which the tenant-scoped getter cannot
// see.
func (s *AuditService) chainSource(ctx context.Context, tenantID shared.ID, e auditdom.ChainEntry) (*auditdom.AuditLog, error) {
	if tenantID == auditdom.SystemChainTenantID {
		return s.auditRepo.GetSystemByID(ctx, e.AuditLogID)
	}
	return s.auditRepo.GetByTenantAndID(ctx, tenantID, e.AuditLogID)
}

// chainRow is the classifier's view of a chain entry and its audit log.
func chainRow(e auditdom.ChainEntry, log *auditdom.AuditLog) chainclassify.Row {
	return chainclassify.Row{
		AuditLogID:   e.AuditLogID.String(),
		Position:     e.ChainPosition,
		PrevHash:     e.PrevHash,
		Hash:         e.Hash,
		Action:       log.Action().String(),
		ResourceType: log.ResourceType().String(),
		ResourceID:   log.ResourceID(),
		Result:       log.Result().String(),
		LoggedAt:     log.Timestamp(),
	}
}

// chainAppender is implemented by a repository that extends a chain
// atomically across processes (read tail + insert under one per-tenant lock).
type chainAppender interface {
	AppendNextChainEntry(ctx context.Context, tenantID shared.ID, build func(prevHash string) auditdom.ChainEntry) error
}

// appendChainEntry computes the next hash in the per-tenant chain and
// persists it. Safe to call with any audit_log; rows without a tenant
// ID extend the system chain.
//
// Concurrency: two writers for the same tenant must never read the same
// prev_hash and both extend it (that forks the chain and every later
// verification fails). The Postgres repository reads the tail and inserts
// under a per-tenant advisory transaction lock, which holds across API
// replicas. chainMu only covers repositories without that capability
// (tests), within one process.
func (s *AuditService) appendChainEntry(ctx context.Context, log *auditdom.AuditLog) {
	// Tenant-less events (every auth.login / auth.register / auth.failed —
	// 86% of the trail on the live database) used to return here, which left
	// them with no tamper evidence at all. They now extend a dedicated system
	// chain instead. See auditdom.SystemChainTenantID for why a sentinel
	// rather than a nullable column.
	tid := auditdom.SystemChainTenantID
	if tenantPtr := log.TenantID(); tenantPtr != nil {
		tid = *tenantPtr
	}

	// Deterministic payload: scalar columns that uniquely identify
	// the audit log. Changes feed the hash via the log fields below
	// rather than full JSON so minor schema tweaks do not invalidate
	// older hashes.
	payload := fmt.Sprintf("%s|%s|%s|%s",
		log.Action().String(),
		log.ResourceType().String(),
		log.ResourceID(),
		log.Result().String(),
	)
	build := func(prev string) auditdom.ChainEntry {
		return auditdom.ChainEntry{
			AuditLogID: log.ID(),
			TenantID:   tid,
			PrevHash:   prev,
			Hash:       cryptopkg.ComputeAuditChainHash(prev, log.ID().String(), payload, log.Timestamp()),
		}
	}

	if a, ok := s.auditRepo.(chainAppender); ok {
		if err := a.AppendNextChainEntry(ctx, tid, build); err != nil {
			s.logger.Warn("chain: append failed (audit log persisted, chain has a gap)",
				"tenant_id", tid.String(), "audit_log_id", log.ID().String(), "error", err)
		}
		return
	}

	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	prev, err := s.auditRepo.LatestChainHash(ctx, tid)
	if err != nil {
		s.logger.Warn("chain: failed to read prev hash; skipping entry",
			"tenant_id", tid.String(), "error", err)
		return
	}
	if err := s.auditRepo.AppendChainEntry(ctx, build(prev)); err != nil {
		s.logger.Warn("chain: append failed (audit log persisted, chain has a gap)",
			"tenant_id", tid.String(),
			"audit_log_id", log.ID().String(),
			"error", err,
		)
	}
}

// AuditEvent represents an audit event to log.
type AuditEvent struct {
	Action       auditdom.Action
	ResourceType auditdom.ResourceType
	ResourceID   string
	ResourceName string
	Result       auditdom.Result
	Severity     auditdom.Severity
	Changes      *auditdom.Changes
	Message      string
	Metadata     map[string]any
}

// NewSuccessEvent creates a success audit event.
func NewSuccessEvent(action auditdom.Action, resourceType auditdom.ResourceType, resourceID string) AuditEvent {
	return AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       auditdom.ResultSuccess,
		Metadata:     make(map[string]any),
	}
}

// NewFailureEvent creates a failure audit event.
func NewFailureEvent(action auditdom.Action, resourceType auditdom.ResourceType, resourceID string, err error) AuditEvent {
	event := AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       auditdom.ResultFailure,
		Metadata:     make(map[string]any),
	}
	if err != nil {
		event.Metadata["error"] = err.Error()
	}
	return event
}

// NewDeniedEvent creates a denied audit event.
func NewDeniedEvent(action auditdom.Action, resourceType auditdom.ResourceType, resourceID string, reason string) AuditEvent {
	event := AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       auditdom.ResultDenied,
		Severity:     auditdom.SeverityHigh,
		Metadata:     make(map[string]any),
	}
	if reason != "" {
		event.Metadata["reason"] = reason
	}
	return event
}

// WithResourceName sets the resource name.
func (e AuditEvent) WithResourceName(name string) AuditEvent {
	e.ResourceName = name
	return e
}

// WithChanges sets the changes.
func (e AuditEvent) WithChanges(changes *auditdom.Changes) AuditEvent {
	e.Changes = changes
	return e
}

// WithMessage sets the message.
func (e AuditEvent) WithMessage(message string) AuditEvent {
	e.Message = message
	return e
}

// WithSeverity sets the severity.
func (e AuditEvent) WithSeverity(severity auditdom.Severity) AuditEvent {
	e.Severity = severity
	return e
}

// WithMetadata adds metadata.
func (e AuditEvent) WithMetadata(key string, value any) AuditEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	e.Metadata[key] = value
	return e
}

// ============================================
// QUERY OPERATIONS
// ============================================

// ListAuditLogsInput represents the input for listing audit logs.
type ListAuditLogsInput struct {
	TenantID      string   `validate:"omitempty,uuid"`
	ActorID       string   `validate:"omitempty,uuid"`
	Actions       []string `validate:"max=20"`
	ResourceTypes []string `validate:"max=10"`
	ResourceID    string   `validate:"max=255"`
	Results       []string `validate:"max=3"`
	Severities    []string `validate:"max=4"`
	RequestID     string   `validate:"max=100"`
	Since         *time.Time
	Until         *time.Time
	SearchTerm    string `validate:"max=255"`
	Page          int    `validate:"min=0"`
	PerPage       int    `validate:"min=0,max=100"`
	SortBy        string `validate:"omitempty,oneof=logged_at action resource_type result severity"`
	SortOrder     string `validate:"omitempty,oneof=asc desc"`
	ExcludeSystem bool
}

// ListAuditLogs retrieves audit logs with filtering and pagination.
func (s *AuditService) ListAuditLogs(ctx context.Context, input ListAuditLogsInput) (pagination.Result[*auditdom.AuditLog], error) {
	filter := auditdom.NewFilter()

	if input.TenantID != "" {
		tenantID, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return pagination.Result[*auditdom.AuditLog]{}, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
		}
		filter = filter.WithTenantID(tenantID)
	}

	if input.ActorID != "" {
		actorID, err := shared.IDFromString(input.ActorID)
		if err != nil {
			return pagination.Result[*auditdom.AuditLog]{}, fmt.Errorf("%w: invalid actor id format", shared.ErrValidation)
		}
		filter = filter.WithActorID(actorID)
	}

	if len(input.Actions) > 0 {
		actions := make([]auditdom.Action, 0, len(input.Actions))
		for _, a := range input.Actions {
			actions = append(actions, auditdom.Action(a))
		}
		filter = filter.WithActions(actions...)
	}

	if len(input.ResourceTypes) > 0 {
		types := make([]auditdom.ResourceType, 0, len(input.ResourceTypes))
		for _, rt := range input.ResourceTypes {
			types = append(types, auditdom.ResourceType(rt))
		}
		filter = filter.WithResourceTypes(types...)
	}

	if input.ResourceID != "" {
		filter = filter.WithResourceID(input.ResourceID)
	}

	if len(input.Results) > 0 {
		results := make([]auditdom.Result, 0, len(input.Results))
		for _, r := range input.Results {
			results = append(results, auditdom.Result(r))
		}
		filter = filter.WithResults(results...)
	}

	if len(input.Severities) > 0 {
		severities := make([]auditdom.Severity, 0, len(input.Severities))
		for _, sev := range input.Severities {
			severities = append(severities, auditdom.Severity(sev))
		}
		filter = filter.WithSeverities(severities...)
	}

	if input.RequestID != "" {
		filter = filter.WithRequestID(input.RequestID)
	}

	if input.Since != nil {
		filter = filter.WithSince(*input.Since)
	}

	if input.Until != nil {
		filter = filter.WithUntil(*input.Until)
	}

	if input.SearchTerm != "" {
		filter = filter.WithSearchTerm(input.SearchTerm)
	}

	if input.SortBy != "" {
		filter = filter.WithSort(input.SortBy, input.SortOrder)
	}

	if input.ExcludeSystem {
		filter = filter.WithExcludeSystem(true)
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.auditRepo.List(ctx, filter, page)
}

// GetAuditLog retrieves an audit log of the tenant. A system row (tenant_id
// IS NULL) or another tenant's row is not found.
func (s *AuditService) GetAuditLog(ctx context.Context, tenantID shared.ID, auditLogID string) (*auditdom.AuditLog, error) {
	parsedID, err := shared.IDFromString(auditLogID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.auditRepo.GetByTenantAndID(ctx, tenantID, parsedID)
}

// GetResourceHistory retrieves audit history for a specific resource within a tenant.
// tenantID MUST be provided to prevent cross-tenant reads (F-2).
func (s *AuditService) GetResourceHistory(ctx context.Context, tenantID shared.ID, resourceType, resourceID string, page, perPage int) (pagination.Result[*auditdom.AuditLog], error) {
	p := pagination.New(page, perPage)
	return s.auditRepo.ListByResource(ctx, tenantID, auditdom.ResourceType(resourceType), resourceID, p)
}

// GetUserActivity retrieves audit logs for a specific user within a tenant.
// tenantID MUST be the caller's tenant — the underlying ListByActor query is
// scoped to it so one tenant cannot read another tenant's user activity.
func (s *AuditService) GetUserActivity(ctx context.Context, tenantID shared.ID, userID string, page, perPage int) (pagination.Result[*auditdom.AuditLog], error) {
	actorID, err := shared.IDFromString(userID)
	if err != nil {
		return pagination.Result[*auditdom.AuditLog]{}, fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}

	p := pagination.New(page, perPage)
	return s.auditRepo.ListByActor(ctx, tenantID, actorID, p)
}

// ============================================
// RETENTION OPERATIONS
// ============================================

// ============================================
// STATISTICS
// ============================================

// GetActionCount returns the count of a specific action within a time range.
func (s *AuditService) GetActionCount(ctx context.Context, tenantID string, action auditdom.Action, since time.Time) (int64, error) {
	var tid *shared.ID
	if tenantID != "" {
		parsedID, err := shared.IDFromString(tenantID)
		if err != nil {
			return 0, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
		}
		tid = &parsedID
	}

	return s.auditRepo.CountByAction(ctx, tid, action, since)
}

// ============================================
// CONVENIENCE METHODS FOR COMMON EVENTS
// ============================================

// LogUserCreated logs a user creation event.
func (s *AuditService) LogUserCreated(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(auditdom.ActionUserCreated, auditdom.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s created", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserUpdated logs a user update event.
func (s *AuditService) LogUserUpdated(ctx context.Context, actx AuditContext, userID, email string, changes *auditdom.Changes) error {
	event := NewSuccessEvent(auditdom.ActionUserUpdated, auditdom.ResourceTypeUser, userID).
		WithResourceName(email).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("User %s updated", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserSuspended logs a user suspension event.
func (s *AuditService) LogUserSuspended(ctx context.Context, actx AuditContext, userID, email, reason string) error {
	event := NewSuccessEvent(auditdom.ActionUserSuspended, auditdom.ResourceTypeUser, userID).
		WithResourceName(email).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("User %s suspended: %s", email, reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogMemberAdded logs a member addition event.
func (s *AuditService) LogMemberAdded(ctx context.Context, actx AuditContext, membershipID, email, role string) error {
	event := NewSuccessEvent(auditdom.ActionMemberAdded, auditdom.ResourceTypeMembership, membershipID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("Member %s added with role %s", email, role)).
		WithMetadata("role", role)
	return s.LogEvent(ctx, actx, event)
}

// LogMemberRemoved logs a member removal event.
func (s *AuditService) LogMemberRemoved(ctx context.Context, actx AuditContext, membershipID, email string) error {
	event := NewSuccessEvent(auditdom.ActionMemberRemoved, auditdom.ResourceTypeMembership, membershipID).
		WithResourceName(email).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Member %s removed", email))
	return s.LogEvent(ctx, actx, event)
}

// LogMemberRoleChanged logs a member role change event.
func (s *AuditService) LogMemberRoleChanged(ctx context.Context, actx AuditContext, membershipID, email, oldRole, newRole string) error {
	changes := auditdom.NewChanges().Set("role", oldRole, newRole)
	event := NewSuccessEvent(auditdom.ActionMemberRoleChanged, auditdom.ResourceTypeMembership, membershipID).
		WithResourceName(email).
		WithChanges(changes).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Member %s role changed from %s to %s", email, oldRole, newRole))
	return s.LogEvent(ctx, actx, event)
}

// LogInvitationCreated logs an invitation creation event.
func (s *AuditService) LogInvitationCreated(ctx context.Context, actx AuditContext, invitationID, email, role string) error {
	event := NewSuccessEvent(auditdom.ActionInvitationCreated, auditdom.ResourceTypeInvitation, invitationID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("Invitation sent to %s with role %s", email, role)).
		WithMetadata("role", role)
	return s.LogEvent(ctx, actx, event)
}

// LogInvitationAccepted logs an invitation acceptance event.
func (s *AuditService) LogInvitationAccepted(ctx context.Context, actx AuditContext, invitationID, email string) error {
	event := NewSuccessEvent(auditdom.ActionInvitationAccepted, auditdom.ResourceTypeInvitation, invitationID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("Invitation accepted by %s", email))
	return s.LogEvent(ctx, actx, event)
}

// LogPermissionDenied logs a permission denied event.
func (s *AuditService) LogPermissionDenied(ctx context.Context, actx AuditContext, resourceType auditdom.ResourceType, resourceID, action, reason string) error {
	event := NewDeniedEvent(auditdom.ActionPermissionDenied, resourceType, resourceID, reason).
		WithMessage(fmt.Sprintf("Permission denied for %s on %s %s: %s", action, resourceType, resourceID, reason))
	return s.LogEvent(ctx, actx, event)
}

// LogAuthFailed logs an authentication failure event.
func (s *AuditService) LogAuthFailed(ctx context.Context, actx AuditContext, reason string) error {
	event := NewFailureEvent(auditdom.ActionAuthFailed, auditdom.ResourceTypeToken, "", nil).
		WithSeverity(auditdom.SeverityCritical).
		WithMessage(fmt.Sprintf("Authentication failed: %s", reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogUserLogin logs a user login event.
func (s *AuditService) LogUserLogin(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(auditdom.ActionAuthLogin, auditdom.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s logged in", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserLogout logs a user logout event.
func (s *AuditService) LogUserLogout(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(auditdom.ActionAuthLogout, auditdom.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s logged out", email))
	return s.LogEvent(ctx, actx, event)
}

// LogUserRegistered logs a user registration event.
func (s *AuditService) LogUserRegistered(ctx context.Context, actx AuditContext, userID, email string) error {
	event := NewSuccessEvent(auditdom.ActionAuthRegister, auditdom.ResourceTypeUser, userID).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("User %s registered", email))
	return s.LogEvent(ctx, actx, event)
}

// ============================================
// AGENT AUDIT EVENTS
// ============================================

// LogSensorCreated logs a sensor creation event.
func (s *AuditService) LogSensorCreated(ctx context.Context, actx AuditContext, sensorID, sensorName, sensorType string) error {
	event := NewSuccessEvent(auditdom.ActionSensorCreated, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithMessage(fmt.Sprintf("Sensor '%s' created (type: %s)", sensorName, sensorType)).
		WithMetadata("sensor_type", sensorType)
	return s.LogEvent(ctx, actx, event)
}

// LogSensorUpdated logs a sensor update event.
func (s *AuditService) LogSensorUpdated(ctx context.Context, actx AuditContext, sensorID, sensorName string, changes *auditdom.Changes) error {
	event := NewSuccessEvent(auditdom.ActionSensorUpdated, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("Sensor '%s' updated", sensorName))
	return s.LogEvent(ctx, actx, event)
}

// LogSensorDeleted logs a sensor deletion event.
func (s *AuditService) LogSensorDeleted(ctx context.Context, actx AuditContext, sensorID, sensorName string) error {
	event := NewSuccessEvent(auditdom.ActionSensorDeleted, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityCritical).
		WithMessage(fmt.Sprintf("Sensor '%s' deleted", sensorName))
	return s.LogEvent(ctx, actx, event)
}

// LogSensorActivated logs a sensor activation event.
func (s *AuditService) LogSensorActivated(ctx context.Context, actx AuditContext, sensorID, sensorName string) error {
	event := NewSuccessEvent(auditdom.ActionSensorActivated, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithMessage(fmt.Sprintf("Sensor '%s' activated", sensorName))
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialCreated logs a credential creation event.
func (s *AuditService) LogCredentialCreated(ctx context.Context, actx AuditContext, credID, name, credType string) error {
	event := NewSuccessEvent(auditdom.ActionCredentialCreated, auditdom.ResourceTypeToken, credID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Credential '%s' (%s) created", name, credType)).
		WithMetadata("type", credType)
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialUpdated logs a credential update event.
func (s *AuditService) LogCredentialUpdated(ctx context.Context, actx AuditContext, credID, name string) error {
	event := NewSuccessEvent(auditdom.ActionCredentialUpdated, auditdom.ResourceTypeToken, credID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Credential '%s' updated", name))
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialDeleted logs a credential deletion event.
func (s *AuditService) LogCredentialDeleted(ctx context.Context, actx AuditContext, credID string) error {
	event := NewSuccessEvent(auditdom.ActionCredentialDeleted, auditdom.ResourceTypeToken, credID).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Credential %s deleted", credID))
	return s.LogEvent(ctx, actx, event)
}

// LogCredentialAccessed logs a credential access (decrypt) event.
func (s *AuditService) LogCredentialAccessed(ctx context.Context, actx AuditContext, credID, name string) error {
	event := NewSuccessEvent(auditdom.ActionCredentialAccessed, auditdom.ResourceTypeToken, credID).
		WithResourceName(name).
		WithSeverity(auditdom.SeverityHigh). // Accessing secrets is high sensitivity
		WithMessage(fmt.Sprintf("Credential '%s' decrypted/accessed", name))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleSourceCreated logs a rule source creation event.
func (s *AuditService) LogRuleSourceCreated(ctx context.Context, actx AuditContext, sourceID, name, sourceType string) error {
	event := NewSuccessEvent(auditdom.ActionRuleSourceCreated, auditdom.ResourceTypeRuleSource, sourceID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Rule Source '%s' (%s) created", name, sourceType)).
		WithMetadata("type", sourceType)
	return s.LogEvent(ctx, actx, event)
}

// LogRuleSourceUpdated logs a rule source update event.
func (s *AuditService) LogRuleSourceUpdated(ctx context.Context, actx AuditContext, sourceID, name string) error {
	event := NewSuccessEvent(auditdom.ActionRuleSourceUpdated, auditdom.ResourceTypeRuleSource, sourceID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Rule Source '%s' updated", name))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleSourceDeleted logs a rule source deletion event.
func (s *AuditService) LogRuleSourceDeleted(ctx context.Context, actx AuditContext, sourceID, name string) error {
	event := NewSuccessEvent(auditdom.ActionRuleSourceDeleted, auditdom.ResourceTypeRuleSource, sourceID).
		WithResourceName(name).
		WithMessage(fmt.Sprintf("Rule Source '%s' deleted", name))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleOverrideCreated logs a rule override creation event.
func (s *AuditService) LogRuleOverrideCreated(ctx context.Context, actx AuditContext, overrideID, pattern string) error {
	event := NewSuccessEvent(auditdom.ActionRuleOverrideCreated, auditdom.ResourceTypeRuleOverride, overrideID).
		WithResourceName(pattern).
		WithMessage(fmt.Sprintf("Rule Override for '%s' created", pattern))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleOverrideUpdated logs a rule override update event.
func (s *AuditService) LogRuleOverrideUpdated(ctx context.Context, actx AuditContext, overrideID, pattern string) error {
	event := NewSuccessEvent(auditdom.ActionRuleOverrideUpdated, auditdom.ResourceTypeRuleOverride, overrideID).
		WithResourceName(pattern).
		WithMessage(fmt.Sprintf("Rule Override for '%s' updated", pattern))
	return s.LogEvent(ctx, actx, event)
}

// LogRuleOverrideDeleted logs a rule override deletion event.
func (s *AuditService) LogRuleOverrideDeleted(ctx context.Context, actx AuditContext, overrideID, pattern string) error {
	event := NewSuccessEvent(auditdom.ActionRuleOverrideDeleted, auditdom.ResourceTypeRuleOverride, overrideID).
		WithResourceName(pattern).
		WithMessage(fmt.Sprintf("Rule Override for '%s' deleted", pattern))
	return s.LogEvent(ctx, actx, event)
}

// LogSensorDeactivated logs a sensor deactivation event.
func (s *AuditService) LogSensorDeactivated(ctx context.Context, actx AuditContext, sensorID, sensorName, reason string) error {
	event := NewSuccessEvent(auditdom.ActionSensorDeactivated, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s' deactivated: %s", sensorName, reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogSensorRevoked logs a sensor revocation event.
func (s *AuditService) LogSensorRevoked(ctx context.Context, actx AuditContext, sensorID, sensorName, reason string) error {
	event := NewSuccessEvent(auditdom.ActionSensorRevoked, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityCritical).
		WithMessage(fmt.Sprintf("Sensor '%s' access revoked: %s", sensorName, reason)).
		WithMetadata("reason", reason)
	return s.LogEvent(ctx, actx, event)
}

// LogSensorCommandsReleased logs the platform taking back the commands a
// sensor held when it was revoked or disabled (RFC-040 §5.2): requeued went
// back to the queue, failed were addressed to that sensor only.
func (s *AuditService) LogSensorCommandsReleased(ctx context.Context, actx AuditContext, sensorID, sensorName, why string, requeued, failed []string) error {
	event := NewSuccessEvent(auditdom.ActionSensorCommandsReleased, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s' %s: %d held commands re-queued, %d failed", sensorName, why, len(requeued), len(failed))).
		WithMetadata("trigger", why).
		WithMetadata("requeued_command_ids", requeued).
		WithMetadata("failed_command_ids", failed)
	return s.LogEvent(ctx, actx, event)
}

// LogSensorKeyRegenerated logs a sensor API key regeneration event.
func (s *AuditService) LogSensorKeyRegenerated(ctx context.Context, actx AuditContext, sensorID, sensorName string) error {
	event := NewSuccessEvent(auditdom.ActionSensorKeyRegenerated, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s' API key regenerated", sensorName))
	return s.LogEvent(ctx, actx, event)
}

// LogSensorKeyRenewed logs a sensor rotating its own API key (POST /agent/renew).
// overlap is true when the renewed key was issued as an additional key row so
// the superseded key keeps working until its own expiry (rotation overlap).
//
// The new key is always an octs_ key. fromLegacy marks the renewal that moved
// the sensor off a legacy rda_ key: the metadata then carries
// previous_key_format "rda" and upgraded_from_legacy_key true. Only format
// names are recorded, never key material (not even a prefix).
func (s *AuditService) LogSensorKeyRenewed(ctx context.Context, actx AuditContext, sensorID, sensorName string, expiresAt *time.Time, overlap, fromLegacy bool) error {
	msg := fmt.Sprintf("Sensor '%s' renewed its API key", sensorName)
	previous := "octs"
	if fromLegacy {
		msg = fmt.Sprintf("Sensor '%s' renewed its API key and moved from a legacy rda_ key to the octs_ format", sensorName)
		previous = "rda"
	}
	event := NewSuccessEvent(auditdom.ActionSensorKeyRenewed, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityMedium).
		WithMessage(msg).
		WithMetadata("overlap", overlap).
		WithMetadata("key_format", "octs").
		WithMetadata("previous_key_format", previous).
		WithMetadata("upgraded_from_legacy_key", fromLegacy)
	if expiresAt != nil {
		event = event.WithMetadata("expires_at", expiresAt.UTC().Format(time.RFC3339))
	}
	return s.LogEvent(ctx, actx, event)
}

// LogSensorKeyRenewalRefused records a sensor renewal refused because, by the
// time it could rotate, the key it authenticated with had been revoked,
// expired or regenerated, or the sensor disabled. Severity high: someone
// still holds a key an administrator meant to kill.
func (s *AuditService) LogSensorKeyRenewalRefused(ctx context.Context, actx AuditContext, sensorID, sensorName, reason string) error {
	event := NewDeniedEvent(auditdom.ActionSensorKeyRenewalRefused, auditdom.ResourceTypeSensor, sensorID, reason).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s' key renewal refused: %s", sensorName, reason))
	return s.LogEvent(ctx, actx, event)
}

// LogSensorIdentityCloned records that two live processes used the same
// sensor key (clone detection). Severity high: the key has been copied or is
// shared between replicas, and the administrator should regenerate it.
func (s *AuditService) LogSensorIdentityCloned(ctx context.Context, actx AuditContext, sensorID, sensorName string, instances int) error {
	event := NewSuccessEvent(auditdom.ActionSensorIdentityCloned, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s': two processes are using the same API key", sensorName)).
		WithMetadata("live_instances", instances)
	return s.LogEvent(ctx, actx, event)
}

// LogSensorJobRefusedByLocalPolicy records a sensor refusing a job under the
// local policy its network owner installed (RFC-040 detection A11). Severity
// high: the platform asked the sensor for something the owner forbids.
func (s *AuditService) LogSensorJobRefusedByLocalPolicy(ctx context.Context, actx AuditContext, sensorID, sensorName, commandID, rule string) error {
	event := NewSuccessEvent(auditdom.ActionSensorJobRefusedByLocalPolicy, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s' refused a job under its local policy (%s)", sensorName, rule)).
		WithMetadata("command_id", commandID).
		WithMetadata("rule", rule)
	return s.LogEvent(ctx, actx, event)
}

// LogAPIKeyCreated logs the creation of a tenant `oct_` API key. Only the key
// id, name and granted scopes are recorded — nothing derived from the secret
// (the hash-chained audit row must not carry key material, not even a prefix).
func (s *AuditService) LogAPIKeyCreated(ctx context.Context, actx AuditContext, keyID, keyName string, scopes []string) error {
	event := NewSuccessEvent(auditdom.ActionAPIKeyCreated, auditdom.ResourceTypeAPIKey, keyID).
		WithResourceName(keyName).
		WithSeverity(auditdom.SeverityMedium).
		WithMessage(fmt.Sprintf("API key '%s' created", keyName)).
		WithMetadata("scopes", scopes)
	return s.LogEvent(ctx, actx, event)
}

// LogAPIKeyRevoked logs the revocation of a tenant `oct_` API key.
func (s *AuditService) LogAPIKeyRevoked(ctx context.Context, actx AuditContext, keyID, keyName string) error {
	event := NewSuccessEvent(auditdom.ActionAPIKeyRevoked, auditdom.ResourceTypeAPIKey, keyID).
		WithResourceName(keyName).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("API key '%s' revoked", keyName))
	return s.LogEvent(ctx, actx, event)
}

// LogAPIKeyDeleted logs the deletion of a tenant `oct_` API key.
func (s *AuditService) LogAPIKeyDeleted(ctx context.Context, actx AuditContext, keyID string) error {
	event := NewSuccessEvent(auditdom.ActionAPIKeyDeleted, auditdom.ResourceTypeAPIKey, keyID).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage("API key deleted")
	return s.LogEvent(ctx, actx, event)
}

// LogSensorConnected logs when a sensor first connects (comes online).
func (s *AuditService) LogSensorConnected(ctx context.Context, actx AuditContext, sensorID, sensorName, ipAddress string) error {
	event := NewSuccessEvent(auditdom.ActionSensorConnected, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithMessage(fmt.Sprintf("Sensor '%s' connected from %s", sensorName, ipAddress)).
		WithMetadata("ip_address", ipAddress)
	return s.LogEvent(ctx, actx, event)
}

// LogSensorDisconnected logs when a sensor goes offline (timeout).
func (s *AuditService) LogSensorDisconnected(ctx context.Context, actx AuditContext, sensorID, sensorName string) error {
	event := NewSuccessEvent(auditdom.ActionSensorDisconnected, auditdom.ResourceTypeSensor, sensorID).
		WithResourceName(sensorName).
		WithMessage(fmt.Sprintf("Sensor '%s' disconnected (heartbeat timeout)", sensorName))
	return s.LogEvent(ctx, actx, event)
}
