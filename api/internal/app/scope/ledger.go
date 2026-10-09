package scope

// The job signer's scope ledger (RFC-040 §5.6 points 4 and 5,
// docs/architecture/job-signing.md "Scope ledger"): every committed change
// to what authorizes probes (a scope entry or a target exclusion coming
// into or leaving effect, a tier or expiry change) is sent to the signer,
// which signs jobs only inside its own copy.
//
// commitEntry and commitExclusion are the one hook: every write of this
// service that can change what is in effect goes through them, and so must
// any other path that puts an entry into effect (programs, letters).
//
//   - A widening goes to the signer BEFORE it is saved, and the change fails
//     when the signer refuses it or does not answer: the database never
//     holds scope the signer did not accept.
//   - A narrowing is saved first and sent after, best effort: narrowing is
//     never blocked by the signer. One that did not reach it is caught by
//     the periodic sync (SyncLedger), which can only narrow.
//
// Approvals are this service's: the entry's recorded approvals, its
// requester and its approvals_required (the tenant's policy, loadPolicy),
// and for an exclusion taken out of effect the reviewer AuthorizeReduction
// accepted. The signer checks them again (P2: as the API recorded them).

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/metrics"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// LedgerFeed is the job signer's ledger (*signer.Client). A refusal is a
// *jobsign.RefusalError; any other error means the signer did not answer.
type LedgerFeed interface {
	ApplyLedger(ctx context.Context, ch jobsign.LedgerChange) (jobsign.LedgerApplyResult, error)
	SyncLedger(ctx context.Context, snap jobsign.LedgerSnapshot) (jobsign.LedgerSyncResult, error)
	LedgerStatus(ctx context.Context) (jobsign.LedgerStatus, error)
}

// SetLedger wires the job signer's ledger. Without it scope changes are
// saved as before.
func (s *Service) SetLedger(l LedgerFeed) { s.ledger = l }

// Ledger errors (the handler answers them with their code).
var (
	ErrLedgerRefused = shared.NewDomainError("SCOPE_LEDGER_REFUSED",
		"the job signer refused this scope change; it was not saved", shared.ErrConflict)
	ErrLedgerUnavailable = shared.NewDomainError("SCOPE_LEDGER_UNAVAILABLE",
		"the job signer did not answer; the scope was not widened. Try again", shared.ErrConflict)
)

// exclusionReductionApprovals is the approvals taking an exclusion in effect
// out of effect needs (Exclusion.AuthorizeReduction: one approver other than
// its requester).
const exclusionReductionApprovals = 1

// ledgerEntryOf is t as the ledger holds it, nil when t authorizes nothing
// now.
func ledgerEntryOf(t *scopedom.Target, now time.Time) *jobsign.LedgerEntry {
	if t == nil || !t.InEffect(now) {
		return nil
	}
	return &jobsign.LedgerEntry{
		ID: t.ID().String(), Type: string(t.TargetType()), Pattern: t.Pattern(),
		MaxTier: int(t.MaxTier()), ExpiresAt: utcPtr(t.ExpiresAt()),
	}
}

// ledgerExclusionOf is e as the ledger holds it, nil when e excludes no
// target now (not in effect, expired, or not a target exclusion).
func ledgerExclusionOf(e *scopedom.Exclusion, now time.Time) *jobsign.LedgerExclusion {
	if e == nil || !e.InEffect() || jobsign.Expired(e.ExpiresAt(), now) || !ledgerExclusionType(e.ExclusionType()) {
		return nil
	}
	return &jobsign.LedgerExclusion{
		ID: e.ID().String(), Type: string(e.ExclusionType()), Pattern: e.Pattern(), ExpiresAt: utcPtr(e.ExpiresAt()),
	}
}

// ledgerExclusionType reports whether an exclusion names targets (path,
// finding-type and scanner exclusions are not in the ledger).
func ledgerExclusionType(t scopedom.ExclusionType) bool {
	switch t {
	case scopedom.ExclusionTypeDomain, scopedom.ExclusionTypeSubdomain, scopedom.ExclusionTypeIPAddress,
		scopedom.ExclusionTypeIPRange, scopedom.ExclusionTypeCIDR, scopedom.ExclusionTypeURL, scopedom.ExclusionTypeRepository:
		return true
	}
	return false
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// userRef is id when it is a user id (a UUID), "" otherwise (a system
// path).
func userRef(id string) string {
	u, err := uuid.Parse(id)
	if err != nil || u.String() != id {
		return ""
	}
	return id
}

// commitEntry saves a change to entry t (save) and tells the signer.
// before is the entry's ledger form before the change (ledgerEntryOf),
// deleted says t no longer exists after save.
func (s *Service) commitEntry(ctx context.Context, before *jobsign.LedgerEntry, t *scopedom.Target, deleted bool, save func() error) error {
	now := time.Now().UTC()
	var after *jobsign.LedgerEntry
	if !deleted {
		after = ledgerEntryOf(t, now)
	}
	var op jobsign.LedgerOp
	widens := false
	switch {
	case s.ledger == nil, before == nil && after == nil:
		return save()
	case after == nil:
		op = jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: before.ID}
	case before != nil && sameLedgerEntry(*before, *after):
		return save()
	default:
		op = jobsign.LedgerOp{Op: jobsign.OpPutEntry, Entry: after}
		widens = jobsign.EntryWidens(before, *after, now)
	}
	ch := jobsign.LedgerChange{TenantID: t.TenantID().String(), ChangeID: uuid.NewString(), Approvals: []jobsign.LedgerApproval{},
		Ops: []jobsign.LedgerOp{op}}
	if widens {
		ch.Requester = userRef(t.CreatedBy())
		ch.RequiredApprovals = min(max(t.ApprovalsRequired(), 0), jobsign.MaxPolicyApprovals)
		for _, a := range t.Approvals() {
			if id := userRef(a.UserID); id != "" {
				ch.Approvals = append(ch.Approvals, jobsign.LedgerApproval{UserID: id, ApprovedAt: a.ApprovedAt.UTC()})
			}
		}
	}
	return s.commitLedger(ctx, ch, widens, save)
}

// commitExclusion saves a change to exclusion e (save) and tells the
// signer. before is its ledger form before the change; reviewer is who took
// it out of effect or shortened it (AuthorizeReduction).
func (s *Service) commitExclusion(ctx context.Context, before *jobsign.LedgerExclusion, e *scopedom.Exclusion, deleted bool,
	reviewer string, save func() error,
) error {
	now := time.Now().UTC()
	var after *jobsign.LedgerExclusion
	if !deleted {
		after = ledgerExclusionOf(e, now)
	}
	var op jobsign.LedgerOp
	widens := false
	switch {
	case s.ledger == nil, before == nil && after == nil:
		return save()
	case after == nil && !deleted && e.IsPending():
		// A window extended back to review stays in the ledger as it was
		// until it is approved again: the ledger only keeps the stricter.
		return save()
	case after == nil:
		op = jobsign.LedgerOp{Op: jobsign.OpRemoveExclusion, ID: before.ID}
		widens = jobsign.ExclusionRemoveWidens(before, now)
	case before != nil && sameLedgerExclusion(*before, *after):
		return save()
	default:
		op = jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: after}
		widens = jobsign.ExclusionPutWidens(before, *after, now)
	}
	ch := jobsign.LedgerChange{TenantID: e.TenantID().String(), ChangeID: uuid.NewString(), Approvals: []jobsign.LedgerApproval{},
		Ops: []jobsign.LedgerOp{op}}
	if widens {
		ch.Requester = userRef(e.CreatedBy())
		ch.RequiredApprovals = exclusionReductionApprovals
		if id := userRef(reviewer); id != "" {
			ch.Approvals = append(ch.Approvals, jobsign.LedgerApproval{UserID: id, ApprovedAt: now})
		}
	}
	return s.commitLedger(ctx, ch, widens, save)
}

// commitLedger orders the signer call and the save: a widening is
// accepted by the signer first (or the change fails), a narrowing is saved
// first and sent best effort.
func (s *Service) commitLedger(ctx context.Context, ch jobsign.LedgerChange, widens bool, save func() error) error {
	kind := jobsign.ChangeNarrow
	if widens {
		kind = jobsign.ChangeWiden
		if err := s.applyLedger(ctx, ch, kind); err != nil {
			return err
		}
		return save()
	}
	if err := save(); err != nil {
		return err
	}
	if err := s.applyLedger(context.WithoutCancel(ctx), ch, kind); err != nil {
		s.logger.Warn("scope narrowing not sent to the job signer; the next ledger sync narrows it",
			"tenant_id", ch.TenantID, "change_id", ch.ChangeID, "error", logger.SanitizeError(err))
	}
	return nil
}

// ProgramAttestation labels a widening approved by a program importer's
// attestation of the program's published terms (RFC-065: program entries
// take effect with no approver).
const ProgramAttestation = "program_attestation"

// CommitEntries is the same hook for writes made outside this service
// (bounty programs, RFC-065): put are the entries in effect after the
// write, removed the ids taken out of effect. Entries put widen: they go to
// the signer before save, with requester and no approvals (the policy of
// that path, platformPolicy, asks none); removals narrow and go after.
func (s *Service) CommitEntries(ctx context.Context, tenantID shared.ID, requester string, put []*scopedom.Target,
	removed []shared.ID, platformPolicy string, save func() error,
) error {
	if s.ledger == nil {
		return save()
	}
	now := time.Now().UTC()
	widen := jobsign.LedgerChange{TenantID: tenantID.String(), ChangeID: uuid.NewString(), Requester: userRef(requester),
		Approvals: []jobsign.LedgerApproval{}, PlatformPolicy: platformPolicy}
	for _, t := range put {
		if e := ledgerEntryOf(t, now); e != nil {
			widen.Ops = append(widen.Ops, jobsign.LedgerOp{Op: jobsign.OpPutEntry, Entry: e})
		}
	}
	narrow := jobsign.LedgerChange{TenantID: tenantID.String(), ChangeID: uuid.NewString(), Approvals: []jobsign.LedgerApproval{}}
	for _, id := range removed {
		narrow.Ops = append(narrow.Ops, jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: id.String()})
	}
	if len(widen.Ops) > 0 {
		for start := 0; start < len(widen.Ops); start += jobsign.MaxLedgerOps {
			part := widen
			part.ChangeID = uuid.NewString()
			part.Ops = widen.Ops[start:min(start+jobsign.MaxLedgerOps, len(widen.Ops))]
			if err := s.applyLedger(ctx, part, jobsign.ChangeWiden); err != nil {
				return err
			}
		}
	}
	if err := save(); err != nil {
		return err
	}
	for start := 0; start < len(narrow.Ops); start += jobsign.MaxLedgerOps {
		part := narrow
		part.ChangeID = uuid.NewString()
		part.Ops = narrow.Ops[start:min(start+jobsign.MaxLedgerOps, len(narrow.Ops))]
		if err := s.applyLedger(context.WithoutCancel(ctx), part, jobsign.ChangeNarrow); err != nil {
			s.logger.Warn("scope narrowing not sent to the job signer; the next ledger sync narrows it",
				"tenant_id", part.TenantID, "change_id", part.ChangeID, "error", logger.SanitizeError(err))
		}
	}
	return nil
}

// applyLedger sends ch and maps the answer to the domain errors.
func (s *Service) applyLedger(ctx context.Context, ch jobsign.LedgerChange, kind string) error {
	_, err := s.ledger.ApplyLedger(ctx, ch)
	var rf *jobsign.RefusalError
	switch {
	case err == nil:
		metrics.SignerLedgerFeedTotal.WithLabelValues(kind, "applied").Inc()
		return nil
	case errors.As(err, &rf):
		metrics.SignerLedgerFeedTotal.WithLabelValues(kind, "refused").Inc()
		s.logger.Warn("SECURITY: the job signer refused a scope change", "tenant_id", ch.TenantID,
			"change_id", ch.ChangeID, "kind", kind, "reason", rf.Reason, "detail", logSafe(rf.Detail))
		return &shared.DomainError{Code: ErrLedgerRefused.Code, Message: ErrLedgerRefused.Message + ": " + rf.Reason, Err: ErrLedgerRefused.Err}
	}
	metrics.SignerLedgerFeedTotal.WithLabelValues(kind, "unavailable").Inc()
	s.logger.Warn("the job signer did not answer a scope change", "tenant_id", ch.TenantID, "kind", kind,
		"error", logger.SanitizeError(err))
	return ErrLedgerUnavailable
}

func sameLedgerEntry(a, b jobsign.LedgerEntry) bool {
	return a.ID == b.ID && a.Type == b.Type && a.Pattern == b.Pattern && a.MaxTier == b.MaxTier && sameExpiry(a.ExpiresAt, b.ExpiresAt)
}

func sameLedgerExclusion(a, b jobsign.LedgerExclusion) bool {
	return a.ID == b.ID && a.Type == b.Type && a.Pattern == b.Pattern && sameExpiry(a.ExpiresAt, b.ExpiresAt)
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// LedgerSnapshot is the tenant's scope in effect in the ledger's form: the
// body of a sync and one organization of `server -signer-ledger-export`.
func (s *Service) LedgerSnapshot(ctx context.Context, tenantID string) (jobsign.LedgerSnapshot, error) {
	snap := jobsign.LedgerSnapshot{TenantID: tenantID, Entries: []jobsign.LedgerEntry{}, Exclusions: []jobsign.LedgerExclusion{}}
	targets, err := s.ListActiveTargets(ctx, tenantID)
	if err != nil {
		return snap, err
	}
	exclusions, err := s.ListActiveExclusions(ctx, tenantID)
	if err != nil {
		return snap, err
	}
	now := time.Now().UTC()
	for _, t := range targets {
		if e := ledgerEntryOf(t, now); e != nil && scopedom.ValidatePattern(t.TargetType(), t.Pattern()) == nil {
			snap.Entries = append(snap.Entries, *e)
		}
	}
	for _, x := range exclusions {
		if e := ledgerExclusionOf(x, now); e != nil {
			snap.Exclusions = append(snap.Exclusions, *e)
		}
	}
	return snap, nil
}

// SyncLedger narrows the signer's ledger to the database for every
// organization the ledger holds (the signer never widens from it). It
// catches narrowings that did not reach the signer and changes made outside
// this service.
func (s *Service) SyncLedger(ctx context.Context) error {
	if s.ledger == nil {
		return nil
	}
	st, err := s.ledger.LedgerStatus(ctx)
	if err != nil {
		return err
	}
	if st.Mode == jobsign.LedgerOff {
		return nil
	}
	var errs []error
	for _, tenantID := range st.Tenants {
		snap, err := s.LedgerSnapshot(ctx, tenantID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		res, err := s.ledger.SyncLedger(ctx, snap)
		if err != nil {
			metrics.SignerLedgerFeedTotal.WithLabelValues("sync", "unavailable").Inc()
			errs = append(errs, err)
			continue
		}
		metrics.SignerLedgerFeedTotal.WithLabelValues("sync", "applied").Inc()
		if res.Diverged > 0 {
			s.logger.Warn("scope in effect that the job signer's ledger does not hold (jobs for it are refused until it is approved again)",
				"tenant_id", tenantID, "diverged", res.Diverged)
		}
	}
	return errors.Join(errs...)
}
