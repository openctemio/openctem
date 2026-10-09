package scope

// Re-attestation of long intrusive (t2) entries and the downgrade of the
// forgotten ones (RFC-054 §12.5).
//
// Threat model: a permanent intrusive grant that nobody remembers keeps
// authorizing t2 probes for years. Instead of re-approving it every few
// days, the owners and administrators confirm it every t2_attestation_days;
// an unanswered request downgrades it to t1 after AttestationGrace. The
// downgrade only narrows (t1 still needs the same scope entry), never
// deletes, and is audited as a system decision. Every write is tenant
// scoped and conditional, so two replicas or a concurrent attestation never
// downgrade an entry that was just confirmed.

import (
	"context"
	"errors"
	"fmt"
	"html"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// attestationStore is the persistence the attestation job needs
// (*postgres.ScopeTargetRepository).
type attestationStore interface {
	// TenantsWithIntrusiveEntries lists the tenants with an active t2 entry.
	TenantsWithIntrusiveEntries(ctx context.Context) ([]shared.ID, error)
	// ListActiveIntrusive lists one tenant's active t2 entries.
	ListActiveIntrusive(ctx context.Context, tenantID shared.ID) ([]*scopedom.Target, error)
	// MarkAttestationRequested opens the request when none is open and the
	// entry is still an active t2 entry; false otherwise.
	MarkAttestationRequested(ctx context.Context, tenantID, id shared.ID, now time.Time) (bool, error)
	// DowngradeUnattested sets the entry to t1 when it is still t2 with the
	// same open request; false otherwise (attested meanwhile, done already).
	DowngradeUnattested(ctx context.Context, tenantID, id shared.ID, requestedAt, now time.Time) (bool, error)
}

// SystemAuditor writes audit events (*auditapp.AuditService).
type SystemAuditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// SetAuditor wires the audit log for the system decisions of the scope
// service (attestation requests and downgrades).
func (s *Service) SetAuditor(a SystemAuditor) { s.auditor = a }

// AttestationInterval is the tenant's attestation period.
func (s *Service) attestationInterval(ctx context.Context, tenantID shared.ID) (time.Duration, error) {
	p, err := s.loadPolicy(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	return time.Duration(p.settings.AttestationDays()) * 24 * time.Hour, nil
}

// AttestationInterval answers the tenant's attestation period (for the
// responses).
func (s *Service) AttestationInterval(ctx context.Context, tenantID string) (time.Duration, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return s.attestationInterval(ctx, id)
}

// AttestTarget confirms that an active t2 entry keeps t2 and starts its next
// attestation period. The route requires attack_surface:scope:approve; one
// click, no step-up (it widens nothing).
func (s *Service) AttestTarget(ctx context.Context, targetID, tenantID string, actor Actor) (*scopedom.Target, error) {
	t, err := s.GetTarget(ctx, tenantID, targetID)
	if err != nil {
		return nil, err
	}
	if actor.system() || !actor.CanApprove {
		return nil, ErrWideningNeedsApprove
	}
	now := time.Now().UTC()
	before := ledgerEntryOf(t, now)
	if err := t.Attest(actor.UserID, now); err != nil {
		return nil, err
	}
	// Attesting changes nothing the ledger holds (same pattern, tier and
	// expiry); it goes through the hook like every scope write.
	if err := s.commitEntry(ctx, before, t, false, func() error {
		if err := s.targetRepo.Update(ctx, t); err != nil {
			return fmt.Errorf("failed to attest scope target: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return t, nil
}

// AttestationResult counts what one run of the job did.
type AttestationResult struct {
	Requested  int
	Downgraded int
}

// ReconcileAttestations runs the attestation job once: it asks for the
// attestations that fell due and downgrades the entries whose request went
// unanswered for AttestationGrace. Idempotent; one tenant's failure is
// logged and does not stop the others.
func (s *Service) ReconcileAttestations(ctx context.Context, now time.Time) (AttestationResult, error) {
	var res AttestationResult
	store, ok := s.targetRepo.(attestationStore)
	if !ok {
		return res, nil
	}
	tenants, err := store.TenantsWithIntrusiveEntries(ctx)
	if err != nil {
		return res, fmt.Errorf("list tenants with t2 entries: %w", err)
	}
	for _, tid := range tenants {
		r, err := s.reconcileTenantAttestations(ctx, store, tid, now)
		res.Requested += r.Requested
		res.Downgraded += r.Downgraded
		if err != nil {
			s.logger.Warn("scope attestation: tenant", "tenant_id", tid.String(), "error", logger.SanitizeError(err))
		}
	}
	return res, nil
}

func (s *Service) reconcileTenantAttestations(ctx context.Context, store attestationStore, tid shared.ID, now time.Time) (AttestationResult, error) {
	var res AttestationResult
	interval, err := s.attestationInterval(ctx, tid)
	if err != nil {
		return res, err
	}
	entries, err := store.ListActiveIntrusive(ctx, tid)
	if err != nil {
		return res, err
	}
	for _, t := range entries {
		if t.TenantID() != tid {
			continue
		}
		if req := t.AttestationRequestedAt(); req != nil {
			if now.Before(req.Add(scopedom.AttestationGrace)) {
				continue
			}
			done, err := s.downgradeUnattested(ctx, store, t, *req, now)
			if err != nil {
				return res, err
			}
			if done {
				res.Downgraded++
				s.afterDowngrade(ctx, t)
			}
			continue
		}
		due := t.AttestationDueAt(interval)
		if due == nil || now.Before(*due) {
			continue
		}
		opened, err := store.MarkAttestationRequested(ctx, tid, t.ID(), now)
		if err != nil {
			return res, err
		}
		if opened {
			res.Requested++
			s.requestAttestation(ctx, t, now)
		}
	}
	return res, nil
}

// errAttestedMeanwhile: the conditional downgrade found the request closed
// (confirmed meanwhile, or another run did it); nothing was saved.
var errAttestedMeanwhile = errors.New("attestation request no longer open")

// downgradeUnattested sets t to t1 through the ledger hook (a narrowing:
// saved first with the conditional update, then sent to the signer). It
// reports false when the request was closed meanwhile.
func (s *Service) downgradeUnattested(ctx context.Context, store attestationStore, t *scopedom.Target, req, now time.Time) (bool, error) {
	before := ledgerEntryOf(t, now)
	t.SetMaxTier(scopedom.TierActive, now)
	t.RestoreAttestation(scopedom.AttestationState{AttestedAt: t.AttestedAt(), AttestedBy: t.AttestedBy()})
	err := s.commitEntry(ctx, before, t, false, func() error {
		done, err := store.DowngradeUnattested(ctx, t.TenantID(), t.ID(), req, now)
		if err != nil {
			return err
		}
		if !done {
			return errAttestedMeanwhile
		}
		return nil
	})
	if errors.Is(err, errAttestedMeanwhile) {
		return false, nil
	}
	return err == nil, err
}

// requestAttestation asks the owners, administrators and approvers to keep
// or drop t2 (in-app, email, channels) and audits the request.
func (s *Service) requestAttestation(ctx context.Context, t *scopedom.Target, now time.Time) {
	deadline := now.Add(scopedom.AttestationGrace).UTC().Format("2006-01-02")
	title := "Keep T2 for " + t.Pattern() + "?"
	body := fmt.Sprintf("The scope entry %s %s allows intrusive (T2) probes. Confirm by %s that it still should, or it falls back to non-intrusive (T1). Reason on record: %s",
		t.TargetType(), t.Pattern(), deadline, t.Reason())
	s.NotifyAdmins(ctx, t.TenantID(), title, body)
	s.enqueueChannel(ctx, t, string(integration.EventTypeApprovalRequested), title, body, notificationdom.SeverityMedium)
	s.mailApprovers(ctx, t, "[Scope] "+title, s.attestationMailBody(t, deadline))
	s.auditSystem(ctx, t, auditdom.ActionScopeTargetAttestationRequested, auditdom.SeverityLow,
		"Attestation of an intrusive (t2) scope entry requested", map[string]any{"deadline": deadline})
}

// afterDowngrade tells everyone and audits the downgrade.
func (s *Service) afterDowngrade(ctx context.Context, t *scopedom.Target) {
	title := "Scope entry fell back to T1: " + t.Pattern()
	body := fmt.Sprintf("Nobody confirmed within %d days that %s %s should keep intrusive (T2) probes, so it now allows non-intrusive (T1) probes only. The entry was not removed; raising it to T2 again needs an approval.",
		int(scopedom.AttestationGrace.Hours()/24), t.TargetType(), t.Pattern())
	s.NotifyAdmins(ctx, t.TenantID(), title, body)
	s.enqueueChannel(ctx, t, string(integration.EventTypeSecurityAlert), title, body, notificationdom.SeverityHigh)
	s.auditSystem(ctx, t, auditdom.ActionScopeTargetT2Downgraded, auditdom.SeverityHigh,
		"Intrusive (t2) scope entry downgraded to t1: attestation not confirmed",
		map[string]any{"from_tier": "t2", "to_tier": "t1", "grace_days": int(scopedom.AttestationGrace.Hours() / 24)})
}

func (s *Service) auditSystem(ctx context.Context, t *scopedom.Target, action auditdom.Action, sev auditdom.Severity, msg string, meta map[string]any) {
	if s.auditor == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeScopeTarget, t.ID().String()).
		WithResourceName(t.Pattern()).WithMessage(msg).WithSeverity(sev).WithMetadata("actor", "system")
	for k, v := range meta {
		ev = ev.WithMetadata(k, v)
	}
	if err := s.auditor.LogEvent(ctx, auditapp.AuditContext{TenantID: t.TenantID().String()}, ev); err != nil {
		s.logger.Warn("scope attestation: audit", "error", logger.SanitizeError(err))
	}
}

// mailApprovers emails everyone who may approve scope entries (they may
// attest too). Best effort.
func (s *Service) mailApprovers(ctx context.Context, t *scopedom.Target, subject, body string) {
	if s.mail == nil || s.approvers == nil {
		return
	}
	all, err := s.approvers.ScopeApprovers(ctx, t.TenantID())
	if err != nil {
		s.logger.Warn("scope attestation: list approvers", "error", logger.SanitizeError(err))
		return
	}
	emails := make([]string, 0, len(all))
	for _, a := range all {
		if a.Email != "" {
			emails = append(emails, a.Email)
		}
	}
	if len(emails) > 0 {
		s.mail.SendScopeApprovalMail(ctx, t.TenantID().String(), emails, subject, body)
	}
}

// attestationMailBody is the "keep T2?" email. Values are escaped; the link
// opens the page only (sign-in and the approval permission authorize).
func (s *Service) attestationMailBody(t *scopedom.Target, deadline string) string {
	link := s.webBaseURL + "/scope"
	return fmt.Sprintf(`<p>The scope entry <strong>%s</strong> (%s) allows intrusive (T2) probes.</p>
<p>Reason on record: %s</p>
<p>Confirm by %s that it should keep T2, or it falls back to non-intrusive (T1) probes. Nothing is removed.</p>
<p>Review it: <a href="%s">%s</a> (sign-in required).</p>`,
		html.EscapeString(t.Pattern()), html.EscapeString(t.TargetType().String()), html.EscapeString(t.Reason()),
		html.EscapeString(deadline), html.EscapeString(link), html.EscapeString(link))
}
