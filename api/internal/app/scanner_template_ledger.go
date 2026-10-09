package app

// Custom template versions approved for sensors (RFC-040 §5.8 and §11.5,
// docs/architecture/job-signing.md "Custom templates"). A template version
// reaches a sensor only when people approved it like a scope widening (the
// scope policy's count, never its author) and the job signer recorded its
// digest in its ledger; a job naming any other version is refused by the
// signer. Approvals are counted by the scope policy (scope.Service): no
// second approver model.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TemplateLedger is the job signer's ledger (*signer.Client).
type TemplateLedger interface {
	ApplyLedger(ctx context.Context, ch jobsign.LedgerChange) (jobsign.LedgerApplyResult, error)
}

// TemplateApprovalPolicy is the organization's widening approval count
// (*scope.Service).
type TemplateApprovalPolicy interface {
	EffectiveApprovals(ctx context.Context, tenantID string) (approvals, admins int, err error)
}

// Template approval errors (the handler answers them with their code).
var (
	ErrTemplateLedgerRefused = shared.NewDomainError("TEMPLATE_LEDGER_REFUSED",
		"the job signer refused this template version; it is not approved for sensors", shared.ErrConflict)
	ErrTemplateLedgerUnavailable = shared.NewDomainError("TEMPLATE_LEDGER_UNAVAILABLE",
		"the job signer did not answer; the template version is not approved for sensors. Try again", shared.ErrConflict)
)

// SetLedger wires the job signer's ledger and the approval policy. Without
// a ledger (no job signer) template versions need no approval, as before:
// nothing would enforce it. With a ledger and no policy every version
// needs one approval.
func (s *ScannerTemplateService) SetLedger(l TemplateLedger, p TemplateApprovalPolicy) {
	s.ledger, s.approvalPolicy = l, p
}

// ApprovalsRequired is the approval count a template version needs for
// tenantID: the scope policy's count for a widening (0 without a job
// signer).
func (s *ScannerTemplateService) ApprovalsRequired(ctx context.Context, tenantID string) (int, error) {
	switch {
	case s.ledger == nil:
		return 0, nil
	case s.approvalPolicy == nil:
		return 1, nil
	}
	n, _, err := s.approvalPolicy.EffectiveApprovals(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("read the approval policy: %w", err)
	}
	return min(max(n, 0), jobsign.MaxPolicyApprovals), nil
}

// approveIfPolicyAllows approves a new or changed version at once when the
// policy asks no approval: the signer accepts it before it is saved.
func (s *ScannerTemplateService) approveIfPolicyAllows(ctx context.Context, t *scannertemplate.ScannerTemplate) error {
	required, err := s.ApprovalsRequired(ctx, t.TenantID.String())
	if err != nil {
		return err
	}
	if required > 0 {
		return nil
	}
	if err := s.putTemplate(ctx, t, required); err != nil {
		return err
	}
	t.MarkApprovedForSensors()
	return nil
}

// ApproveTemplateForSensors records actor's approval of the template's
// current version. Once the approvals reach the policy's count, the
// signer must accept the version before it is saved as approved.
func (s *ScannerTemplateService) ApproveTemplateForSensors(ctx context.Context, tenantID, templateID, actorID string) (*scannertemplate.ScannerTemplate, error) {
	t, err := s.GetTemplate(ctx, tenantID, templateID)
	if err != nil {
		return nil, err
	}
	if t.ApprovedForSensors() {
		return t, nil
	}
	if err := t.ApproveForSensors(actorID, time.Now()); err != nil {
		return nil, err
	}
	required, err := s.ApprovalsRequired(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(t.CurrentApprovals()) >= required {
		if err := s.putTemplate(ctx, t, required); err != nil {
			return nil, err
		}
		t.MarkApprovedForSensors()
	}
	if err := s.repo.Update(ctx, t); err != nil {
		return nil, err
	}
	s.logger.Info("scanner template version approved for sensors", "template_id", templateID,
		"approvals", len(t.CurrentApprovals()), "required", required, "approved", t.ApprovedForSensors())
	return t, nil
}

// putTemplate sends the current version to the signer as a widening with
// its approvals; without a ledger nothing is sent.
func (s *ScannerTemplateService) putTemplate(ctx context.Context, t *scannertemplate.ScannerTemplate, required int) error {
	if s.ledger == nil {
		return nil
	}
	ch := jobsign.LedgerChange{TenantID: t.TenantID.String(), ChangeID: uuid.NewString(), RequiredApprovals: required,
		Approvals: []jobsign.LedgerApproval{},
		Ops:       []jobsign.LedgerOp{{Op: jobsign.OpPutTemplate, Template: &jobsign.LedgerTemplate{ID: t.ID.String(), SHA256: t.ContentDigest()}}}}
	if t.ContentAuthorID != nil {
		ch.Requester = t.ContentAuthorID.String()
	}
	for _, a := range t.CurrentApprovals() {
		if u, err := uuid.Parse(a.UserID); err == nil && u.String() == a.UserID {
			ch.Approvals = append(ch.Approvals, jobsign.LedgerApproval{UserID: a.UserID, ApprovedAt: a.ApprovedAt.UTC()})
		}
	}
	_, err := s.ledger.ApplyLedger(ctx, ch)
	var rf *jobsign.RefusalError
	switch {
	case err == nil:
		metrics.SignerLedgerFeedTotal.WithLabelValues(jobsign.ChangeWiden, "applied").Inc()
		return nil
	case errors.As(err, &rf):
		metrics.SignerLedgerFeedTotal.WithLabelValues(jobsign.ChangeWiden, "refused").Inc()
		s.logger.Warn("SECURITY: the job signer refused a template version", "template_id", t.ID.String(),
			"reason", rf.Reason)
		return &shared.DomainError{Code: ErrTemplateLedgerRefused.Code,
			Message: ErrTemplateLedgerRefused.Message + ": " + rf.Reason, Err: ErrTemplateLedgerRefused.Err}
	}
	metrics.SignerLedgerFeedTotal.WithLabelValues(jobsign.ChangeWiden, "unavailable").Inc()
	s.logger.Warn("the job signer did not answer a template version", "template_id", t.ID.String(),
		"error", logger.SanitizeError(err))
	return ErrTemplateLedgerUnavailable
}

// removeTemplate takes a template out of the signer's ledger after it was
// saved (deleted, deprecated, or a new version not yet approved). Best
// effort: the ledger sync removes what does not arrive.
func (s *ScannerTemplateService) removeTemplate(ctx context.Context, t *scannertemplate.ScannerTemplate) {
	if s.ledger == nil {
		return
	}
	ch := jobsign.LedgerChange{TenantID: t.TenantID.String(), ChangeID: uuid.NewString(), Approvals: []jobsign.LedgerApproval{},
		Ops: []jobsign.LedgerOp{{Op: jobsign.OpRemoveTemplate, ID: t.ID.String()}}}
	if _, err := s.ledger.ApplyLedger(context.WithoutCancel(ctx), ch); err != nil {
		metrics.SignerLedgerFeedTotal.WithLabelValues(jobsign.ChangeNarrow, "unavailable").Inc()
		s.logger.Warn("template removal not sent to the job signer; the next ledger sync removes it",
			"template_id", t.ID.String(), "error", logger.SanitizeError(err))
		return
	}
	metrics.SignerLedgerFeedTotal.WithLabelValues(jobsign.ChangeNarrow, "applied").Inc()
}

// LedgerTemplates are tenantID's active templates whose current version is
// approved for sensors: the templates of a ledger sync or export.
func (s *ScannerTemplateService) LedgerTemplates(ctx context.Context, tenantID string) ([]jobsign.LedgerTemplate, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	active := scannertemplate.TemplateStatusActive
	out := []jobsign.LedgerTemplate{}
	for page := 1; ; page++ {
		res, err := s.repo.List(ctx, scannertemplate.Filter{TenantID: &tid, Status: &active}, pagination.New(page, 100))
		if err != nil {
			return nil, err
		}
		for _, t := range res.Data {
			if t.Status.IsUsable() && t.ApprovedForSensors() && len(out) < jobsign.MaxLedgerTemplates {
				out = append(out, jobsign.LedgerTemplate{ID: t.ID.String(), SHA256: t.ContentDigest()})
			}
		}
		if len(res.Data) == 0 || int64(page*100) >= res.Total {
			return out, nil
		}
	}
}
