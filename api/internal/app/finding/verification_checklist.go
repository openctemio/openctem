package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// maxChecklistNotes bounds the free-text notes of a checklist.
const maxChecklistNotes = 4000

// VerificationChecklistService reads and edits a finding's verification
// checklist. Completing it is a verification step: the person who completes
// it is recorded (completed_by / completed_at) and that record is what the
// transition engine reads to let a second person resolve a critical finding.
// Every call is tenant-scoped and limited to findings in the caller's data
// scope (an out-of-scope finding reads as not found).
type VerificationChecklistService struct {
	db        *sql.DB
	dataScope *datascope.Enforcer
}

// NewVerificationChecklistService creates the service.
func NewVerificationChecklistService(db *sql.DB, dataScope *datascope.Enforcer) *VerificationChecklistService {
	return &VerificationChecklistService{db: db, dataScope: dataScope}
}

// ChecklistUpdate is the set of changes of one edit; nil fields are untouched.
type ChecklistUpdate struct {
	ExposureCleared     *bool
	EvidenceAttached    *bool
	RegisterUpdated     *bool
	MonitoringAdded     *bool
	RegressionScheduled *bool
	Notes               *string
}

// ChecklistView is a checklist as the API returns it. ID is empty when the
// finding has no checklist yet (a read never creates one).
type ChecklistView struct {
	Checklist *vulnerability.VerificationChecklist
	FindingID shared.ID
}

// ChecklistChange describes what an edit did, for the audit row.
type ChecklistChange struct {
	ChangedItems []string
	Complete     bool
	// Completed is true when this edit recorded the actor as the completer.
	Completed bool
	// Cleared is true when this edit dropped an earlier completion.
	Cleared bool
}

// checklistOpenStatuses are the statuses a checklist can still be edited in.
func checklistEditable(status string) bool {
	for _, s := range vulnerability.ActiveFindingStatuses() {
		if string(s) == status {
			return true
		}
	}
	return false
}

// findingStatusInScope returns the finding's status after the tenant and
// data-scope checks.
func (s *VerificationChecklistService) findingStatusInScope(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, tenantID, findingID shared.ID) (string, error) {
	var status string
	err := q.QueryRowContext(ctx,
		`SELECT status FROM findings WHERE id = $1 AND tenant_id = $2`,
		findingID.String(), tenantID.String()).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: finding not found", shared.ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("read finding: %w", err)
	}
	if s.dataScope != nil {
		if err := s.dataScope.AssertFinding(ctx, tenantID, findingID); err != nil {
			return "", fmt.Errorf("%w: finding not found", shared.ErrNotFound)
		}
	}
	return status, nil
}

// Get returns the finding's checklist, or a view with a nil checklist when it
// has none. It writes nothing.
func (s *VerificationChecklistService) Get(ctx context.Context, tenantID, findingID shared.ID) (*ChecklistView, error) {
	if _, err := s.findingStatusInScope(ctx, s.db, tenantID, findingID); err != nil {
		return nil, err
	}
	c, err := loadVerificationChecklist(ctx, s.db, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	return &ChecklistView{Checklist: c, FindingID: findingID}, nil
}

// Update applies an edit by actor. The checklist row is created on first
// edit. After the edit: all required items true records actor as the
// completer (when the edit changed an item or the checklist was not complete
// before); any required item false clears the completion. Only open findings
// (new through fix_applied) take edits.
func (s *VerificationChecklistService) Update(ctx context.Context, tenantID, findingID, actor shared.ID, in ChecklistUpdate) (*ChecklistView, *ChecklistChange, error) {
	if in.Notes != nil && utf8.RuneCountInString(*in.Notes) > maxChecklistNotes {
		return nil, nil, fmt.Errorf("%w: notes are limited to %d characters", shared.ErrValidation, maxChecklistNotes)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	status, err := s.findingStatusInScope(ctx, tx, tenantID, findingID)
	if err != nil {
		return nil, nil, err
	}
	if !checklistEditable(status) {
		return nil, nil, fmt.Errorf("%w: the verification checklist can only be edited on an open finding (status is %s)", shared.ErrValidation, status)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO finding_verification_checklists (finding_id, tenant_id) VALUES ($1, $2) ON CONFLICT (finding_id) DO NOTHING`,
		findingID.String(), tenantID.String()); err != nil {
		return nil, nil, fmt.Errorf("create checklist: %w", err)
	}
	var (
		id                  string
		exposure, evidence  bool
		register            bool
		monitoring, regress sql.NullBool
		notes               string
		by                  sql.NullString
	)
	err = tx.QueryRowContext(ctx, `
		SELECT id, exposure_cleared, evidence_attached, register_updated, monitoring_added,
		       regression_scheduled, COALESCE(notes, ''), completed_by
		FROM finding_verification_checklists
		WHERE finding_id = $1 AND tenant_id = $2 FOR UPDATE`,
		findingID.String(), tenantID.String()).Scan(&id, &exposure, &evidence, &register, &monitoring, &regress, &notes, &by)
	if err != nil {
		return nil, nil, fmt.Errorf("lock checklist: %w", err)
	}
	wasComplete := by.Valid
	// Compare before and after through the domain object.
	cl := vulnerability.NewVerificationChecklist(findingID, tenantID)
	_ = cl.UpdateItem("exposure_cleared", exposure)
	_ = cl.UpdateItem("evidence_attached", evidence)
	_ = cl.UpdateItem("register_updated", register)
	if monitoring.Valid {
		_ = cl.UpdateItem("monitoring_added", monitoring.Bool)
	}
	if regress.Valid {
		_ = cl.UpdateItem("regression_scheduled", regress.Bool)
	}
	var changed []string
	apply := func(key string, cur bool, curSet bool, v *bool) error {
		if v == nil {
			return nil
		}
		if !curSet || cur != *v {
			changed = append(changed, key)
		}
		return cl.UpdateItem(key, *v)
	}
	for _, a := range []struct {
		key    string
		cur    bool
		curSet bool
		v      *bool
	}{
		{"exposure_cleared", exposure, true, in.ExposureCleared},
		{"evidence_attached", evidence, true, in.EvidenceAttached},
		{"register_updated", register, true, in.RegisterUpdated},
		{"monitoring_added", monitoring.Bool, monitoring.Valid, in.MonitoringAdded},
		{"regression_scheduled", regress.Bool, regress.Valid, in.RegressionScheduled},
	} {
		if err := apply(a.key, a.cur, a.curSet, a.v); err != nil {
			return nil, nil, err
		}
	}
	newNotes := notes
	if in.Notes != nil {
		newNotes = *in.Notes
	}

	change := &ChecklistChange{ChangedItems: changed, Complete: cl.IsComplete()}
	var upd *string // nil clears the completion
	if cl.IsComplete() {
		if !wasComplete || len(changed) > 0 {
			if err := cl.MarkComplete(actor); err != nil {
				return nil, nil, err
			}
			change.Completed = true
			v := actor.String()
			upd = &v
		} else {
			v := by.String // untouched completion stays
			upd = &v
		}
	} else if wasComplete {
		change.Cleared = true
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE finding_verification_checklists SET
			exposure_cleared = $3, evidence_attached = $4, register_updated = $5,
			monitoring_added = $6, regression_scheduled = $7, notes = $8,
			completed_by = $9::uuid,
			completed_at = CASE
				WHEN $9::uuid IS NULL THEN NULL
				WHEN $10 THEN NOW()
				ELSE completed_at END,
			updated_at = NOW()
		WHERE finding_id = $1 AND tenant_id = $2`,
		findingID.String(), tenantID.String(),
		cl.ExposureCleared(), cl.EvidenceAttached(), cl.RegisterUpdated(),
		cl.MonitoringAdded(), cl.RegressionScheduled(), newNotes,
		upd, change.Completed)
	if err != nil {
		return nil, nil, fmt.Errorf("update checklist: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}
	view, err := s.Get(ctx, tenantID, findingID)
	if err != nil {
		return nil, nil, err
	}
	return view, change, nil
}
