package postgres

// Absence decided from the receipt (docs/architecture/ingest-receipts.md,
// "Absence"). A finding counts as seen by an ingest when the ingest's receipt
// has an action row for it (created, still_detected, reopened or closed):
// the receipt writer records every finding the report named, before and
// whatever the outcome of the finding writes. findings.scan_id is not proof
// of absence: a concurrent upload of the same tool overwrites it with its own
// id, and a sighting write that lost a deadlock leaves the old one, and either
// made a finding the scanner did report look unseen and closed it.
//
// A receipt whose action list is incomplete (no receipt at all, or one past
// the per-receipt action cap) cannot prove that anything was not seen, so it
// closes nothing (ingestreport.ErrReceiptIncomplete).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// receiptSeenSQL is true when the finding of the table alias has an action
// row on the receipt named by the placeholder receiptArg (a uuid parameter).
func receiptSeenSQL(alias, receiptArg string) string {
	return `EXISTS (SELECT 1 FROM finding_ingest_actions fia
		WHERE fia.receipt_id = ` + receiptArg + `::uuid AND fia.finding_id = ` + alias + `.id
			AND fia.tenant_id = ` + alias + `.tenant_id)`
}

// AbsenceReceipt returns the receipt whose action rows decide what the given
// source did not report: the receipt must exist in the tenant and hold every
// action (not truncated). Otherwise it returns ingestreport.ErrReceiptIncomplete.
func (r *FindingRepository) AbsenceReceipt(ctx context.Context, tenantID shared.ID, source ingestreceipt.Source) (shared.ID, error) {
	kind, ref, err := resolveReceiptSource(ctx, r.db, tenantID, source)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return shared.ID{}, ingestreport.ErrReceiptIncomplete
		}
		return shared.ID{}, err
	}
	return absenceReceiptByRef(ctx, r.db, tenantID, kind, ref)
}

// AbsenceReceiptByID is AbsenceReceipt for a receipt known by id (an upload).
func (r *FindingRepository) AbsenceReceiptByID(ctx context.Context, tenantID, receiptID shared.ID) (shared.ID, error) {
	var truncated bool
	err := r.db.QueryRowContext(ctx, `SELECT actions_truncated FROM ingest_receipts WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), receiptID.String()).Scan(&truncated)
	return checkAbsenceReceipt(receiptID, truncated, err)
}

func absenceReceiptByRef(ctx context.Context, q rowQuerier, tenantID shared.ID, kind ingestreceipt.SourceKind, ref string) (shared.ID, error) {
	var (
		id        string
		truncated bool
	)
	err := q.QueryRowContext(ctx, `SELECT id::text, actions_truncated FROM ingest_receipts
		WHERE tenant_id = $1 AND source_kind = $2 AND source_ref = $3`, tenantID.String(), string(kind), ref).Scan(&id, &truncated)
	if err != nil {
		return checkAbsenceReceipt(shared.ID{}, false, err)
	}
	rid, err := shared.IDFromString(id)
	if err != nil {
		return shared.ID{}, fmt.Errorf("absence receipt id: %w", err)
	}
	return checkAbsenceReceipt(rid, truncated, nil)
}

func checkAbsenceReceipt(id shared.ID, truncated bool, err error) (shared.ID, error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return shared.ID{}, ingestreport.ErrReceiptIncomplete
	case err != nil:
		return shared.ID{}, fmt.Errorf("load absence receipt: %w", err)
	case truncated:
		return shared.ID{}, ingestreport.ErrReceiptIncomplete
	}
	return id, nil
}

// commandAbsenceReceipt is the receipt of the query's command (its scan
// run's, for a command of a run).
func (r *FindingRepository) commandAbsenceReceipt(ctx context.Context, tenantID shared.ID, q ingestreport.CoverageQuery) (shared.ID, error) {
	if q.CommandID.IsZero() {
		return shared.ID{}, ingestreport.ErrReceiptIncomplete
	}
	cmd := q.CommandID
	return r.AbsenceReceipt(ctx, tenantID, ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &cmd})
}
