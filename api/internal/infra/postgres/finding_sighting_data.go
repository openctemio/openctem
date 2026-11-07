package postgres

// One write per ingest batch for what the batch's sightings carry beyond the
// finding row: the interop data merged onto the finding (finding_interop.go)
// and the source's own record of each finding (finding_source_records.go).
// Both are set-based over the batch's fingerprints and both are pinned to
// the tenant; together they are one statement per chunk, so per-source
// records cost an ingest no extra round trip (ingest query budget,
// tests/integration/ingest_budget_test.go).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// interopAndSourceRecordsSQL is interopUpdateSQL with the source-record
// upsert as a data-modifying CTE: $1 tenant, $2..$15 the interop arrays
// (interopArgs), then the upsert's parameters (sourceRecordsUpsert). Either
// half may get empty arrays and then writes nothing. The two halves write
// different tables; the upsert's key check on findings (KEY SHARE) does not
// conflict with the update's FOR NO KEY UPDATE locks.
var interopAndSourceRecordsSQL = func() string {
	ctes, insert := sourceRecordsUpsert(interopArgCount)
	return "\nWITH " + ctes + ",\nsource_records_written AS (\n" + insert + "\nRETURNING 1\n),\n" +
		interopLocked + "\n" + interopUpdate
}()

// emptyInteropArgs are interopArgs for a chunk without interop data.
func emptyInteropArgs() []any {
	args := make([]any, 0, interopArgCount)
	args = append(args, pq.Array([]string{}))
	for range interopArgCount - 2 {
		args = append(args, pq.Array([]sql.NullString{}))
	}
	return append(args, pq.Array([]string{}))
}

// StoreSightingData writes the interop data of a batch's sightings
// (UpdateInteropBatch) and what src reported for each of the tenant's
// findings (UpsertSourceRecords) in one statement per chunk. A source that
// is not a sighting channel keeps no records (the interop data is still
// written, and the error says why). Should the combined statement fail,
// each half is retried on its own, so one half's failure never loses the
// other's data.
func (r *FindingRepository) StoreSightingData(ctx context.Context, tenantID shared.ID,
	interop []vulnerability.InteropUpdate, src vulnerability.SourceIdentity, records []vulnerability.SourceRecordValues) error {
	var recErr error
	var recs sourceRecordBatch
	if len(records) > 0 {
		recs, recErr = newSourceRecordBatch(src, records)
	}
	if recErr != nil || len(recs.fps) == 0 {
		_, err := r.UpdateInteropBatch(ctx, tenantID, interop)
		return errors.Join(recErr, err)
	}

	// The global lock order of findings rows (finding_lock_order.go).
	interop = slices.Clone(interop)
	sortByFingerprint(interop, func(u vulnerability.InteropUpdate) string { return u.Fingerprint })
	chunks := max(recs.chunks(), (len(interop)+maxInteropBatch-1)/maxInteropBatch)
	var errs []error
	for i := range chunks {
		start := min(i*maxInteropBatch, len(interop))
		part := interop[start:min(start+maxInteropBatch, len(interop))]
		if err := r.storeSightingChunk(ctx, tenantID, part, recs, i); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// storeSightingChunk writes chunk i of both halves in one statement, or
// each half alone when that statement fails.
func (r *FindingRepository) storeSightingChunk(ctx context.Context, tenantID shared.ID,
	interop []vulnerability.InteropUpdate, recs sourceRecordBatch, i int) error {
	recArgs, err := recs.args(i)
	if err != nil {
		_, ierr := r.UpdateInteropBatch(ctx, tenantID, interop)
		return errors.Join(err, ierr)
	}
	iArgs := interopArgs(interop)
	if iArgs == nil {
		iArgs = emptyInteropArgs()
	}
	args := make([]any, 0, 1+len(iArgs)+len(recArgs))
	args = append(args, tenantID.String())
	args = append(args, iArgs...)
	args = append(args, recArgs...)
	combined := retryWriteConflict(ctx, func() error {
		_, execErr := r.db.ExecContext(ctx, interopAndSourceRecordsSQL, args...)
		return execErr
	})
	if combined == nil {
		return nil
	}
	_, ierr := r.UpdateInteropBatch(ctx, tenantID, interop)
	_, rerr := r.upsertSourceRecordChunk(ctx, tenantID, recs, i)
	if ierr == nil && rerr == nil {
		return nil
	}
	return errors.Join(fmt.Errorf("store finding sighting data: %w", combined), ierr, rerr)
}
