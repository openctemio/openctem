package findingpractice

// The compliance SLA re-baseline (-sla): an open compliance finding written
// before compliance had its own policy carries a vulnerability deadline.
// Deadlines only tighten on their own, so moving it to the compliance window
// is an explicit, audited extension counted from first detection, never from
// now (docs/architecture/finding-practices.md, "Compliance SLA").
//
// A dry run reports aggregates per tenant only. -apply writes, page by page,
// the deadlines that move later (never earlier), with a sla_rebaselined
// timeline entry per finding (both deadlines) and an undo file (CSV of
// tenant, finding, previous deadline and status, new deadline) written
// before each page is committed.

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lib/pq"

	slaapp "github.com/openctemio/openctem/server/internal/app/sla"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/server/pkg/domain/sla"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SLAReport is one tenant's compliance re-baseline aggregates.
type SLAReport struct {
	// Considered is the open compliance findings with a deadline.
	Considered int `json:"considered"`
	// Extended is those whose compliance deadline is later than the stored one.
	Extended int `json:"extended"`
	// Unchanged is those whose stored deadline stays (already as late, or the
	// compliance policy gives no deadline).
	Unchanged int `json:"unchanged"`
	// OverdueBefore and OverdueAfter count overdue findings now and after.
	OverdueBefore int `json:"overdue_before"`
	OverdueAfter  int `json:"overdue_after"`
	// ExtensionDays is the sum of the extensions, in whole days.
	ExtensionDays int64 `json:"extension_days"`
	// Applied is the deadlines written (with -apply).
	Applied int `json:"applied"`
}

// errUndoRequired refuses a re-baseline apply without an undo file.
var errUndoRequired = errors.New("-sla -apply needs -undo <file>: the previous deadlines are written there first")

const slaPageSQL = `
	SELECT id, COALESCE(asset_id::text, ''), COALESCE(priority_class, ''), severity,
	       COALESCE(first_detected_at, created_at), sla_deadline, COALESCE(sla_status, '')
	FROM findings
	WHERE tenant_id = $1 AND id > $2
	  AND finding_type = 'compliance' AND is_open_finding_status(status) AND sla_deadline IS NOT NULL
	ORDER BY id
	LIMIT $3`

type slaMove struct {
	id, status string
	from, to   time.Time
}

func rebaselineTenant(ctx context.Context, db *sql.DB, tid string, opts Options, undo *csv.Writer) (*SLAReport, error) {
	svc := slaapp.NewService(postgres.NewSLAPolicyRepository(&postgres.DB{DB: db}), logger.NewNop())
	deadline, err := svc.SLADeadlineFunc(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("read sla policies: %w", err)
	}
	rep := &SLAReport{}
	now := time.Now().UTC()
	after := "00000000-0000-0000-0000-000000000000"
	for {
		moves, last, n, err := slaPage(ctx, db, tid, after, opts.BatchSize, deadline, now, rep)
		if err != nil {
			return nil, err
		}
		if opts.Apply && len(moves) > 0 {
			written, err := applySLAPage(ctx, db, tid, moves, undo)
			if err != nil {
				return nil, err
			}
			rep.Applied += written
		}
		if n < opts.BatchSize {
			return rep, nil
		}
		after = last
	}
}

func slaPage(ctx context.Context, db *sql.DB, tid, after string, limit int, deadline slaapp.DeadlineFunc, now time.Time, rep *SLAReport) ([]slaMove, string, int, error) {
	rows, err := db.QueryContext(ctx, slaPageSQL, tid, after, limit)
	if err != nil {
		return nil, "", 0, fmt.Errorf("read compliance findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		moves []slaMove
		last  string
		n     int
	)
	for rows.Next() {
		var (
			id, asset, class, sev, status string
			detected, old                 time.Time
		)
		if err := rows.Scan(&id, &asset, &class, &sev, &detected, &old, &status); err != nil {
			return nil, "", 0, fmt.Errorf("scan compliance finding: %w", err)
		}
		n++
		last = id
		rep.Considered++
		if old.Before(now) {
			rep.OverdueBefore++
		}
		severity, perr := vulnerability.ParseSeverity(sev)
		if perr != nil {
			severity = vulnerability.SeverityMedium
		}
		next, derr := deadline(asset, sladom.PracticeCompliance, class, severity, detected)
		if derr != nil || next.IsZero() || !next.After(old) {
			rep.Unchanged++
			if old.Before(now) {
				rep.OverdueAfter++
			}
			continue
		}
		rep.Extended++
		rep.ExtensionDays += int64(next.Sub(old) / (24 * time.Hour))
		if next.Before(now) {
			rep.OverdueAfter++
		}
		moves = append(moves, slaMove{id: id, status: status, from: old, to: next})
	}
	return moves, last, n, rows.Err()
}

// applySLAMovesSQL moves each deadline only when it is still the one read
// (a finding changed since is left as it is) and the finding is still an
// open compliance finding. The transaction is marked as an explicit SLA
// change, so the tighten-only guard lets the deadline move later.
const applySLAMovesSQL = `
	UPDATE findings f SET sla_deadline = v.to_at, sla_kev_capped = false
	FROM unnest($2::uuid[], $3::timestamptz[], $4::timestamptz[]) AS v(id, from_at, to_at)
	WHERE f.tenant_id = $1 AND f.id = v.id AND f.sla_deadline = v.from_at
	  AND f.finding_type = 'compliance' AND is_open_finding_status(f.status)
	RETURNING f.id`

const slaActivitySQL = `
	INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, created_at)
	VALUES ($1, $2, $3, $4, 'system', 'system: finding-practice', $5, 'auto', NOW())`

func applySLAPage(ctx context.Context, db *sql.DB, tid string, moves []slaMove, undo *csv.Writer) (int, error) {
	if undo == nil {
		return 0, errUndoRequired
	}
	for _, m := range moves {
		if err := undo.Write([]string{tid, m.id, m.from.UTC().Format(time.RFC3339Nano), m.status, m.to.UTC().Format(time.RFC3339Nano)}); err != nil {
			return 0, fmt.Errorf("write undo file: %w", err)
		}
	}
	undo.Flush()
	if err := undo.Error(); err != nil {
		return 0, fmt.Errorf("write undo file: %w", err)
	}

	ids := make([]string, len(moves))
	from := make([]time.Time, len(moves))
	to := make([]time.Time, len(moves))
	byID := make(map[string]slaMove, len(moves))
	for i, m := range moves {
		ids[i], from[i], to[i] = m.id, m.from, m.to
		byID[m.id] = m
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL openctem.sla_restart = on`); err != nil {
		return 0, fmt.Errorf("mark sla change: %w", err)
	}
	moved, err := updatedIDs(ctx, tx, tid, ids, from, to)
	if err != nil {
		return 0, err
	}
	for _, id := range moved {
		m := byID[id]
		raw, err := json.Marshal(map[string]any{
			"reason":                "compliance_policy",
			"previous_sla_deadline": m.from.UTC().Format(time.RFC3339),
			"sla_deadline":          m.to.UTC().Format(time.RFC3339),
			"previous_sla_status":   m.status,
		})
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, slaActivitySQL, shared.NewID().String(), tid, id,
			string(vulnerability.ActivitySLARebaselined), raw); err != nil {
			return 0, fmt.Errorf("record re-baseline: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(moved), nil
}

func updatedIDs(ctx context.Context, tx *sql.Tx, tid string, ids []string, from, to []time.Time) ([]string, error) {
	rows, err := tx.QueryContext(ctx, applySLAMovesSQL, tid, pq.Array(ids), pq.Array(from), pq.Array(to))
	if err != nil {
		return nil, fmt.Errorf("move deadlines: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// openUndo creates the undo file (never overwrites one) with its header.
func openUndo(path string) (*os.File, *csv.Writer, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen path
	if err != nil {
		return nil, nil, fmt.Errorf("create undo file: %w", err)
	}
	w := csv.NewWriter(f)
	if err := w.Write([]string{"tenant_id", "finding_id", "previous_sla_deadline", "previous_sla_status", "sla_deadline"}); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, w, nil
}
