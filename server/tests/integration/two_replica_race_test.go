package integration

// Two-replica race suite (RFC-046 §11, P1.11): the guarantees that let more
// than one API replica run (B4) are exercised with two "replicas", each with
// its own connection pool, racing on one database. Every test runs many
// rounds so a lost race shows up as a duplicate, not as luck.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const raceRounds = 20

// replicas opens two independent pools on the test database.
func replicas(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping the two-replica race suite")
	}
	open := func() *sql.DB {
		db, err := sql.Open("postgres", url)
		if err != nil {
			t.Skipf("open db: %v", err)
		}
		db.SetMaxOpenConns(4)
		t.Cleanup(func() { _ = db.Close() })
		if err := db.PingContext(context.Background()); err != nil {
			t.Skipf("cannot reach DATABASE_URL: %v", err)
		}
		return db
	}
	return open(), open()
}

// race runs a and b at the same moment and waits for both.
func race(a, b func()) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; a() }()
	go func() { defer wg.Done(); <-start; b() }()
	close(start)
	wg.Wait()
}

// Scheduler: both replicas see the same due occurrence; exactly one claims
// it, and the occurrence key refuses a second run for it.
func TestTwoReplicas_SchedulerClaimsEachOccurrenceOnce(t *testing.T) {
	dbA, dbB := replicas(t)
	ctx := context.Background()
	tenantID := seedLifecycleTenant(ctx, t, dbA)
	scanID := seedLifecycleScan(ctx, t, dbA, tenantID)
	scansA := postgres.NewScanRepository(&postgres.DB{DB: dbA})
	scansB := postgres.NewScanRepository(&postgres.DB{DB: dbB})
	runsA := postgres.NewScanRunRepository(&postgres.DB{DB: dbA})
	runsB := postgres.NewScanRunRepository(&postgres.DB{DB: dbB})

	due := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for round := 0; round < raceRounds; round++ {
		occurrence := due.Add(time.Duration(round) * time.Minute)
		next := occurrence.Add(time.Minute)
		if _, err := dbA.ExecContext(ctx, `UPDATE scans SET next_run_at = $2, status = 'active' WHERE id = $1`,
			scanID.String(), occurrence); err != nil {
			t.Fatal(err)
		}
		var okA, okB bool
		var errA, errB error
		race(
			func() { okA, errA = scansA.ClaimScheduledRun(ctx, tenantID, scanID, occurrence, &next) },
			func() { okB, errB = scansB.ClaimScheduledRun(ctx, tenantID, scanID, occurrence, &next) },
		)
		if errA != nil || errB != nil {
			t.Fatalf("round %d: claim errors %v / %v", round, errA, errB)
		}
		if okA == okB {
			t.Fatalf("round %d: claimed by A=%v B=%v, want exactly one", round, okA, okB)
		}

		// Even if both went on to create the run, the occurrence key lets
		// one through.
		mk := func() *scanrun.Run {
			tpl, _ := shared.IDFromString("00000000-0000-0000-0000-000000000001")
			r, _ := scanrun.NewRun(tpl, tenantID, nil, scanworkflow.TriggerTypeSchedule, "", map[string]any{})
			r.ScanID = &scanID
			occ := occurrence
			r.ScheduledFor = &occ
			return r
		}
		var cErrA, cErrB error
		race(
			func() { cErrA = runsA.CreateRunIfUnderLimit(ctx, mk(), 1000, 1000) },
			func() { cErrB = runsB.CreateRunIfUnderLimit(ctx, mk(), 1000, 1000) },
		)
		created := 0
		for _, e := range []error{cErrA, cErrB} {
			switch {
			case e == nil:
				created++
			case errors.Is(e, scanrun.ErrOccurrenceAlreadyRun), errors.Is(e, shared.ErrConflict):
			default:
				t.Fatalf("round %d: create run: %v", round, e)
			}
		}
		if created != 1 {
			t.Fatalf("round %d: %d runs created for one occurrence, want 1", round, created)
		}
		// Settle it so the next round's scheduled run is not an overlap.
		if _, err := dbA.ExecContext(ctx, `UPDATE scan_runs SET status = 'completed', completed_at = NOW()
			WHERE scan_id = $1 AND status IN ('pending', 'running')`, scanID.String()); err != nil {
			t.Fatal(err)
		}
	}
}

// Command claim: two sensors on two replicas claim the same pending
// commands; each command goes to exactly one of them.
func TestTwoReplicas_CommandClaimedOnce(t *testing.T) {
	dbA, dbB := replicas(t)
	ctx := context.Background()
	tenantID := seedLifecycleTenant(ctx, t, dbA)
	sensor := func(name string) string {
		id := shared.NewID().String()
		if _, err := dbA.ExecContext(ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
			VALUES ($1, $2, $3, $4, 'p', 'active')`, id, tenantID.String(), name+"-"+id[:8], "h-"+id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	sA, sB := sensor("a"), sensor("b")
	cmdsA := postgres.NewCommandRepository(&postgres.DB{DB: dbA})
	cmdsB := postgres.NewCommandRepository(&postgres.DB{DB: dbB})

	for round := 0; round < raceRounds; round++ {
		id := shared.NewID()
		if _, err := dbA.ExecContext(ctx, `INSERT INTO commands (id, tenant_id, type, status, payload)
			VALUES ($1, $2, 'scan', 'pending', '{}')`, id.String(), tenantID.String()); err != nil {
			t.Fatal(err)
		}
		var okA, okB bool
		var errA, errB error
		race(
			func() { okA, errA = cmdsA.ClaimForSensor(ctx, tenantID, id, sA) },
			func() { okB, errB = cmdsB.ClaimForSensor(ctx, tenantID, id, sB) },
		)
		if errA != nil || errB != nil {
			t.Fatalf("round %d: claim errors %v / %v", round, errA, errB)
		}
		if okA == okB {
			t.Fatalf("round %d: claimed by A=%v B=%v, want exactly one", round, okA, okB)
		}
		var holder string
		if err := dbA.QueryRowContext(ctx, `SELECT sensor_id::text FROM commands WHERE id = $1`, id.String()).Scan(&holder); err != nil {
			t.Fatal(err)
		}
		if (okA && holder != sA) || (okB && holder != sB) {
			t.Fatalf("round %d: the winner does not hold the command (holder %s)", round, holder)
		}
	}
}

// Audit chain: two replicas append to one tenant's chain at once; the chain
// never forks (every prev_hash is the hash of the entry before it).
func TestTwoReplicas_AuditChainNeverForks(t *testing.T) {
	dbA, dbB := replicas(t)
	ctx := context.Background()
	tenantID := seedLifecycleTenant(ctx, t, dbA)
	repoA := postgres.NewAuditRepository(&postgres.DB{DB: dbA})
	repoB := postgres.NewAuditRepository(&postgres.DB{DB: dbB})

	appendOne := func(repo *postgres.AuditRepository) error {
		log, err := audit.NewAuditLog(audit.ActionScanConfigTriggered, audit.ResourceTypeScanConfig, shared.NewID().String(), audit.ResultSuccess)
		if err != nil {
			return err
		}
		log.WithTenantID(tenantID)
		if err := repo.Create(ctx, log); err != nil {
			return err
		}
		return repo.AppendNextChainEntry(ctx, tenantID, func(prev string) audit.ChainEntry {
			sum := sha256.Sum256([]byte(prev + log.ID().String()))
			return audit.ChainEntry{AuditLogID: log.ID(), TenantID: tenantID, PrevHash: prev, Hash: hex.EncodeToString(sum[:])}
		})
	}
	for round := 0; round < raceRounds; round++ {
		var errA, errB error
		race(func() { errA = appendOne(repoA) }, func() { errB = appendOne(repoB) })
		if errA != nil || errB != nil {
			t.Fatalf("round %d: append errors %v / %v", round, errA, errB)
		}
	}

	rows, err := dbA.QueryContext(ctx, `SELECT prev_hash, hash FROM audit_log_chain WHERE tenant_id = $1 ORDER BY chain_position`, tenantID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	prev, n := "", 0
	for rows.Next() {
		var p, h string
		if err := rows.Scan(&p, &h); err != nil {
			t.Fatal(err)
		}
		if p != prev {
			t.Fatalf("entry %d: prev_hash %q, want %q: the chain forked", n, p, prev)
		}
		prev = h
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 2*raceRounds {
		t.Fatalf("chain has %d entries, want %d", n, 2*raceRounds)
	}
}
