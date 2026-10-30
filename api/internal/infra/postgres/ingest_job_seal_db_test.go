package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func sealTestRepo(t *testing.T) (*IngestJobRepository, *sql.DB, shared.ID) {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping ingest job sealing DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return NewIngestJobRepository(&DB{DB: db}), db, newIngestJobTestTenant(t, db)
}

// queuePlainV1 stores n plaintext protocol v1 jobs of size bytes each, queued
// an hour ago, and returns their ids in queue order.
func queuePlainV1(t *testing.T, repo *IngestJobRepository, db *sql.DB, tenant shared.ID, n, size int) []ingestjob.ID {
	t.Helper()
	ids := make([]ingestjob.ID, 0, n)
	for i := range n {
		payload := bytes.Repeat([]byte{byte('a' + i)}, size)
		stored, _, err := repo.Enqueue(context.Background(), ingestjob.NewJob(tenant, nil, fmt.Sprintf("seal-%d", i), "trivy", payload))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE ingest_jobs SET created_at = NOW() - interval '1 hour' + ($2 || ' seconds')::interval WHERE id = $1`,
			stored.ID().String(), i); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, stored.ID())
	}
	return ids
}

// fakeSeal stands in for the sealer: it stores a recognizable sealed form.
func fakeSeal(j *ingestjob.Job) error {
	size := int64(len(j.Payload()))
	j.SetSealedPayload("test-key", append([]byte("sealed:"), j.Payload()[:1]...), size)
	return nil
}

func sealState(t *testing.T, db *sql.DB, id ingestjob.ID) (sealed bool, failed bool) {
	t.Helper()
	var key sql.NullString
	var mark sql.NullTime
	if err := db.QueryRow(`SELECT payload_key_id, payload_seal_failed_at FROM ingest_jobs WHERE id = $1`, id.String()).
		Scan(&key, &mark); err != nil {
		t.Fatal(err)
	}
	return key.Valid, mark.Valid
}

// A row that cannot be sealed is reported and marked, the rows around it are
// sealed in the same step, and the marked row is not picked again until its
// mark expires.
func TestSealPlaintextSensorPayloads_UnsealableRowIsSkipped(t *testing.T) {
	repo, db, tenant := sealTestRepo(t)
	ctx := context.Background()
	ids := queuePlainV1(t, repo, db, tenant, 3, 100)
	bad := ids[0] // the oldest: it would head every batch

	seal := func(j *ingestjob.Job) error {
		if j.ID() == bad {
			return errors.New("seal refused")
		}
		return fakeSeal(j)
	}
	run, err := repo.SealPlaintextSensorPayloads(ctx, time.Now(), 10, 1<<20, seal)
	if err != nil {
		t.Fatal(err)
	}
	if run.Picked != 3 || run.Sealed != 2 || len(run.Failed) != 1 || run.Failed[0].JobID != bad || run.Failed[0].TenantID != tenant {
		t.Fatalf("run %+v", run)
	}
	if s, f := sealState(t, db, bad); s || !f {
		t.Fatalf("unsealable row: sealed=%v marked=%v", s, f)
	}
	for _, id := range ids[1:] {
		if s, f := sealState(t, db, id); !s || f {
			t.Fatalf("row %s: sealed=%v marked=%v", id, s, f)
		}
	}

	// Not picked again.
	run, err = repo.SealPlaintextSensorPayloads(ctx, time.Now(), 10, 1<<20, seal)
	if err != nil || run.Picked != 0 || len(run.Failed) != 0 {
		t.Fatalf("second run %+v err %v", run, err)
	}

	// Its mark expires: tried again (and sealed once the cause is gone).
	if _, err := db.Exec(`UPDATE ingest_jobs SET payload_seal_failed_at = NOW() - interval '2 days' WHERE id = $1`, bad.String()); err != nil {
		t.Fatal(err)
	}
	run, err = repo.SealPlaintextSensorPayloads(ctx, time.Now(), 10, 1<<20, fakeSeal)
	if err != nil || run.Picked != 1 || run.Sealed != 1 {
		t.Fatalf("retry run %+v err %v", run, err)
	}
}

// A step holds at most maxBytes of payloads (a first row over it goes alone),
// and the rows left are taken by the next step.
func TestSealPlaintextSensorPayloads_BatchIsCappedByBytes(t *testing.T) {
	repo, db, tenant := sealTestRepo(t)
	ctx := context.Background()
	queuePlainV1(t, repo, db, tenant, 4, 1000)

	loaded := 0
	count := func(j *ingestjob.Job) error { loaded++; return fakeSeal(j) }
	run, err := repo.SealPlaintextSensorPayloads(ctx, time.Now(), 100, 2500, count)
	if err != nil || run.Picked != 2 || run.Sealed != 2 || loaded != 2 {
		t.Fatalf("capped step %+v loaded=%d err %v", run, loaded, err)
	}
	run, err = repo.SealPlaintextSensorPayloads(ctx, time.Now(), 100, 10, count)
	if err != nil || run.Picked != 1 || run.Sealed != 1 {
		t.Fatalf("a row over the cap must go alone: %+v err %v", run, err)
	}
	run, err = repo.SealPlaintextSensorPayloads(ctx, time.Now(), 100, 1<<20, count)
	if err != nil || run.Picked != 1 || run.Sealed != 1 {
		t.Fatalf("last step %+v err %v", run, err)
	}
}

// Protocol v1 jobs are sealed like segments, and finishing a v1 job empties
// its payload.
func TestSensorV1Jobs_SealedThenEmptiedOnComplete(t *testing.T) {
	repo, db, tenant := sealTestRepo(t)
	ctx := context.Background()
	ids := queuePlainV1(t, repo, db, tenant, 1, 50)

	if run, err := repo.SealPlaintextSensorPayloads(ctx, time.Now(), 10, 1<<20, fakeSeal); err != nil || run.Sealed != 1 {
		t.Fatalf("v1 job not sealed: %+v %v", run, err)
	}
	var key sql.NullString
	var bytesN sql.NullInt64
	var payload []byte
	if err := db.QueryRow(`SELECT payload_key_id, payload_bytes, payload FROM ingest_jobs WHERE id = $1`, ids[0].String()).
		Scan(&key, &bytesN, &payload); err != nil {
		t.Fatal(err)
	}
	if key.String != "test-key" || bytesN.Int64 != 50 || !bytes.HasPrefix(payload, []byte("sealed:")) {
		t.Fatalf("stored v1 row: key=%v bytes=%v payload=%q", key, bytesN, payload)
	}
	// A sealed job is read back as sealed (the worker opens it).
	got, err := repo.GetByID(ctx, tenant, ids[0])
	if err != nil || !got.PayloadSealed() || got.PayloadBytes() != 50 {
		t.Fatalf("read back: %v sealed=%v", err, got != nil && got.PayloadSealed())
	}

	if _, err := db.Exec(`UPDATE ingest_jobs SET status = 'processing', attempts = 1 WHERE id = $1`, ids[0].String()); err != nil {
		t.Fatal(err)
	}
	if err := repo.Complete(ctx, ids[0], 1, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT octet_length(payload) FROM ingest_jobs WHERE id = $1`, ids[0].String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("payload of a finished v1 job kept (%d bytes, %v)", n, err)
	}
}

func TestTenantQueuedBytes(t *testing.T) {
	repo, db, tenant := sealTestRepo(t)
	ctx := context.Background()
	other := newIngestJobTestTenant(t, db)
	ids := queuePlainV1(t, repo, db, tenant, 2, 300)
	queuePlainV1(t, repo, db, other, 1, 9000)

	if n, err := repo.TenantQueuedBytes(ctx, tenant); err != nil || n != 600 {
		t.Fatalf("queued bytes %d err %v, want 600 (another tenant's must not count)", n, err)
	}
	// A sealed row counts its decoded size, not the ciphertext's.
	if _, err := repo.SealPlaintextSensorPayloads(ctx, time.Now(), 10, 1<<20, fakeSeal); err != nil {
		t.Fatal(err)
	}
	if n, _ := repo.TenantQueuedBytes(ctx, tenant); n != 600 {
		t.Fatalf("after sealing %d, want 600", n)
	}
	// Finished jobs do not count.
	if _, err := db.Exec(`UPDATE ingest_jobs SET status = 'completed' WHERE id = $1`, ids[0].String()); err != nil {
		t.Fatal(err)
	}
	if n, _ := repo.TenantQueuedBytes(ctx, tenant); n != 300 {
		t.Fatalf("after completing one %d, want 300", n)
	}
}
