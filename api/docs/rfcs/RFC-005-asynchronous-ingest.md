# RFC-005: Asynchronous Ingest — Decouple Accept from Process

- **Status**: Proposed
- **Created**: 2026-06-04
- **Owner**: Platform / Ingest
- **Problem**: Agents push large scan reports (up to 100k findings / 100k assets, 50 MB compressed). Today the API parses, correlates, and writes the **entire** report inside the HTTP request — the agent connection and a DB connection are held for the whole write. Under many concurrent agents this saturates API workers and the DB connection pool and degrades user-facing latency. We need ingest to absorb large bursts without blocking agents or starving interactive traffic.

---

## 1. Current state

Path: `routes/scanning.go registerAgentRoutes` → `ingest_handler.go IngestCTIS` → `internal/app/ingest/service.go Ingest` → `processor_{assets,components,cves,findings}` → postgres repos.

What already exists and works well (do **not** redo):

- API-key auth (`AuthenticateSource`), gzip/zstd decompression, 50 MB body limit, **per-tenant token-bucket rate limit**, a **chunk endpoint** for very large reports.
- Logical-level batching everywhere: `CheckFingerprintsExist`, `CreateBatchWithResult`, `AutoReopenByFingerprintsBatch`, `EnrichBatchByFingerprints`.
- Recent write-throughput work (this milestone):
  - findings → single multi-row INSERT (#123)
  - assets → single multi-row upsert (#124)
  - CVE upsert already multi-row
  - auto-resolve → one set-based query (#125)
  - enrichment folded into the insert; per-finding post-update removed (#126)

After that work the **per-report DB work is close to optimal**, but it is still **all synchronous inside the request**. That is the remaining ceiling.

### Why synchronous is the ceiling

```
agent ──HTTP POST /agent/ingest──► API worker ──┐
                                                 ├─ parse 50–100 MB JSON   (CPU + RSS)
        (connection held the whole time)         ├─ correlate assets       (DB)
                                                 ├─ upsert assets/cves      (DB)
                                                 ├─ insert findings         (DB)
                                                 └─ auto-resolve            (DB)
agent ◄──────────── 201 + counts ───────────────┘   (seconds … minutes)
```

- One slow/huge report ties up an API worker goroutine **and** a DB connection for its whole duration.
- N agents finishing scans at the same time (e.g. nightly pipelines) → N concurrent heavy writes → DB pool exhaustion → interactive queries (dashboards, triage) queue behind ingest.
- No backpressure other than the token bucket (which rejects, it doesn't smooth).
- No retry: a transient DB error fails the whole agent upload; the agent must resend the full 50 MB.
- Memory: `io.ReadAll` + full unmarshal holds the entire object graph per in-flight request; peak RSS scales with `body_size × concurrency`.

## 2. Goals / Non-goals

**Goals**

1. Agent upload returns in **near-constant time** regardless of report size — accept, persist raw, enqueue, return `202`.
2. Bound and **smooth** ingest concurrency so it can't exhaust the DB pool or starve interactive traffic.
3. **Per-tenant fairness** — one noisy tenant/agent cannot monopolize ingest.
4. **At-least-once with idempotency** — transient failures retry automatically; duplicate/re-sent reports don't double-process.
5. Preserve all current correctness (dedup by fingerprint, auto-resolve rules, enrichment, audit).

**Non-goals**

- Changing the CTIS payload format or the parsing/correlation/write logic (reuse `ingest.Service.Ingest` verbatim inside the worker).
- Streaming/partial parse (tracked separately as Tier-2; complementary, not required here).
- Multi-region / cross-cluster queue. Single Postgres + in-process workers is the target; the design leaves room for an external queue later.

## 3. Proposed design

Split the endpoint into **accept** (fast, in request) and **process** (async, in a worker pool).

```
                         ┌──────────────── API replica ────────────────┐
agent ─POST /ingest──►   │ accept: validate envelope, store raw payload, │
                         │         INSERT ingest_jobs(status=pending),    │  ◄─ returns 202 + job_id
                         │         return 202                              │
                         └───────────────────────────────────────────────┘
                                          │ (rows in DB)
                         ┌──────────────── worker pool (per replica) ─────┐
                         │ claim N pending jobs FOR UPDATE SKIP LOCKED     │
                         │   weighted-fair across tenants                  │
                         │ → ingest.Service.Ingest(report)                 │
                         │ → status=completed (+counts) | failed (+retry)  │
                         └────────────────────────────────────────────────┘
agent ─GET /ingest/jobs/{id}──► status + counts (poll, optional)
```

### 3.1 Accept endpoint

`POST /api/v1/agent/ingest` (and the format-specific variants) change behaviour:

1. Auth + decompress + body-limit + rate-limit (unchanged middleware).
2. **Cheap envelope validation only**: valid JSON, `version` present, `assets`+`findings` counts within limits (`ValidateReport` already does the count checks — keep that, it's O(1) on already-parsed slices… see §6 note).
3. Persist the **raw decompressed payload** + metadata into `ingest_jobs` (status `pending`), keyed by an **idempotency key** = `(tenant_id, report_id, sha256(payload))`.
4. Return `202 Accepted`:

```json
{ "job_id": "0192...", "status": "pending", "report_id": "scan-abc" }
```

`Location: /api/v1/agent/ingest/jobs/0192...` for polling.

### 3.2 ingest_jobs table

```sql
CREATE TABLE ingest_jobs (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    agent_id      UUID,
    report_id     TEXT,
    source_type   TEXT,
    payload       BYTEA,            -- decompressed CTIS JSON (or pointer to object store)
    payload_sha   BYTEA NOT NULL,   -- sha256 for idempotency + integrity
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending|processing|completed|failed|dead
    attempts      INT  NOT NULL DEFAULT 0,
    max_attempts  INT  NOT NULL DEFAULT 5,
    priority      INT  NOT NULL DEFAULT 0,
    result        JSONB,            -- counts (assets/findings created/updated) on success
    error         TEXT,             -- last error on failure
    locked_by     TEXT,             -- worker/replica id holding the claim
    locked_at     TIMESTAMPTZ,
    available_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- backoff: not claimable before this
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Idempotency: same payload submitted twice => same job, processed once.
CREATE UNIQUE INDEX ux_ingest_jobs_idem ON ingest_jobs (tenant_id, report_id, payload_sha);

-- Claim scan: pending & due, oldest first.
CREATE INDEX ix_ingest_jobs_claim ON ingest_jobs (status, available_at)
    WHERE status IN ('pending', 'processing');
```

**Payload storage**: `BYTEA` in Postgres is simplest and transactional. For very large payloads (tens of MB × high volume) this bloats the table and WAL; the design keeps an abstraction (`PayloadStore`) so we can switch to object storage (S3/MinIO) with only a pointer in the row. Start with `BYTEA` + a TTL cleaner; revisit if table growth is a problem.

### 3.3 Worker pool + claiming

A background controller (mirrors the existing notification-outbox worker and job-recovery controllers) runs on each API replica:

```sql
-- Claim a batch atomically; SKIP LOCKED lets replicas claim disjoint sets.
UPDATE ingest_jobs SET status='processing', locked_by=$1, locked_at=NOW(), attempts=attempts+1
WHERE id IN (
    SELECT id FROM ingest_jobs
    WHERE status='pending' AND available_at <= NOW()
    ORDER BY priority DESC, available_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT $2
)
RETURNING ...;
```

- **Bounded concurrency**: a fixed worker count (config, e.g. `INGEST_WORKERS=4` per replica) caps simultaneous heavy writes → protects the DB pool. This is the core backpressure.
- For each claimed job: decode payload → `ingest.Service.Ingest(ctx, agent, input)` (reused unchanged) → on success `status=completed, result=counts`; on error `status` back to `pending` with `available_at = NOW() + backoff(attempts)`, or `dead` when `attempts >= max_attempts`.
- **Crash recovery**: a sweeper resets rows stuck in `processing` with `locked_at` older than a lease timeout back to `pending` (same pattern as `job_recovery` controller).

### 3.4 Per-tenant fairness

Plain `ORDER BY available_at` is FIFO and lets a tenant that submits 1,000 reports starve others. Use **weighted fair queuing** like the platform-job queue already does:

- Claim query partitions by tenant and round-robins (e.g. `ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY available_at)` then order by that rank, then age). 
- Optional age bonus so old jobs don't starve under heavy multi-tenant load.

Reuse the WFQ approach from `internal/infra/postgres` platform-job queuing rather than inventing a new one.

### 3.5 Backpressure to agents

- The per-tenant token bucket stays on the accept path (cheap rejects).
- Add a **queue-depth guard**: if a tenant has more than `K` pending jobs, the accept endpoint returns `429 Too Many Requests` + `Retry-After`, so well-behaved agents slow down instead of piling up unbounded payload rows.

### 3.6 Status endpoint

`GET /api/v1/agent/ingest/jobs/{id}` → `{ status, result?, error? }`. Agents may poll to confirm processing and surface counts in CI logs. Polling is optional — fire-and-forget is valid for agents that don't care.

## 4. API contract change

| Before | After |
|---|---|
| `201 Created` + full counts (synchronous) | `202 Accepted` + `job_id` (async); counts via status poll |

This is a **breaking change** for any agent/SDK that reads the synchronous counts from the POST response. Mitigations in §6.

## 5. Failure handling & idempotency

- **Idempotency**: accept upserts on `(tenant_id, report_id, payload_sha)`. A re-sent identical payload returns the existing `job_id` (and its status) instead of creating a duplicate — agents that retry after a network blip don't double-ingest. Findings already dedup by fingerprint, but this also protects asset/CVE/component work and saves the recompute.
- **Retries**: transient errors (DB deadlock, timeout) → exponential backoff via `available_at`; `dead` after `max_attempts`, surfaced via an admin view + metric.
- **Partial success**: `ingest.Service` already returns partial counts and per-finding errors; store them in `result` so a "completed with errors" job is visible.

## 6. Backward compatibility & rollout

Phased, behind a config flag, so we never break running agents:

1. **Phase 0 (this RFC + plumbing)**: add `ingest_jobs` table + `PayloadStore` + worker controller, **dark**. Endpoint still synchronous.
2. **Phase 1 (opt-in)**: `INGEST_MODE=async` flag. When on, the endpoint enqueues + returns `202`; when off, current synchronous behaviour. Default off.
3. **Phase 2 (SDK/agent support)**: agents learn to accept `202` + poll the status endpoint (or fire-and-forget). Ship a `sync=true` query param / `Prefer: respond-sync` header that an old agent can use to force the legacy synchronous path during the transition.
4. **Phase 3 (default async)**: flip default to async once agents are updated; keep the sync path as a fallback for one release.

> **Note on validation (§3.1)**: cheap envelope validation still requires parsing the JSON to count assets/findings. To keep accept truly O(small), either (a) accept counts from a small uncompressed header the agent sends, or (b) do a streaming token-count without building the full object graph. Otherwise accept still pays the full unmarshal cost (just not the DB cost). This is the natural seam to land the Tier-2 streaming parse. Acceptable to start with full-parse-on-accept and optimize later, since the DB work (the dominant cost) is what moves async.

## 7. Observability

- Metrics: `ingest_jobs_enqueued_total`, `ingest_job_duration_seconds` (parse vs DB stages), `ingest_queue_depth{tenant}`, `ingest_jobs_dead_total`, worker utilization.
- An admin endpoint / dashboard panel for queue depth and dead jobs (reuse the outbox admin pattern).

## 8. Alternatives considered

1. **External queue (Redis Streams / NATS / SQS)** instead of a DB table. Pros: purpose-built, less DB load. Cons: another moving part + delivery/ordering semantics to manage; the codebase already does DB-backed `FOR UPDATE SKIP LOCKED` queues (outbox, platform jobs) and Postgres is already a hard dependency. **Decision**: DB-backed first; the `PayloadStore`/queue interfaces leave room to swap later.
2. **Just raise worker/DB pool limits**. Doesn't bound concurrency or give fairness/retries; trades one resource cliff for another.
3. **Keep synchronous, shard by tenant**. Doesn't solve single-large-report latency or burst smoothing.
4. **Process in-request but stream-write**. Helps memory, not the connection-holding or burst problems.

## 9. Implementation plan (phased PRs)

1. Migration: `ingest_jobs` + indexes. `PayloadStore` (BYTEA impl) + repo (`Enqueue`, `ClaimBatch`, `Complete`, `Fail`, `GetByID`, idempotency upsert).
2. Worker controller (bounded pool, claim→process→complete/fail, backoff, crash sweeper) reusing `ingest.Service.Ingest`.
3. Accept-path async mode behind `INGEST_MODE` flag (default off) + status endpoint + queue-depth 429.
4. Per-tenant WFQ in the claim query.
5. Metrics + admin view + dead-letter handling.
6. SDK/agent: 202 + poll; `sync` escape hatch; flip default.

## 10. Open questions

- Payload storage threshold for moving from `BYTEA` to object store — measure table/WAL growth in Phase 1.
- Retention/TTL for completed `ingest_jobs` rows (archive vs delete; keep `result` counts for how long?).
- Does any caller depend on the synchronous counts beyond CI ergonomics? Audit SDK + CI snippets before flipping the default.
- Chunk endpoint interaction: chunked uploads should assemble into a single `ingest_jobs` row once complete (verify chunk store is shared/Redis, not per-instance memory — flagged in the ingest analysis).
