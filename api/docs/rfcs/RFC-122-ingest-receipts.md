# RFC-122: Import and run receipts

| | |
|---|---|
| Status | Accepted (2026-10-22). Built in steps; [ingest-receipts.md](../architecture/ingest-receipts.md) says what is shipped |
| Scope | api (`pkg/domain/ingestreceipt`, `pkg/domain/ingestpayload`, `internal/app/ingest`, `internal/app/ingestqueue`, `internal/app/findingimport`, `internal/app/cirun`, findings import and CI upload routes, migrations), web (import page, scan run page, finding detail) |
| Architecture | [ingest-receipts.md](../architecture/ingest-receipts.md), [finding-import.md](../architecture/finding-import.md) |
| Related | RFC-026 (sensor results ingest), RFC-040 (result binding), RFC-043 (deduplication), RFC-048 (list query contract), RFC-051 (CI runs), RFC-041 (API conventions) |

## 1. Summary

People trust automation only when they can see what each run did. Every
upload and every sensor run gets a **receipt**: how many findings it
created, saw again (still detected), reopened, closed, left untouched,
skipped and failed to store, and a per-finding action log that links each
finding to the receipt with what was done to it. The same writer feeds the
daily ingest-outcome fact the dashboards read.

A receipt describes; it never decides. Findings are closed only by the
coverage rules that already exist (a covered sensor run of an explicit
scope, a source's own mitigation statement) and, for uploads, only when the
upload declares full coverage of an explicit scope (§5). A partial upload
never closes anything.

## 2. Decisions

| ID | Decision |
|---|---|
| D1 | One receipt per upload (one `POST /findings/imports` request, all its files) and per sensor run: a scan run (all commands of its steps), a command outside a run, a CI run, a connector run, a report a sensor pushed without a command. The upload table `finding_imports` becomes `ingest_receipts`; its rows are kept as upload receipts, so `findings.scan_id` and `assets.import_id` keep naming their producer. |
| D2 | Vocabulary on the wire: `created`, `updated` (still detected), `reactivated` (reopened), `closed`, `untouched`, `skipped`, `failed`. `untouched` is `null` when no scope was declared: then nothing was expected of the source. |
| D3 | `finding_ingest_actions(receipt_id, finding_id, action)` with actions `created`, `still_detected`, `reopened`, `closed`; one row per receipt and finding, the first action recorded wins (a finding a run created is not counted again as still detected by a later batch of the same run). At most 50,000 rows per receipt; past it the counts keep counting and `actions_truncated` is set. Rows are kept 90 days. |
| D4 | Counts grow by the rows a delta actually added, so a finding two batches of one run both report counts once. |
| D5 | A coverage decision of a command (`EvaluateCommandCoverage`) records what it closed and the open findings of the covered scope it neither saw nor closed (`untouched`) in `ingest_receipt_coverage`, one row per command, replaced when the decision is evaluated again. A receipt is `coverage = full` only through such a decision (or a full-coverage upload). |
| D6 | `dash_ingest_day(tenant, day, source_kind, tool)` is upserted by the same writer in the same transaction: reports, received, created, still detected, reopened, closed, skipped, failed, suppressed. Kept 13 months. No partitions: one row per tenant, day, source kind and tool is small. |
| D7 | Receipt errors are `{index, code}` with fixed codes (`store_failed`, `file_<kind>`); a report's own text never reaches a receipt. A sensor report without a command is keyed by a hash of the sensor and the report id, never by the id as sent. |
| D8 | The writer is best-effort after the findings are stored: a failed receipt write is logged and counted (`openctem_ingest_receipt_write_failures_total`), the ingest stands. An upload's receipt, on the other hand, is created before anything is written: without it nothing is imported. A segment of a command's run whose receipt write failed is retried, because that receipt decides absence (D14). |
| D14 | Absence is decided from the receipt, not from `findings.scan_id`: a covered run closes an open finding of its scope only when the finding has no action row on the run's receipt. A concurrent run of the same tool overwrites `scan_id`, and a lost sighting write leaves an old one, so `scan_id` cannot prove that a finding was not reported. A missing or truncated receipt closes nothing (`receipt_incomplete`). |
| D9 | Visibility (§4): receipts and their counts are organization-wide figures. |
| D10 | Retention: action rows 90 days, run receipts 400 days, facts 400 days, one hourly job on one replica. Upload receipts stay: each is the producer record of what its upload wrote. |
| D11 | `POST /findings/imports` replaces `POST /findings/import` (no alias: the route was only called by the web console). It answers `201` with `Location: /api/v1/findings/imports/{id}` and the receipt; a preview (`dry_run=true`) answers `200` and writes nothing. |
| D12 | `Idempotency-Key` on `POST /findings/imports` is stored in Postgres (`idempotency_keys`), never only in a cache, and fails closed: when the store cannot be read or written the request is refused with 503 before anything is imported (§6). |
| D13 | The new list endpoints refuse unknown query parameters (400 `INVALID_FILTER`) and cap `per_page` at 100. |

## 3. Data model

- `ingest_receipts`: tenant, `source_kind` + `source_ref` (unique per
  tenant), actor (uploads), tool, format and file-name hash (uploads),
  `coverage` (`partial` | `full`) and `coverage_note`, `status`
  (`processing` | `completed` | `failed`), the counts, `actions_recorded`,
  `actions_truncated`, `errors`, timestamps.
- `finding_ingest_actions`: tenant, receipt, finding, action, time. The
  finding merge moves a loser's rows to the survivor (a receipt that already
  acted on the survivor keeps its own row).
- `ingest_receipt_coverage`: one row per receipt and command with the
  decision note and its untouched count.
- `dash_ingest_day`: the daily fact (D6).

Every table has `tenant_id` with a cascade from `tenants`, every query is
scoped by it, and the row-level security policies are in shadow mode like
the other tenant tables.

## 4. Visibility and authorization

A receipt's counts are about the whole organization: a run that covered
assets outside a restricted member's data scope counts findings that member
cannot see. So:

- The routes are gated by `findings:read`.
- A caller who sees the organization (an owner, an administrator or a
  full-data role with no hidden private-program assets, or a holder of
  `dashboards:org:view`) lists every receipt with its stored counts.
- Every other caller lists only the receipts they started themselves (their
  own uploads, which ran under their data scope and so counted only what
  they may see). Any other receipt is 404, never 403.
- The per-finding actions are filtered by the caller's data scope and the
  findings list's pentest visibility rule for everyone: a receipt never
  names a finding the caller cannot open.
- A finding's own "last seen in" entries are readable by whoever may read
  the finding; they carry the receipt id, its kind, the tool, the action and
  the time, not the receipt's counts.
- Another tenant's receipt is 404 everywhere.

## 5. Closing findings

| Source | May close | How |
|---|---|---|
| Upload without a declared scope (the default) | never | the ingest runs with partial coverage whatever the file says |
| Upload with `coverage=full` and an explicit scope (asset ids + the file's tool) | yes | open findings of that tool on those assets that the upload did not report, through the same guards as a covered scan (blinding guard, protected human sources, secrets never closed, the uploader's data scope must hold every declared asset, any failed or skipped record closes nothing); the uploader needs `findings:status`, `findings:bulk_update` and step-up, as for a bulk close |
| Sensor run, protocol v2, bound to a command | yes | the existing coverage rules (`EvaluateCommandCoverage`), unchanged |
| Source mitigation statement (Tenable.sc) | yes | the existing source-asserted resolve, in enforce mode |
| Anything else | never | |

## 6. Idempotency

`Idempotency-Key` (1 to 128 printable ASCII characters) on
`POST /findings/imports`:

- Stored in `idempotency_keys(tenant_id, principal, route, key_hash,
  request_sha256, state, status, response, receipt_id, expires_at)`; the key
  is hashed, the principal is the user or API key behind the request, so one
  member's key never replays another member's import.
- The request fingerprint is the SHA-256 of the canonical query parameters
  and of each part's form name and content hash, in order. File names and the
  multipart boundary are labels and do not count, so a client that retries
  the same files gets the same fingerprint.
- Same key and fingerprint after a success: the stored answer is replayed
  (`Idempotent-Replayed: true`), the receipt id is the same, nothing is
  imported again. Same key, another fingerprint: 422
  `IDEMPOTENCY_KEY_REUSED`. Same key while the first request runs: 409 with
  `Retry-After`. A failure releases the key.
- Fail closed: a store that cannot claim, read or finish the key refuses
  the request with 503 before any file is read for import.
- Kept 24 hours; an hourly job deletes expired keys.
- Without a key, the same files (same fingerprint) from the same principal
  within 10 minutes are the same upload: the answer names the first
  upload's receipt (`Idempotent-Replayed: true`). A CI run's upload is keyed
  by the run and the SHA-256 of the body, so the same body sent to the run
  again is always the same upload.

## 6a. Accept fast, apply async

CI results (`POST /api/v1/ci/runs/{id}/results`) and committed file imports
(`POST /api/v1/findings/imports`) are no longer applied inside the request,
where a large report ran into the request timeout and many concurrent
uploads competed for the API's connections. The request stores the upload
and answers **202**; the ingest worker applies it from the existing
`ingest_jobs` queue (no new broker).

- **Accept.** The tenant comes from the credential (run token, session, API
  key). What is cheap is checked at once: a CTIS report from a CI run is
  decoded with the bounded pre-check and must name only the run's
  repository (400 otherwise); the run takes a report slot (409 after the
  verdict or past the cap); an import's parameters, coverage declaration
  and Idempotency-Key are checked as before. Tool exports and import files
  are parsed by the worker. The raw bytes are stored in `ingest_payloads`,
  one row per part, gzip-compressed and sealed with AES-256-GCM under a key
  derived per tenant from `APP_ENCRYPTION_KEY` (HKDF; the additional data
  binds each row to its tenant, job and part, so a row copied elsewhere does
  not open; previous keys still open their rows during a rotation). Parts
  are capped at 128 MiB each, 64 per upload. Then one job (`kind`
  `ci_results` or `finding_import`, `source_ref` the run or the receipt) is
  enqueued, idempotent by `(tenant, report id, digest)`.
- **Answer.** CI: `202` with `upload_id` and `Location:
  /api/v1/ci/runs/{id}/results/{report_id}`. Import: `202` with the receipt
  id (receipt status `queued`) and `Location: /api/v1/findings/imports/{id}`.
- **Apply.** The worker opens the parts, re-reads what the job needs at the
  time it runs (the CI run; the uploader's data scope from the caller
  recorded at accept, so a narrowed scope applies and a removed member is
  refused), applies them exactly as the request did, stores the result on
  the job (counts, the decided results a CI job may hide, an import's
  per-file results), finishes the receipt, and deletes the parts and the
  job's envelope. A failure a retry cannot fix (an unreadable file, a
  report outside the run's repository, a run already judged, a part that
  does not open) is dead at once with a fixed `error_code`; others retry
  (2 s, 4 s, 8 s ... capped at a minute for uploads) and are dead after 5
  attempts (`apply_failed`). A dead import marks its receipt `failed` with
  that code; its parts are kept 7 days.
- **Read.** `GET /api/v1/ci/runs/{id}/results/{report_id}?wait=N` (run
  token) and `GET /api/v1/findings/imports/{id}/result?wait=N` answer
  `queued`, `processing`, `applied` (with the result) or `failed` (with the
  code); `wait` (at most 10 s, so the answer fits the server's write
  timeout) long-polls. An upload of another run or tenant is 404; an
  import's result is visible to whoever may read its receipt.
- **CI gate.** `POST /ci/runs/{id}/evaluate` waits up to 10 s for the run's
  uploads. Still pending: `503 INGEST_PENDING` with `Retry-After`, and the
  runner asks again (one command for the pipeline). The verdict's save is
  refused while any upload of the run is pending, so a verdict is never
  computed over part of the results, even for an upload accepted during the
  wait. An upload that failed for good fails the run (`upload_not_applied`).
- A preview (`dry_run=true`) still runs in the request: it writes nothing.

Threat model additions: the raw report is stored before secrets are masked,
hence sealed per tenant, never served back, and deleted once applied; a
hostile file is parsed only in the worker, with the importers' caps, and
its failure surfaces as a fixed code (never its text); the uploader's rights
are re-resolved when the job runs, never widened: the worker re-reads the
uploader's membership (a member who left or was suspended meanwhile is
refused with `uploader_not_permitted`, a demoted administrator imports with
the member's data scope); the gate fails closed on a pending or failed
upload. A job's stored report is deleted in the statement that records it
completed (a crash before that re-applies the upload), and at once when it
fails for good with a fixed code (only `apply_failed` keeps it, for a retry
of the same upload).

## 6b. Fairness and limits

Many CI pipelines, sensors and people upload at once; the queue keeps every
organization moving and every scope consistent.

- **Lanes.** `ingest_jobs.lane`: 0 urgent (a CI report with a critical
  finding or a CVE in the KEV catalogue, decided by the server from the
  decoded report), 1 interactive (a person's import, a CI upload a gate
  waits on), 2 bulk (sensor reports). The claim takes urgent first, then
  interactive, then bulk; within a lane it is fair across organizations by
  share: jobs an organization already has running count, so the one holding
  fewer workers goes first (each one's next job before anyone's second),
  then by age. A report cannot ask for a lane, but the server derives it
  from what the report says, so an organization's urgent lane goes ahead of
  others for one job at a time (its first, with nothing of it running);
  further urgent jobs of that organization queue as interactive. Flooding
  critical findings orders an organization's own work, never the whole
  worker pool.
- **One job per scope.** `ingest_jobs.scope_key` names the asset scope a job
  writes: a CI run's repository, an organization's imports, a sensor
  report's segments and commit. At most one job per key is processing: the
  claim skips a scope with a running job and takes one job per scope per
  batch, and the unique partial index `ux_ingest_jobs_scope_running` makes a
  concurrent claim of the same scope by another worker fail (that job is
  skipped). Twenty jobs of a CI matrix on one repository apply one after
  another instead of deadlocking on the same rows.
- **Running cap.** An organization has at most `INGEST_MAX_RUNNING_PER_TENANT`
  (2, half the workers of one server) jobs processing across servers, so the
  other organizations always have workers.
- **Workers.** Each server runs `INGEST_WORKERS` (4) workers; each claims one
  job at a time. The asset and finding writes go through their own pool
  (`DB_INGEST_MAX_CONNS`, 8, all idle-kept), so a burst of uploads cannot
  take the API's connections.
- **Back-pressure.** At accept (CI, import, sensor segment), an organization
  with `INGEST_MAX_PENDING_PER_TENANT` (100) unfinished jobs gets `429`
  (`INGEST_QUEUE_FULL`; sensors `queue-full`) with a `Retry-After` from how
  fast its jobs drained over the last 5 minutes (5 s to 5 min). A depth that
  cannot be read refuses the upload with `503` and `Retry-After` (fail
  closed); nothing is stored. An import is checked before its receipt is
  written, so a refused one leaves no trace.
- **Poison.** A job is claimed only while `attempts < max_attempts`
  (attempts count at claim). A lease that expires on the last attempt (a
  payload that crashes or hangs the worker) makes the job dead with
  `apply_failed`; its owner is told (the import's receipt fails, the CI gate
  fails the run).

## 6c. Queue hygiene

- The hourly, single-replica `ingest-queue-retention` job deletes, in batches
  of 5,000: stored upload parts as soon as nobody will open them (the job was
  applied, the part expired — 7 days after a failure — or an upload staged it
  and never got a job, after an hour); finished jobs (completed or dead) and
  finished protocol v2 reports (with their jobs) after 30 days. Receipts keep
  what each upload did (their own retention, §3).
- A quarantined sensor report is marked accepted only once it was applied.
  An accept first claims the item (`applying_at`, it stays pending): a second
  accept or a discard meanwhile is refused (409); a failed apply drops the
  claim so the item can be accepted again; a claim older than 15 minutes (a
  crashed server) no longer blocks.

## 7. API

| Route | Gate | Notes |
|---|---|---|
| `POST /api/v1/findings/imports` | `findings:write` + `assets:write` + `assets:import` | multipart; `202` + `Location` (the receipt, status `queued`), applied by the ingest worker (§6a); `dry_run=true` previews in the request (`200`) |
| `GET /api/v1/findings/imports/{id}/result` | `findings:read` | state of a committed upload (`queued`, `processing`, `applied`, `failed` + `error_code`), its per-file results and its receipt; `wait` ≤ 10 s; visible as the receipt |
| `POST /api/v1/ci/runs/{id}/results` | CI run token | `202` + `upload_id` + `Location` (§6a); the same body to the run again is the same upload |
| `GET /api/v1/ci/runs/{id}/results/{report_id}` | CI run token | state of the run's upload and, once applied, its counts and decided results; `wait` ≤ 10 s; another run's upload is 404 |
| `GET /api/v1/findings/imports` | `findings:read` | list of receipts (§4); filters `source_kind`, `source_ref`; `page`, `per_page` ≤ 100; unknown parameter → 400 |
| `GET /api/v1/findings/imports/{id}` | `findings:read` | one receipt, counts by severity of the visible actions |
| `GET /api/v1/findings/imports/{id}/actions` | `findings:read` | the per-finding actions the caller may see; filter `action` |
| `GET /api/v1/findings/{id}/imports` | `findings:read` | the receipts that acted on one finding, newest first |

## 8. Threat model

| Threat | Control |
|---|---|
| Cross-tenant read of a receipt or its actions | `tenant_id` on every table and every statement; 404 for another tenant's id; DB tests |
| Counts or finding ids outside a restricted member's scope | organization view required for others' receipts; actions filtered by data scope and pentest visibility; tests with a restricted member |
| A partial upload or a hostile report closing findings | an upload closes only with a declared full scope inside the uploader's data scope, through the coverage guards; a sensor report never closes by absence (only the per-command coverage rules); tests |
| Unbounded action rows (DoS) | 50,000 rows per receipt, `actions_truncated`; retention job; batched purge |
| Hostile report text stored on a receipt | fixed error codes; hashed report keys |
| Double import on a client retry | durable idempotency store; fail closed; replay returns the same receipt |
| Idempotency key replayed by another member | key scoped by tenant, principal and route; hashed |

## 9. Plan

1. Receipts data model and writer (uploads, sensor runs, coverage decisions,
   the daily fact, retention).
2. Receipts API, durable `Idempotency-Key`, `POST /findings/imports`.
3. Full-coverage uploads (`coverage=full` with an explicit scope).
4. Web: receipts on the import page and the scan run page, "last seen in"
   on the finding detail (en and vi).
5. Accept fast, apply async (§6a): CI results and committed imports stored
   sealed and applied by the ingest worker; the CI gate waits on the run's
   uploads.
6. Fairness and limits (§6b): lanes, one running job per scope, a running
   cap, workers on their own pool, fail-closed back-pressure, poison cap.
7. Queue hygiene (§6c): queue retention; quarantine accepted after apply.
