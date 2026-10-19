# Audit Hash Chain

Every `audit_logs` row is pinned into a per-tenant SHA-256 chain in
`audit_log_chain` (migration 000154). Editing or deleting an audit row after the
fact breaks the chain from that point on, and the break is detectable.

## How it works

| Piece | Where |
|---|---|
| Hash primitive: `SHA-256(prev_hash \| audit_log_id \| payload \| timestamp)` | `pkg/crypto/audit_chain.go` |
| Append on every `LogEvent` (serialised by `chainMu`) | `internal/app/audit/service.go` (`appendChainEntry`) |
| Tenant-less events (logins, failed logins) go to the system chain `ffffffff-…` | `auditdom.SystemChainTenantID` |
| Verify: `GET /api/v1/audit-logs/verify` (admin), 409 + `breaks[]` on a break | `AuditService.VerifyChain` |
| Hourly verification of every tenant | `internal/infra/controller/audit_chain_verify.go` |
| Classify breaks (one implementation, shared by the CLI and the server) | `internal/app/audit/chainclassify` |
| Classify breaks offline, every tenant | `cmd/chainaudit` |
| Classify and rebaseline one organization from the admin console | `GET`/`POST /api/v1/admin/tenants/{tenantId}/audit-chain[/rebaseline]` (`AuditService.ClassifyChain`, `RebaselineChainIfExplained`) |
| There is no tenant rebaseline route: the organization's owner is the insider the chain guards against, so a rebaseline is a platform-operator action (admin console, above) | |
| Retention: archive and prune the oldest prefix past `AUDIT_RETENTION_DAYS` | `AuditService.PruneExpiredChains`, `internal/infra/controller/data_expiration.go`, migration 001010 |

`payload` is `action|resource_type|resource_id|result`. The timestamp is
rounded to microseconds, as PostgreSQL stores it.

## Retention

Tenant audit logs stay online for `AUDIT_RETENTION_DAYS` (default and minimum
365). The hourly data-expiration controller then prunes the **oldest
contiguous prefix** of each chain (tenant chains and the system chain), never
rows in the middle:

1. read up to 1000 of the chain's oldest entries logged before the cutoff,
   stopping at the first newer one;
2. write them, chain entry plus the audit row as stored, to
   `AUDIT_ARCHIVE_DIR/<tenant>/audit-<first>-<last>-<time>.jsonl.gz`
   (mode 0600, synced to disk) and hash the file;
3. in one transaction, under the same advisory lock appends take: check the
   entries are still exactly the chain's oldest ones and the last still has the
   hash that was read, insert an `audit_chain_anchors` row (anchor hash = the
   last pruned entry's hash, positions, counts, archive path and SHA-256), and
   delete the entries, their rebaseline archive rows and their audit rows.

A chain that changed in between (a rebaseline, a racing append) is skipped and
retried next run; its archive file is removed. Without `AUDIT_ARCHIVE_DIR`
nothing is deleted and the controller logs one warning.

Every walk starts from the newest anchor instead of `""`: verify, classify and
rebaseline expect the first remaining entry to link to it, and an append to a
chain with no entries left links to it too. To check a pruned prefix, recompute
its hashes from the archive lines (oldest first, `prev_hash` of the first line
= the previous anchor or `""`); the last line's hash must equal the anchor.

The old rule "keep high and critical rows forever" no longer applies online:
it deleted rows from the middle of the chain (which the foreign key refused, so
retention never ran). Every pruned row, whatever its severity, is in the
archive.

## Rebaselining

A rebaseline re-signs a tenant's whole chain from the current `audit_logs`
rows. It treats the current data as correct, so it removes evidence of
tampering just as easily as it removes harmless breaks. It exists for one
case only: breaks left by the old timestamp-precision bug, where the stored
hash used a timestamp value PostgreSQL never kept (see the package comment of
`internal/app/audit/chainclassify`).

### When to use it

Only after `chainaudit` explains every break:

```bash
DATABASE_URL=postgres://… go run ./cmd/chainaudit
```

Rebaseline only when it reports `UNEXPLAINED : 0`. Each unexplained row is
either a defect nobody has characterized yet or a real tamper. Investigate it
first: a rebaseline would erase the difference.

Classes (`chainclassify.Class`):

| Class | Meaning | Blocks a rebaseline |
|---|---|---|
| `verifies` | recomputes to the stored hash with the current code | no |
| `legacy_truncate` | matches at `stored_ts - 1µs`: the #79..#361 truncate/round defect | no |
| `pre_79_nanosecond` | matches once the lost sub-microsecond remainder is brute forced back: the original nanosecond hash | no |
| `unexplained` | matches none of the above | **yes** |
| `source_missing` | the `audit_logs` row behind the chain row is gone (server walk only) | **yes** |
| `link_broken` | `prev_hash` is not the previous row's stored hash, so a chain row was removed or re-ordered (server walk only) | **yes** |

### From the platform admin console

Organizations → an organization → **Audit chain** shows the classification
(any admin role) and, for a **super admin**, a **Rebaseline** action:

1. `GET /api/v1/admin/tenants/{tenantId}/audit-chain` classifies the whole
   chain and returns the counts per class, the blocking rows (and a few
   examples of each explained class) and a `fingerprint`: a SHA-256 over every
   row's position, ids, hashes, hashed fields and class.
2. The administrator types the organization's name and a **fresh** code from
   the console authenticator (step-up: the session's own sign-in code is spent,
   a wrong code counts toward the console lockout and is audited as
   `console.step_up_failed`).
3. `POST …/audit-chain/rebaseline` `{"fingerprint", "totp_code"}` re-runs the
   classification inside the same locked walk that computes the new hashes and
   refuses with **409**, rewriting nothing, when any row is blocking
   (`AUDIT_CHAIN_UNEXPLAINED`, with the classification in `details`) or the
   fingerprint differs from the reviewed one (`AUDIT_CHAIN_CHANGED`: the
   organization kept working, so review again). On success it verifies the
   chain and returns the result.

The archive row's `actor_id` is the administrator's `users` account; the
organization's `audit.chain_rebaselined` event is attributed to
`platform-admin:<email>` and carries `classification_fingerprint`; the platform
log gets a high-severity `organization.audit_chain_rebaseline` row (refusals
included, never the code).

### Not from the tenant API

The tenant API has no rebaseline route. The chain exists to make changes by a
privileged insider evident, and the organization's owner is the most
privileged insider, so letting them re-sign it would defeat its purpose, even
behind step-up. The organization owner reads the chain state (`GET /api/v1/audit-logs/verify`)
and asks the platform operator, who rebaselines from the admin console after
reviewing the classification. `tests/unit/admin_only_actions_test.go` fails
if a tenant-plane route reaches a rebaseline.

The rebaseline refuses with **409** and changes nothing when:

- a chain entry points at an `audit_logs` row that no longer exists. That is a
  tamper signal, and a rebaseline must not cover it up;
- the chain changed while the rebaseline ran (an entry was appended, or an
  entry no longer holds the hashes that were read).

### What is kept

One transaction does all of the following. If any step fails, the chain keeps
its old hashes and nothing is archived.

| Table (migration 000244) | Contents |
|---|---|
| `audit_chain_rebaselines` | One row per rebaseline: `id`, `tenant_id`, `actor_id`, `entries_total`, `entries_rewritten`, `created_at` |
| `audit_chain_rebaseline_entries` | One row per rewritten entry: `audit_log_id`, `chain_position`, `old_prev_hash`, `old_hash`, `new_prev_hash`, `new_hash` |

Only entries whose hashes actually change are archived. Neither table has a
foreign key to `tenants` or `users`. Like `audit_log_chain`, they are evidence:
they outlive the organization and the admin who ran the rebaseline.

After the commit, the rebaseline writes a **critical** `audit.chain_rebaselined`
event (resource type `audit_chain`, resource id = the rebaseline id). Its
metadata holds `rebaseline_id`, `entries_total`, `entries_rewritten` and
`actor_id`. The event is added to the newly signed chain. A refused or failed
attempt writes the same action with result `failure`.

### Reviewing archived hashes

```sql
-- Every rebaseline of a tenant
SELECT id, actor_id, entries_total, entries_rewritten, created_at
  FROM audit_chain_rebaselines
 WHERE tenant_id = $1
 ORDER BY created_at DESC;

-- What one rebaseline overwrote, next to the audit row each hash covered
SELECT e.chain_position, e.audit_log_id, l.action, l.logged_at,
       e.old_prev_hash, e.old_hash, e.new_prev_hash, e.new_hash
  FROM audit_chain_rebaseline_entries e
  JOIN audit_logs l ON l.id = e.audit_log_id
 WHERE e.tenant_id = $1 AND e.rebaseline_id = $2
 ORDER BY e.chain_position;
```

To check that an archived `old_hash` was a legacy-precision hash and not a
tamper, recompute it from the `audit_logs` row and `old_prev_hash` the way
`chainclassify` does: try the stored timestamp minus 1µs (`LegacyMatch`), then the
brute-forced nanosecond remainder (pre-#79 rows). If one of them matches, the
break was the known bug. If none does, the audit row changed after it was
signed.

The rebaseline also appears in the audit log itself: filter on action
`audit.chain_rebaselined`.

## The administrators' audit log

`admin_audit_logs` (platform administrators' actions) has its own, single
chain, built differently from the tenant chain: the database computes it
(migration 002545), so every writer is covered, the API, the console service
and the `bootstrap-admin` CLI alike (it writes its `admin.created`,
`admin.replaced` and `admin.relinked` entries in the same transaction as the
change, with `postgres.CreateAdminAuditLogTx`).

| Piece | Where |
|---|---|
| Chain columns on the row: `chain_position`, `prev_hash`, `hash` | `admin_audit_logs` |
| `hash = SHA-256(prev_hash \| payload)`, payload = every other column as a fixed-order JSON array, the timestamp as epoch microseconds | `admin_audit_row_payload`, `admin_audit_row_hash` (SQL) |
| Append: a `BEFORE INSERT` trigger takes a transaction-scoped advisory lock, reads the tail and overwrites whatever chain values the writer sent | `admin_audit_chain_append` |
| Append-only: `UPDATE`, `DELETE` and `TRUNCATE` are refused by triggers, and the API role holds no `UPDATE`/`DELETE`/`TRUNCATE` grant on the table (the migration and `deploy/postgres/least-privilege-roles.sql` revoke them) | `admin_audit_refuse_change` |
| Retention: `admin_audit_prune(cutoff, max_rows)` (`SECURITY DEFINER`, runs as the table owner) deletes only the oldest prefix older than `max(cutoff, now - 365 days)` and records an anchor | `admin_audit_chain_anchors`; the admin audit retention controller calls it |
| Verify: recompute each online row with the same SQL function, check links from the newest anchor and that no position is missing | `AuditLogRepository.VerifyChain`; `GET /api/v1/admin/audit-logs/chain` (any admin, Security > Activity); `bootstrap-admin verify-audit [-json]` (exit 1 on a break) |

Off-box copy (`ADMIN_AUDIT_SINK`). The chain cannot stop the table owner from
re-signing it, so the API ships the administrators' audit log to a destination
the database operator cannot write. Off unless set. Implementation:
`internal/infra/auditsink`, an exclusive controller (one replica at a time,
under the controller lease) with its cursor in `admin_audit_forward_cursor`.

| Setting | Meaning |
|---|---|
| `ADMIN_AUDIT_SINK` | `https://collector/path`, `syslog+tls://host:port` or `file:///path`. Plaintext `syslog+tcp://` and `syslog+udp://` are not supported. An unusable value stops the API at boot. |
| `ADMIN_AUDIT_SINK_SECRET` | HMAC-SHA256 key of the webhook, at least 32 bytes, required for https and refused otherwise. Never logged. |
| `ADMIN_AUDIT_SINK_SYSLOG_CA_FILE` | PEM roots for the syslog collector (default: system roots). |
| `ADMIN_AUDIT_SINK_SYSLOG_CLIENT_CERT`, `_CLIENT_KEY` | PEM client certificate and key (set together), for mutual TLS. |
| `ADMIN_AUDIT_SINK_HEAD_INTERVAL` | Head-only export when no row is new (15 minutes). |

**Delivery.** Rows go out in chain order in batches of up to 500 (at most 10
batches per run, every 15 seconds). The cursor (position and hash of the last
accepted row) moves forward only after the sink accepted the batch (a 2xx for
the webhook, the collector closing the TLS stream after reading it for syslog, a synced line for the file), so
delivery is at-least-once: a failure, a crash or a failed cursor save re-sends
the batch. The receiver de-duplicates on the chain position; the batch id is
`<first>-<last>` (or `head-<position>`). A failed run backs off exponentially
from 15 seconds up to 15 minutes. The cursor never moves backwards.

**Payload.** One JSON object per batch: `version`, `batch_id`, `sent_at`,
`first_position`, `last_position`, `rows`, `head` (`position`, `hash`) and
`chain` (`verified`, `ok`, `breaks`, `truncated`, `verified_at`). Each row has
`position`, `prev_hash`, `hash`, `id`, `at`, `admin_id`, `admin_email`,
`action`, `resource_type`, `resource_id`, `resource_name`, `method`, `path`,
`status`, `ip`, `success`, `error` and `severity`. The request body and the
user agent are withheld (the hash covers them, so the database row can still be
checked against it). The columns are explicit: `AdminAuditShippedColumns` and
`AdminAuditWithheldColumns` together name every column of `admin_audit_logs`,
and `TestAdminAuditSinkColumns_DB` fails when a column is added without a
decision, so nothing leaves the box by accident.

**Webhook authentication.** Headers `X-OpenCTEM-Timestamp` (unix seconds),
`X-OpenCTEM-Batch-Id` and `X-OpenCTEM-Signature: sha256=<hex HMAC-SHA256(secret,
timestamp + "." + body)>`. The receiver verifies the signature in constant time
and refuses a timestamp older than a few minutes. Each batch carries its own
send time. Redirects are never followed. The client is the operator's (the URL
is an environment setting, usually a collector on a private network, so it is
not dialed through the SSRF guard); errors name the host and the reason only,
never the URL or the secret.

**Syslog.** RFC 5424 messages (one per row and one for the head) over TLS 1.2+
(RFC 5425, octet-counting frames), verified against the roots above. Configure
the client certificate and key and require them on the collector (mutual TLS)
so nobody else can write rows or a head into the copy. Restrict who can read
the copy too: it holds what the table holds, less the request body.

Syslog has no application-level acknowledgement. After the batch is written
the sender half-closes and counts it delivered only when the collector reads
to the end and closes its side cleanly before the 20 second deadline; a
timeout or a reset fails the batch and it is re-sent. That proves less than the
webhook's 2xx or the file's fsync: a collector can close and still drop the
batch. Prefer https or file where the copy must be provable.

**Gaps.** The forwarder checks that each batch continues the cursor (first
position is the cursor's plus one and its previous hash is the cursor's hash).
When it does not, rows were removed or rewritten after delivery: it logs
`admin_audit_forward_gap`, raises `openctem_admin_audit_forward_gaps_total` and
adds a `gap` object (`expected_position`, `first_position`,
`prev_hash_matches`) to the batch, and keeps delivering so the copy never stalls.

**Chain state and head export.** The forwarder verifies the chain every hour
and puts the result in every export. `chain.verified` is false until a
verification ran, and again after one that could not run: the export never
repeats an older good result as current; a failed run is retried within five
minutes. When nothing is new it still sends a row-less batch every
`ADMIN_AUDIT_SINK_HEAD_INTERVAL`, so the receiver can alarm on silence and
compare the head with what the database later claims. Someone who controls the
database can re-sign the whole chain, but cannot change the heads and rows
already sent: compare them with `GET /api/v1/admin/audit-logs/chain` or
`bootstrap-admin verify-audit -json`.

**Alerts.** Prometheus: `openctem_admin_audit_forward_consecutive_failures`
(above 0 for several minutes), `..._forward_failures_total{sink}`,
`..._forward_rows_total`, `..._forward_lag_rows`, `..._forward_lag_seconds`,
`..._forward_last_success_timestamp_seconds` (alert when it stops moving),
`openctem_admin_audit_chain_ok` (0 on a break), `..._chain_breaks_total` and
`..._chain_verify_errors_total`. Error logs: `admin audit forward failed`,
`admin audit forwarder is lagging` (oldest unsent row older than 10 minutes)
and `admin_audit_chain_break` (the SIEM keyword).

The administrator a row names is history: the foreign key from `admin_id` to
`admin_users` is dropped, so deleting an administrator never rewrites a row.

Threat model. The chain detects a row edited or removed by anyone who can
bypass the triggers (the table owner disabling them, a restore from an edited
dump); it cannot stop the owner from re-signing the whole chain: that is what
the off-box copy (`ADMIN_AUDIT_SINK`) is for. With the single-role database
setup the API role is the owner, so the guarantee then rests on the triggers
alone; the least-privilege roles make it a database permission.

