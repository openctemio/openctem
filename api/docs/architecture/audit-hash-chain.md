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
| Rebaseline: `POST /api/v1/audit-logs/rebaseline` (owner only) | `AuditService.RebaselineChain` |
| Retention: archive and prune the oldest prefix past `AUDIT_RETENTION_DAYS` | `AuditService.PruneExpiredChains`, `internal/infra/controller/data_expiration.go`, migration 000943 |

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

### From the tenant API

As the organization's owner:

```
POST /api/v1/audit-logs/rebaseline
→ 200 {"ok": true, "rebaseline_id": "…", "entries_total": 812, "entries_rewritten": 80}
```

The rebaseline refuses with **409** and changes nothing when:

- a chain entry points at an `audit_logs` row that no longer exists. That is a
  tamper signal, and a rebaseline must not cover it up;
- the chain changed while the rebaseline ran (an entry was appended, or an
  entry no longer holds the hashes that were read).

An intact chain can still be rebaselined. It is recorded with
`entries_rewritten: 0`.

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
