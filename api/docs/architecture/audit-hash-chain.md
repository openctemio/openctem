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
| Classify breaks offline | `cmd/chainaudit` |
| Rebaseline: `POST /api/v1/audit-logs/rebaseline` (owner only) | `AuditService.RebaselineChain` |

`payload` is `action|resource_type|resource_id|result`. The timestamp is
rounded to microseconds, as PostgreSQL stores it.

## Rebaselining

A rebaseline re-signs a tenant's whole chain from the current `audit_logs`
rows. It treats the current data as correct, so it removes evidence of
tampering just as easily as it removes harmless breaks. It exists for one
case only: breaks left by the old timestamp-precision bug, where the stored
hash used a timestamp value PostgreSQL never kept (see the header of
`cmd/chainaudit/main.go`).

### When to use it

Only after `chainaudit` explains every break:

```bash
DATABASE_URL=postgres://… go run ./cmd/chainaudit
```

Rebaseline only when it reports `UNEXPLAINED : 0`. Each unexplained row is
either a defect nobody has characterized yet or a real tamper. Investigate it
first: a rebaseline would erase the difference.

Then, as a tenant owner or admin:

```
POST /api/v1/audit-logs/rebaseline
→ 200 {"ok": true, "rebaseline_id": "…", "entries_total": 812, "entries_rewritten": 80}
```

The rebaseline refuses with **409** and changes nothing when:

- a chain entry points at an `audit_logs` row that no longer exists. That is a
  tamper signal, and a rebaseline must not cover it up;
- the chain changed while the rebaseline ran (an entry was appended, or an
  entry no longer holds the hashes that were read);
- the chain is longer than the 10,000 entries one rebaseline walks.

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
`chainaudit` does: try the stored timestamp minus 1µs (`legacyMatch`), then the
brute-forced nanosecond remainder (pre-#79 rows). If one of them matches, the
break was the known bug. If none does, the audit row changed after it was
signed.

The rebaseline also appears in the audit log itself: filter on action
`audit.chain_rebaselined`.
