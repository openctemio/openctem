# Durable jobs

Background work that must not be lost is a row in `durable_jobs`, written in
the same database transaction as the change that needs it, and run by a
worker that retries it. Redis is not involved: a Redis restart, eviction or
outage cannot drop these jobs.

## Kinds (shipped)

| Kind | Queued by | Runs |
|---|---|---|
| `jira_status_sync` | a finding status change, single or bulk, of a finding linked to a ticket (`VulnerabilityService`) | `jira.SyncService.SyncFindingStatus` |
| `github_status_sync` | the same status change (a finding links to at most one provider; the other push is a no-op) | `ticketing.GitHubTicketService.SyncFindingStatus` |
| `invitation_email` | creating an invitation, and resending one (token rotation) | `auth.EmailService.SendTeamInvitationEmail` (tenant SMTP, then platform e-mail) |

## How it works

```
service                                   repository (one transaction)
  ctx = durablejob.WithEnqueue(ctx, job)    UPDATE findings ... / INSERT tenant_invitations ...
  repo.Update(ctx, ...)  ───────────────▶   if the write changed a row:
                                              INSERT INTO durable_jobs ... ON CONFLICT (kind, subject_id)
                                                WHERE status = 'pending' DO UPDATE SET payload, next_attempt_at
                                            COMMIT  (both or neither)

durable-jobs controller (every 5 s, every replica)
  UPDATE ... SET status = 'processing', attempts + 1, locked_until = now() + 2 min
    WHERE id IN (SELECT ... due AND kind = ANY(handled kinds) FOR UPDATE SKIP LOCKED LIMIT 50)
  run the handler (1 min timeout)
    ok                         → DELETE the row
    permanent error / 8th try  → status = 'dead', payload cleared, last_error kept
    other error                → status = 'pending', next_attempt_at = now() + 30 s × 2^(n-1) (≤ 1 h)
  a processing row whose lease passed (worker died) is claimed again
```

- **One pending job per subject and kind** (partial unique index): a burst of
  status changes queues one push, and a resend replaces the unsent e-mail of
  the old token. A retry that finds a newer pending job for its subject is
  dropped in its favour.
- **Idempotent handlers.** A status push reads the finding's current status
  and skips when the ticket already has it; a push for a finding whose status
  did not move, or that is not linked to that provider, does nothing. An
  e-mail is at least once: a worker that dies after sending and before
  deleting the row sends it again.
- **Kinds without a handler are not claimed**, so a replica without SMTP
  leaves invitation e-mails to one that has it.

## Security

- **Tenant isolation:** every row carries `tenant_id` (cascade on tenant
  delete); handlers act for the row's tenant only, and every statement that
  touches one row is also scoped by `tenant_id`. A pending row is never
  replaced by a job of another tenant.
- **Secrets:** the invitation link token, which the database otherwise holds
  only as a hash, is in the payload sealed with the application encryption key
  (`APP_ENCRYPTION_KEY`, AES-256-GCM) together with the recipient. It is
  deleted with the row after sending, and cleared when the job is given up.
- **No echo loop:** only OpenCTEM-initiated status changes queue a push; the
  inbound ticket webhooks update findings through another path.

## Operations

- Dead jobs stay in `durable_jobs` with `status = 'dead'` and `last_error`;
  each is also logged at error level ("durable job given up").
- Upgrade: status pushes and invitation e-mails still queued in Redis by the
  previous version are not run. A status push is caught up by the next status
  change; an invitation can be resent.

## Key files

```
pkg/domain/durablejob/job.go                    kinds, Job, WithEnqueue/FromContext, Store
internal/infra/postgres/durable_job_repository.go  insert in the caller's tx, Claim/Complete/Retry/Bury
internal/infra/postgres/finding_transition.go   status writes queue context jobs in their transaction
internal/infra/postgres/tenant_repository.go    invitation create/resend queue the e-mail job
internal/infra/controller/durable_jobs.go       the worker (claim, run, retry, bury)
internal/infra/jobs/durable_jobs.go             handlers; invitation payload sealing
migrations/002933_durable_jobs.up.sql           the table
```
