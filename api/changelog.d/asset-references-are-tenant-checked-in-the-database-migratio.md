### Security: asset references are tenant-checked in the database (migrations 000920-000922)

- Every table that stores an asset id next to a `tenant_id` (27 columns:
  findings, exposures, exposure events, pipeline runs, scan sessions,
  suppressions, SLA policies, scope rows, grants, relationships, ...) gets a
  composite foreign key `(tenant_id, asset) → assets(tenant_id, id)`: a row of
  one organization can no longer point at another organization's asset,
  whatever writes it. Backstop for the application checks on `POST /findings`,
  exposure create/ingest and pipeline runs (research doc 21b, C1/C3/C4).
- **Deploy note:** `000921` first counts existing cross-tenant references and
  refuses to run, changing nothing, if there are any. See
  `docs/deployment/safe-deploy-and-migrations.md` ("Asset tenant foreign keys")
  for the listing query and the recovery steps. `000920` builds an index
  `CONCURRENTLY`; `000922` validates without blocking writes.
