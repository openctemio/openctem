### Fixed: technology backfill no longer stops when a tenant is deleted mid-run
- Marking a tenant as backfilled after it was deleted is now a no-op instead of an error that aborted the run for every remaining tenant.
