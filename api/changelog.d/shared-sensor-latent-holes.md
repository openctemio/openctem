### Security: shared (platform) sensors: three latent holes closed before access opens

- An organization's own sensor never takes a job queued for shared sensors:
  the poll, the doorbell, the batch claim and the claim by id now exclude
  `is_platform_job`. Before, the routing decision "shared sensors" was
  silently overridden and the organization's sensor ran the job.
- A shared sensor's grant is least privilege whatever writes it: no tenant
  credentials, no unsolicited (push) results, tier 1 at most, public targets,
  no remote update. The sensors insert trigger used to grant it
  `legacy-broad` with credentials, push ingest and tier 2; a new
  `sensor_grants` trigger clamps later edits and sensors flagged shared after
  creation, and the migration clamps existing rows (migration 002481
  `shared_sensor_grant_least_privilege`).
- Every workflow step queued for shared sensors goes through the scan
  trigger's target check (no asset group, no internal target, domain proof
  where the operator requires it, no bug-bounty program target) on the step's
  own targets. A run started from a workflow directly had no such check.
- Upgrade note: no action. Shared sensors stay unavailable to every
  organization; jobs already queued for shared sensors now expire after the
  queue limit instead of running on an organization's sensor.
