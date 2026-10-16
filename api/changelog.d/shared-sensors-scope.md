### Security: shared sensors have no tenant (sensor scope replaces the platform flag)

- A sensor now has a scope: `organization` (a sensor of one organization, as before) or `instance` (a shared sensor that belongs to the instance). `sensors.scope` replaces `sensors.is_platform_sensor`, and a shared sensor's `tenant_id` is `NULL` instead of the operator organization's id, so a shared row can no longer match an organization's queries or claims (RFC-100 §3.1, migration `002711_sensor_scope`).
- The scope is fixed when the sensor is created; a sensor can no longer be turned into a shared one later.
- A shared sensor's key never authenticates into an organization: no tenant context, 403 `scope-denied` on the tenant-bound sensor routes. Every organization route on one sensor still answers 404 for a shared sensor.
- The migration moves existing shared sensors to `scope = 'instance'` with no tenant, clears the tenant of their grant and keys, and removes their zone memberships, tool settings, collector assets and ingest reports (rows an organization-only table cannot hold for them).
- A shared sensor's grant is limited to the job types scan, validate and retest: no limit becomes exactly these, any other list its intersection with them. Existing shared sensors' grants are narrowed by the migration.
- **Upgrade note:** the migration drops the column `sensors.is_platform_sensor`. Stop the API during the deploy (the old code reads the dropped column), run the migrations, then start the new API. The downgrade refuses while shared sensors exist: delete them first.
