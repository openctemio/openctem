### Security: run status, retry release, group counters and ingest job writes now carry the tenant

- Updating a scan run's status, releasing a failed retry claim, recalculating an asset group's counters and completing or failing an ingest job were written by id alone. Each now also requires the tenant of the row, so an id of another tenant changes nothing. The callers already hold the tenant.
- The tenant-SQL lint now requires the tenant predicate in the statement's own WHERE. A `tenant_id` inside a subquery or CTE no longer protects the outer statement.
