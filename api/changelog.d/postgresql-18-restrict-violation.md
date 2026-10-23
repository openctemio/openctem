### Fixed: deleting a proxy pool that a sensor still uses answers 409 on PostgreSQL 18

- PostgreSQL 18 reports a RESTRICT foreign key that refuses a delete as SQLSTATE 23001 instead of 23503. The foreign-key check now accepts both, so deleting an in-use proxy pool again answers "pool in use" (409) instead of an internal error on PostgreSQL 18. Found by the new PostgreSQL 16/18 CI job.
