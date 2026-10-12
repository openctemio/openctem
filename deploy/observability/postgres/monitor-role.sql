-- Least-privilege login role for the Postgres metrics exporter
-- (api/docs/operations/monitoring.md, "Postgres exporter role").
--
-- pg_monitor reads the statistics views and settings only: it cannot read
-- or change any table. Run once as a superuser (or the database owner with
-- CREATEROLE), with the password from OBS_PG_MONITOR_PASSWORD:
--
--   docker compose exec -T postgres psql -U openctem -d openctem \
--     -v pw="$OBS_PG_MONITOR_PASSWORD" -f - < deploy/observability/postgres/monitor-role.sql
--
-- Idempotent: re-running it updates the password.

SELECT format('CREATE ROLE openctem_monitor LOGIN PASSWORD %L', :'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openctem_monitor')
\gexec

SELECT format('ALTER ROLE openctem_monitor WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 3', :'pw')
\gexec

GRANT pg_monitor TO openctem_monitor;

-- With the least-privilege roles (api/deploy/postgres/least-privilege-roles.sql)
-- PUBLIC cannot connect to the database: grant CONNECT explicitly (and only that).
SELECT format('GRANT CONNECT ON DATABASE %I TO openctem_monitor', current_database())
\gexec
