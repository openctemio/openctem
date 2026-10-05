-- =============================================================================
-- OpenCTEM least-privilege database roles (owner decision D-6)
-- =============================================================================
-- Creates or repairs two roles and moves the schema to them:
--
--   migrator (default openctem_migrator)  owns the schema; runs migrations.
--   app      (default openctem_app)       what the API connects as: DML on the
--                                         application tables, nothing else.
--
-- Neither role is SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS,
-- and neither is a member of pg_read_server_files, pg_write_server_files or
-- pg_execute_server_program (so no COPY ... TO/FROM a server file or PROGRAM).
--
-- Run as a superuser, connected to the OpenCTEM database. Idempotent: run it
-- again after restoring a dump, after a migration was applied as another role,
-- or to rotate a password.
--
--   psql "postgres://<superuser>@<host>:5432/<db>" -v ON_ERROR_STOP=1 \
--        -v app_password="$DB_PASSWORD" -v migrator_password="$DB_MIGRATE_PASSWORD" \
--        -f least-privilege-roles.sql
--
-- Optional variables: app_user (openctem_app), migrator_user
-- (openctem_migrator). A password variable left empty keeps the role's current
-- password (a new role then has none and cannot log in until one is set).
--
-- See docs/deployment/database-roles.md.
-- =============================================================================

\set ON_ERROR_STOP on
\if :{?app_user}
\else
  \set app_user openctem_app
\endif
\if :{?migrator_user}
\else
  \set migrator_user openctem_migrator
\endif
\if :{?app_password}
\else
  \set app_password ''
\endif
\if :{?migrator_password}
\else
  \set migrator_password ''
\endif

-- Keep the passwords below out of the server log whatever log_statement says.
SET log_statement = 'none';
SET log_min_duration_statement = -1;
SET client_min_messages = warning;

SELECT set_config('openctem.app_user', :'app_user', false),
       set_config('openctem.migrator_user', :'migrator_user', false);

DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'run this script as a superuser (connected as %)', current_user;
    END IF;
    IF current_setting('openctem.app_user') = current_setting('openctem.migrator_user') THEN
        RAISE EXCEPTION 'app_user and migrator_user must be different roles';
    END IF;
    IF current_setting('openctem.app_user') = current_user
       OR current_setting('openctem.migrator_user') = current_user THEN
        RAISE EXCEPTION 'app_user/migrator_user must not be the superuser running this script (%)', current_user;
    END IF;
END
$$;

-- -----------------------------------------------------------------------------
-- 1. The roles: LOGIN, and explicitly none of the dangerous attributes.
-- -----------------------------------------------------------------------------
SELECT format('CREATE ROLE %I LOGIN', r)
FROM unnest(ARRAY[:'migrator_user', :'app_user']) AS r
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) \gexec

SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT', r)
FROM unnest(ARRAY[:'migrator_user', :'app_user']) AS r \gexec

SELECT format('ALTER ROLE %I PASSWORD %L', :'migrator_user', :'migrator_password')
WHERE :'migrator_password' <> '' \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'app_user', :'app_password')
WHERE :'app_password' <> '' \gexec

-- No role memberships at all for the app (the predefined pg_* file/program
-- roles included), and none of the file/program roles for the migrator.
SELECT format('REVOKE %I FROM %I', g.rolname, m.rolname)
FROM pg_auth_members am
JOIN pg_roles g ON g.oid = am.roleid
JOIN pg_roles m ON m.oid = am.member
WHERE m.rolname = :'app_user'
   OR (m.rolname = :'migrator_user'
       AND g.rolname IN ('pg_read_server_files', 'pg_write_server_files',
                         'pg_execute_server_program', 'pg_read_all_data',
                         'pg_write_all_data')) \gexec

-- -----------------------------------------------------------------------------
-- 2. Extensions the migrations use. Created here by the superuser so the
--    migrator never needs to; CREATE EXTENSION IF NOT EXISTS in a migration is
--    then a no-op.
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------------------------
-- 3. Database and schemas. The application schemas are public plus any schema
--    a migration created (000213 created `deprecated`; 001056 dropped it).
--    Nobody else (PUBLIC) may
--    connect, create temp tables or create objects in them.
-- -----------------------------------------------------------------------------
CREATE TEMP VIEW app_schemas AS
    SELECT n.oid, n.nspname FROM pg_namespace n
    WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
      AND NOT EXISTS (SELECT 1 FROM pg_depend d
                      WHERE d.classid = 'pg_namespace'::regclass AND d.objid = n.oid AND d.deptype = 'e');

SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT format('GRANT CONNECT, TEMPORARY, CREATE ON DATABASE %I TO %I', current_database(), :'migrator_user') \gexec
-- TEMPORARY: the EPSS import stages rows in a temp table (threatintel_repository).
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I', current_database(), :'app_user') \gexec

SELECT format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC', nspname) FROM app_schemas \gexec
SELECT format('ALTER SCHEMA %I OWNER TO %I', nspname, :'migrator_user') FROM app_schemas \gexec
SELECT format('GRANT USAGE ON SCHEMA %I TO %I', nspname, :'app_user') FROM app_schemas \gexec
SELECT format('REVOKE CREATE ON SCHEMA %I FROM %I', nspname, :'app_user') FROM app_schemas \gexec

-- golang-migrate's tracker, created ahead of the first migration on a fresh
-- database (same definition migrate uses) so it is the migrator's and the app
-- only ever gets SELECT on it (section 5).
CREATE TABLE IF NOT EXISTS public.schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL);

-- -----------------------------------------------------------------------------
-- 4. Ownership: every object in those schemas that is not part of an
--    extension moves to the migrator (earlier migrations ran as a superuser).
-- -----------------------------------------------------------------------------
-- Tables, partitioned tables, views, materialized views, foreign tables.
-- Sequences owned by a column follow their table.
SELECT format('ALTER %s %I.%I OWNER TO %I',
              CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                             WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END,
              n.nspname, c.relname, :'migrator_user')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.oid IN (SELECT oid FROM app_schemas)
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :'migrator_user')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e') \gexec

-- Free-standing sequences.
SELECT format('ALTER SEQUENCE %I.%I OWNER TO %I', n.nspname, c.relname, :'migrator_user')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.oid IN (SELECT oid FROM app_schemas) AND c.relkind = 'S'
  AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :'migrator_user')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype IN ('e', 'a', 'i')) \gexec

-- Functions and procedures.
SELECT format('ALTER %s %s OWNER TO %I',
              CASE p.prokind WHEN 'p' THEN 'PROCEDURE' WHEN 'a' THEN 'AGGREGATE' ELSE 'FUNCTION' END,
              p.oid::regprocedure, :'migrator_user')
FROM pg_proc p
WHERE p.pronamespace IN (SELECT oid FROM app_schemas)
  AND p.proowner <> (SELECT oid FROM pg_roles WHERE rolname = :'migrator_user')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e') \gexec

-- Enums, domains, ranges and stand-alone composite types (not a table's row type).
SELECT format('ALTER %s %I.%I OWNER TO %I',
              CASE t.typtype WHEN 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
              n.nspname, t.typname, :'migrator_user')
FROM pg_type t
JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE n.oid IN (SELECT oid FROM app_schemas)
  AND t.typtype IN ('e', 'd', 'c', 'r')
  AND (t.typtype <> 'c' OR (SELECT c.relkind FROM pg_class c WHERE c.oid = t.typrelid) = 'c')
  AND t.typowner <> (SELECT oid FROM pg_roles WHERE rolname = :'migrator_user')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype IN ('e', 'i')) \gexec

-- -----------------------------------------------------------------------------
-- 5. What the app may do, on today's objects...
-- -----------------------------------------------------------------------------
SELECT format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', nspname, :'app_user') FROM app_schemas \gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I', nspname, :'app_user') FROM app_schemas \gexec
-- The migration tracker is read (the startup schema check), never written.
SELECT format('REVOKE INSERT, UPDATE, DELETE ON public.schema_migrations FROM %I', :'app_user') \gexec
-- The EPSS and KEV feeds replace their whole global catalog with TRUNCATE.
SELECT format('GRANT TRUNCATE ON public.%I TO %I', t, :'app_user')
FROM unnest(ARRAY['epss_scores', 'kev_catalog']) AS t
WHERE to_regclass('public.' || t) IS NOT NULL \gexec
SELECT format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA %I TO %I', nspname, :'app_user') FROM app_schemas \gexec
SELECT format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO %I', nspname, :'app_user') FROM app_schemas \gexec
SELECT format('GRANT USAGE ON TYPE %I.%I TO %I', n.nspname, t.typname, :'app_user')
FROM pg_type t
JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE n.oid IN (SELECT oid FROM app_schemas) AND t.typtype IN ('e', 'd', 'r')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e') \gexec

-- -----------------------------------------------------------------------------
-- 6. ...and on everything a later migration (run as the migrator) creates.
-- -----------------------------------------------------------------------------
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', :'migrator_user', :'app_user') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I', :'migrator_user', :'app_user') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT EXECUTE ON FUNCTIONS TO %I', :'migrator_user', :'app_user') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT USAGE ON TYPES TO %I', :'migrator_user', :'app_user') \gexec

-- -----------------------------------------------------------------------------
-- 7. Verify. Any failure here aborts with a non-zero exit.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    app  text := current_setting('openctem.app_user');
    mig  text := current_setting('openctem.migrator_user');
    r    record;
    bad  text;
BEGIN
    FOR r IN SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
             FROM pg_roles WHERE rolname IN (app, mig) LOOP
        IF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls THEN
            RAISE EXCEPTION 'role % still has a privileged attribute', r.rolname;
        END IF;
    END LOOP;

    SELECT string_agg(g, ', ') INTO bad
    FROM unnest(ARRAY['pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program',
                      'pg_read_all_data', 'pg_write_all_data', 'pg_signal_backend', 'pg_monitor']) AS g
    WHERE pg_has_role(app, g, 'USAGE') OR (g LIKE 'pg\_%server%' AND pg_has_role(mig, g, 'USAGE'));
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'app/migrator inherit a predefined role: %', bad;
    END IF;

    SELECT string_agg(nspname, ', ') INTO bad FROM app_schemas
    WHERE has_schema_privilege(app, oid, 'CREATE') OR NOT has_schema_privilege(app, oid, 'USAGE');
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'role % can create objects in (or cannot use) schema: %', app, bad;
    END IF;

    SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.oid IN (SELECT oid FROM app_schemas) AND c.relkind IN ('r', 'p')
      AND NOT has_table_privilege(app, c.oid, 'SELECT, INSERT, UPDATE, DELETE')
      AND c.relname <> 'schema_migrations';
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'role % is missing DML on: %', app, bad;
    END IF;

    SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.oid IN (SELECT oid FROM app_schemas) AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
      AND pg_get_userbyid(c.relowner) <> mig
      AND NOT EXISTS (SELECT 1 FROM pg_depend d
                      WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e');
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'not owned by %: %', mig, bad;
    END IF;
END
$$;

\echo 'least-privilege roles: OK (' :migrator_user ' owns the schema, ' :app_user ' has DML only)'
