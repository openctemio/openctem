-- schema-fingerprint.sql: one sorted line per schema object of the current
-- database, for comparing two databases that should have the same schema
-- (migration-order-check.sh, upgrade-test.sh).
--
--   psql "$URL" -X -At -v ON_ERROR_STOP=1 -f .github/scripts/schema-fingerprint.sql > a.txt
--
-- Covers tables and their kinds, columns (type, nullability, default,
-- identity, generation, collation), constraints (domains included), indexes,
-- views, functions and procedures, triggers, enum labels in order, domains,
-- sequences, partitions, row-level security and its policies, and
-- extensions. Leaves out what legitimately differs between two databases
-- with the same schema: data, owners, grants, OIDs, statistics, and the
-- physical order of columns (columns added by migrations applied in another
-- order end up in another order; nothing reads them by position).
WITH s AS (
  SELECT oid, nspname FROM pg_namespace
  WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
    AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%'
),
ext AS ( -- objects that belong to an extension are the extension's
  SELECT objid FROM pg_depend WHERE deptype = 'e'
),
rel AS (
  SELECT c.oid, c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity, c.relispartition,
         c.relpartbound, s.nspname
  FROM pg_class c JOIN s ON s.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND c.oid NOT IN (SELECT objid FROM ext)
)
-- One line per object: whitespace (newlines in expressions) collapsed.
SELECT l FROM (SELECT regexp_replace(line, '\s+', ' ', 'g') AS l FROM (
  SELECT format('relation %s.%s kind=%s rls=%s force_rls=%s', nspname, relname, relkind,
                relrowsecurity, relforcerowsecurity) AS line
  FROM rel
  UNION ALL
  SELECT format('partition %s.%s of %s %s', r.nspname, r.relname, p.inhparent::regclass,
                pg_get_expr(r.relpartbound, r.oid))
  FROM rel r JOIN pg_inherits p ON p.inhrelid = r.oid
  WHERE r.relispartition
  UNION ALL
  SELECT format('column %s.%s.%s %s notnull=%s default=%s identity=%s generated=%s collation=%s',
                r.nspname, r.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
                coalesce(pg_get_expr(d.adbin, d.adrelid), '-'), a.attidentity, a.attgenerated,
                coalesce(co.collname, '-'))
  FROM rel r
  JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped
  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  LEFT JOIN pg_collation co ON co.oid = a.attcollation AND a.attcollation <> 0
       AND co.collname <> 'default'
  WHERE r.relkind <> 'S'
  UNION ALL
  SELECT format('constraint %s.%s %s %s', s.nspname,
                CASE WHEN c.conrelid <> 0 THEN c.conrelid::regclass::text ELSE c.contypid::regtype::text END, c.conname,
                pg_get_constraintdef(c.oid, true))
  FROM pg_constraint c JOIN s ON s.oid = c.connamespace
  WHERE c.contype <> 'n' -- PostgreSQL 18 lists NOT NULL here too; columns carry it
  UNION ALL
  SELECT format('index %s', pg_get_indexdef(i.indexrelid))
  FROM pg_index i JOIN rel r ON r.oid = i.indrelid
  UNION ALL
  SELECT format('view %s.%s md5=%s', nspname, relname, md5(pg_get_viewdef(oid, true)))
  FROM rel WHERE relkind IN ('v', 'm')
  UNION ALL
  SELECT format('function %s.%s(%s) md5=%s', s.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
                md5(pg_get_functiondef(p.oid)))
  FROM pg_proc p JOIN s ON s.oid = p.pronamespace
  WHERE p.prokind IN ('f', 'p') AND p.oid NOT IN (SELECT objid FROM ext)
  UNION ALL
  SELECT format('trigger %s', pg_get_triggerdef(t.oid, true))
  FROM pg_trigger t JOIN rel r ON r.oid = t.tgrelid
  WHERE NOT t.tgisinternal
  UNION ALL
  SELECT format('enum %s.%s %s', s.nspname, t.typname,
                (SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid = t.oid))
  FROM pg_type t JOIN s ON s.oid = t.typnamespace
  WHERE t.typtype = 'e' AND t.oid NOT IN (SELECT objid FROM ext)
  UNION ALL
  SELECT format('domain %s.%s %s notnull=%s default=%s', s.nspname, t.typname,
                format_type(t.typbasetype, t.typtypmod), t.typnotnull, coalesce(t.typdefault, '-'))
  FROM pg_type t JOIN s ON s.oid = t.typnamespace
  WHERE t.typtype = 'd' AND t.oid NOT IN (SELECT objid FROM ext)
  UNION ALL
  SELECT format('sequence %s.%s %s inc=%s min=%s max=%s start=%s cycle=%s', r.nspname, r.relname,
                format_type(q.seqtypid, NULL), q.seqincrement, q.seqmin, q.seqmax, q.seqstart, q.seqcycle)
  FROM rel r JOIN pg_sequence q ON q.seqrelid = r.oid
  UNION ALL
  SELECT format('policy %s.%s %s cmd=%s permissive=%s roles=%s using=%s check=%s', r.nspname, r.relname,
                p.polname, p.polcmd, p.polpermissive,
                (SELECT string_agg(CASE WHEN x = 0 THEN 'public' ELSE pg_get_userbyid(x) END, ',' ORDER BY 1)
                 FROM unnest(p.polroles) AS x),
                coalesce(pg_get_expr(p.polqual, p.polrelid), '-'),
                coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '-'))
  FROM pg_policy p JOIN rel r ON r.oid = p.polrelid
  UNION ALL
  SELECT format('extension %s', extname) FROM pg_extension
) lines) x
ORDER BY l COLLATE "C";
