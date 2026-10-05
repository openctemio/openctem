-- Backfill the definition columns of the existing catalog rows (RFC-044 §8 P1).
-- https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md
--
-- Every existing row is a global CVE entry. kind ('vulnerability'),
-- namespace ('CVE') and lifecycle ('published') already hold through the
-- column defaults of 000820; this fills what differs per row:
--
--   external_id   = cve_id.
--   origin        = 'kev' when CISA KEV lists the CVE (a trusted feed vouches
--                   for the identity), else 'report': no feed inserts catalog
--                   rows today, so every other row was created from a report.
--   cvss_version  = the version the stored vector names (CVSS:3.1/... -> 3.1;
--                   a bare v2 vector -> 2.0); unknown stays NULL.
--   nicknames     = the entries of `aliases` that are not identifiers
--                   ("Log4Shell"). The identifier-shaped ones are NOT turned
--                   into global identifiers: they were written by reports or
--                   seeds, and only the OSV/GHSA/CVE List feeds may assert a
--                   global alias (RFC-044 §5.5). `aliases` itself is left as
--                   it is until it is dropped (decision D9).
--
-- Safe on a large catalog: batches of 5000 rows by id, each committed on its
-- own, so no lock is held for longer than one batch. Each batch suspends the
-- updated_at trigger inside its own transaction (a schema backfill is not a
-- content change, and the change is never visible to another session: the
-- trigger is enabled again before the batch commits). A batch that cannot
-- get its lock within 5 s retries instead of queueing traffic behind it.
-- Re-running is harmless: every assignment is idempotent.
--
-- The whole file is ONE statement on purpose: COMMIT inside a DO block is
-- allowed only when the block is not part of a larger transaction, and a
-- multi-statement migration file runs as one implicit transaction.
DO $$
DECLARE
    nil_id   CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
    last_id  uuid := nil_id;
    next_id  uuid;
    attempts int;
BEGIN
    LOOP
        SELECT b.id INTO next_id
        FROM (SELECT id FROM vulnerabilities WHERE id > last_id ORDER BY id LIMIT 5000) b
        ORDER BY b.id DESC
        LIMIT 1;
        EXIT WHEN next_id IS NULL;

        attempts := 0;
        LOOP
            BEGIN
                PERFORM set_config('lock_timeout', '5s', true);
                ALTER TABLE vulnerabilities DISABLE TRIGGER trigger_vulnerabilities_updated_at;

                UPDATE vulnerabilities v
                SET external_id = COALESCE(v.external_id, v.cve_id),
                    origin = CASE
                        WHEN v.origin = 'report'
                             AND EXISTS (SELECT 1 FROM kev_catalog k WHERE k.cve_id = v.cve_id)
                        THEN 'kev' ELSE v.origin END,
                    cvss_version = COALESCE(v.cvss_version, CASE
                        WHEN v.cvss_vector ~ '^CVSS:[0-9]+\.[0-9]+/'
                            THEN substring(v.cvss_vector FROM '^CVSS:([0-9]+\.[0-9]+)/')
                        WHEN v.cvss_vector ~ '^\(?AV:[LAN]/AC:[HML]/Au:[MSN]/'
                            THEN '2.0'
                        END),
                    nicknames = CASE WHEN cardinality(v.nicknames) > 0 THEN v.nicknames ELSE COALESCE((
                        SELECT array_agg(s.n ORDER BY s.first_ord)
                        FROM (
                            SELECT btrim(u.a) AS n, min(u.o) AS first_ord
                            FROM unnest(v.aliases) WITH ORDINALITY AS u(a, o)
                            WHERE btrim(u.a) <> ''
                              AND btrim(u.a) !~* '^[a-z][a-z0-9]*-[a-z0-9:._-]*[0-9][a-z0-9:._-]*$'
                            GROUP BY btrim(u.a)
                        ) s), '{}') END
                WHERE v.id > last_id AND v.id <= next_id
                  AND v.tenant_id IS NULL
                  AND v.cve_id IS NOT NULL;

                ALTER TABLE vulnerabilities ENABLE TRIGGER trigger_vulnerabilities_updated_at;
                EXIT;
            EXCEPTION WHEN lock_not_available THEN
                attempts := attempts + 1;
                IF attempts >= 60 THEN
                    RAISE;
                END IF;
                PERFORM pg_sleep(1);
            END;
        END LOOP;

        COMMIT;
        last_id := next_id;
    END LOOP;
END
$$;
