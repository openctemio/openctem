-- Issue type per kind of issue on a ticketing integration
-- (docs/architecture/ticketing-integration.md, "Issue types").
--
-- config.ticketing.issue_type (one issue type name used for findings and
-- remediation tasks alike) becomes config.ticketing.issue_types.finding and
-- .task (the name only; the console stores the id on the next save), and the
-- old key is removed. An issue_types entry already present wins.
--
-- Live impact: rewrites the config of ticketing integrations that set an
-- issue type (a handful of rows). Old API code reading the new shape uses
-- the stock types until it is replaced.

UPDATE integrations
   SET config = jsonb_set(config, '{ticketing}',
           ((config -> 'ticketing') - 'issue_type')
           || jsonb_build_object('issue_types',
                  jsonb_build_object(
                      'finding', jsonb_build_object('name', btrim(config -> 'ticketing' ->> 'issue_type')),
                      'task',    jsonb_build_object('name', btrim(config -> 'ticketing' ->> 'issue_type')))
                  || COALESCE(config -> 'ticketing' -> 'issue_types', '{}'::jsonb)))
 WHERE category = 'ticketing'
   AND jsonb_typeof(config -> 'ticketing') = 'object'
   AND jsonb_typeof(config -> 'ticketing' -> 'issue_type') = 'string'
   AND btrim(config -> 'ticketing' ->> 'issue_type') <> '';

-- A blank or malformed old value carries nothing: drop the key.
UPDATE integrations
   SET config = jsonb_set(config, '{ticketing}', (config -> 'ticketing') - 'issue_type')
 WHERE category = 'ticketing'
   AND jsonb_typeof(config -> 'ticketing') = 'object'
   AND (config -> 'ticketing') ? 'issue_type';
