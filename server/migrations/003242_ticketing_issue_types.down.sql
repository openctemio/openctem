-- Back to one issue type name: the finding type's name (else the task's).
UPDATE integrations
   SET config = jsonb_set(config, '{ticketing}',
           ((config -> 'ticketing') - 'issue_types')
           || CASE WHEN COALESCE(config -> 'ticketing' -> 'issue_types' -> 'finding' ->> 'name',
                                 config -> 'ticketing' -> 'issue_types' -> 'task' ->> 'name', '') <> ''
                   THEN jsonb_build_object('issue_type',
                            COALESCE(config -> 'ticketing' -> 'issue_types' -> 'finding' ->> 'name',
                                     config -> 'ticketing' -> 'issue_types' -> 'task' ->> 'name'))
                   ELSE '{}'::jsonb END)
 WHERE category = 'ticketing'
   AND jsonb_typeof(config -> 'ticketing') = 'object'
   AND (config -> 'ticketing') ? 'issue_types';
