### Changed: emerging-threat fan-out looks up affected organizations once per page of events

- The emerging-threat planner used to run one affected-organizations query per vulnerability event (two lookups each, one of them a full read of the software inventory), so a large vulnerability-feed import with hundreds of thousands of events cost the database close to an hour. It now resolves a page of 500 events with one query: about 50 ms per page instead of about 5 s. Which organizations get alerts, the wait on id gaps and rejection handling are unchanged. No migration.
