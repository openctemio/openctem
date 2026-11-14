### Security: the app role can no longer write an extension schema's migration tracking tables

- The database roles script (`deploy/postgres/least-privilege-roles.sql`) took write access to the migration tracking tables (`schema_migrations`, `schema_migrations_applied`) away from the app role in `public` only, and granted it full DML on every table of an extension's schema, those tables included. A role that can write them can make the next migration run skip a migration or run one again. The script now takes INSERT, UPDATE, DELETE and TRUNCATE on those two tables back from the app role and `PUBLIC` in every application schema, and its verification fails if the app can still write one. Re-run the script (or let the next release's install step run it) on a database that holds an extension schema.
- Docs: server/docs/deployment/database-roles.md ("The bootstrap script")

### Fixed: no "set but not read" start-up warning for a key an extension declares

- A server built with extensions logged `environment: <KEY> is set but not read by the API` for every config key an extension declared (for example the off-box administrators' audit stream settings), and a declared key close to a core name would have been refused as a typo. The start-up environment check now counts the build's declared extension keys as read; unknown keys are still warned about and typos of core names still refused, and a removed setting no extension declares still stops the start.
- Docs: server/docs/deployment/database-roles.md ("The bootstrap script", "How it is tested"), server/docs/development/extension-api.md (Migrations, Config keys)
