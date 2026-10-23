### Added: import mappings turn any CSV, JSON or XML export into findings

- An organization can save import mappings: documents in the CTIS mapping language (`openctem.io/mapping/v1`) that convert a CSV, JSON, JSON Lines or XML file into CTIS with no code. They live under `/api/v1/import-mappings`, with immutable versions, validate, a preview on a sample of at most 5 MiB that stores nothing, and three built-in templates (generic findings CSV, generic findings JSON, JUnit-style XML). RFC-126, migration `003360_import_mappings`.
- An upload names a mapping with `format=mapping:<name or id>[@<version>]` on `POST /api/v1/findings/imports` and on the CI upload `POST /api/v1/ci/runs/{id}/results`. The import is always partial coverage: it closes nothing, and `coverage=full` is refused with it. It is recorded as tool and source `mapped:<name>`, and the receipt format is `mapping:<name>@<n>`.
- Reading mappings needs `integrations:read` or `assets:import`. Writing, validating and previewing need `integrations:manage`, and deleting also needs step-up. Every write is audited (`import_mapping.created`, `.version_created`, `.updated`, `.deleted`). Preview is rate-limited per organization.

### Security: import mappings cannot set reserved fields or collapse identities

- A mapping sets only allow-listed members. The organization, asset ownership and criticality, statuses, provenance, fingerprints, KEV and EPSS flags, branch and commit are reserved. Finding types are limited to vulnerability and misconfiguration.
- A mapping that makes findings declares its identity members. A constant identity is refused. A new version that changes the identity needs explicit confirmation and is marked `identity_changed`.
- A mapping of another organization is unknown by name and by id.
- XML samples and uploads are read without any document type declaration, so no entities and no external resources. CSV cells are kept as text, and CSV exports keep neutralising formula cells.
- The ctis module is pinned to the commit that adds CSV and XML mapping inputs (ctis PR #76) until the next ctis release.
