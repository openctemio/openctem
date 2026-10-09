### Added: bug-bounty programs, authorization sources and the Researcher role (data model)

- Migration 001454 adds `bounty_programs`, `bounty_program_exclusions`, the scope entry columns `authorization_source` (default `ownership` for every existing entry) and `program_id`, the scope snapshot tables, the permissions `attack_surface:programs:read|write` (owner and admin) and the built-in **Researcher** role (`00000000-0000-0000-0000-000000000005`, no full data access). RFC-065.
- No behaviour changes yet: the programs routes, the gate rules and the snapshots arrive in the next pull requests.
- A custom role may no longer be created with the slug `researcher`.
