### Added: follow public bug-bounty programs from a signed feed

- The platform imports a signed feed of public bug-bounty programs (`PROGRAM_FEED_DIR`, `PROGRAM_FEED_ROOT_KEY_ID`) into a catalog: pinned root, key set never rolled back, newer sequence only, file hashes checked, every record validated. It never calls the bug-bounty platforms. RFC-065 §16.
- `GET /api/v1/programs/catalog` lists the catalog; `POST /api/v1/programs/subscriptions` follows a program: its entries are created inactive and nothing is scanned actively until a member accepts the terms (`POST /api/v1/programs/{id}/reactivate`).
- Feed changes reach followed programs: removals apply at once; new targets, changed rules or terms take the entries out of effect until the terms are accepted again (administrators are notified); a closed program is suspended.
