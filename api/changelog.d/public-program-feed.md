### Added: follow public bug-bounty programs from a signed program feed

- The platform imports the signed public program feed (`PROGRAMFEED_DIR`, `PROGRAMFEED_ROOT_KEY_ID`) into a catalog: pinned root, key set never rolled back, newer sequence only, the delta only on top of the applied sequence, file hashes and sizes checked, every record validated. It never calls the bug-bounty platforms. RFC-065 §16.
- `GET /api/v1/programs/catalog` lists the catalog; `POST /api/v1/programs/subscriptions` follows a program: its entries are created inactive and nothing is scanned actively until a member accepts the terms (`POST /api/v1/programs/{id}/reactivate`).
- A feed target is never permission to test: only targets the program published become entries; targets the feed inferred are suggestions a member confirms (`POST /api/v1/programs/{id}/targets/confirm`), which asks for a new acceptance.
- Feed changes reach followed programs: removals apply at once; new targets, changed rules or terms take the entries out of effect until the terms are accepted again (administrators are notified); a closed, paused or dropped program is suspended.
