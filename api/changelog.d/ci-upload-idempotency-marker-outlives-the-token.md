### Fixed: the CI upload idempotency marker outlives a slow ingest

- The in-flight marker of an `Idempotency-Key` upload now lives at least as long as the run token (15 minutes) or the request deadline when later, so a slow ingest is not replayed in parallel. A finished request overwrites or releases the key only while the stored record still carries its own body hash, so it never clobbers another request's record. A store failure between the two lookups is logged.
