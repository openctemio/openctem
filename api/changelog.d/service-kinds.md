### Added: service kinds

- Every service asset now carries a normalised kind (its application protocol: rdp, smb, http, redis, modbus, ...), the kind's category (remote access, database, industrial control, ...) and how the kind is known (protocol fingerprint, TLS negotiation, HTTP probe, reported, guessed from the port). A kind guessed from the port is always labelled a guess. The keys are set by the platform only: REST and import refuse them, reports cannot set them.
- The Services, HTTP services and Open ports views filter by kind, category and source, with labels in English and Vietnamese.
- Migration `20261105123637_service_kind_backfill` classifies stored services from their own properties and moves a transport misfiled as `protocol` on open ports to `transport`. Design: `docs/architecture/service-kinds.md`.
