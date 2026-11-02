### Fixed: a sensor stopped before approval can pair again with its key

- A sensor keeps the key it generated, so starting it again with a new pairing
  code (or after its code expired) used to answer `500` and then rate-limit the
  sensor, and re-pairing needed its data volume wiped. The new start now closes
  the key's earlier requests that nobody approved (audited as
  `sensor.pairing_superseded`) and opens the new one; started again with the
  same code, the sensor re-uses its own request.
- A key that was ever registered to a sensor is refused `409` with the problem
  type `pairing-key-registered` (a key never pairs twice, into any
  organization); a start that loses a race for its key answers `409`
  `pairing-key-busy` with a `Retry-After`. A code another key holds is still
  never taken over. No migration.
