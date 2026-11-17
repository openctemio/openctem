### Security: a pairing code pairs only into the organization that made it

- A sensor that starts with a pairing code that no longer pairs (expired, used, cancelled, held by another sensor, or never made) now pairs under a new code that it prints with its approval link, and the old code finds nothing in any organization. Before, such a start kept the old code as a request of no organization, so anyone holding a leaked install snippet could look the sensor up and approve it into their own organization. The organization that made the code gets a `sensor.pairing_code_refused` audit record with the key fingerprint and source address. A code that is still open attaches to its organization exactly as before.
- Docs: server/docs/architecture/sensor-pairing.md
