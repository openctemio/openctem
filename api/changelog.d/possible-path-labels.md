### Changed: exposure chains and attack paths are labelled possible, not proven

- Each exposure chain and the routes to one asset carry `proof: "possible"` in the API; the MCP tool `get_exposure_chains` describes them as possible paths, not proven ones, with a `proof_note`.
- The exposure chains page, the attack paths page and the dashboard's crown-jewel paths show "Possible path, not proven", and their wording says "could reach". No migration.
