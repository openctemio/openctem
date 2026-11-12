### Security: a relayed request must carry the credential of the sensor its relay route names

- A request that came through a sensor relay names the sensor of its route; a bearer key of any other sensor is now refused like a bad credential, as a signed request already was. No cross-tenant access was possible through it (the answer stays sealed to the sender), so this is defence in depth.
- Two unused command lookups that read across organizations (by job auth token, and the shared queue position) are removed.
- New DB-backed tests prove that no sensor of one organization (or shared sensor that does not hold the job) can claim, change, read the secrets, logs or reports of, or learn of another organization's jobs; they run as a required CI gate by name (`.github/scripts/cross-tenant-gate.sh`).
