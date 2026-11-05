### Security: secrets reach sensor tools sealed, per task, only for the refs a signed job lists

- A claimed scan, retest, validate or proxy test job lists the secrets it may use (payload member `secrets`, names only) before it is signed; the refs are recorded per claim (migration `20261105013221_command_secret_grants`).
- `POST /api/v2/sensor/commands/{id}/secrets` answers the values for one task, sealed with HPKE to a single-use key in the request, only to a key-bound sensor (signed request) holding the command's lease under the epoch in the signed body, with a trusted grant, for refs recorded at claim, a bounded number of times. Shared sensors must be confined and get each held job's organization values only. Every refusal is command-not-found; deliveries and refusals are audited (`secret.delivered`, `secret.refused`) without values.
- An untrusted sensor no longer receives proxy pool credentials, and a job's proxy credentials are those of the pool recorded when it was claimed, not the sensor's current pool.
- The egress report reads the lease epoch from its body (`lease_epoch`, required); the lease header is no longer read there.
- Credentials in a scan's settings are refused on create, update and clone (`SCANNER_CONFIG_SECRET`, naming the keys only), and a scan stored with one is blocked at trigger with the same code, so the value never reaches a command. Values that only look random stay warnings. Existing rows are not rewritten.
- **Upgrade note:** sensors must run the SDK release of the same version (task secrets); bearer-key sensors get no secrets and must be paired again to a key-bound identity. Scans whose settings hold a credential must be edited to remove it before they run again.

### Removed: the egress-credentials sensor route

- `POST /api/v2/sensor/commands/{id}/egress-credentials` is removed without an alias: the proxy pool's credentials are the task secret `egress_proxy`.

### Added: organization keys for the third-party sources scan tools query

- Settings, Scanning, Tool source keys: an organization stores its own keys of the data sources scan tools query (subfinder's passive sources: securitytrails, shodan, censys, virustotal and the others; the provider registry is the contract's). Keys are encrypted with `APP_ENCRYPTION_KEY` and bound to their organization and source (a ciphertext copied to another row does not open), never shown again (last four characters only), can be replaced, switched off and removed; every change needs an administrator with a fresh step-up and is audited (migration `20261104150216_tool_source_keys`).
- A key reaches a sensor only as a task secret of that organization's job. A key whose first part names where the tool connects (intelx and zoomeye `HOST:KEY`, redhuntlabs `ENDPOINT_URL:KEY`) is accepted only for the provider's own service.
- Design: `docs/architecture/task-secrets.md`, `docs/rfcs/RFC-149-task-secrets.md`.
- Sensor config check `runtime.task_root_memory`: warns when the directory where tools write files for a run (with the keys a task received) is on disk instead of in memory.
