### Added: proxy pools for sensor scan traffic

- Organization proxy pools (`/api/v1/proxy-pools`): paste a list of `http`, `https`, `socks5` or `socks5h` proxies, one per line, set an organization default (public targets only) or give a sensor its own pool or Direct (all targets). Migration `sensor_proxy_pools` adds the tables and the `sensors:egress:read|write|delete` permissions (owner and admin; write and delete are admin-only).
- Proxy credentials are stored encrypted and never returned; a pasted line keeps stored credentials with `••••`. Endpoints on loopback, link-local, metadata, multicast or reserved addresses are refused.
- Every scan and retest job carries the claiming sensor's pool (no credentials) inside the signed payload; the leasing sensor fetches the credentials per job and reports per-endpoint health. The platform scores endpoints, quarantines dead ones and re-admits them after a back-off.

### Behaviour change: a sensor whose jobs use a proxy pool needs proxy support

- While a pool applies to a sensor (its own, or the organization default), the sensor gets scan and retest jobs only if it reports proxy support and network confinement (a sensor release with the proxy feature, running tools under network confinement, the daemon default). Older sensors keep their other jobs; set their network path to Direct to scan without the pool.
