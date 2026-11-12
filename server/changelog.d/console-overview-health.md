### Changed: the platform console overview says whether the installation is healthy

- The Overview opens with an Installation strip: services, storage, backups, platform sensors and the database schema, each as a state in words with a link to the page that explains it.
- Needs attention is one compact list (a row per problem) and the customer numbers follow it, so they stay on the first screen.
- "No sensor is online" replaces "sensors does not answer its health check", volumes on one filesystem are reported once, and every administrator gets the way to an overdue break-glass test.
- Counts read as real plurals ("1 request", "2 requests") instead of "request(s)".

### Fixed: console support access without the support permission

- Support access no longer shows "Support grants could not be loaded: insufficient permissions" to a read-only session: it offers the elevation instead and does not send the request the API would refuse.
