### Security: required scan identification, enforced fail closed

- The platform, an organization or a bug-bounty program can require identification: every HTTP request of a scan must carry an identification header or the query parameter. A lower layer can never turn off a higher layer's requirement.
- A job that requires identification but has no header and no query parameter at any layer fails at claim with `IDENTIFICATION_REQUIRED_MISSING` and a message naming the fix. It is never delivered.
- Such a job goes only to a sensor that reports `http.identity.required@1`. An older sensor would drop the requirement silently, so the job waits for one that reports it (a claim by id answers `IDENTIFICATION_REQUIRED_UNSUPPORTED`). On the sensor, a tool that cannot carry the identification gets it from the task's forwarder, or the task is refused before it sends a request.
- Turning an organization's requirement off is audited at high severity. Program imports and re-imports record the identification rules in force.
- **Upgrade note:** update sensors to a release that reports `http.identity.required@1` before turning the requirement on. Until then, required jobs wait (fail closed).

### Added: User-Agent rotation and an identification query parameter

- Each layer (platform, organization, bug-bounty program) can set a User-Agent rotation list instead of one User-Agent: at most 200 distinct values, 1-256 printable ASCII characters each. The winning layer's list is used whole. An enforced platform User-Agent locks the list too.
- Each target host of a run gets one value of the list, the same for every request of the run to that host (HMAC-SHA-256 keyed by the run over the canonical host; contract `identity.SelectUserAgent`). Jobs carry `user_agents` and `user_agent_key` (the scan run id). `user_agent` holds the first value for sensors without rotation.
- The platform and organizations can set one identification query parameter (`query`, `tool_http_query`; name and value 1-64 of letters, digits and `. _ ~ -`). The platform can enforce it.
- The run detail can show what each step's requests were sent with: the sensor's `http_identity` report is stored on the step (`sensor_settings.sent_with`). It is bounded and cleaned, secret-looking values are masked, and it is display only.
