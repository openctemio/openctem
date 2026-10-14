### Fixed: taint traces reach the finding for every producer, and a re-scan replaces a changed trace

- SARIF `codeFlows` are now stored as the finding's data flow (ctis maps them; before, they were dropped). semgrep and opengrep traces were already mapped and now share the same bounds and path rules.
- Data flows are stored for re-sighted findings too, not only for new ones. A re-scan whose trace differs from the stored one replaces the finding's flows in one transaction. An identical trace is not rewritten: migration `002118_finding_data_flow_trace_hash` adds `finding_data_flows.trace_hash`. A report without a trace keeps the stored one. The per-finding caps (50 flows, 100 steps) still hold.
- Ingest normalizes every received trace again (`ctis.NormalizeDataFlow`), whichever producer sent it. Paths become repository-relative: absolute paths of the scanning machine and paths leaving the repository are dropped. Credentials in step snippets are masked, and the bounds hold.
- Sanitizer steps are kept in step order. They were dropped before. End line, end column and the function of a step are stored too.
- The trace never feeds the finding's fingerprint.
- The API's unused SARIF code-flow converter and the data-flow repository methods without a tenant filter are deleted. Every flow query now joins `findings` and filters on the tenant.

### Security: the data-flow endpoint applies the finding's own access gate

- `GET /api/v1/findings/{id}/dataflows` applies the same tenant, data-scope and pentest-campaign check as `GET /api/v1/findings/{id}`. Before, it called the service as an administrator and relied on the route guard alone. A caller who may not read the finding gets 404.
