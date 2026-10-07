### Added: scan capability contracts (typed ports, standard params, versions)

- Each scan stage is now a versioned capability (`scan.ports@1`) with a contract: input and output **port types** from a closed set of ten (`root_domain`, `hostname`, `ip`, `cidr`, `service`, `url`, `repository`, `container_image`, `cloud_account`, `finding`), standard params with types and bounds, and the fields a report must carry. Each implementation maps the params it accepts to the tool's own config key.
- An adapter table names the capability that turns one port type into another (for example `hostname → url`: `probe.http`). The workflow editor offers it on an incompatible connection.
- Taxonomy v1 lists 22 capabilities. Nine are planned, with a contract and no implementation yet: they are served with `available: false` and are never routed.
- `GET /api/v1/scans/stages` serves the contracts, the implementations (with `batch` and `params`), `port_types` and `adapters`. Existing fields are unchanged.
- Whether a tool takes a target list per task now comes from the catalogue instead of a hardcoded scanner map. Behaviour is unchanged.
