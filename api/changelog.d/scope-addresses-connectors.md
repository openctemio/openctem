### Added: addresses behind in-scope names, offered in one click

- `GET /api/v1/scope/suggestions/addresses` lists the public addresses your in-scope names resolve to that no scope entry covers, with the names each came from and the cloud provider when known, narrowed to your data scope. Shared addresses (an edge or CDN provider, or names of three or more registrable domains resolve to them) are left out and counted. Nothing is added automatically: add the chosen ones with `POST /scope/targets/bulk`. RFC-054 §14.7.

### Behaviour change: a connector's synced inventory is in scope

- The names, addresses and hosts a connector syncs (Tenable.sc, DefectDojo) get their exact scope entries after each sync, so they can be scanned without adding them by hand. On by default; turn it off per connector with the integration config switch `inventory_in_scope: false`. Only in the Off and On scan approval modes; at most 1000 new entries per sync; guardrails and the job signer's ledger apply to each entry; one notice to the administrators per sync; private addresses, internal names and repositories get no entry; exclusions and the deny list still win. RFC-054 §14.8.
