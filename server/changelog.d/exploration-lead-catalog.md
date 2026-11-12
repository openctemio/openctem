### Added: lead type catalog for exploration

- `server/configs/lead-types.yaml` lists each kind of exploration question with its typed next actions
  (stage catalog capabilities, per subject asset type), allowed params, prior band, value weight,
  attempt limit and reason codes. `make generate-lead-types` writes the Go and TypeScript catalogs;
  the generator refuses a capability or asset type the catalogs do not know, and every action takes
  the stage catalog's tier. First types: `dns.takeover_check`, `version.confirm`,
  `asset.gone_with_findings`.
