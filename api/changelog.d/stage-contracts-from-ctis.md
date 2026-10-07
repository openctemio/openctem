### Changed: capability contracts come from the ctis capability taxonomy

- The scan-stage catalog now reads each capability's contract from `github.com/openctemio/ctis/capability`, the copy the SDK and the sensor also read (RFC-055). That covers the ports, the standard params, the tier floor and the required-output rules. The literal contracts in `stage/contract.go` are gone.
- The catalog keeps only platform data:
  - the stored asset pairs each port carries;
  - the implementations and their defaults;
  - the fan-out caps;
  - the display names of the required fields.
- At start, the API refuses a catalog stage whose tier differs from its capability's floor, or a capability the taxonomy does not know.
- `GET /api/v1/scans/stages` adds `phase`, `ctem_stage`, `attack` (MITRE ATT&CK) and `d3fend` to each capability.
- Three planned capabilities are listed: `discover.cloud`, `sbom.generate` and `import.file` (cross-cutting).
- `verify.finding` gains its standard param `mode` (`retest` or `exploit_check`).
- Existing fields of `/scans/stages` are unchanged for the 22 capabilities it listed.
