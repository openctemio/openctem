### Added: the platform keeps each tool's full descriptor from the sensor manifest

- A tool on the tool contract reports its whole `tool.yaml` (canonical JSON) in the sensor manifest. The platform now keeps it in the sensor's manifest version, next to the contract: `tools[].contract.descriptor`. `Manifest.ToolDescriptor(name)` reads it. Planning, the workflow builder and the tools API will read the tool's capabilities, params, batch shape and presentation from it (RFC-055).
- A descriptor that does not qualify is dropped and listed in the manifest's ignored items with the reason `invalid-descriptor`; the contract is kept. A descriptor qualifies when it:
  - hashes to the contract's digest;
  - is a JSON object of the same format and version;
  - is at most 64 KiB;
  - holds no control or bidirectional-override character in any string or key.

### Security: a sensor cannot show one descriptor and enforce another

- The descriptor must hash to the digest the sensor reports for the contract it enforces, so the descriptor the platform shows is the one the sensor enforces.
- Descriptors are stored per sensor inside its tenant's manifest. One tenant never sees another tenant's descriptor.
- Strings are checked because the console will show them as text.
