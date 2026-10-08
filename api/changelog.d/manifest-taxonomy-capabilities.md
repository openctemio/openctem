### Fixed: sensors on the tool contract register their capabilities

- Sensors from v0.11.0 report each tool's capability from the OpenCTEM taxonomy (`vuln.templates`, `scan.ports`, `scan.ports@1`) next to the older words. The platform only knew the older words and ignored every taxonomy id as `unknown-capability`, so the manifest registered with "6 items ignored".
- Capability names are now also accepted when they are in the taxonomy (`ctis/capability`), with or without their major version. The older words stay accepted until they are retired (RFC-055 §10.1).
- A name in neither list is still ignored.
