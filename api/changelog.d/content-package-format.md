### Added: content package format (`openctem.io/package/v1`)

- RFC-099 defines one package format for rules, templates, wordlists, profiles, report templates, playbooks,
  policy packs, tool adapters, sensor products and feeds: a manifest (`package.yaml`) beside an artifact addressed
  by its SHA-256 digest, with permissions, licence (including whether a service may use it), dependencies,
  compatibility ranges and provenance.
- The JSON schema ships in `api/pkg/contentpkg/schema/package.v1.schema.json`; `pkg/contentpkg` parses and
  validates manifests (strict decoding, no YAML anchors or custom tags, bounded size, reserved namespaces).
- No behaviour change yet: signatures, the catalog and the console follow.
