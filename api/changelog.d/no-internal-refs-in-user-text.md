### Changed: user-facing text no longer cites internal design documents

- Error and help texts, metric descriptions, the authorization reference, API annotations, the sensor protocol spec, shipped JSON schemas, the environment-variable reference and generated sensor policy templates now explain themselves in plain words instead of pointing at RFC numbers or research notes.
- A CI gate (`go test ./tools/lint/internalrefs/`) and a web test (`src/lib/i18n/__tests__/no-internal-references.test.ts`) fail when a string, an API annotation, a shipped schema or an i18n value cites one again.
