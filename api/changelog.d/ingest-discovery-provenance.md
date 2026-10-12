### Security: a sensor cannot label a planted asset as hand-made or discovered in the future

- A sensor report set a new asset's `discovery_source` and `discovered_at` from its own properties. This let a planted asset never go stale and look as if a person had made it, in two ways:
  - A source such as `manual`, `import` or `integration` falls in a category the asset lifecycle leaves alone by default.
  - A discovery time in the future kept the asset inside its grace period.
- Sensor reports now record such sources as `sensor`. Scanner categories such as `dns` and `cert_transparency` are kept.
- Every ingest now records a future discovery time as now.
- Uploads by people and imports keep their own provenance.
