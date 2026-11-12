### Security: one validator for asset tags on every write path

- Asset tags are now checked by one validator wherever they are written: the create, update, repository-create and CSV import APIs, and every import through CTIS ingest (sensor reports, connectors, importers). A tag is 1 to 50 characters, with no control, bidirectional, zero-width or newline characters, no `<` or `>`, no leading `=`, `+`, `-` or `@` (a CSV export would run it as a formula), and no reserved platform namespace (`sys:`, `system:`, `program:`, `source:`, `platform:`, `bug-bounty`, `dangling_cname`).
- A person who sets a refused tag gets a validation error naming the reason. A CSV row with a refused tag is reported as an error. An import drops the tag and counts it in the metric `openctem_ingest_asset_tags_dropped_total{reason}`; one import sets at most 20 tags per asset.
- Before, ingest had no length or character limit. A tag over 50 characters made the asset impossible to save from the console, and a sensor could write any string, including `bug-bounty`, which the asset list filter also reads for per-program visibility.
- A tag an asset already carries is never re-checked, so an existing long or reserved-looking tag does not block saving the asset.
- Follow-ups (not in this change): protected tags that rules read, bulk tagging on the server, cloud resource tags.
