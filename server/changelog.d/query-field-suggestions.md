### Changed: query field suggestions lead with the fields people filter by, each explained

- In Query mode of the findings, assets and scans lists, the field suggestions now start with the
  fields people filter by (findings: severity, state, status, priority, kev, epss, cve, assignee…),
  then relation fields (asset.…), then the other fields, with record identifiers (`id`, `asset_id`,
  `branch_id`…) last. With nothing typed the list shows them under headings (Common, Asset, More
  fields, Identifiers); with a prefix typed, fields whose name starts with it come first.
- Short names are suggested (`kev`, `epss`, `cve`, `assignee`, `domain`, `ip`…) and typing one offers
  its operators and values as the full path does.
- Each row says what the field means in plain words (English and Vietnamese), with an example where
  it helps (`epss>=0.5`) and the kind of value it takes; operators say what they do.
- An empty field with no recent queries offers the fields to start from.
- `GET /api/v1/query/schema` lists the fields in that order and adds `aliases` (short names, shortest
  first) and `group` (`common`, a relation such as `asset`, `more`, `identifier`) to each field.
  Additive: existing fields of the response are unchanged.
- Docs: server/docs/architecture/query-language.md
