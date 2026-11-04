### Changed: new global products and versions get deterministic ids

- A global product the vulnerability feed or the curated list creates now gets `uuidv5` over its canonical product key (`cpe:<part>:<vendor>:<product>`, or `purl:<type>/<namespace>/<name>`), and a version of a global product gets `uuidv5` over its identity (product, scheme, normalised or raw version, qualifier, edition) (RFC-143 §6). A catalog rebuilt anywhere, in any order, gives the same ids, so tenant rows never need remapping.
- Tenant-private products and versions keep random ids (they are tenant data).
- Migration 20261104182326 adds the database functions `vuln_catalog_product_id` and `vuln_catalog_version_id`, which compute the same ids; a golden test pins both implementations. It changes no existing row: rows written before it keep their ids until a separate, rehearsed rekey migration.
