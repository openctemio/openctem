### Added: asset attributes follow the most trusted, most recent source

- Every source's latest value of an asset's criticality, owner reference, exposure and data classification is recorded with when the source saw it (migration `001652_asset_attribute_sources`, RFC-069). The asset shows a person's lock first, then the organization's precedence for the attribute, then the newest observation, then confidence; a source not heard from within its TTL stops counting. A report delivered late never undoes a newer one.
- `GET /api/v1/assets/{id}/attribute-sources` shows each attribute's deciding source and every other source's value; `PUT`/`DELETE /api/v1/assets/{id}/attribute-sources/{attribute}/lock` sets and locks, or releases (`assets:write`, data scope). `GET`/`PUT /api/v1/organization/settings/asset-reconciliation` sets the precedence and TTLs (owner/admin).

### Security: sensors no longer set an asset's owner or data classification

- A sensor report is always a scan source, whatever it claims, and scanners are not trusted for criticality, owner or data classification by default. Ingest no longer fills `owner_ref` or `data_classification` on existing assets, and an asset a sensor creates does not take them. An organization can trust scanners for an attribute in its settings.

### Behaviour change: imports and integrations update criticality, owner and classification

- Before, the first value written stayed forever. Now an import or an integration (DefectDojo sync) updates these attributes on assets nobody locked. A person's create or edit is a lock until released on the asset page.
- **Upgrade note:** the migration turns the values people set into locks (assets created by a person, and attributes changed by a person in the asset history), so nothing a person set changes at upgrade.
