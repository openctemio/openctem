### Removed: scan profile template_mode and custom_template_ids

- A scan profile's `tools_config.<tool>.template_mode` and `custom_template_ids` were stored but never used. Dispatch takes custom templates only from the scan (`scanner_config.custom_template_ids`), where the organization opt-in, the policy preflight and scan governance check them. Both fields are removed from the profile API and the web types.
- A create or update request that still sets either field is refused with 400. Before, the field was saved and silently ignored. Profile responses no longer carry them.
- Template selection per profile comes back as a content block that resolves to pinned, signed snapshots in the scan's job. That work is planned; this release does not include it.
- Rows written earlier keep the keys inside the `tools_config` JSON; they are dropped when a profile is read and are not written back. No migration.
