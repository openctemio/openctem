### Added: one inventory for every asset type

- `/assets?types=<type>` (and `&sub_type=` for a registry alias such as IAM users) turns the inventory into that type's list, from the asset type registry: its name in the header, its registry columns, attribute filters (`properties=key:value`), counts for its yes/no attributes, a scope column for scannable types, and an empty state that says how to find the type.
- Create, edit and delete work for every type from the inventory: the forms are generated from the type's registry attributes and write schema keys only; a yes/no attribute left empty stays unknown.
- CSV export of the whole filtered inventory, with the type's attributes; row actions (open link, copy IPs or name, repository scan and sync); bulk delete and bulk repository scan/sync.
