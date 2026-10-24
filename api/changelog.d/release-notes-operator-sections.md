### Changed: release notes group migrations, identity and contract changes under operator headings

- Pull requests are labelled automatically by the files they change: `notes:migration`, `notes:destructive-migration` (a migration that drops, renames or truncates), `notes:identity` (finding fingerprint or identity code, or the CTIS module version) and `notes:api-contract` (HTTP handlers, routes, the sensor protocol).
- The release train's changelog preview, and `changelog.py release --labels`, print an **Upgrade notes** block that lists the fragments of those pull requests under these headings, ahead of the categories.
- No operator action.
