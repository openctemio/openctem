### Added: organization wordlists and a record of what each enumeration job read

- Organizations can add their own DNS label lists (paste or upload a `.txt`) with `/api/v1/wordlists` (`scans:content:read` / `scans:content:write`). Lines are normalised to DNS labels; invalid and secret-looking lines are dropped and reported. Lists are versioned, can be switched off, and every change is audited.
- Every enabled list joins the organization's subdomain enumeration jobs inline, after the labels learned from its names and before the platform pack, on its own and shared sensors.
- `GET /api/v1/wordlists/preview?root=` counts what an enumeration job of a root would query, per source.
- Each signed job records what it read (pack name, version and digest; generated lists with source, lines and sha256; organization lists with their versions) in `commands.content_pins`, shown as `content_pins` on the run's tasks.
