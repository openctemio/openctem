### Added: products seen with their version hidden join the software inventory

- A technology detection or an HTTP `Server` header that names a curated public application (nginx, Apache HTTP Server, IIS and the rest of the curated list) without a version now becomes a software link with an empty version. Any other version-less name (a private product, a CDN, a security header) stays a technology only, so it never becomes a catalog row.
- The emerging-threat alert's "possibly affected" tier and the vulnerability page's "Possible" bucket now list those assets. Only established links count there: an asset whose version is known is no longer listed as possibly affected through an older version-less row.
- A version read later (any source) replaces the version-less link at once; hiding the version again does not bring the version-less link back.
- The new `asset-software-link-backfill` controller links the version-less technologies stored before this release: tenant by tenant, in batches of 500, resumable from its saved position (table `asset_software_versionless_backfill`, migration `20261118175210`; a new table, nothing populated is locked), and idempotent. It queues the linked assets for matching.
- Docs: server/docs/architecture/vulnerability-matching.md, server/docs/architecture/asset-technologies.md, server/docs/architecture/software-version-history.md
