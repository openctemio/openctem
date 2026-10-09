### Added: software inventory captured from scan output

- Ingest now records which products and versions each asset runs (RFC-066): typed CTIS technologies and services, HTTP technology strings (`Name:version`), the HTTP `Server` header, service banners, open-port versions and the operating system CPE.
- Products and versions live once in a shared software catalog (`software_products`, `software_product_aliases`, `software_versions`); a row is global only for public identities (a curated list of about 80 common products), and everything else a tenant observes is private to that tenant. Assets link to versions in `asset_software`, with the location, source, evidence and a confidence score; a newer version at the same location supersedes the old link.
- Migration 001616. No API or UI yet; the vulnerability matcher and the asset Software tab build on it.
