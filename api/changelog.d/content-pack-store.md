### Added: content pack store for organization uploads (RFC-061 K2)

- `/api/v1/content-packs`: upload, list, get, download and revoke immutable packs of templates, rules and wordlists, plus the organization's content-signing public key.
  - Permissions: `scans:content:read` and `scans:content:write` (owner and admin, migration 001384).
  - Uploads and revocations need a recent sign-in.
- **Ingest:**
  - safe in-memory unpacking: no links or devices, path and size limits;
  - a canonical tar whose SHA-256 is the digest;
  - lint and tier classification per kind (nuclei templates, semgrep rules, wordlists, namespaced kinds);
  - a credential scan that blocks the pack until acknowledged;
  - a DSSE signature with the organization's content key.
- **Signing key:** new optional `APP_CONTENT_SIGNING_KEY`. When unset, the key is derived from `APP_ENCRYPTION_KEY` under its own label.
- **Storage:** archives are stored once per organization and digest, never shared between organizations, and re-checked against the digest whenever they are read.
- Docs: `docs/architecture/content-packs.md`.
