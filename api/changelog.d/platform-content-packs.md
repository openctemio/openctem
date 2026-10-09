### Added: platform content packs with stable and canary channels (RFC-061 K2)

- `/api/v1/admin/content-packs`:
  - a super admin uploads a pack, or imports an upstream release by https URL with its required sha256 (checked before parsing, fetched through the SSRF guard);
  - revokes a pack;
  - points the `stable` or `canary` channel of a name at a pack.

  Any admin reads. Every write needs a reason and a fresh console authenticator code (`totp_code`) and is audited with the reason.
- Platform packs are signed with the platform content key, kept apart from organization packs (migration 001568), and readable by every organization at `/api/v1/platform-content-packs` (`scans:content:read`).
- Upstream lint leaves out the files that fail it instead of refusing the release:
  - refused template protocols, self-contained templates, unsafe regexes and non-template YAML are left out;
  - templates with attack payloads in their requests are kept as T2.
- Revoking a pack moves its channels back to the previous good pack.

### Fixed: nuclei templates written with a `tcp:` block were refused as having no execution block

- The template validator now counts `tcp` (nuclei v3 network templates) as an execution block, for custom templates and content packs.
