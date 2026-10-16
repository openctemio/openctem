### Added: content catalog with offline import, installs, approval and revocation

- New tables (migration 002571) and permissions `content:read` and `content:install` (owners and administrators get
  both, members and viewers `content:read`).
- `POST /api/v1/admin/content-catalog/import` (super admin, reason and console authenticator code, audited)
  verifies a signed offline bundle and stores it in one transaction, with rollback protection on the key set,
  index and revocation list (a list with the same sequence must have the same bytes).
- `/api/v1/content`: browse the catalog, install, update, pin, roll back and uninstall packages per organization,
  with an optional approval step (a second member approves), an audit row per action, dependency, compatibility
  and license checks, and revocation that marks installations revoked.
- Approving a request and carrying it out commit in one transaction. Switching the approval option off takes
  effect 24 hours later and notifies the owners and administrators; switching it on is immediate.
- **Upgrade note:** imports are refused until a catalog root is configured (`CONTENT_TRUST_ROOT_KEY_IDS`) or
  pinned in a release. Setting `CONTENT_TRUST_ROOT_KEY_IDS` or `CONTENT_SIGSTORE_TRUSTED_ROOT` writes a
  high-severity admin audit row at startup.
