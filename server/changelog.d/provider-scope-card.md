### Behaviour change: scope entries on provider shared addresses are paused until answered

- An address, CIDR or range scope entry lying wholly inside a range a provider publishes for infrastructure many organizations share no longer authorizes active checks until someone answers it on the Scope page. Scans skip those addresses with the reason `provider_address`; names that point at them are still scanned, and nothing is deleted. The Scope page explains the pause in a banner, and **Keep scanning** resumes active scanning in one step.
- Organization scope setting **Hold shared provider addresses until answered** (`hold_provider_entries`, on by default): an organization that turns it off gets the previous behaviour. Turning it off needs a recent re-authentication, is audited at high severity and notifies the administrators.
- **Upgrade note:** after the upgrade, review the Scope page of each organization that has such entries; until answered, active checks of those addresses stop.

### Added: answer scope entries on provider shared addresses in one place

- The Scope page shows a card, only when there is something to decide, for scope entries that are addresses (or ranges wholly inside a range) a provider publishes for infrastructure many organizations share, such as Microsoft 365 mail front ends or Amazon CloudFront and Cloudflare edges. One row per provider: **Move to out of scope** (recommended; previewed, then each entry becomes a do_not_scan exclusion of the same address with its origin kept, and the entry is turned off, in one transaction) or **Keep scanning** (re-authentication required). Names that point at those addresses stay in scope. Addresses a person confirmed as the organization's inside such a range are listed under their provider to keep or move.
- New endpoints: `GET /api/v1/scope/provider-addresses` (scope read), `POST /api/v1/scope/provider-addresses/move` (scope write, `preview` first; no re-authentication, it only narrows) and `POST /api/v1/scope/provider-addresses/keep` (scope write and re-authentication). Audited: each exclusion and entry, plus `scope_target.provider_moved` and `scope_target.provider_kept` (high) with the counts and ids.
- A review rule never adds an entry on a provider's shared addresses (`PROVIDER_SHARED_RANGE`).
- The provider range list is refreshed (version 2026-11-19.1), and a unit test now fails once it is more than 30 days old.
- Migration `20261119023815_scope_provider_keeps` (a new table, nothing populated is locked).
- Docs: server/docs/architecture/provider-shared-addresses.md
