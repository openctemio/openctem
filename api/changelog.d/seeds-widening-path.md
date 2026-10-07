### Security: adding an EASM seed goes through the scope approval path

- A root-domain seed authorizes active checks of every name under it and
  confirms them into the inventory, yet `POST /api/v1/easm/seeds` needed only
  `attack_surface:scope:write` (held by members), with no re-authentication,
  approval or notification. A new seed is now created as the permanent scope
  entry `*.<domain>` through the scope entry path: it needs
  `attack_surface:scope:approve` and step-up re-authentication, follows the
  organization's approval count (`202` with a pending entry until another
  administrator approves), refuses public suffixes and shared provider
  domains, notifies every administrator and is audited as a scope entry.
- A member gets `403 WIDENING_NEEDS_APPROVER`; members request one-off
  entries on `POST /api/v1/scope/targets`.
- Turning a seed's discovery back on (`PATCH /api/v1/easm/seeds/{id}`) needs
  `attack_surface:scope:approve` and step-up, and notifies the
  administrators.
- **Upgrade note:** existing seeds are unchanged. New seeds appear as scope
  entries (`*.<domain>`) rather than in the seed list, and the response of
  `POST /api/v1/easm/seeds` is the scope entry.

### Security: domains verified for SSO sign-in no longer authorize scans

- A domain a platform administrator verified for SSO sign-in (purpose `sso`)
  authorized active checks of every name under it in the tenant, with no
  tenant screen showing it. Only domains the organization verified for
  attack-surface work (purpose `easm`) authorize now; an SSO domain still
  counts as proof of control for platform sensors.
- **Upgrade note:** a name covered only by an SSO-verified domain is refused
  with `no_entry` until an administrator adds a scope entry for it.
