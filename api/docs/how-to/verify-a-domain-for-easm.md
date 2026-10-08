# Verify a domain for attack-surface management

Verifying a domain proves your organization controls its DNS. Names
discovered under a verified domain (for example through Certificate
Transparency) are confirmed as yours automatically, with the strong
`fqdn_under_verified_root` rule, instead of waiting in the review queue.

This verification is for attack-surface management only. **It never lets
anyone sign in:** domains for SSO sign-in are set up by your platform
administrator in the admin console.

## Who can do it

A member with `attack_surface:scope:write` (owners and admins have it) in an
organization with the Attack surface module. Removing a domain needs
`attack_surface:scope:delete`.

## Steps

1. Open **Scoping › Scope › Domain proof**. Type the domain and select
   **Prove a domain** (for a domain already listed, select **Check** on its
   row).
2. Select **Start verification**.
3. Publish the TXT record shown at your DNS provider:
   - host: `_openctem-verify.<your domain>`
   - value: `openctem-domain-verification=<token>`
4. Select **Check now**. DNS changes can take a while to appear; you can check
   up to 10 times per hour for the whole organization.
5. When the domain shows **Verified**, names under it confirm automatically
   from the next discovery run on.

Proof does not authorize scanning by itself: scope entries do (a root domain
to discover from is a scope entry such as `*.example.com` with discovery on).
Proof is what platform sensors and intrusive checks require, and it marks the
scope entries at or under the domain as verified.

## Keep the record in place

Every verified domain is re-checked every 12 hours. If the record is gone,
the domain becomes **failed**: names under it stop confirming automatically
(already-confirmed assets stay confirmed), and the domain shows the record
again so you can republish it.

## API

| Call | Permission |
|---|---|
| `GET /api/v1/easm/verified-domains` | `attack_surface:scope:read` |
| `POST /api/v1/easm/verified-domains` `{"domain": "example.com"}` → TXT record | `attack_surface:scope:write` |
| `POST /api/v1/easm/verified-domains/{id}/verify` (10 per organization per hour, 429 with `Retry-After`) | `attack_surface:scope:write` |
| `DELETE /api/v1/easm/verified-domains/{id}` | `attack_surface:scope:delete` |

Every call except the list is audited at high severity
(`easm_verified_domain.*`). Domains your administrator set up for SSO are
listed with `managed: true` and cannot be checked or removed here. Public
suffixes (`co.uk`, `github.io`) and shared consumer domains (`gmail.com`) are
refused. Another organization verifying the same domain is independent of
yours, and nothing reveals it.
