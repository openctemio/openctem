# How to enable Restricted Data Scope (fail-closed)

By default OpenCTEM's per-user data scope is **fail-open**: a non-admin who has
**no** asset assignment sees **all** of the tenant's assets and findings. Enabling
**Restricted Data Scope** flips this to **fail-closed** (Tenable's "No Access"
default): a non-admin sees **only** the assets they're assigned — directly or via
a group — and their findings. No assignment ⇒ no data.

Use this to give developers / asset owners a scoped view (only what they own),
instead of the whole tenant.

> **This changes behaviour.** Read the rollout order below before enabling, or
> members with no assignment will suddenly see nothing.

## What changes when enabled

| | Fail-open (default) | Restricted (fail-closed) |
|--|--|--|
| Non-admin **with** assignments | sees assigned assets/findings | sees assigned assets/findings (same) |
| Non-admin with **no** assignment | sees **everything** | sees **nothing** |
| Owner / admin (`IsAdmin`) | sees everything | sees everything (always bypass) |

Applies to: the assets inventory, the findings list, their severity-count cards,
and single asset/finding fetches (a non-accessible id returns 404, not the row).

## Rollout order (do this first)

1. **Create groups** for your teams (Settings → Access Control → Teams) and add
   members to them.
2. **Assign assets** to those groups — directly, or with **Assignment Rules** that
   route matching assets to a group. For a single person and a single asset,
   use **Grant access** in the *Direct access* section of the asset's Owners
   tab. Naming someone an **owner** does **not** give them access: owners are
   accountable and get the asset's findings assigned, but see the asset only
   through a group or a grant.
3. Confirm each member who needs broad visibility is in a group that covers the
   assets they need. **An analyst who should see everything needs a group holding
   all assets** — under fail-closed there is no implicit "see all".
4. Only then enable the flag.

## Enable it

Set the tenant **Security** setting `restricted_data_scope` to `true`
(Settings → Organization → General → **Security** — owner-only; or via the tenant
settings API). It takes effect within ~60s (a short policy cache).

To roll back, set it to `false` — the tenant immediately returns to fail-open.

## Notes

- **Admins/owners always bypass** data scope, in both modes — this is unchanged.
- The flag is **per-tenant**; other tenants are unaffected.
- Assignment plumbing is unchanged — this only changes what happens when a user
  has **no** accessible assets (show-all vs show-nothing).
