# RFC-145: Enterprise licence verification and entitlements

| | |
|---|---|
| Status | Accepted (2026-11-02). Designed only: nothing in this document is implemented yet |
| Scope | api (licence verifier, subscription store, entitlement service, admin API, seams), web console (Subscription page), helm-charts and openctem-ansible (seed), sdk-go consumers (add-on components) |
| Related | RFC-040 (signed jobs), RFC-142 (feed relay), [limits and feature denies](../architecture/limits.md) |

## 1. Summary

A self-managed installation runs the Community edition by default. An installation that buys
commercial entitlements from the vendor proves it with one signed licence file. The licence only
ever **adds** capabilities from a fixed registry of entitlement keys; it never denies or caps a
Community feature, so a licensed installation is never worse off than an unlicensed one.

The platform verifies the licence offline with a public key compiled into the core, makes no
outbound call for it, and keeps all customer data readable whatever the licence state. Components
that ship separately under commercial terms verify the same licence themselves.

## 2. Goals and non-goals

Goals: activation that works air-gapped; one verify-and-store path for every way a licence can
arrive; renewal without a restart or a gap; expiry that degrades only the licensed extras; an
audit trail; no telemetry by default.

Non-goals: digital rights management that can harm a customer's data or access; hard seat or asset
caps; a mandatory activation or sync service; changing the plan limits a hosted service applies
through its control plane (those stay deny and limit based, see the limits architecture doc).

## 3. The licence file

- A text file (JSON, `*.octlic`) with two DSSE envelopes: `license` and `keyset`. A one-line base64
  form is accepted for environment variables and paste. At most 64 KiB, strict decoding, unknown
  top-level keys refused. Schema `openctem.io/license/v1`; it stays v1 until 1.0 and gains only
  additive optional keys.
- The `keyset` is signed by a root key that is compiled into the core (the current root and a
  pre-staged next root, so a root rotation is one release away). There is no environment or flag
  override: only a rebuilt core can change the root. It reuses the versioned, expiring, rollback-
  refusing key-set format of `pkg/feedsign`.
- The `license` is signed by a key listed in that key set. A key set lists at most 8 issuing keys,
  is valid for at most 3 years, and carries a `revoked` list of licence ids and key ids.
- Verification accepts a licence only when: the key set verifies against an embedded root; the key
  set version is not below the stored high-water mark; the licence signature verifies against a key
  of the set; the licence id is not revoked; the optional installation binding matches.

Claims (payload type `application/vnd.openctem.license+json`): `schema`, `id` (stable per contract
term; a renewal gets a new id), `customer_id`, `type` (`enterprise`, `trial`, `non_production`),
`licensee.name` (organisation name only, never a personal e-mail), `issued_at`, `not_before`,
`expires_at`, `grace_days` (14 by default, 0 for trials), `entitlements` (keys from the registry),
`meters` (soft commercial units such as asset bands and add-on instances), `addons` (per add-on
image reference, signing identity and minimum version), `bind.installation_ids` (optional; empty
means not bound), `renewal.url` (optional), and `issuer` (name, portal and support URLs).

Every vendor-specific string (issuer, portal, registry, signing identity) travels inside the signed
claims, so the open source core names no commercial brand and the vendor can change those values
by reissuing.

## 4. Ways in

All four end in the same verify-and-store call.

| Path | How | Egress |
|---|---|---|
| Upload or paste (default) | Console, System, Subscription: drop the file or paste text; the page previews licensee, type, dates, entitlements and binding; step-up; activate | none |
| Install seed | `LICENSE_FILE=/path` or `LICENSE=<base64>` (Helm `license.existingSecret`, Ansible `openctem_license_file`). Verified on boot and stored only when newer than the active licence; an invalid seed is logged and changes nothing | none |
| Activation code (later) | The admin's browser exchanges a short code for the file at the issuer's portal and hands it to the normal upload call. The platform itself makes no outbound request | browser only |
| Relay renewal (later, opt-in) | When the licence has `renewal.url` and automatic renewal is on, the controller schedules a daily `feed.relay@1` GET of that exact URL through a platform-owned relay sensor (RFC-142). The result is verified like an upload and stored only when newer | one GET from the relay sensor; nothing sent |

The portal address used by the activation code comes from the brand configuration of the commercial
build; in Community the code box is hidden and the page says to upload a file. The relay stays
GET-only on one path-pinned URL taken from a signed claim, so a compromised API gains no outbound
channel and a compromised relay can withhold a renewal but never forge one.

## 5. Gating model

- A new feature class `grant_required` in `pkg/domain/limits`: an **entitlement key registry** (key,
  kind `instance` or `tenant`, display name, documentation link, what stops on expiry), off unless
  granted. A guard test fails when a registry key is undocumented or when a check bypasses the
  entitlement service. Deny-based features keep their existing semantics untouched.
- Grant sources: `license` (installation-wide, every organization) and `control_plane` (hosted
  service, per organization), through a new `limits.GrantSource` interface.
- One entry point: `entitlement.Service.Addon(ctx, tenantID, key) AddonState` with states `none`,
  `active`, `expiring`, `grace`, `expired` plus a read-only deadline and a reason code.
  `RequireAddon` returns the existing feature-denied error with code `ADDON_NOT_LICENSED` or
  `ADDON_LICENSE_EXPIRED`. Evaluation fails closed for licensed extras only; a Community feature
  never depends on it.
- **Meters are soft.** They never feed `Check`. The service reports used against licensed amounts
  for the Subscription page and the usage export; exceeding a meter shows a banner to platform
  administrators and a line in the export, and nothing is refused.

## 6. Lifecycle

| State | When | Effect |
|---|---|---|
| Community | no licence | licensed extras off, everything else on |
| Trial | `type=trial`, 30 days, no grace | as licensed, with a banner |
| Active | from `not_before` until 30 days before expiry | entitlements on |
| Expiring | last 30 days | unchanged; banner and e-mails to platform administrators at 30, 14, 7 and 1 days |
| Grace | `expires_at` to `expires_at + grace_days` | unchanged; red banner |
| Expired | after grace | licensed components produce no new data; their settings are read-only for 30 days, then hidden; **all data is kept** and stays readable, editable and exportable |
| Removed | an administrator removes it | as Expired at once, after a confirmation that names what stops |

Never, in any state: a read-only instance, blocked sign-in, changes to SSO, MFA, audit or any
security control, deleted data, or stopped Community jobs.

- **Renewal without restart.** Storing a newer valid licence is a database write plus `pg_notify`;
  every replica reloads (a 60 s poll is the backstop). A future-dated licence waits in history and
  switches on at its `not_before`, so uploading early causes no gap. Overlapping valid licences are
  not merged: the one with the later `not_before` that is valid now wins.
- **History.** Every licence ever stored is kept (`subscription_licenses`, append-only).
- **Binding.** Not bound by default, because binding to a URL or host breaks recovery, high
  availability and renames. An installation id (a UUID created by the first migration) is shown and
  reported in usage exports; `bind.installation_ids` is set only when a contract asks.
- **Clock.** Effective time is the maximum of the current time, the stored high-water mark and the
  newest stored `issued_at`, so winding the clock back cannot revive an expired licence, and a bad
  clock can never lock anyone out.
- **Non-production licences** carry the same entitlements and a permanent notice.

## 7. Enforcement seams

1. **Pairing**: a licensed first-party component pairs only when its entitlement is active,
   expiring or in grace, and its image identity matches the signed `addons` claim.
2. **Ingest and dispatch**: data produced by, and work dispatched to, a licensed first-party
   component are refused when the entitlement is expired; running work finishes.
3. **Hand-down**: the platform sends the active licence to paired components over the signed sensor
   channel (on pairing and on change). The component verifies it with its own embedded root and its
   own monotonic clock and, past grace, stops accepting new work while keeping its local spool under
   its retention rule. This check lives in separately distributed code, so patching the core (which
   the open licence permits) does not enable it.
4. **Snippets and install kits** take image and signing identity from the `addons` claim. Without the
   entitlement the console shows the open alternative (bring-your-own collector through CTIS, a
   third-party AI worker on the published protocol), which stays free.

## 8. Usage report

An optional "Export usage report" action produces a JSON file signed with an instance key created
at first boot (tamper evidence across reports, not proof). It holds the licence id, installation
id, period, core version, the current and period-maximum value of each meter, and counts of
organizations, sensors and add-on instances. It never contains user names or e-mails, host names,
IPs, URLs, asset identifiers, findings, or organization names or ids. The file is shown in full
before download. A missing report never changes the instance.

## 9. Authorization and audit

- New permission `platform.settings.license.write` (platform owner role only); reading uses
  `platform.settings.read`. Organization members never read the licence file; they see only the add-on
  state of their own organization.
- Add, replace and remove require step-up authentication and write a Critical audit entry (previous
  and new licence id, type, dates, entitlement difference, source `upload`, `code`, `seed` or
  `relay`, actor, IP). Seed and relay act as system actors. Rejections (bad signature, wrong
  binding, rolled-back key set, revoked id) are audited as warnings with a reason code and never the
  file content.
- Console route `/system/subscription` next to Limits and Software updates: status, validity, grace,
  installation id, usage against licence, entitlements with state, history, automatic renewal toggle.
  All strings use the i18n catalogs (en and vi).

## 10. Threat model

| Threat | Control |
|---|---|
| Forged or edited licence | Ed25519 over the DSSE encoding; key set signed by an embedded root; strict decoding; size bound |
| Self-issued licence through configuration | The root is not overridable by environment or flag; the licensed components still refuse |
| Replay of an old licence after renewal or revocation | Newest valid wins; key-set version high-water; `revoked` list in newer key sets |
| Clock rolled back to extend validity | Effective-time high-water mark |
| Issuing key compromised | New key set listing new keys and revoking the old key id; the root stays offline |
| Root compromised | Pre-staged next root; a core release drops the old root; licences reissued |
| Licence file leaked | Short terms (12 months, trials 30 days), `revoked` list, optional binding, contract; a leaked file cannot harm any instance |
| Another organization's administrator or a tenant user | Only the platform owner permission can change the licence; tenants cannot read it |
| Compromised API abusing the renewal relay | GET-only, one path-pinned URL from a signed claim, no data in the request |
| Compromised relay sensor | Can withhold, cannot forge: the platform verifies |
| Activation code theft | Redeemable only for that customer's licences, limited redemptions, rate limited, revocable; the output is a licence, not a secret |
| Forked or unsigned add-on image | Image identity checked against the signed claim; the component's own check |
| Privacy | No automatic telemetry; manual export shown before download; organization name only |
| Availability harm from a licensing bug | Evaluation can only switch licensed extras; any verifier error keeps the previous state; Community is never affected |

Tenant isolation: the licence is installation-wide state owned by platform administrators. Grants it
yields are the same for every organization; per-organization data is never read to decide them.

## 11. Implementation plan

Naming: `pkg/licensekey` (verify) and `internal/app/subscription` (store, state). Neither uses the
`license` prefix, which `pkg/domain/licensepolicy` (SPDX policy) already holds.

1. `pkg/licensekey`: wrapper and claims, verification on `pkg/feedsign` key sets, embedded roots,
   revoked list, binding, effective-time rules. Table tests: wrong root, tampered claim, expired,
   future `not_before`, rolled-back key set, revoked id, binding mismatch, oversize, unknown key.
2. Migration for `subscription_licenses`, installation id and time high-water;
   `internal/app/subscription`; `limits.GrantSource`, the `grant_required` class,
   `Service.Addon` and `RequireAddon`; add-on rows in the module entitlements. Tests: Community has the
   extras off and every existing feature unchanged; grace to expired transitions; a tenant cannot read
   the licence.
3. Admin API (`GET`, `POST`, `DELETE` under `/api/v1/admin/subscription`), usage export, permission,
   step-up, audit, boot seed.
4. Console Subscription page, banners, e-mails, i18n, tenant locked state.
5. Seams from section 7.
6. Documentation: rewrite of the "Later sources" section of the limits architecture doc, a
   subscription operations guide, Helm `license.existingSecret`, Ansible `openctem_license_file`.
7. Later: activation code, relay renewal, licence-bound image pull credentials, offline bundles.

## 12. Alternatives rejected

- Mandatory online activation or daily synchronization: needs platform egress and a fixed telemetry
  field list.
- Activation POST through the relay sensor: would turn the relay into a write channel.
- Binding to a URL or hardware fingerprint by default: breaks recovery, high availability, renames.
- Hard seat or asset caps, or a read-only instance after expiry: would make the licensed edition worse
  than Community and withhold data access.
- Encrypting the payload: the key ships with the code, so signing alone is the honest design.
- JWT instead of DSSE: DSSE and key sets already exist, are reviewed and give one envelope format.

## 13. Corrections to the current documents

The limits architecture doc plans a licence source "yielding limits and denies". For self-managed
installations that is replaced by grants only with soft meters (this RFC). The hosted control plane
keeps writing limits and denies.
