# RFC-145: Grants and the guarantees of any grant provider

| | |
|---|---|
| Status | Accepted (2026-11-02; re-scoped 2026-11-03: the open core holds the grant seam and the guarantees; licence files, their verifier and storage belong to the extension that provides grants) |
| Scope | api: `pkg/domain/limits/grants.go`, `internal/app/entitlement/grants.go`; the extension API registers a provider |
| Related | [limits and feature denies](../architecture/limits.md), [edition model](../architecture/edition-model.md), [editions](../development/editions.md) |

## 1. Summary

Some features of a custom build are **off unless granted**. The open core defines the shape of that
answer and the one place it is asked; it never names a grant key, a plan, a tier, an edition or a
brand, and it contains no licence verification, no keys and no licence storage. The Community build
has no grant provider: every grant is `none`, there are no notices, and nothing changes.

A build's extension may register one grant provider. Where the provider gets its answer is the
extension's business: a signed offline licence file on a self-managed installation, or the hosted
service's control plane. This RFC fixes what every provider must guarantee, so an installation is
never worse off with an extension than without it.

## 2. Goals and non-goals

Goals: one entry point for every gate on a grant; fail closed for grants only; a Community build that
behaves exactly as before; guarantees that hold for any provider.

Non-goals: the licence file format, its verifier and lifecycle (owned by the providing extension);
plan limits and feature denies of a hosted service (they stay limits and denies written by the
control plane, see the limits architecture doc).

## 3. The seam

| Part | Where |
|---|---|
| `GrantKey`, `GrantStatus` (`none`, `expired`, `grace`, `expiring`, `active`), `Grant`, `Notice`, `GrantProvider`, `ErrGrantRequired` | `pkg/domain/limits/grants.go` |
| `entitlement.Service.Addon`, `RequireAddon`, `Notices` | `internal/app/entitlement/grants.go` |
| Registering a provider (at most one per build) | the public extension API |

- Every gate calls `Addon` or `RequireAddon`, never a provider directly. `RequireAddon` refuses with
  403 `ADDON_NOT_LICENSED`, or `ADDON_LICENSE_EXPIRED` once a grant has ended.
- Grant keys are defined by the extension that checks them. The core holds none.
- `Notices` are installation-wide banners for platform administrators, named by a stable code the
  console translates; they carry no organization data.

## 4. Guarantees every provider keeps

1. **A grant only adds.** No Community feature, limit or security control depends on a grant.
   Sign-in, SSO, MFA, audit and every security control are never grants.
2. **Fail closed for grants only.** A provider error, an answer for another key or an unknown status
   is `none` for that grant; it never stops the server or affects anything else.
3. **Data is always kept.** When a grant ends, the feature produces no new data and its settings stay
   readable (read-only) for `GrantReadOnlyPeriod`; its data stays readable, editable and exportable.
   Nothing makes an instance read-only, blocks sign-in or deletes data.
4. **No phone home.** A provider on a self-managed installation makes no outbound call to decide a
   grant.
5. **Tenant isolation.** A provider never reads one organization's data to decide another's grant;
   an installation-wide grant is the same for every organization.
6. **Downgrade is clean.** Removing the extension leaves its data unused; nothing in the core reads
   it.

## 5. Threat model

| Threat | Control |
|---|---|
| A patched core enabling a grant | Nothing to unlock in the core: the granted code ships only in the extension, which checks its own source |
| A provider bug harming availability | Grants fail closed for grants only; Community paths never consult a grant |
| A grant used to weaken security | Security controls are never grants (guarantee 1), refused in review by the extension API rules |
| Cross-organization leak through grants | Guarantee 5; grants carry no organization data |
| Notices leaking organization data | Notices are installation-wide codes with an optional date |

## 6. Implementation

0. The grant seam with the Community default (no provider) and tests: every grant off without a
   provider, every Community feature allowed, a failing provider fails closed for grants only.
1. The extension API registers one provider per build (a second is refused at start).
2. Points that let an extension gate its own surfaces on a grant (routes declare their grant; web
   navigation rows carry it) land with the extension API.
3. Seams in core flows that an extension may veto (for example admitting a paired component whose
   signed identity requires a grant) are generic extension points named by function; the core
   still names no grant key.

## 7. Alternatives rejected

- Licence verification in the core: the core is open and patchable, so a check there protects
  nothing, and the Community build has nothing to unlock.
- Grants that yield limits or denies: a grant would then be able to make an installation worse off.
- Mandatory online activation: needs platform egress and telemetry.
