# RFC-104: Sign-up modes and organization joining

| | |
|---|---|
| Status | Accepted (2026-10-15). Implemented: the `SIGNUP_MODE` ceiling with the start-up guards and the console lock; verification of every self-registered account under `domain`/`open`. Designed: the policy split, domain policies, join requests, the onboarding fork, account and organization lifecycle, sign-up events, the region field |
| Scope | api, web, deployment |
| Related | RFC-022 (admin console), RFC-025 (user onboarding), RFC-079 (console platform settings), RFC-095 (role templates and invitations) |

## 1. Summary

A self-hosted deployment must not let strangers register. The hosted service must let a person
create an account and, when they have no organization, create one. Both run the same code.

The design has two keys:

1. **`SIGNUP_MODE`**, read from the server environment, is the deployment's ceiling. No API can
   change it.
2. The **console sign-up policy** (Console > System > Sign-up, super admin + fresh authenticator
   code, audited) is a runtime switch below it.

The policy in force is the stored policy clamped to the ceiling. A stolen console session cannot
open registration on a deployment whose configuration keeps it closed, and the hosted service
keeps a runtime switch to pause sign-up during an abuse wave.

## 2. Ceiling values

| `SIGNUP_MODE` | Accounts | Organizations |
|---|---|---|
| `disabled` (default) | platform administrator, invitation, organization SSO/SCIM | platform administrator |
| `domain` | the above, plus public sign-up for an address on a domain an organization verified; the person joins that organization by its join policy | platform administrator |
| `open` | anyone (not a disposable address), within the console policy | self-service, within the console policy and the limits |

Order: `disabled` < `domain` < `open`. Organization SSO just-in-time membership, SCIM and
invitations are not affected by the ceiling: the organization chose those people.

## 3. Start-up guards

The server refuses to start when:

- `SIGNUP_MODE` has an unknown value;
- `domain` or `open` has no working platform e-mail. Every self-registered address is verified;
  an address that cannot be verified must never become an account that is matched to invitations
  or domains;
- `domain` or `open` runs without local accounts (`AUTH_PROVIDER=oidc`);
- `open` runs in production without CAPTCHA keys, unless `SIGNUP_CAPTCHA=off-i-understand`
  records the operator's acceptance;
- the retired `TENANT_CREATION_MODE` is still set.

While running, public sign-up also closes whenever the platform e-mail stops working
(fail-closed).

## 4. Verification

Under `domain` and `open`, every self-registered account verifies its address before it can sign
in. The organization setting `email_verification_mode` governs accounts invited into that
organization only. One organization's setting never decides platform-wide sign-up, and missing
SMTP never skips verification of a self-registered account.

## 5. Planned steps

1. Ceiling, guards and console lock.
2. Verification hardening (section 4).
3. Policy split: `accounts` (closed, domain, open) and `workspaces` (admin_only, self_service)
   in the console policy, each at or below the ceiling; admission outcomes `domain_account` and
   `sso_required`.
4. Domain policy per verified domain: join policy (off, approval, auto), default role,
   discoverable, SSO required, new workspaces allowed or blocked, include subdomains. All effects
   are off by default and stop when the domain lapses.
5. Join requests, scoped to the organization, with an onboarding API that returns opaque
   per-user references instead of organization ids or slugs.
6. Onboarding web flow: invitations, then organizations the verified domain may join, then
   "create a workspace".
7. Enumeration fixes: home-realm discovery returns an opaque handle, uniform slug answers.
8. Account deletion with a 14-day grace, organization deletion with a 14-day grace, and a
   suspended organization state.
9. Sign-up events with minimal fields for the hosted-service control plane, and internal
   suspend and limit endpoints.
10. `tenants.region`, set from `DEPLOYMENT_REGION` and fixed.

## 6. Security

| Threat | Control |
|---|---|
| A compromised console opens registration on a closed deployment | the ceiling lives in the server environment; 409 `SIGNUP_LOCKED_BY_DEPLOYMENT` |
| Unverified addresses gain access | `domain`/`open` need working e-mail; self-registered accounts always verify |
| Bot sign-ups on an open deployment | CAPTCHA required in production, rate limits, disposable-address block |
| One organization's setting weakens platform sign-up | the organization setting governs only its invited accounts |

## 7. Upgrade

`TENANT_CREATION_MODE` is removed. `admin_only` (the old default) is `SIGNUP_MODE=disabled`, the
new default, so the variable can simply be removed. `self_service` is `SIGNUP_MODE=open`, which
also needs the platform e-mail and, in production, the Turnstile keys. Existing users,
organizations and sessions are not affected.
