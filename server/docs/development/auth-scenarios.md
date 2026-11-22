# Sign-in scenarios: state space, expected outcomes and coverage

Everything between "a person arrives" and "they are working inside an
organization", and leaving and coming back, modelled as a state space. Each
state has one expected outcome: where the person lands, the one next step
shown, which tokens exist, and what must never happen. Two suites check it:

- `server/tests/authscenarios` (Go, black box against a scratch stack): every
  token decision of the API for every state (`TestSignInMatrix`) and the
  events while signed in (`TestWhileSignedIn`).
- `web/e2e/specs/58-sign-in-journeys.spec.ts` (Playwright): the journeys a
  person sees in the console, with an invariant checker on every journey.

## Why

A person signed in with Google for the first time, accepted an invitation to
an organization that requires two-factor authentication, and was locked out:
the organization token was refused (`MFA_ENROLLMENT_REQUIRED`, a social
session never passes our second step), the account-space token was refused
(409, the account now has an organization), the second step could not start
(a federated session cannot enroll), and the console signed them out. Signing
in again with Google led to the same place. Each piece was correct on its own;
the combination was a dead end. The suites below test combinations.

## Dimensions

| Dimension | Values |
|---|---|
| Sign-in method | password; password + authenticator; Google, Microsoft, GitHub (social: method `sso`, no issuing organization, account without a password); the organization's own OIDC provider; its own SAML provider; another organization's provider (a person who also has their own account). Passkeys exist only for the platform console; there is no e-mail link sign-in. |
| Account | new or existing; e-mail verified or not; locked (failed attempts); blocked by the platform; deletion pending; password reset pending; authenticator enrolled or not; social identity linked or not; same e-mail at another provider |
| Organization rules | none; 2FA required for everyone; 2FA required for administrators (member and administrator roles); identity provider required (SSO enforced; owner break-glass); identity provider must prove a second factor; IP allow-list; suspended by the platform; verified-domain automatic join; personal (free-mail) accounts blocked or allowed with 2FA |
| Membership | none; pending invitation (first time); invitation expired, revoked, already used, for another e-mail, unknown token; returning member; member of two organizations with different rules; suspended or removed while signed in; role raised while signed in; directory (SCIM) provisioned or deprovisioned |
| Session events | access token expiry and refresh; refresh token rotation with two tabs; a tab that missed a rotation; sign-out in another tab; organization switch in two tabs; the rules tightened while signed in; the session expired; deep link to an organization page while not admitted; an invitation link opened while signed in as someone else |
| Platform | console administrator accounts and break-glass accounts never sign in to the tenant app; support access |

## Expected outcomes

The specification lives in code (`expect` in
`server/tests/authscenarios/model_test.go`, `expected` in the e2e spec). In words:

| Method | open | 2FA required (or admin rule, admin role) | identity provider required | provider must prove 2FA | suspended | IP allow-list |
|---|---|---|---|---|---|---|
| password | opens | refused `MFA_ENROLLMENT_REQUIRED`; second step in this session; then opens | refused `SSO_REQUIRED`; sign in through the provider; then opens | as 2FA required | refused `ORGANIZATION_SUSPENDED`; account space | refused with a reason code; account space |
| password + authenticator | opens | opens | as password | opens | as above | as above |
| social (no authenticator) | opens | refused `MFA_ENROLLMENT_REQUIRED`; **our second step in this session (set up an authenticator)**; then opens | as password | as 2FA required | as above | as above |
| social with authenticator | opens | refused; **verify the authenticator in this session**; then opens | as password | as 2FA required | as above | as above |
| organization's own OIDC / SAML | opens | opens (the organization chose that provider) | opens | opens only with proof; otherwise refused with a code that says the provider must prove it; sign in again at the provider | as above | as above |
| another organization's provider (own account exists) | refused `OWN_SIGN_IN_REQUIRED`; sign in with the own account; then opens | same | same | same | as above | as above |

The membership never changes the outcome, only the way there: a first-time
invitee accepts, a returning member exchanges the token, a member of two
organizations keeps the other one open throughout.

## Invariants (checked in every scenario)

1. **No dead end.** After a refusal the session still reaches something: another
   organization, the account space (account token), or a next step that starts
   in this session; or the refusal asks the person to sign in again and that
   sign-in exists for the account and works. A refusal whose only advice is
   "sign in again" with the same method is a dead end.
2. **No bypass.** An organization never opens for a session its rules refuse,
   including after accepting an invitation, after a removal, after a rule
   change and from a stale or second tab. These are security failures and
   never go to the known-failures list.
3. **Every refusal names its reason.** A 4xx carries an API error code the
   console can turn into a page; no bare 403, no 5xx anywhere on the path.
4. **An issued organization token works** on the organization's own record.
5. **(e2e)** After every journey the person is inside the organization, in the
   account space, or on a page that says why and shows one next step. `/login`
   is reached at most once without the test opening it (a logout loop shows as
   several), and a refused API call is never followed by `/login` without a
   reason on the page.

## Seeding federated sign-ins

No identity provider round trip happens in either suite. A federated sign-in
is seeded as its callback leaves it: the session row gets `auth_method`
(`sso` or `saml`), `idp_tenant_id` (the issuing organization; none for
social) and `mfa_evidence`, and the account gets the provider and no
password. The suites therefore test everything after the provider said yes,
which is where the decisions are. Decisions taken inside a callback before
the session exists (for example a second step offered during a social
sign-in) are covered only through their effect on the session, unless the
suite points the API at a stand-in provider (below).

## Running a sign-in against a stand-in provider (test builds only)

A binary built with the build tag `authtestseam` reaches the social
providers' endpoints (authorization, token, signing keys, profile APIs of
Google, Microsoft and GitHub) at a stand-in:
`AUTHTESTSEAM_PROVIDER_URL=<base>` turns `https://<host><path>` into
`<base>/<host><path>` for the API's own calls, and
`AUTHTESTSEAM_PROVIDER_BROWSER_URL` (default: the same) for the browser's
authorization redirect. The identity rules do not change: an id_token still
carries the provider's real issuer and our client id, and is verified
against the stand-in's keys. Even a test binary ignores the variables unless
`APP_ENV` is `test` or `e2e` (unset, `production`, `staging` and every other
value never apply them), and it logs a warning at start-up whenever they apply.

A build without the tag (every release image) compiles
`internal/app/auth/provider_endpoints_release.go` instead and reads no
variable; `provider_endpoints_test.go` proves which file each build compiles,
that the environment changes nothing in a release build, and that no
Dockerfile, bake file, Makefile, script or workflow outside the test suites
passes the tag.

- Go suite: `ci/run.sh` builds the API with the tag; set
  `AUTHSCEN_PROVIDER_URL` (and `AUTHSCEN_PROVIDER_BROWSER_URL`) to point it at
  a stand-in. The workflow also runs the tagged end-to-end test
  `TestProviderTestSeam_SignInAgainstAStandIn` (code exchange, id_token
  verification, profile APIs, against an in-process stand-in).
- Browser suite: `server/tests/testseam/Dockerfile` rebuilds the e2e API
  image's server binary with the tag
  (`--build-arg API_IMAGE=<the e2e API image>`).

## Known failures

A scenario that fails on the current code is listed with its expected outcome
in `server/tests/authscenarios/known-failures.txt` (Go) or
`web/e2e/sign-in-journeys.known-failures.txt` (Playwright). A listed scenario
still runs: its failure is reported, not failed, and the job fails once it
passes until its line is removed. A bypass is never listed.

## Running

```bash
# Go suite: scratch Postgres + Redis, the API built from this tree, the suite
server/tests/authscenarios/ci/run.sh -v
# against another version: the server/ (or api/) directory of that checkout
AUTHSCEN_SERVER_DIR=/path/to/release/checkout/api server/tests/authscenarios/ci/run.sh
# Playwright journeys: the e2e stack (web/e2e/ci) seeds E2E_JOURNEY_*; the
# spec also needs E2E_DATABASE_URL (web/e2e/ci/.env)
npx playwright test e2e/specs/58-sign-in-journeys.spec.ts
```

CI runs the Go suite on pull requests that touch the sign-in code
(`.github/workflows/api-auth-scenarios.yml`) and the journeys with the e2e
suite (area `@auth`).
