# RFC-018 — Identity exposure discovery from EntraID (MFA / privilege / stale)

- Status: **Proposed** — Phase 0 (exposure vocabulary) shipped in this PR; Phase 1+ (the emitter) requires new admin-consented Microsoft Graph scopes and is **not** built.
- Area: CTEM Discovery — external-exposure connectors, identity surface.
- Related: RFC-009 (Enterprise SSO: SAML + SCIM), `docs/architecture/multi-tenant-entraid-model.md`, `internal/app/exposurebridge` (the misconfiguration/secret projection this mirrors).

## 1. Goal

Give OpenCTEM's Exposure Register a first-class **identity attack surface**, realizing
the CTEM principle *exposure ≠ vulnerability* for identity: a human/privileged
account without strong MFA, an enabled account that stopped signing in, or a
principal holding a privileged directory role it does not need are **exposures**,
not CVEs. They belong next to leaked credentials and misconfigurations in the
Exposure Register, deduped/reactivated by the same machinery, tagged with a
CTEM-ID category where one fits, and fed into prioritization/attack-path like any
other exposure.

The most tractable first source is the customer's **Microsoft Entra ID** directory,
which most tenants already connect for SSO.

## 2. Feasibility — what the EntraID integration can read TODAY (grounded)

The existing integration is **delegated OIDC login only**. Concretely:

- Configured/stored Graph scopes are `openid email profile User.Read`
  (`pkg/domain/identityprovider/entity.go` default scopes;
  `docs/how-to/configure-entraid.md` §API permissions; `OAUTH_MICROSOFT_SCOPES`).
- The only Graph call is the userinfo endpoint `https://graph.microsoft.com/v1.0/me`,
  reached with the **user's** authorization-code access token during their login
  (`identityprovider.AuthEndpoints`). The token grant is `authorization_code`
  only — there is **no** `client_credentials` / app-only token anywhere in the
  codebase (verified: the only `grant_type` set is `authorization_code`).
- No refresh token is persisted for background use; the stored client secret is
  used solely for the interactive auth-code exchange.
- SCIM (RFC-009) exists but is **inbound provisioning push** (IdP → us): it can
  create/deactivate users and map groups → OpenCTEM roles. It does **not** convey
  MFA registration, sign-in activity, or Entra directory-role assignments, and it
  is IdP-driven rather than something we can query on a schedule.

**Conclusion:** with today's delegated `User.Read` on `/me`, we can read only the
*currently-signing-in* user's basic profile. We **cannot** enumerate the directory,
nor read MFA registration, privileged-role assignments, sign-in risk, or last
sign-in. Every proposed identity exposure needs directory-wide, background
(app-only) reads that the integration does not hold.

### Scopes required for a real emitter (app-only / admin consent)

| Signal | Exposure type | Graph resource | Application permission |
|--------|---------------|----------------|------------------------|
| MFA registration state | `identity_mfa_gap` | `/reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` (+ `UserAuthenticationMethod.Read.All` for per-method detail) |
| Last interactive sign-in | `identity_stale_principal` | `/users?$select=signInActivity,accountEnabled` | `AuditLog.Read.All` + `User.Read.All` |
| Privileged directory roles | `identity_overprivileged` | `/roleManagement/directory/roleAssignments` (+ `roleDefinitions`) | `RoleManagement.Read.Directory` |
| (Phase 2) Sign-in risk | future `identity_risky_signin` | `/identityProtection/riskyUsers` | `IdentityRiskyUser.Read.All` (Entra ID P2) |

All are **application** permissions requiring tenant-admin consent — a different
consent than the delegated login scopes we have. This is why the emitter is a
bigger lift and is **not** built blind here.

## 3. Decision

**Build the exposure vocabulary now; design the emitter, do not half-build it.**

Shipping a scheduled emitter today would either (a) require credentials no tenant
has granted, or (b) emit empty/synthetic data — the "silently-inert control"
failure mode. Instead this PR lands the **real, non-inert** foundation the emitter
will produce into, and this document specifies the emitter so Phase 1 is a
straight implementation once a tenant grants app-only consent.

## 4. What shipped in this PR (Phase 0)

- Three exposure event types in the domain vocabulary
  (`pkg/domain/exposure/value_objects.go`): `identity_mfa_gap`,
  `identity_stale_principal`, `identity_overprivileged` — added to
  `AllEventTypes()`, `IsValid()`, `ParseEventType()`, and `IsPositiveExposure()`
  (all three increase exposure).
- Migration `000210_exposure_identity_event_types` extends the
  `chk_exposure_events_type` CHECK constraint with the three values (additive;
  the column is `VARCHAR(50)` gated by CHECK, so new types require a migration —
  this one — but no schema/shape change).
- Unit tests: domain-level (`identity_event_types_test.go`) for validity, stable
  persisted strings, and exposure-positivity; plus the create-path coverage in
  `tests/unit/exposure_service_test.go`.

Nothing emits these yet — that is Phase 1. They are additive vocabulary, harmless
until an emitter exists, and are exactly what that emitter will write.

## 5. Emitter design (Phase 1)

Mirror `internal/app/exposurebridge` (the misconfiguration/secret → ExposureEvent
projection) and the scheduled-controller pattern used by
`internal/infra/controller/ctemid_refresh.go` / `threat_intel_refresh.go`.

**Credential surface.** Add an app-only credential to the tenant's Entra config
(either new fields on `identity_providers` — `graph_app_client_id`,
`graph_app_secret_encrypted`, consented — or, cleaner, a dedicated
`integration` of a new `entra_identity` type so the login IdP and the read-only
directory reader stay separable). Secret encrypted with the existing AES-256-GCM
`APP_ENCRYPTION_KEY` path. **Tenant isolation is mandatory and comes from the
integration/provider config, never from any Graph response** (per the
integrations-tenant-isolated rule): the controller iterates tenants, resolves
that tenant's own app registration, and every emitted `ExposureEvent` is stamped
with the config's `tenant_id`.

**Reader.** A per-tenant `client_credentials` Graph client (new code — none
exists today) fetches the three reports, page by page, fail-open: a tenant whose
consent is missing/expired is logged and skipped, never aborting others.

**Projection → ExposureEvent.** For each finding, build an event with:
- `event_type` = one of the three;
- `severity` derived from posture (e.g. MFA gap on a privileged principal →
  `critical`; on a standard user → `medium`; stale > 90d enabled → `high`);
- `source` = `entra_identity`, `details.discovery_source = "entra_identity"`
  (same provenance-labeling discipline as the bridge);
- `details` = evidence (principal id/UPN — hashed or masked per privacy stance,
  role name, days-since-signin, MFA methods count), plus `owner` (the principal
  itself / its manager) and a reachability hint (privileged role ⇒ higher);
- **fingerprint** stable per `(tenant, event_type, principal_object_id)` so a
  re-run folds onto the same Exposure Register row and **reactivates** it if it
  had been resolved — reusing the exposure repo dedupe path, not a new table.
- Auto-resolve: a principal that now has MFA / has signed in / lost the role is
  no longer returned, so the controller resolves its open event (same lifecycle
  as attack-surface exposures that disappear).

**Schedule.** Daily, alongside `ctemid_refresh`, behind a per-tenant enablement
flag on the integration (absent config = source simply does not run).

## 6. CTEM-ID mapping (honest)

The coded CTEM-ID taxonomy (`pkg/domain/ctemid/category.go`) is an **external
threat-feed** vocabulary: `brand_impersonation`, `credential_dumps`,
`infected_devices`, `lookalike_domains`, `ransomware`, `source_code_exposure`,
`system_exposure`, `other`. It has **no first-class identity-posture class**, so
the mapping is approximate and should be recorded as a hint in `details.ctem_id`
rather than overstated:

| Exposure type | Best-fit CTEM-ID category | Note |
|---------------|---------------------------|------|
| `identity_mfa_gap` | `system_exposure` | Posture weakness; no clean identity class exists. |
| `identity_overprivileged` | `system_exposure` | Same. |
| `identity_stale_principal` | `system_exposure` (or `credential_dumps` if the account also appears in a breach feed) | Stale accounts are prime credential-stuffing targets. |

A follow-up may add a dedicated `identity_exposure` CTEM-ID category rather than
forcing these under `system_exposure`. Deliberately left out of this PR to avoid
mis-tagging.

## 7. Phased plan

- **Phase 0 (this PR):** exposure vocabulary + migration + tests. ✅
- **Phase 1:** app-only credential config + per-tenant `client_credentials` Graph
  reader + scheduled controller + projection for the three types + tenant-isolation
  and fail-open tests. Requires tenant admin consent to the scopes in §2.
- **Phase 2:** sign-in risk (`riskyUsers`, needs Entra ID P2) as
  `identity_risky_signin`; a dedicated identity CTEM-ID category; UI surfacing on
  the Exposures view (filter by the identity types).

## 8. Non-goals / scope notes

- No Graph app-only client, controller, or config surface is built here — that is
  Phase 1 and needs consented scopes.
- Okta/Google Workspace identity exposures are out of scope for v1 (Entra first);
  the event types are provider-neutral, so a later Okta reader can reuse them.
- Privacy: principal identifiers in `details` should be masked/hashed per the
  tenant's data stance before Phase 1 ships.
