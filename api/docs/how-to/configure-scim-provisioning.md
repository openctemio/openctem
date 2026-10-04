# How to configure SCIM provisioning

Let your identity provider (Okta, Microsoft Entra ID, …) **provision and
deprovision users** into an OpenCTEM tenant over SCIM 2.0. Deactivation in the IdP
suspends the OpenCTEM membership **immediately** (0-second offboarding).
Architecture: [scim-provisioning.md](../architecture/scim-provisioning.md).

> Roles: listing SCIM tokens and editing group mappings needs the **admin** or
> **owner** team role; minting and revoking a token is **owner only** (a token
> can create, suspend and re-role every member). Mapping a group **to `admin`**
> (or changing or removing such a mapping) is **owner only** too.

## 1. Generate a SCIM token

**Settings → Integrations → SCIM → Generate token:**

- Give it a **Name** (e.g. "Okta production") and click **Generate**.
- The full token (`oct_scim_…`) is shown **once** in the reveal dialog — copy it
  now and store it securely. It cannot be shown again (regenerate if lost).

Tokens are stored as a peppered HMAC, never in plaintext. Revoking a token (the
**Ban** action) cuts the IdP's access immediately.

## 2. Point your IdP at the SCIM endpoint

From the **SCIM endpoint** card, copy the base URL:

```
<your-origin>/scim/v2
```

In the IdP's SCIM provisioning config, set:

- **Base URL:** `<your-origin>/scim/v2`
- **Auth:** HTTP bearer — `Authorization: Bearer oct_scim_…`

The tenant is derived from the token, so **one token = one tenant** (cross-tenant
provisioning is impossible by construction). Supported: Users (`GET/POST/PUT/
PATCH/DELETE /Users`) and Groups (`/Groups`), plus discovery
(`ServiceProviderConfig`, `ResourceTypes`, `Schemas`). PATCH accepts both Okta and
Azure AD member-op styles.

## 3. Provision users (and, optionally, roles via groups)

- **Push users** from the IdP. A new user is created passwordless and added as an
  active tenant member with role **`member`** by default. Re-pushing an existing
  active member is idempotent.
- **Deactivate** (IdP `active:false` / DELETE) → the membership is suspended and
  all sessions + permission cache are cleared immediately. Reactivate to restore.
- **Group → role mapping:** a pushed group whose `displayName` is `member` or
  `viewer` (case-insensitive) maps its members to that role; effective role =
  the highest matched. A group grants **`admin` only through a mapping the
  owner configured** (a group named "admin" is not enough). `owner` is **never**
  assignable via SCIM.

> **Gotcha — group→role mapping has no UI.** Custom mappings (e.g. an IdP group
> `Acme-OpenCTEM-Admins` → `admin`) are configured **via the API only**:
> `PUT /api/v1/scim-tokens/group-mappings` with
> `{"mappings":{"Acme-OpenCTEM-Admins":"admin"}}`. Without a mapping, group members
> fall back to `member`.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| IdP gets 401 | Token revoked or wrong — check it's active in the tokens table; regenerate if lost (one-time reveal). |
| New users all land as `member` | Expected unless a group→role mapping applies (API-only, above). |
| Can't set someone as owner via IdP | By design — `owner` is never SCIM-assignable. |
| Admin group members are not promoted | The admin mapping was not saved by the owner (or predates migration `000830`). Have the owner `PUT` the mappings again. |
| `403` saving group mappings | Only the owner can add, change or remove a mapping to `admin`. |
| An administrator was not demoted when removed from the IdP group | By design until the owner configures an admin mapping: SCIM does not demote hand-appointed administrators. |
| Deprovisioned user still "in" | Deactivation suspends the tenant membership (immediate) but retains the global user record; that's expected. |
| PATCH returns `invalidPath` | The IdP sent an unsupported PATCH path — only standard user/group member ops are supported. |

> SCIM provisioning is separate from **SAML SSO login** (Settings → Integrations →
> SAML SSO). For Entra/OIDC login see [configure-entraid.md](./configure-entraid.md).
