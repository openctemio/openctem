# Organization settings: storage, concurrency and failure handling

Organization (tenant) settings live in one JSONB column, `tenants.settings`.
Each top-level key is a **section**: `general`, `security`, `branding`,
`branch`, `ai`, `risk_scoring`, `pentest`, `asset_identity`,
`asset_lifecycle`, `retest`. The key `subscribed_bundles` is written by the
module bundle store. The data-scope policy is the separate column
`tenants.members_without_group_see`.

Code: `pkg/domain/tenant/settings.go` (typed sections),
`pkg/domain/tenant/settings_section.go` (section keys, ETags, per-section
decode), `internal/app/tenant/settings_write.go` (the write path),
`internal/infra/postgres/tenant_repository.go` (`UpdateSettingsSection`,
`UpdateProfile`).

## Who reads what

- `GET /tenants` and `GET /tenants/{t}` return the organization **profile
  only** (id, name, slug, description, logo, plan). They no longer carry the
  settings blob, which any member could read.
- `GET /tenants/{t}/settings` returns `general`, `branding` and `pentest` to
  every member; `security` (IP allowlist, allowed domains, MFA, email
  verification) and `risk_scoring` only to owners and admins. The fields are
  absent for other roles (owner decision B20).
- The legacy `api` section (API key switch, outbound webhook URL and a
  plaintext `webhook_secret`) was never read by anything. `PATCH
  /settings/api` is removed and migration 001052 deletes the stored key.

## Organization slug

The slug keys the SAML/SSO sign-in and ACS URLs. Renaming it is owner-only
(403 for admins; a profile save with the unchanged slug still works for
admins) and refused while the organization has a usable SSO identity provider
(400): the URLs registered at the IdP would stop working, and with SSO
enforced everyone but the owner would be locked out (owner decision B13). A
rename is audited at High.

## Writes: one section at a time, compare-and-swap

Every settings writer goes through `TenantService.writeSettingsSection`:

1. Read the tenant and the section's stored value.
2. Apply the change to that section only.
3. Persist it with a compare-and-swap on that key alone:

```sql
UPDATE tenants
   SET settings = jsonb_set(COALESCE(settings,'{}'), ARRAY[$section], $next, true),
       updated_at = NOW()
 WHERE id = $tenant
   AND (COALESCE(settings,'{}') -> $section) IS NOT DISTINCT FROM $expected
```

Consequences:

- Saving one section never rewrites another. Before this, every writer
  rewrote the whole blob from a snapshot read earlier, so a general-settings
  save, the asset-lifecycle dry-run stamp or a branding save could silently
  revert a concurrent change to the IP allowlist, the MFA requirement, SSO
  enforcement or the bundle subscription.
- A writer whose snapshot of the same section is stale loses the CAS. Without
  `If-Match` the service re-reads and re-applies the partial change (at most 3
  attempts), so fields the caller did not send keep the concurrent value.
- The organization profile (name, slug, description, logo URL) is written by
  `UpdateProfile`, which never touches `settings`.

## Optimistic concurrency for clients: ETag / If-Match

- `GET /tenants/{t}/settings` and every section `PATCH` that returns the full
  settings object carry `etags`: the entity tag of each section **as stored**
  (a hash of its canonical JSON).
- Section `GET`/`PATCH` endpoints (`pentest`, `risk-scoring`,
  `asset-lifecycle`, `asset-identity`, `/organization/settings/retest`, and the
  section `PATCH`es) also set the `ETag` response header for their section.
- A section write may send `If-Match: <etag>`. When the section changed since,
  the API answers **409 `SETTINGS_CONFLICT`** with
  `details: {section, etag, current}`; `current` is the stored section with
  secrets redacted (`RedactSettings`). Without `If-Match` the write behaves as
  described above.
- The web console sends the section tag from its cached `GET /settings` on the
  general, security, branding and API saves (`useSettingsSectionMutation`), and
  on a conflict reloads the settings and shows the server message.

## Failure handling: a corrupt section fails closed

- Sections are decoded one by one (`SettingsFromMapChecked`). A section that
  cannot be decoded falls back to its own default; the others are unaffected.
  (Before, one wrongly typed key reset every section, including security, to
  defaults: empty IP allowlist, MFA off.)
- Enforcement points read security with `Tenant.SecuritySettingsStrict()`, which
  returns an error for an unreadable security section:
  - the IP allowlist gate denies the request;
  - the SSO enforcement gate and the token-mint SSO check refuse;
  - the token-mint 2FA check refuses, and "does any of my organizations require
    2FA" counts the organization as requiring it.
- A write to an unreadable section is refused (500, logged as an error), so it
  is never overwritten with defaults. Writes to other sections still work.
  An operator fixes the stored JSON.

## Audit: every change carries a diff

Configuration changes are written to the tenant audit log with a field-level
before/after diff (`internal/app/audit/settings_diff.go`, `DiffChanges` /
`NewChangeEvent`):

- the diff holds only the fields that changed, as dotted paths
  (`ip_whitelist`, `webhook.url`); `metadata.changed_fields` lists them;
- a field whose name marks a secret (`*secret*`, `*password*`, `api_key`,
  `access_key`, `*token*`, `credentials`, ...) is recorded as `"[changed]"`,
  never as its value;
- strings are cut at 256 characters and lists at 50 items.

Severity follows what the change does, not which endpoint it came through:

| Change | Severity |
|---|---|
| security: 2FA requirement off, SSO enforcement off, IP allowlist emptied | Critical |
| security: IP allowlist widened (an entry outside every previous range), allowed domains widened or removed, email verification `never`, private-target local policy off, session timeout longer | High |
| security: any other change (tightening, neutral) | Medium |
| organization slug renamed (SAML/SSO URLs depend on it) | High |
| organization name, description, logo | Low |
| SCIM token created | High |
| SCIM token revoked | Medium |
| evidence storage configuration (`storage_config.updated`, keys redacted) | High |
| invitation canceled or declined (`invitation.deleted`), resent (`invitation.resent`) | Low |
| integration created / enabled / disabled / plain update | Medium |
| integration update that changes credentials (`integration.credentials_changed`) or a URL | High |
| integration deleted | High |
| Jira/GitHub inbound webhook secret read (the response carries it) or rotated | High |
| pending notification deleted from the outbox / retried | Medium / Low |
| SLA policy created or updated | Medium; High when any window got longer |
| SLA policy deleted | High |
| priority rule created / updated / deleted (re-classifies findings) | High |
| scope rule created / updated / deleted (changes what members see) | High |
| assignment rule created / updated / deleted | Medium |
| template source created / updated / enabled / disabled / deleted | Medium |

Integration diffs are taken from the redacted API view, without fields that
change on their own (status, sync times, counters); header maps and the
password in a URL's user info are never recorded.

Every other section save (general, branding, branch, pentest, risk scoring,
asset lifecycle/identity, retest) keeps its action and severity and
now carries the diff too.

## Tests

- `internal/app/tenant/settings_cas_db_test.go` (Postgres): racing saves of two
  sections both persist; a stale `If-Match` is refused and the stored value is
  unchanged; bundles, the dry-run stamp and a profile save do not disturb other
  keys; a corrupt security section is never rewritten and reads fail closed.
- `pkg/domain/tenant/settings_section_test.go`: per-section decode, ETag
  stability, `If-Match` parsing.
- `internal/infra/http/handler/settings_conflict_test.go`: the 409 body redacts
  secrets.
- `web/src/features/organization/api/__tests__/use-tenant-settings-if-match.test.tsx`.
- `internal/app/audit/settings_diff_test.go`, `internal/app/tenant/settings_audit_test.go`:
  diff, redaction, truncation, severity rules.
- `internal/app/tenant/settings_audit_db_test.go`, `internal/infra/http/handler/scim_token_audit_db_test.go`,
  `internal/infra/http/handler/storage_config_audit_db_test.go` (Postgres): one
  audit row per change with actor, diff and severity; no secret in the row.
- `internal/infra/http/handler/config_audit_db_test.go` (Postgres): priority
  rule create/update/delete rows (High, actor, diff); SLA and integration
  severity/view rules.

## Hidden until wired

A settings control is shown only when something reads its value (owner
decisions B5, B6). These are hidden in the web console, and
`web/src/config/__tests__/inert-settings-controls.test.ts` keeps them hidden:

- organization session timeout (until per-organization session policy is
  enforced; the stored value is no longer sent on save);
- organization industry, timezone and default language;
- the second language picker on Preferences (the user menu picks the language);
- the e-mail digest and desktop notifications (no sender yet);
- the asset-lifecycle "manual reactivation grace".

The `/settings/integrations/saml` and `/verified-domains` explainer pages
redirect (308) to Authentication, which carries the same "SSO is configured by
your platform administrator" card. Modules "Remove my changes" says what the
server does: it deletes your per-module overrides, so modules follow your
bundles again (a module outside them turns off).
