### Behaviour change: the crown-jewel flag is the assets.is_crown_jewel column

- **The crown-jewel flag is the `assets.is_crown_jewel` column** (owner
  decision O5). It was written into `properties.is_crown_jewel`, while the
  scoping summary read the column, so the two disagreed. Migration 000778
  backfills the column from the property (JSON `true` or the string `"true"`,
  any case; anything else reads as false), removes the key from properties
  and makes the column `NOT NULL DEFAULT FALSE`. Priority classification, the
  attack-path graph, exposure chains, threat models, the executive
  dashboard, the crown-jewel filter and dedup merge (a merged crown jewel
  keeps the flag) read the column; asset responses carry `is_crown_jewel`.
  Only `PATCH /assets/{id}/crown-jewel` writes it: assets:write, the asset in
  the caller's data scope (404 otherwise), audited. `is_crown_jewel` stays a
  reserved key, so a create, update, import or sensor report cannot set it
  through properties. **Upgrade note:** a crown jewel marked by a pod of the
  previous release while the migration runs must be marked again.

- **`POST /api/v1/assets` for an asset that already exists is a 409** (owner
  decision O4). A name, or an address the name correlates to (IP/hostname),
  that matches an asset of the organization used to merge the request into
  that asset; it now creates and changes nothing. The 409 carries
  `details.existing_asset_id` only when that asset is in the caller's data
  scope; otherwise it is the same generic conflict for every match, so it
  reveals nothing about an asset the caller cannot see. Another
  organization's assets never match. The web offers to open the existing
  asset. Sensor ingest and the SCM repository import
  (`POST /api/v1/assets/repository`) keep their merge paths. **Upgrade
  note:** an API client that relied on the create upserting must handle the
  409 (update the named asset) or send its data through ingest.

- **Tenable rolling coverage of private addresses needs a scan zone.**
  The coverage dispatcher now applies scan create's private-range policy:
  a private address is dispatched only when a scan zone of the tenant
  covers it (and the pinned sensor, if any, is in that
  zone). Tenants that rotated internal assets without zones see those
  assets skipped (logged) until they add a zone.

- **`*.example.com` means the subdomains of example.com, not example.com
  itself.** The scope matcher used to let a wildcard domain pattern match the
  bare name too, which is not what the pattern says (RFC-042 §6.13, F17).
  `**.example.com` means the same as `*.example.com`. Matching ignores case
  and a trailing dot, and compares names in their IDNA form
  (`*.bücher.example` matches `shop.xn--bcher-kva.example`). The web's scope
  preview already matched this way. Both directions change:
  - **Scope targets:** a target `*.example.com` no longer puts
    `example.com` in scope (coverage counts, `POST /scope/check`, overlap
    warnings). This only narrows scope. Existing targets are not rewritten:
    add `example.com` as its own target if the apex should stay in scope.
  - **Exclusions:** an exclusion `*.example.com` no longer excludes
    `example.com` from scans. So that nothing excluded today is scanned
    tomorrow, migration 000292 adds an apex sibling (`example.com`, same
    type, status, approval and expiry) for every existing domain/subdomain
    exclusion written `*.x` or `**.x`, except rejected ones and names that
    already have their own row. The siblings have `created_by =
    system:migration-000292` and a reason naming the wildcard row; the down
    migration removes exactly those. New wildcard exclusions cover
    subdomains only: request the apex separately.

- **Organizations are created by the platform administrator by default.**
  `TENANT_CREATION_MODE` now defaults to `admin_only` (was `self_service`).
  Signed-in users can no longer create organizations themselves
  (`POST /api/v1/auth/create-first-team` and `POST /api/v1/tenants` return
  403); the administrator creates them in the console or with
  `bootstrap-admin -org-*`. Existing organizations and memberships are
  unaffected. To keep self-service creation (SaaS or trial installs), set
  `TENANT_CREATION_MODE=self_service` (Helm: `api.tenantCreationMode=self_service`).
  Any value other than `self_service` is treated as admin-only.
