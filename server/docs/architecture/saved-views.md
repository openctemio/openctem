# Saved views

A saved view is a named lens on one list page of the console: the page's
filters, sort, columns and density under a name. A member saves the current
state, opens it later, updates it, deletes it, shares it with a team or (with
`findings:views:share`) with the organization, and pins it.

| Part | Status |
|---|---|
| `GET/POST /api/v1/views`, `GET/PUT/DELETE /api/v1/views/{id}` | **Shipped** |
| Page registry: every list page of the web console has a page key | **Shipped** |
| Views with a validated filter that run on the server (`?view=<id>`): `findings`, `vulnerabilities`, `assets` | **Shipped** |
| Views of the other pages: the list state kept as page params, opened by the page | **Shipped** (API); the Views menu of each list is added with its redesign |
| Sidebar pins (`/api/v1/me/pins`) of a saved view | **Shipped** for `findings` views only |
| Saved views of the admin console lists | Not available: see [Pages without views](#pages-without-views) |

Key files: `pkg/domain/savedview/pages.go` (the page registry),
`pkg/domain/savedview/view.go`, `internal/app/savedview/service.go`,
`internal/infra/http/handler/saved_view_handler.go`,
`internal/infra/http/routes/saved_views.go`,
`internal/infra/postgres/saved_view_repository.go`. The filter contract of the
three pages whose views run on the server is
[the list query contract](list-query-contract.md#saved-views).

## The page registry

The pages that have saved views are one list in the server,
`pkg/domain/savedview/pages.go`. Each entry names:

- the **page key** a view is stored under (`page` in the API);
- the **web route** of the list;
- the **permission that reads the list**. Listing, saving and opening a view
  of the page needs it.

Rules of a key:

- It is the web route without its leading slash, with `/` written as `.`:
  `/scans/runs` is `scans.runs`. Lower-case letters, digits and `-` in
  segments joined by `.`, at most 64 characters.
- It is stable. A view stores its key, so a route that is renamed keeps its
  key, and a page that is removed leaves its key unused (views under a key
  that is no longer registered are not found).
- A key that is not registered is refused with `400`, on every method. The
  `saved_views.page` column only checks the key's shape
  (`chk_saved_views_page`); the registry decides which keys exist.

### Registering a new list

1. Add one line to `pages` in `pkg/domain/savedview/pages.go`:
   `page("/the/route", permission.TheListRead)`, with the permission the
   list's own `GET` endpoint requires. No migration.
2. If no registered page names that permission yet, add it to the route gate
   in `internal/infra/http/routes/saved_views.go`
   (`TestSavedViewRouteGateIsTheRegistry` says so).
3. Add its row to the table below.
4. If the list has a filter field registry (`pkg/filterspec`) and should run
   views on the server with `?view=<id>`, also add its `PageConfig` where the
   service is built (`internal/server/services.go`) and call
   `applySavedView` in its list handler; see the
   [list query contract](list-query-contract.md#saved-views).

`tests/unit/saved_view_pages_coverage_test.go` walks the route tree of the web
console and of the admin console: a page route that is neither registered nor
listed in `PagesWithoutViews` (same file as the registry, with a reason) fails
the build, and so does a registered key missing from the table below.

### Page keys

| Page key | Web route | Permission |
|---|---|---|
| `assets` | `/assets` | `assets:read` |
| `assets.attention` | `/assets/attention` | `assets:read` |
| `assets.changes` | `/assets/changes` | `assets:read` |
| `assets.duplicates` | `/assets/duplicates` | `assets:read` |
| `assets.groups` | `/assets/groups` | `assets:groups:read` |
| `assets.suggestions` | `/assets/suggestions` | `assets:read` |
| `attack-simulation` | `/attack-simulation` | `validation:read` |
| `attack-surface.certificates` | `/attack-surface/certificates` | `assets:read` |
| `attack-surface.changes` | `/attack-surface/changes` | `assets:read` |
| `attack-surface.discovery` | `/attack-surface/discovery` | `scans:read` |
| `attack-surface.exposures` | `/attack-surface/exposures` | `findings:exposures:read` |
| `attack-surface.external` | `/attack-surface/external` | `assets:read` |
| `attack-surface.lookalikes` | `/attack-surface/lookalikes` | `attack_surface:scope:read` |
| `attack-surface.pages` | `/attack-surface/pages` | `assets:read` |
| `attack-surface.review` | `/attack-surface/review` | `assets:read` |
| `attack-surface.technologies` | `/attack-surface/technologies` | `assets:read` |
| `attack-surface.web` | `/attack-surface/web` | `assets:read` |
| `attacker-profiles` | `/attacker-profiles` | `ctem:attacker_profiles:read` |
| `automations` | `/automations` | `automations:read` |
| `business-services` | `/business-services` | `ctem:business_services:read` |
| `business-units` | `/business-units` | `assets:read` |
| `ci-cd` | `/ci-cd` | `scans:ci:read` |
| `compliance` | `/compliance` | `compliance:frameworks:read` |
| `components` | `/components` | `assets:components:read` |
| `control-testing` | `/control-testing` | `validation:read` |
| `controls` | `/controls` | `ctem:compensating_controls:read` |
| `credentials` | `/credentials` | `findings:credentials:read` |
| `crown-jewels` | `/crown-jewels` | `assets:read` |
| `cycles` | `/cycles` | `ctem:cycles:read` |
| `emerging-threats` | `/emerging-threats` | `findings:vulnerabilities:read` |
| `exceptions` | `/exceptions` | `findings:suppressions:read` |
| `exposures.code` | `/exposures/code` | `findings:read` |
| `exposures.misconfigurations` | `/exposures/misconfigurations` | `findings:read` |
| `exposures.secrets` | `/exposures/secrets` | `findings:read` |
| `exposures.vulnerabilities` | `/exposures/vulnerabilities` | `findings:read` |
| `findings` | `/findings` | `findings:read` |
| `findings.approvals` | `/findings/approvals` | `findings:read` |
| `findings.imports` | `/findings/imports` | `findings:read` |
| `findings.ready-to-close` | `/findings/ready-to-close` | `findings:read` |
| `findings.triage` | `/findings/triage` | `findings:status` |
| `pentest.campaigns` | `/pentest/campaigns` | `pentest:campaigns:read` |
| `priority-rules` | `/priority-rules` | `ctem:priority_rules:read` |
| `programs` | `/programs` | `attack_surface:programs:read` |
| `remediation.campaigns` | `/remediation/campaigns` | `findings:remediation:read` |
| `remediation.suggestions` | `/remediation/suggestions` | `findings:remediation:read` |
| `remediation.tasks` | `/remediation/tasks` | `findings:remediation:read` |
| `scans` | `/scans` | `scans:read` |
| `scans.approvals` | `/scans/approvals` | `scans:read` |
| `scans.runs` | `/scans/runs` | `scans:read` |
| `scans.workflows` | `/scans/workflows` | `scans:workflows:read` |
| `scope` | `/scope` | `attack_surface:scope:read` |
| `scope.domain-proof` | `/scope/domain-proof` | `attack_surface:scope:read` |
| `scope.letters` | `/scope/letters` | `attack_surface:scope:read` |
| `scope.networks` | `/scope/networks` | `attack_surface:scope:read` |
| `sensors` | `/sensors` | `sensors:read` |
| `settings.api-keys` | `/settings/api-keys` | `integrations:api_keys:read` |
| `settings.asset-sources` | `/settings/asset-sources` | `team:update` |
| `settings.audit-log` | `/settings/audit-log` | `audit:read` |
| `settings.domains` | `/settings/domains` | `team:update` |
| `settings.integrations.import-mappings` | `/settings/integrations/import-mappings` | `integrations:read` |
| `settings.integrations.notifications` | `/settings/integrations/notifications` | `integrations:read` |
| `settings.integrations.notifications.history` | `/settings/integrations/notifications/history` | `integrations:manage` |
| `settings.integrations.notifications.outbox` | `/settings/integrations/notifications/outbox` | `integrations:manage` |
| `settings.integrations.scanners` | `/settings/integrations/scanners` | `integrations:read` |
| `settings.integrations.scm` | `/settings/integrations/scm` | `integrations:read` |
| `settings.integrations.siem` | `/settings/integrations/siem` | `integrations:read` |
| `settings.integrations.ticketing` | `/settings/integrations/ticketing` | `integrations:read` |
| `settings.integrations.ticketing.mappings` | `/settings/integrations/ticketing/mappings` | `integrations:read` |
| `settings.members` | `/settings/members` | `team:members:read` |
| `settings.pentest.checklists` | `/settings/pentest/checklists` | `validation:read` |
| `settings.pentest.templates` | `/settings/pentest/templates` | `validation:read` |
| `settings.roles` | `/settings/roles` | `team:roles:read` |
| `settings.scanning.capabilities` | `/settings/scanning/capabilities` | `scans:tools:read` |
| `settings.scanning.credentials` | `/settings/scanning/credentials` | `scans:secret_store:read` |
| `settings.scanning.detection-rules` | `/settings/scanning/detection-rules` | `scans:content:read` |
| `settings.scanning.profiles` | `/settings/scanning/profiles` | `scans:profiles:read` |
| `settings.scanning.proxies` | `/settings/scanning/proxies` | `sensors:egress:read` |
| `settings.scanning.scan-windows` | `/settings/scanning/scan-windows` | `scans:read` |
| `settings.scanning.sensor-products` | `/settings/scanning/sensor-products` | `sensors:read` |
| `settings.scanning.templates` | `/settings/scanning/templates` | `scans:templates:read` |
| `settings.scanning.tool-sources` | `/settings/scanning/tool-sources` | `scans:secret_store:read` |
| `settings.scanning.tools` | `/settings/scanning/tools` | `scans:tools:read` |
| `settings.scanning.wordlists` | `/settings/scanning/wordlists` | `scans:content:read` |
| `settings.service-accounts` | `/settings/service-accounts` | `team:members:read` |
| `settings.sla-policies` | `/settings/sla-policies` | `settings:sla:read` |
| `settings.sso-approvals` | `/settings/sso-approvals` | `team:update` |
| `settings.teams` | `/settings/teams` | `team:groups:read` |
| `settings.trusted-organizations` | `/settings/trusted-organizations` | `team:update` |
| `threat-intel` | `/threat-intel` | `findings:vulnerabilities:read` |
| `threat-intel.detections` | `/threat-intel/detections` | `threat_intel:read` |
| `threat-intel.iocs` | `/threat-intel/iocs` | `threat_intel:read` |
| `threat-model` | `/threat-model` | `assets:read` |
| `validation.retests` | `/validation/retests` | `validation:read` |
| `vulnerabilities` | `/vulnerabilities` | `findings:vulnerabilities:read` |

### Pages without views

`PagesWithoutViews` in `pkg/domain/savedview/pages.go` lists every console
route that deliberately has no views, with its reason: dashboards and hubs,
settings forms, graphs, wizards and editors, the member's own account pages,
the personal pages every member opens (`/my-work`, `/notifications`: a view
is gated by the read permission of its page's list, and they have none),
and the fixed presets of the Needs attention list (they share the views of
`assets.attention`). Detail and edit pages (a route with an id) need no entry.

The lists of the **admin console** are excluded too. A saved view is stored
per organization and belongs to a member of it; an administrator of the
installation signs in to no organization, so those lists need a store of
their own before they can offer views. That is not designed yet.

## What a view stores

| Field | Pages with a filter registry (`findings`, `vulnerabilities`, `assets`) | Every other page |
|---|---|---|
| `filter` | A filter document, validated against the page's fields on save and again on every run | Always `{}`; sending a filter or `query` is `400` |
| `page_params` | The page's own params next to the filter (search mode; the vulnerabilities list's `kev`, `epss_gte`, `q`, `sort`), validated by the page | The whole list state as the page's own URL params (filters, sort, search) |
| `group_by` | One of the page's group dimensions | Not accepted (a grouping is a page param) |
| `columns`, `density` | Up to 50 column ids (`[A-Za-z0-9_]{1,64}`), a density word | The same |

For a page without a filter registry the server is a store, not an
interpreter: `page_params` is a flat map of text to text. It is never parsed
as a filter, compiled to SQL or run, on save or later. The list page that
opens the view reads the params exactly as it reads its own URL, through the
validation its list endpoint already applies to a request, so a stored value
can do nothing a typed URL could not. Names and values are returned as JSON
strings only; the console renders them as text.

Never SQL, never results: a view of any page holds a query, and it runs as
the person using it, with their organization, data scope and visibility.

## Limits

| Limit | Value |
|---|---|
| Views per person in an organization, all pages | 100 (`409` beyond) |
| Views per person on one page | 50 (`409` beyond) |
| Views shared with one group | 100 |
| Views shared with the organization | 100 |
| Views returned by one list request | 500 |
| Name | 1 to 120 characters, no control characters |
| Description | Up to 500 characters |
| Request body | 48 KB |
| `filter` | 32 KB stored (`chk_saved_views_filter_size`) |
| `page_params` of a page without a filter registry | 32 params; a name is `[a-z][a-z0-9_.-]{0,63}`; a value is up to 1024 bytes of text without control characters; names and values together up to 3072 bytes (4096 bytes stored, `chk_saved_views_page_params`) |
| `page_params` sent next to a filter | 16 params, each validated by the page |
| `columns` | 50 |

The caps are checked when a view is created; a member over a new cap keeps
their views and can update and delete them.

## Authorization and isolation

The routes ask for the least a caller needs, the read permission of at least
one list that has views (`403` otherwise). The gate that decides is per page
key, in the service, for every request.

| Request | Check | Refusal |
|---|---|---|
| Any | A signed-in member (a user-less API key has no views) | `403` |
| `GET /views?page=<key>`, `POST /views` | `<key>` is registered | `400` |
| | The caller holds the page's permission | `403` with `details.missing_permissions` |
| `GET/PUT/DELETE /views/{id}`, `POST /views` with `from_view_id` | The view is in the caller's organization and visible to them (own, shared with one of their active groups, or shared with the organization) | `404` |
| | The caller holds the permission of the view's page | `404` |
| `PUT`, `DELETE` | The caller owns the view | `403` (only for a view they can see) |
| `group_id` | The caller is a member of that active group of the organization | `400` |
| `share_with_org` | `findings:views:share` | `403` |

- The `403` of a page key depends only on the key and the caller's
  permissions. It is the same whether the page has views or not, so it tells
  nothing about them. By id, a view the caller may not use is always `404`,
  with a body that carries nothing of the view.
- Every statement carries the organization of the authenticated principal;
  the organization is never read from the request. A view of another
  organization is `404` for reads, updates and deletes.
- Sharing is unchanged by the registry: personal by default, one group the
  owner belongs to, or the organization with `findings:views:share`. A shared
  view is still only usable by a member who may read its page's list.
- Changes are audit-logged (`saved_view.created`, `.updated`, `.deleted`)
  with the page key and the sharing, never the filter values.

## Using a view from a list page

- `findings`, `vulnerabilities`, `assets`: request the list with
  `?view=<id>`; the server applies the stored filter as the caller, with the
  request's own params on top.
- Every other page: read the view (`GET /views?page=<key>` returns the
  views with their `page_params`, `columns` and `density`), put `page_params`
  into the page's URL params and load the list as usual. To save, send the
  page's current URL params as `page_params`.
