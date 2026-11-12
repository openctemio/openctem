# Organization switch: one epoch per organization

A person who belongs to several organizations switches between them in the
console: with the sidebar's organization card, with a link that names another
organization (`?org=`), on the MCP consent page, or in another tab of the same
browser. The server is the authority: every request is authorized against
the organization in the session's access token, never one sent by the client,
and an id of another organization answers like an unknown id. The console
must not keep anything of the previous organization either: its rows, its ids
in the address, its filters, its selection, a read still in flight, or a
draft.

## The rule

Everything under the dashboard shell belongs to one **organization epoch**.
A switch ends the epoch, and the new one starts from nothing. Pages do not
reset themselves: the mechanism does it for every page, so a new page cannot
forget to.

| What could survive                                                                                                                          | How the switch handles it                                                                                                                                                                                                                                                                                                                                               | Where                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Address: `page`, filters, sort, selected or open record in the query                                                                        | Replaced by the section's list root without a query (`/findings?page=5&...` -> `/findings`)                                                                                                                                                                                                                                                                             | `src/lib/org-switch-landing.ts`, `TenantEpochBoundary`                               |
| Address: a record id in the path (`/findings/<id>`, `/scans/<id>`)                                                                          | Replaced by the section's list root (`/findings`), or the dashboard when the section has no page of its own or the new organization does not grant it (`RouteGuard`)                                                                                                                                                                                                    | same, `src/components/route-guard.tsx`                                               |
| Component state (page number, rows, selection, open panel, form input)                                                                      | The whole tree under the boundary unmounts at once and mounts again under a key of the new epoch, after the address has landed                                                                                                                                                                                                                                          | `src/components/layout/tenant-epoch-boundary.tsx`                                    |
| SWR cache, SWR dedupe of a read in flight                                                                                                   | A fresh SWR cache per epoch (`SWRConfig provider`, keyed by the epoch); module code mutates through `@/lib/swr-mutate`, never SWR's global `mutate` (ESLint `no-restricted-imports`, `tenant-epoch.test.ts`)                                                                                                                                                            | `tenant-epoch-boundary.tsx`, `src/lib/swr-mutate.ts`                                 |
| A read in flight, a GET coalesced by URL, a primed view part                                                                                | Aborted (`TENANT_CHANGED`), the GET coalescing table and the primed views are dropped                                                                                                                                                                                                                                                                                   | `src/lib/tenant-epoch.ts` (`endTenantEpoch`), `TenantProvider`                       |
| WebSocket subscriptions                                                                                                                     | The socket provider is under the boundary: it closes and opens again under the new session                                                                                                                                                                                                                                                                              | `src/context/websocket-provider.tsx`                                                 |
| Browser storage (triage queue ids, list context, "back to app" address, last dashboard, drafts, recent queries, permission and logo caches) | Keyed by organization, or dropped on every switch; every file that touches storage is classified in `org-scoped-storage.test.ts`                                                                                                                                                                                                                                        | `src/lib/org-scoped-storage.ts`                                                      |
| The back button                                                                                                                             | Each address of the tab is remembered with the organization it was shown in (sessionStorage, addresses only); going back to one of another organization lands on its list root instead, also when the back button loads a new document                                                                                                                                  | `tenant-epoch.ts`, `TenantEpochBoundary`                                             |
| Another tab still showing the old organization                                                                                              | The switching tab tells the others (BroadcastChannel); a tab also checks the session cookie on focus, when it becomes visible and on a back/forward cache restore. The API client refuses to send any request while the cookie names another organization than the tab renders, and the tab resets the same way first, with the notice "Another tab switched to {name}" | `tenant-epoch.ts` (`tenantRequestSignal`), `src/lib/api/client.ts`, `TenantProvider` |

A link that names the new organization (`OrgLinkGate`) and the MCP consent page
keep their address: `switchTeam(id, { keepLocation: true })`. The tree still
mounts again with a fresh cache.

## Adding a page

Nothing to do for the switch. When the page has a dynamic segment
(`[id]`), add the route to `DYNAMIC_PAGE_ROUTES` (and, when a static page sits
beside it, `STATIC_BESIDE_DYNAMIC`); `org-switch-landing.test.ts` rebuilds
both lists from `src/app` and fails until they match. When the page keeps
something in browser storage, key it by organization or add the key to
`org-scoped-storage.ts`; `org-scoped-storage.test.ts` fails until the file is
classified.

## What the server still enforces

The client mechanism stops stale state from being shown or sent. It is not the
security boundary: the API derives the organization from the access token,
`POST /api/v1/auth/token` checks membership in the target organization and
rotates the refresh token, list and bulk endpoints constrain every id to that
organization in SQL, and a record of another organization answers 404 like an
unknown one. A stale tab or a replayed request therefore cannot read or change
another organization's data; the client side only makes sure the person never
sees or acts on a mixed view.

Tests: `src/lib/__tests__/{org-switch-landing,tenant-epoch,org-scoped-storage}.test.ts`,
`src/components/layout/__tests__/tenant-epoch-boundary.test.tsx`,
`src/context/__tests__/tenant-provider-epoch.test.tsx`,
`src/lib/api/__tests__/client-tenant-epoch.test.ts`, and the browser spec
`e2e/specs/56-organization-switch.spec.ts`.
