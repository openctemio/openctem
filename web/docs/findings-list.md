# Findings list

How `/findings` behaves. The code is in `src/app/(dashboard)/findings/page.tsx`,
`src/features/findings/components/` (`finding-row-menu.tsx`, `finding-phone-card.tsx`) and the shared
`src/features/shared/components/data-table/`.

## Selection

- A selection belongs to the rows on screen. Changing the page, the page size, the sort, the search, a
  filter, the view or the grouping clears it, so a bulk action never reaches a row the user cannot see. The
  flat table does this itself for page, page size and sort (`DataTable`), and the page adds the filters,
  search and view to `resetSelectionKey`.
- Phone cards carry the same checkbox and the same action menu as a table row. The menu is one component
  (`FindingRowMenu`) used by both, so the two never offer different actions. Selecting a card is a
  separate control from opening it.
- Bulk assign goes through the shared client `post()`, so a step-up challenge is answered by the
  re-authentication dialog and an error body becomes the message.
- A click anywhere on a row opens the finding drawer, except on the row's own controls.
- `j` and `k` open the next and previous finding while the drawer is open, and are listed in Help,
  Keyboard shortcuts.
- The row menu items that need the full flow (assign, change status, mark as false positive) say they open
  it ("Open to assign…").

## Empty and error states

The list is in exactly one of these, and each says what to do next
(`src/features/findings/lib/empty-kind.ts`, `findings-empty-state.tsx`):

| Kind        | When                                                            | Next action                                      |
| ----------- | --------------------------------------------------------------- | ------------------------------------------------ |
| Nothing yet | the organization has no findings and nothing narrows the list   | Import results, Set up a scan, Integrations      |
| No match    | filters, the search, a context scope or the state hide findings | Clear filters or search, Search all statuses     |
| No access   | the list read was refused (403)                                 | names the missing permission when the server did |

- The total comes from the scope-only stats. When it is unknown, the list never claims the organization is empty.
- A failed list is an inline alert in the table area with Retry and the server's request id (Copy request ID).
  The heading, search, filters and chips stay, and there is no toast on top of it.
- A refetch keeps the rows on screen with a thin progress bar above the table.
- Set up a scan and Integrations show only to someone who can open those pages (`scans:read`, `integrations:read`).

## Export

Export runs on the server only (`GET /api/v1/findings/export`, `src/features/findings/api/export-findings.ts`).

- Without `findings:export` there is no Export control. There is no client-side copy of the current page.
- The export carries the list's filters and sort (not the page). The API applies the caller's data scope.
- When the list total is above the `X-Export-Max-Rows` cap, the toast says how many findings were exported and
  asks to narrow the filters. The `/api/v1` proxy passes the export headers through.
- A 403 names the missing permission. A 429 says an export of yours is still running.

## Translation

Every string on the list, and in the shared table, facet panel, bulk bar, filter button, filter sheet and
saved-views menu, comes from `t()` with a key in the English and Vietnamese catalogs.
`src/features/findings/__tests__/list-i18n.test.ts` fails on a hard-coded string in those files or a key
missing from either catalog. Table columns carry a translated `meta.label`, so the View menu lists names, not ids.

## Quick views

The sidebar lists seven built-in views under Findings, each with a live count: Active, Needs triage, My queue,
SLA breached, Pending approval, Accepted · expiring, Closed. They replace the metric strip and the state tabs;
the dashboard owns the KPI tiles.

- The API defines the views (`GET /findings/quick-views`). Each view carries the exact `GET /findings` query
  string, so a view's count equals the total of the list it opens, in the viewer's own data scope. The web keeps
  no second definition (`src/features/findings/lib/quick-views.ts`).
- A view is a plain link: `/findings?<params>`. A view with no `state` of its own is opened with `state=all`,
  because the page's default is the Open lens and the count counted every state.
- A row is active when the URL is exactly that view (page, sort, search and grouping do not count).
- The views show, and their counts are requested, only on the list page. Other pages pay nothing.
- A zero count shows nothing. SLA breached is in the error colour when above zero. Awaiting verification, which
  was a metric card, is a button in the list's first row while something waits and the viewer can verify.
- The first row names the view and its total. A URL that is no quick view reads "Custom view".

## Request budget

A cold load of `/findings` sends at most 5 API requests: the session bootstrap, the support-access banner, one
stats response (the organization total, for the empty state), one quick-views response and the list. The source
catalog loads when the Source filter opens (or a source is already picked). Refresh sends each request once.
`e2e/request-budget.json` holds the number.
