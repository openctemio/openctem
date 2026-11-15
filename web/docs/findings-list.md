# Findings list

How `/findings` behaves. The code is in `src/app/(dashboard)/findings/page.tsx`,
`src/features/findings/components/` (`finding-row-menu.tsx`, `finding-phone-card.tsx`) and the shared
`src/features/shared/components/data-table/`.

## Selection

- A selection belongs to the rows on screen. Changing the page, the page size, the sort, the search, a
  filter, the view or the grouping clears it, so a bulk action never reaches a row the user cannot see. The
  flat table does this itself for page, page size and sort (`DataTable`), and the page adds the filters,
  search and view to `resetSelectionKey`.
- Phone cards carry the same action menu as a table row. The menu is one component (`FindingRowMenu`)
  used by both, so the two never offer different actions. A phone has no header checkbox, so selection is a
  mode: "Select" in the toolbar's More (the shared `DataTable` adds it wherever the list has bulk actions)
  shows a checkbox on every card and opens the bulk bar with nothing selected yet. The bar's count is a menu:
  "Select all on this page (25)", then "Select all N that match" (the same server-side change by filter as
  on a desktop, with the same limit note above 10,000) and "Clear selection". X or Escape ends select
  mode. On a phone the bar is a full-width bottom row of two lines (the count and X, then the actions), every
  control 36, and the page keeps room for it under the last card. Selecting a card is a separate control
  from opening it.
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

## Filters

The toolbar row reads: the search field, the two fixed scopes **Practice** and **State**, then **Add filter**
(shortcut `f`): an icon-only square at the toolbar's control height (the shared `AddFilterButton`). Every
active filter is a chip in the row under it. Code: `src/features/findings/filters/`.

- **Practice** ("Practice: Vulnerabilities", the default: every practice but compliance; Compliance, each
  other practice that holds findings, All) and **State** ("State: Open", the default; Fixed, Dispositioned,
  Closed, All) are base chips (`FindingsBaseChips`, the shared `FilterSelect` with `clearable={false}`): first
  after the search, never removed, no counts (the count shows once, beside the view name). They write the
  `practice` and `state` params. While an open saved view sets a scope itself, the chip reads "Set by the
  view" until one is picked. On a narrow toolbar the key ("Practice:") folds away and stays in the accessible
  name. On a phone they move to the top of the Filters sheet. In Query mode they step aside with Add filter.
- There is no Filters button from 1024px up: Add filter is the one filter entry, and its last row, **Show the
  filter panel**, opens the facet panel beside the list (closed from its own header). Below 1024px the Filters
  button opens the same facets in a sheet.
- Chips read as label and value ("Severity: Critical, High"); other operators keep their word ("Severity is
  not Low", "EPSS score ≥ 0.5").

- The page URL carries the API's own filter params (`severity`, `severity_not`, `epss_score_gte`...), so a
  filter is a URL param and a chip is a reading of one. The facet panel and Add filter write the same params.
- **Add filter** is generated from `GET /meta/filters/findings`: a searchable list grouped by Exploitation,
  Finding, Asset and Work (anything the web has no group for lands in Other), then an editor typed by the field:
  choices for an enum, an operator and a number, quick date ranges that look back for a seen date and ahead for
  a deadline, Yes or No, "is empty", a member picker for people. A field the API adds appears with no web change
  (its label falls back to the humanised field name until a translation is added).
- The contract names only the fields the viewer may use. The picker also hides the asset-derived fields (asset
  tag, criticality, group, owner) without `assets:read`. The API remains the authority.
- A filter the page does not draw itself goes to the API as it is. The contract is fetched only when the picker
  opens or the URL holds such a filter; a list that uses only page-owned filters loads with no extra request.
- Chips from the open saved view come first, show a lock and have no remove button: switch or edit the view.
  A view whose conditions are a tree (an `any` or a `not` below the top) shows one locked chip naming that.
  The picker disables a field the view already sets, because the server lets a request filter replace the
  view's own condition on that field.
- A param no field knows is shown as an unknown filter with a remove button and is kept out of the request. If
  the API refuses one (a 400 `INVALID_FILTER` naming the param) the list says "This link has a filter we do not
  know" and offers to remove it, instead of a failed load.
- Chip text is escaped, isolated text; a value from a link never becomes markup.
- The row is the shared `FilterChipsRow`: the quiet locked chip for what the list leaves out (informational
  findings, drawn with the shared `LockedChip`) first, the chips (the ones that do not fit fold into "+N
  more"), then Clear. The count is said once, beside the view name in the first row, never on the
  chips row. Nothing in the row shrinks under its content. The row shows only when it holds something.
- On a phone every list toolbar (the shared `ListToolbar`) is two lines, never more: the search field alone on
  the first; on the second the filter tokens and the chips (the locked chip first) in a strip that scrolls
  sideways, with a fade on an edge that has more past it, and the icon actions (saved views, group, refresh)
  pinned at the end, all 36 tall on one centre line. Nothing folds into "+N more" and nothing wraps.

## Query mode

The search field has a Basic | Query switch at its end (one code icon toggle on a phone; Ctrl+/ switches
too): one field, two ways to write the same filter (`ListSearch` `query`, `useListQueryMode` in
`features/query`). Assets and scans use the same field.

- Basic to Query shows the whole filter as text printed by the server (`POST /query/parse` with the page's
  params), the State lens and the Practice switch included as the list applies them (`state=open
practice!=compliance`). The client never builds query text itself.
- Enter applies a valid text and the field stays in Query mode: a filter chips can show is written back as the
  flat params (links keep their form), anything else as one `fq` text. The text owns the State lens and the
  Practice switch: what it leaves out is not restricted (`state=all`, `practice=all`), and a practice set the
  switch cannot show keeps the whole text as `fq`. A round trip without an edit changes nothing.
- Escape puts back the applied text. Switching to Basic with an edit not applied yet applies it first; a text
  the parser refuses keeps Query mode.
- A refused text shows one line under the field with the problem and its column, and the field selects the
  problem (it scrolls there). The list keeps the last valid result.
- In Query mode the chips, Add filter and Clear step aside (the context chips stay); in Basic mode an `fq`
  filter is one Advanced chip whose text opens Query mode.

## Request budget

A cold load of `/findings` sends at most 5 API requests: the session bootstrap, the support-access banner, one
stats response (the organization total, for the empty state), one quick-views response and the list. The source
catalog loads when the Source filter opens (or a source is already picked). Refresh sends each request once.
`e2e/request-budget.json` holds the number.
