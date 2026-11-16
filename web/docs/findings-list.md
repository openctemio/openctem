# Findings list

How `/findings` behaves. The code is in `src/app/(dashboard)/findings/page.tsx`,
`src/features/findings/components/` (`finding-row-menu.tsx`, `finding-phone-card.tsx`) and the shared
`src/features/shared/components/data-table/`.

## Columns

- Priority, the title (a real link to `/findings/{id}`: a plain click opens the drawer, Ctrl/Cmd/Shift or a
  middle click opens the page in a new tab), Location (the asset), Severity, Signals and EPSS, Status and
  Due / SLA show by default in every view; Source and Created are under Display. Columns and their widths:
  select 40, Priority 76 (its header word and sort arrow in English and Vietnamese), title at least 280 (it
  takes the rest), Location 112 to 160, Severity 88, Signals and EPSS 140, Status 120, Due / SLA 112, Source
  130, Created 120, actions 48.
- Every row is one line, so rows are the table's density heights: 40, 32 compact, 52 comfortable. The
  title cell is the title then its id (the CVE, linked to its vulnerability page, else the rule id); the
  title gives way first and its whole text is the link's tooltip and name. Location is the asset name with
  its markers; the path or URL on the asset is in the name's tooltip and accessible name (the place itself
  when there is no asset name). Status is one line (a sub-status beside it gives way first). Due / SLA is
  the time left ("In 5 d") as plain text while on track and as a pill in the SLA colour when at risk or late
  ("3 d overdue"); the SLA state is in its name and tooltip, the state word shows when there is no
  deadline, and a shield marks a deadline the known-exploited cap shortened. The scanner is in the drawer.
  The drawer, opened by a click or tap on the row, shows everything a cell cuts.
- Column priority keeps the title at 280 or more: the table drops Severity below a 1,170 px frame (a 1496
  screen with the sidebar open), Signals and EPSS below 1,010 (1336) and Due / SLA below 850 (1176). Turning
  a dropped column on under Display shows it again while the list is open; the saved columns are not
  changed by the width.
- With no `sort` in the URL the list is in the server's order (priority first), and the Priority header
  says so (`aria-sort`). The footer counts "findings".

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

## More menu

The page has one overflow ("More") menu at a time.

- Wide, the view's title row ends with Refresh, Export and Task from filters and has no More. Copy link is in the page
  header's More under "This view", after Import results and Approvals.
- Narrow and on a phone, Export and Task from filters fold into the title row's More together with Copy link, and the
  page header's More does not repeat it. A header menu left with a single item merges into the title row's More.
- No menu opens with a single item: when one action is left and it has an icon, the More button becomes that action in
  the same place and size (the bulk bar's "Remediation task" is one). This is a rule of the shared action menu, so it
  holds on every list page.
- The exception is a lone destructive action (Delete, Remove, Revoke, Disable): it never becomes a bare button, so a
  row cannot be mis-tapped into it. It stays behind the More trigger, the one menu that may hold a single item, and
  the one-item console error does not fire for it. Where the row already has another direct action (Test on a
  control), that action joins the menu, so the row has one More with both.

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
  view" until one is picked. Each keeps one width per language whatever its value (sized by every value it can
  show, Practice by every practice; "Set by the view" is cut to that width with its full text in the
  tooltip), so picking a value moves nothing. On a narrow toolbar the key ("Practice:") folds away and stays
  in the accessible name. On a phone they move to the top of the Filters sheet. In Query mode they stay in place with Add filter, dimmed and inactive (the text owns the filter), so the switch moves nothing.
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
- The row is the shared `FilterChipsRow`, exactly one line of one height (32): the quiet locked chip for what
  the list leaves out (informational findings, drawn with the shared `LockedChip`, at most half the row) first,
  the chips (the ones that do not fit fold into "+N more", a popover listing them, each removable), and Reset to
  view or Clear filters pinned at the row's end. The count is said once, beside the view name in the first row,
  never on the chips row. The row shows only when it holds something: the list moves down once when it
  appears, and never again while filters change.
- Nothing in the list's header moves while it is used: Practice, State, Group and Views keep one width per
  language (a value or a view's own name is cut, in full in the tooltip and the accessible name; the
  unsaved-changes dot has its room kept), so the search field beside them takes one width per toolbar width
  (and holds it in Query mode), and Export and Task from filters stay in the title row while grouped. `e2e/specs/62-list-toolbar-stability`
  checks every toolbar and title-row box (0 px) through filters, grouping, views, the mode switch and typing on
  Findings, Assets and Scans at 1440, 1024, 768 and 390 px in both languages.
- On a phone every list toolbar (the shared `ListToolbar`) is two lines, never more: the search field alone on
  the first; on the second the filter tokens and the chips (the locked chip first) in a strip that scrolls
  sideways, with a fade on an edge that has more past it, and the icon actions (saved views, group, refresh)
  pinned at the end, all 36 tall on one centre line. Nothing folds into "+N more" and nothing wraps.

## Query mode

A Basic | Query switch is the first control of the toolbar row, its own control right before the search field
(a two-segment switch, 32 tall, of a fixed width per language on a toolbar of 64rem and more, as at 1440 px with
the sidebar; one code icon toggle below that, 32 px, 36 on a phone, where it sits before the joined Filters button;
which one shows follows the toolbar's width only; Ctrl+/ switches too). The field's end holds only its own controls (clear in
Basic; help, expand and run in Query), and the field holds its width when the mode switches (Query mode takes the
filter tokens away; the field does not grow into their room until the toolbar itself is resized), so switching
modes moves and resizes nothing: one field, two ways to write the same filter (`ListSearch` `query`, `useListQueryMode` in
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
- In Query mode the chips and Clear step aside (the context chips stay; Add filter and the base chips stay dimmed and inactive); in Basic mode an `fq`
  filter is one Advanced chip whose text opens Query mode.
- A saved view stores the search mode as the page param `mode=query`. Basic is the default, so a view saved in Basic
  mode sends no `page_params` at all (`savedViewBody` in `src/features/saved-views/api/use-saved-views.ts` is the one
  place that decides); a view without it opens in Basic. When a save fails, the Save view dialog stays open with the
  name kept and shows the reason.

## Request budget

A cold load of `/findings` sends at most 5 API requests: the session bootstrap, the support-access banner, one
stats response (the organization total, for the empty state), one quick-views response and the list. The source
catalog loads when the Source filter opens (or a source is already picked). Refresh sends each request once.
`e2e/request-budget.json` holds the number.
