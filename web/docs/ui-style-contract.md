# UI style contract

One way to build each kind of screen. Every page follows these rules; a
deviation needs a reason written next to it in code. The Findings page
(`src/app/(dashboard)/findings/page.tsx`) is the reference implementation of a
list page.

Decisions D14–D16 cover density, default sort, saved views, "Scroll all", the
batch-bar rule, server facets, honest dashboard tiles and the three empty-state
kinds.

## 1. Page anatomy

Every page, top to bottom:

1. **`<Main>`** — never a hand-rolled wrapper, never `overflow-*` overrides.
2. **`<PageHeader title description>`** — the only `<h1>` on the page.
   - Title: short noun ("Findings", "Scan profiles"), sentence case.
   - Description: one sentence saying what the page is for.
   - Actions (children): at most **one primary** button (`size="sm"`) plus up
     to **two** `variant="outline"` buttons. Anything more goes into a `⋯`
     "More" dropdown. Icon-only buttons need `aria-label` and a tooltip.
3. **Tabs** (only if the page has sub-views) — `<Tabs>` directly under the
   header with `className="mt-4"`. The default underline style is the only tab
   style: no `className` overrides that change its look (no grids, pills,
   backgrounds). Put the active tab in the URL (`?tab=`).
   - **Section tabs** — when the sub-views are separate routes (Remediation:
     Tasks | Solution families; Exposures: Overview | Vulnerabilities | …), use
     the shared `<SectionTabs>`, placed the same way: directly under the header
     with `className="mt-4"` (its own `mb-5` spaces the content), or
     `"mt-4 mb-0"` when the next block already carries `mt-5`. Define the list once in
     `src/config/section-tabs.ts` and pass it as the sidebar item's `sections`:
     the sidebar shows ONE row for the section (active on every tab's route), the
     command palette lists each tab. Never a third sidebar level for them.
4. **Sidebar**: the main sidebar collapses and its width can be resized
   (persisted per user, between 13rem and 20rem). Its links are the same in
   every organization. Settings and the admin console keep their own rail.
5. **Content blocks** separated by `mt-5` (or `space-y-5` / `gap-5`).

## 2. Headline numbers

- **List pages** (a table is the main content): one `<MetricStrip>` (2–6
  metrics) under the header/tabs. A metric that maps to a filter gets
  `onClick` + `active` and toggles that filter.
- **Overview / dashboard pages**: `<StatsCard>` in a grid. One variant only:
  label top-left, muted icon top-right, value, optional caption.
- Never: pastel icon tiles, coloured card borders, coloured icons before the
  label, card-in-card stat grids.
- A share of capacity (job slots in use, quota spent) is the shared `<Meter>`
  (`role="meter"`, a label saying what it measures), in a metric's `detail`,
  a `DetailStat` or a row. Not a hand-made bar.
- Every number on a dashboard opens the list it counts, with the same filter
  (not the unfiltered page).
- A number that cannot be computed shows "Not enough data" and what is
  missing, never 0 or a perfect score.
- No cross-customer or industry benchmarks: a self-hosted platform has no
  honest population to compare with. Compare with the tenant's own trend or
  target.
- Graph analytics (attack paths, exposure chains) lead with a ranked list of
  choke points (paths × critical assets); the graph is one click away.
- Colour a number only when it is a problem **and** greater than zero
  (`tone="danger"` / `text-destructive`). A zero is never coloured.

## 3. Lists and tables

- Use the shared `<DataTable>`. No hand-rolled `<Table>` for data lists.
- Do **not** wrap `<DataTable>` in a `<Card>` — it draws its own border.
- Toolbar: search on the left, secondary actions (refresh, export) on the right,
  via `toolbarStart` / `toolbarEnd`. Filters:
  - Facet values and counts come from the server for the current query.
    Dimensions list their top values with counts; measures (risk score,
    CVSS, EPSS, age) use a range slider. A value count is shown only when it
    is computed with every **other** active filter applied; otherwise show
    no count.
  - ≥ 3 filter dimensions → `<FacetFilterPanel>` in a floating sticky card
    (see Findings), toggled from the toolbar, closed by default.
  - 1–2 dimensions → dropdown buttons in the toolbar.
- **The Filters button is icon-only**, and there is exactly one:
  `FilterButton` from `@/features/shared` (`filter-button.tsx`). It is a
  square `size-9` outline button with the `ListFilter` icon, `aria-label` and
  tooltip "Filters", a count badge on its corner and a primary tint when
  filters are applied. Never a "[≡ Filters]" text button.
  - Facet panel (Findings layout): pass `filterToggle` (`open`, `onToggle`,
    `onOpenSheet`, `activeCount`, `controlsId`) to `<DataTable>`, or render
    `<FilterPanelToggle>` yourself when the toolbar is not a DataTable's. It
    toggles the side panel from `lg` up and opens the same panel below `lg`
    in `<FilterSheet>` (full width, close button on its own row, a "Show N
    results" footer). No other left-side sheet.
  - Popover / sheet / dialog of filters: put `<FilterButton activeCount={n} />`
    inside `<PopoverTrigger asChild>` (it forwards its ref and props).
  - The filter icons (`ListFilter`, `Filter`, `Funnel`, …) are imported only by
    `filter-button.tsx`. Dropdown filters and their select triggers carry no
    filter icon; label them with `aria-label="Filter by …"`.
  - Enforced by `src/features/shared/components/__tests__/filter-trigger-governance.test.ts`;
    a non-trigger use of a filter icon needs an allowlist entry with a reason.
- **Context filters** (a deep link's `asset_id`, `scan_id`, `cve_id`, `rule_id`:
  "View findings" from an asset or a scan run) are `<ContextFilterChips>` from
  `@/features/shared`, placed in `toolbarStart` after the search box, never as
  a row of their own above the table (that row pushed the table down when the
  page opened with the parameter). Each chip shows a human label (resolved
  through the tenant-scoped hook; a fixed-width placeholder while loading;
  "Unknown asset" on 404/403) and its X removes only its own parameter. Render
  the same chips in the page's loading skeleton, so they are there from the
  first frame. See `features/findings/components/finding-context-chips.tsx`.
- Filters, search, sort, page and page size live in the URL
  (`useUrlFilter` / `useUrlFilterList`).
- Server-paginated tables pass `sorting`/`onSortingChange`; columns the API
  cannot sort set `enableSorting: false`.
- The first column is the row's name; row actions are the last column with
  `id: 'actions'` (both are pinned automatically).
- **Density** (D14): `compact` (32px rows) or `comfortable` (40px). Single-line
  lists (findings, scans, sensors, single-line asset lists) default to
  compact; lists with multi-line rows (service rows, grouped cards on phones)
  use comfortable. The user switches it from the table's view menu; it is a
  per-user preference, not URL state.
- **Default sort**: every sortable table has exactly one column sorted by
  default, shown by its arrow. A newly clicked column sorts ascending;
  clicking it again toggles the direction.
- **Pagination**: page sizes 25 / 50 / 100. A list that can exceed 10k rows
  may offer **"Scroll all"** (D16), which virtualizes rows
  (`@tanstack/react-virtual` inside `DataTable`) over keyset (cursor) pages
  from the API. It ships only after the list's API has cursor pagination, and
  it never loads the whole set. The page-size view stays the default.
- **Bulk actions**: while rows are selected, the `BulkActionBar` is the only
  place to act on them. Row `⋯` menus are disabled, and the bar always has
  Clear (Escape works too). Bulk endpoints accept IDs or the list's filter.
- **Saved views** (D15): a view stores filter, sort, grouping, columns and
  density for one page, personal or shared with a team. A view never changes
  data. It is **not** a group: dynamic groups are scan and policy targets and
  live under Assets › Groups; views are lenses and live in the toolbar's view
  menu. The UI never offers one in place of the other.

### Grouped lists

A grouped view is the same list, organised under group headers. It is one
`<DataTable>` with `rowGroups`: each group is a full-width header row inside
the table, followed by its rows with the table's normal columns. Sensors
(group by zone / role / version) and Findings (group by CVE / asset / owner /
severity / source / component / type, and the verification queue) are the
reference implementations.

- **One table, never a card per group.** Rows keep their columns, sort,
  selection, row actions, the drawer and the bulk-action bar. A card per group
  shows a summary and hides the rows; at 1440px it fits four groups and no
  findings.
- **Group by is a toolbar select** (`Layers` icon, "No grouping" / "Group" as
  the first option) and lives in the URL (`?group=`). Not tabs.
- **The header row** (`renderHeader`): the group's name first (`font-medium`,
  foreground), then muted meta joined with `·` (type, owner, CVSS, counts).
  Summary counts go on the end (`renderActions`), compact: a status mix such
  as `3 open · 1 fixing · 0 applied · 2 resolved` with a dot coloured only when
  the number is above zero, and at most one mini bar (`% verified`). Hide the
  summary below `lg` before it wraps the name.
- **Group actions** (`renderActions`): `size="sm"` buttons at `h-7`, ghost for
  navigation (View), outline for a change (Mark fixed, Approve). Gate each on
  its permission **and** on the API being able to do it for that group type;
  hide it otherwise (no dead buttons). Two at most; more go in a `⋯` menu.
- **View is a drill-down, pushed onto the history.** It opens the flat list
  with every other filter kept and the group's filter added, through
  `pushUrlSearch` (not the `replaceState` filter writers), so Back returns to
  the grouped view. The URL records the origin (`from=group:<dimension>`) and
  the page shows a breadcrumb rebuilt from the URL alone
  (`DrillDownBreadcrumb`: "Findings › By rule › 10114", the value as
  untrusted text). The drilled filter is an ordinary context chip whose ✕
  removes only its parameter and ends the drill-down. Every group dimension
  needs a list filter, so View exists on all of them (Findings:
  `features/findings/lib/drilldown.ts`).
- **Selection** (`selectable`, with a `select` column): the header gets a
  checkbox that selects the group's rows on screen (indeterminate when some
  are). It feeds the same `BulkActionBar` as the flat list. Turn it on when
  the page has bulk actions.
- **Collapsible** (`collapsible`): a chevron before the name with
  `aria-expanded`. Collapse state is view state, not URL state.
- **Large or server-side groups:** paginate the **groups**, not the rows, and
  load a group's rows when it opens (`groups`, `expandedKeys`,
  `useLazyGroupRows`). Open the first few groups on arrival (Findings: 3),
  show the first 5 rows, then `Showing 5 of 22 · Show 20 more` in the group
  footer (`renderFooter`), up to the API's page cap, then `View all N in the
list`. Pagination says "groups" (`paginationNoun`, `pageSizeLabel`).
- **A dimension the list API cannot filter rows by** is a header-only group
  (no chevron, no requests), never an expandable group with the wrong rows.
  When the API might ignore a row filter, check the rows belong to the group
  and say "These findings open in the list" instead of showing others.
- **Small client lists** (a few hundred rows): group in the browser with
  `getKey` / `order`; the table pages through the rows group by group, so a
  group is not split across pages.
- **Semantics:** each group is its own `<tbody>` named by its header
  (`aria-labelledby`); the header content stays in view while a wide table
  scrolls sideways. Group headers are not sticky vertically (the table frame
  is the scroll container, see section 9).
- **Phone:** the same groups render as section headers between the row cards.

Do not: render groups as separate cards or separate tables, put a chart or a
progress card per group, colour a zero, repeat the group's own value in a
column of every row when it can be hidden, or fetch every group's rows on page
load.

## 4. Cards and sections

- shadcn `<Card>`. A section inside a card: `<CardHeader>` with `<CardTitle>`
  (sentence case) and optional `<CardDescription>`.
- No card inside a card. Group related numbers with a divider or a grid, not a
  nested card.
- Section headings outside cards: `text-base font-semibold`, sentence case.

## 5. Typography

- Sentence case everywhere. No UPPERCASE eyebrows or labels.
- `font-mono` only for identifiers and code: CVE / rule / plugin IDs, hashes,
  IPs, ports, file paths, URLs, API keys, code snippets. Never for numbers,
  labels, statuses or prose.
- Numbers that line up use `tabular-nums`.

## 6. Colour

- Theme tokens only (`bg-card`, `text-muted-foreground`, `border`,
  `text-destructive`, `bg-accent`, …). No palette literals (`text-amber-500`,
  `bg-blue-50`, `#ef4444`) for UI chrome — they break dark mode and the
  palette-drift gate rejects new ones.
- Status meaning has its own tokens, each with a dark-mode value:
  `success` (completed, passed), `warning` (pending, at risk, timed out),
  `info` (running, informational) and `destructive` (failed, errors). Use them
  as `text-success` or a tint such as `bg-warning/15 text-warning`.
- Errors that replace content use the shared `ErrorState` (a destructive
  `Alert` with Retry), never a hand-made red box.
- Severity: `SeverityBadge` / `src/lib/severity-colors.ts`. Criticality:
  `src/lib/criticality-colors.ts`. Charts: the chart colour sources.

## 7. States

- **Loading**: `<Skeleton>` shaped like the content it replaces. Spinners
  (`Loader2`) only inside buttons that are working.
- **Navigating**: no `loading.tsx` inside `(dashboard)` (a test enforces it).
  Each page renders its own skeleton; a route-level loading file only adds a
  second, differently shaped skeleton and makes React hold the page back for
  300 ms. Navigation links in the sidebar, settings rail and breadcrumbs carry
  `NavPendingHint` (`src/components/layout/sidebar-link.tsx`): after 120 ms
  without the next page, the clicked row shows a moving bar and the window a
  top progress bar. Sidebar links use `SidebarLink`, which prefetches on hover
  or focus rather than on render.
- **Empty**: the shared `<EmptyState>` (icon, title, why it is empty and the
  next step, optional primary action, optional secondary link such as docs).
  Three kinds, each worded for its case:
  - **no data yet** (first use): the setup action;
  - **no results** (filters active): "Clear filters";
  - **not enough data** (a metric cannot be computed): what is missing.
    Never a zero or a perfect score in its place.

  No ad-hoc "No X found" text.

- **Unknown facts** (a scanner fact nothing has collected yet: port, HTTP
  status, technologies, TLS, open ports, DNS records …). Never show a default
  as if it were data (no "200", no "TCP", no "valid"), and do not show the
  gap either where space is tight:

  | Where                     | A fact nothing collected                                                                                                                                                   | A known negative ("No TLS", "No open ports", "No technologies detected", a 4xx status) |
  | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
  | List, table, compact cell | Nothing. A cell left with no content shows one muted `—` (`EmptyCell`)                                                                                                     | Shown                                                                                  |
  | Drawer / detail page      | One muted line at the end of the facts: "Not collected yet: port, HTTP status, TLS certificate" (`NotCollectedNote`), only when something is missing. No per-row "Unknown" | Shown                                                                                  |
  | Filters and facets        | Keep the "Not collected" / "Unknown" value where the facet has one, so coverage gaps stay findable                                                                         | Its own value                                                                          |

  The shared service cells (`src/features/assets/components/service-cells/`)
  do this by default: each returns nothing for an unknown fact (`fallback`
  overrides it), `SurfaceFacts` shows the `—` for an all-unknown row, and
  `SurfaceFactsDetail` / a typed page's `notCollected` field option build the
  drawer line. A field the data cannot split into "not collected" and
  "collected, none" (DNS records: no records either way) stays "not
  collected". No dashed "unknown" chips.

- **Error**: `<Alert variant="destructive">` with what failed and a retry.
- Gated / coming-soon pages use the existing shared components.

## 8. Overlays

- Create / edit forms: `<Dialog>` (up to `sm:max-w-lg`; `sm:max-w-2xl` for
  long forms). Large editors: a full page.
- A dialog laid out edge to edge (split panes, a tinted aside, a scrolling
  body with a sticky footer): `<DialogContent showCloseButton={false}
className="flex flex-col gap-0 p-0 sm:p-0 …">` with a `<DialogHeaderBar>`
  (title, description, close) first, then the body. Pass
  `onOpenAutoFocus={(e) => focusDialogBody(e, bodyRef.current)}` (body has
  `tabIndex={-1}`) so it opens on the first field, not on the close button. The close button stays on
  the dialog surface, never on a tinted region; a secondary panel is inset
  (margin + radius), not bled to the edge. Install sensor and Edit sensor are
  the reference. Ordinary dialogs keep the default corner close button.
- Quick detail views: `<Sheet side="right">`. Read top to bottom as state →
  why → what it can do → what it did → identity, with the parts in
  `src/features/shared/components/detail-sheet.tsx`: a `<DetailCallout>`
  first when something is wrong (the problem in plain words, the fix as a
  button; nothing when all is well), a `<DetailStatGrid>` of 2–4
  `<DetailStat>`s (leave out a number the data does not have), then
  `<DetailSections>` (dividers, not cards) ending with identity and trivia
  (IDs, legacy fields) behind a "More details" disclosure. Header: at most one
  primary and one outline button; security and lifecycle actions (rotate key,
  disable, revoke, delete) go in the `⋯` menu. The sensor drawer is the
  reference.
  - The frame is shared too, in `detail-sheet-layout.tsx`: `<DetailSheet>`
    (right drawer from `md`, bottom sheet on phones, header pinned while the
    body scrolls, `width` token), `<DetailHeader>` (the title **wraps**, never
    truncates: it is often the only identifier; `badges` after it, `meta`
    parts joined with `·`, an `actions` row, a `menu` of items for `⋯`) and
    `<DetailTabs>` (underline tabs; `useDetailTab(param, values)` keeps the
    tab in the URL when the page wants it, with a parameter the page does not
    already use).
  - On phones `<DetailSheet>` is a Vaul drawer (`components/ui/drawer.tsx`):
    swipe down from the handle, the header or a body scrolled to its top to
    close; fields and the footer never start a drag; the Close button (44x44
    hit area) and Esc always work; no slide under reduced motion. Never give
    a sheet a swipe-only way out.
  - "View all …" / "Open full page" at the end of a sheet or tab: render
    `<DetailSheetFooter>` (from any component inside the sheet). It is pinned
    under the scrolling body with a top border and the sheet's padding, so it
    is always visible and last in the focus order. Never place such a button
    after the list inside the body.
  - Real checks only: `<DetailChecklist>` ("Health checks: N of M passing",
    folded, failing first) and the `<DetailCallout>` above it appear only
    when the record has such state. Never placeholder checks.
  - Chips of tools or packages: `<DetailChipList>`. Trivia at the end:
    `<DetailDisclosure summary="More details">`; the ID: `<DetailCopyId>`.
- Full detail pages (a record with its own URL): the main column answers
  what / why it matters / how to fix, and a sticky properties rail (`lg`, about
  19rem) holds the editable state and facts as label → value rows. Below `lg`
  the rail moves under the header with the trivia folded. The page names
  itself in the breadcrumb with `useBreadcrumbTitle`. Its drawer reuses the
  page's sections. The finding detail page is the reference
  (`docs/finding-detail.md`).
- Activity and comments, on every page and drawer: `<EntityActivity>` from
  `src/features/activity/` (`docs/ui/activity-panel.md`). The page shows a
  compact "Activity · N comments" summary; it opens the shared
  `ActivityPanel` sheet (feed, filter, composer pinned at the bottom). Never a
  full timeline inline, never an Activity tab, never a hand-rolled comment
  box. A page keeps the open state in the URL (`?activity=open`); a drawer
  keeps it in memory.
- Destructive confirmation: `<ConfirmDialog destructive>`.

## 9. Responsiveness

- Must work from 1000px wide with the sidebar expanded: nothing clipped, no
  page-level horizontal scroll (a wide table scrolls inside its own frame).
- Grids collapse: `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4` style, never a
  fixed column count without breakpoints.
