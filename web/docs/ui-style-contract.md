# UI style contract

One way to build each kind of screen. Every page follows these rules; a
deviation needs a reason written next to it in code. The Findings page
(`src/app/(dashboard)/findings/page.tsx`) is the reference implementation of a
list page.

Decisions D14–D16 cover density, default sort, saved views, "Scroll all", the
batch-bar rule, server facets, honest dashboard tiles and the three empty-state
kinds.

## Sizes

The one place for the console's sizes. Values come from `src/styles/theme.css`;
`src/styles/__tests__/sizes-doc.test.ts` fails when a table here and the theme
disagree. Change both together.

### Control heights

| Context                                                               | Token                     | px  |
| --------------------------------------------------------------------- | ------------------------- | --- |
| App page: every control in a row (buttons, fields, selects)           | `--control-h`             | 32  |
| Small sizes (`sm`, `icon-sm`) inside a dense place (table, bulk bar)  | `--control-h-sm`          | 28  |
| Segment inside a 32 px track                                          | `--control-h-seg`         | 26  |
| Info icon (`xs`)                                                      | `--control-h-xs`          | 24  |
| Entry page without the app sidebar (sign-in, onboarding, invitations) | `--control-h-entry`       | 36  |
| Text field, select (= the row height)                                 | `--control-h-field`       | 32  |
| Below 768 px: buttons, fields, selects, search (as the live UI)       | `--control-h-touch`       | 36  |
| Below 768 px: small sizes (`sm`, `icon-sm`) inside a dense place      | `--control-h-touch-sm`    | 32  |
| Below 768 px: small sizes anywhere else (= the default)               | `--control-h-touch-dense` | 36  |
| Below 768 px: segment inside a 36 px track (`icon-seg`)               | `--control-h-touch-seg`   | 30  |
| Below 768 px: large (`lg`)                                            | `--control-h-touch-lg`    | 40  |
| Below 768 px: invisible touch target height of every button           | `--touch-target`          | 44  |

- Below 768 px buttons have compact content: text 13 px (`text-dense`), padding
  10 px (8 beside an icon), icon 16, gap 6. Fields keep 16 px text (`text-base`),
  so phones never zoom into a focused field; the viewport is never locked. The
  touch target is as wide as the button, so neighbours never share one.
  Icon-only buttons that stand alone in a row (the phone top bar, the drawer's
  Close sidebar, the organization panel's copy button) widen it to a 44 x 44
  square (`PHONE_TOUCH_SQUARE` in `components/layout/header-controls.ts`); in
  the phone bar they are 36 wide and 8 apart, so the squares meet but never
  overlap (`e2e/specs/58-phone-bar.spec.ts`).
- Every control in a row has one height and one centre line: a small size is
  smaller than the default only in a dense place (a table row, the bulk bar,
  `DensityScope`), where every control of the row is small. The page-rhythm
  probe (`probeRowMix` in `e2e/helpers/page-anatomy.ts`) measures each row of
  buttons, fields and selects on every page at 1440 and 390. The bulk bar is
  dense on a desktop only (`DensityScope touch="default"`): below 768 px it is
  a full-width bottom row of two lines with every control 36 (the count is a
  menu: select the page, select all that match, clear), and the page keeps
  room for it under the last row (`--bulk-bar-space`).
- Pages do not restyle kit controls: add a variant to the kit instead. Page
  and feature code (`src/app`, `src/features`, `console/src`) composes
  `Button`, `Input`, `SelectTrigger`, `ListSearch`, `TabsTrigger` and `Badge`
  with their sizes and variants, and never passes a height (`h-*`,
  `min-h-*`, `size-*`), a fixed width on an icon size, padding, a text size or
  a colour in `className`; layout (`w-full`, margins, `shrink-0`) is fine.
  `src/components/ui/__tests__/kit-restyle-ratchet.test.ts` counts today's
  overrides per file (`scripts/kit-restyle-debt.json`, `node
scripts/kit-restyle.mjs --files`); the count may only go down.
- Icon-only buttons are squares at every size (`icon`, `icon-sm`, `icon-seg`, `xs`, or
  `iconOnlyBelow` when the label shows only from a width up), in the tenant
  app and the platform console (`console/src`);
  `src/components/ui/__tests__/icon-button-guard.test.ts` and the page-rhythm
  probe enforce it.
- The platform console renders the same shell parts as the app: the top bar
  (`components/layout/app-header.tsx`, breadcrumb levels from its own
  navigation), the sidebar brand row, context row, nav rows and footer, the
  phone bar and drawer, and the skip link. Its right group is Full screen,
  Theme and the elevation control (`HEADER_ACTIONS_GROUP`).

### Top bar icons

| Context                                     | Class                    | px  |
| ------------------------------------------- | ------------------------ | --- |
| Header icon (32 px button), from 768 px     | `[&_svg]:size-4`         | 16  |
| Phone bar icon (36 px button), below 768 px | `max-md:[&_svg]:size-5!` | 20  |

- Classes from `HEADER_ICON_SIZE` in `components/layout/header-controls.ts`
  (the search trigger matches them); stroke 1.75; the avatar stays 32 / 36.
- At rest the header and phone bar icons are ink (`text-foreground`,
  `HEADER_ICON_COLOUR`) in both themes, not the muted colour; hover and an
  open menu add the hover background.
- Every icon-only control of the shell (header, phone bar, sidebar toggle,
  drawer close, sidebar and rail row icons) has a contrast of at least 4.5:1
  against its background at rest in both themes
  (`e2e/specs/57-header-right-group.spec.ts`, `e2e/specs/58-phone-bar.spec.ts`).

### Sidebar navigation

| Context                                                        | Token               | px  |
| -------------------------------------------------------------- | ------------------- | --- |
| Row: link, section header, pin, footer, settings rail, console | `--nav-row-h`       | 36  |
| A group's child row (section items, quick views)               | `--nav-sub-row-h`   | 32  |
| Phone drawer: every row, child rows included                   | `--nav-row-h-touch` | 44  |
| Row icon (expanded, icon rail, phone drawer)                   | `--nav-icon`        | 20  |
| Child row icon                                                 | `--nav-sub-icon`    | 16  |

- Navigation is not a dense place: the 32 / 16 control scale is for controls
  and tables, not for the sidebar (owner, 2026-11-15).
- One text style for every row, link or section header: 14/20 400 in
  `text-nav-fg` (ink 80% over the ground, as a colour), 16/24 in the phone
  drawer. Icons are muted (`text-muted-foreground`) at rest and ink on hover
  and on the current row. Only the current page differs: the filled row and
  weight 500. A folded section that holds the current page shows ink 500 on
  its header, since its filled child row is hidden. Chevrons are 16 px and
  muted.
- Rows touch (36 px is their own spacing). On the icon rail each row is a
  32 px square with 2 px above and below, so the rail keeps the 36 px rhythm
  and the icon stays at the same x (8 px column + 6 px row padding).
- Section label ("CTEM cycle"): 12/16 500 muted (`text-cap-m
text-muted-foreground`), 16 px above, 8 px below; folds away on the rail.
  Clusters without a label (before Insights) are split by a 36 px block with
  a hairline (`NavClusterDivider`), drawn in both states.
- Classes come from `components/layout/nav-classes.ts` and
  `components/ui/sidebar.tsx`; no page sets a nav row's size or colour.

### Type roles

| Role                              | Class              | Size/line | Weight | Below 768 px |
| --------------------------------- | ------------------ | --------- | ------ | ------------ |
| Caption                           | `text-cap`         | 12/16     | 400    | 12/16        |
| Chip, table header, count         | `text-cap-m`       | 12/16     | 500    | 12/16        |
| Mono (ids, code)                  | `text-code`        | 12/20     | 400    | 12/20        |
| Cells, rows, sidebar, breadcrumbs | `text-dense`       | 13/20     | 400    | 13/20        |
| Body, forms, buttons              | `text-body`        | 14/20     | 400    | 14/20        |
| Card title                        | `text-card-title`  | 14/20     | 600    | 14/20        |
| Section title                     | `text-section`     | 16/24     | 600    | 16/24        |
| Dialog title                      | `text-dialog`      | 20/28     | 600    | 20/28        |
| Page title                        | `text-page`        | 24/32     | 600    | 20/28        |
| Figure                            | `text-figure`      | 24/32     | 600    | 20/28        |
| Lead figure                       | `text-figure-lead` | 32/40     | 600    | 24/32        |
| Hero figure                       | `text-hero`        | 48/56     | 600    | 48/56        |
| Wallboard                         | `text-wall`        | 56/64     | 600    | 56/64        |

### Spacing

| Gap                                       | Token          | px  |
| ----------------------------------------- | -------------- | --- |
| Between page blocks                       | `--sp-page`    | 24  |
| Page header to its tabs; around a section | `--sp-section` | 16  |
| Scale step 1                              | `--sp-1`       | 4   |
| Scale step 2                              | `--sp-2`       | 8   |
| Scale step 3                              | `--sp-3`       | 12  |
| Scale step 4                              | `--sp-4`       | 16  |
| Scale step 6                              | `--sp-6`       | 24  |
| Scale step 8                              | `--sp-8`       | 32  |

### Row density

| Density                                    | Token                                       | px  |
| ------------------------------------------ | ------------------------------------------- | --- |
| Default                                    | `--row-h`                                   | 40  |
| Compact (`data-density="compact"`)         | `--row-h` in `[data-density='compact']`     | 32  |
| Comfortable (`data-density="comfortable"`) | `--row-h` in `[data-density='comfortable']` | 52  |
| Table header                               | `--th-h`                                    | 36  |
| Table header, compact                      | `--th-h` in `[data-density='compact']`      | 32  |

A table cell has no vertical padding: the row height and middle alignment place its content, so a row
measures its density height as long as its content is one line.

A table that scrolls sideways freezes its identifying columns at the start: the checkbox and the
columns marked `pin: 'start'` (else the first data column), within 45 % of the table's frame; a frozen
column without a fixed width keeps its floor and is capped at 420 px. The header cells freeze with the
body cells. A soft edge shows after the frozen group only while content is hidden under it. The row
actions column scrolls with the table as its last column (`pinActions` freezes it, off by default). A
frozen actions column is as wide as its widest action on the page (one line), never wider than its
declared width, and has no box while no row of the page has an action.

Before a table scrolls sideways its columns give way: a column with a range (`minWidth` below its
`width`, such as Location) narrows toward its floor, in proportion to its range (`fit-columns.ts`), and a
name column with a floor is sized by the floor and the room left, never by its text (a long title ends in
its ellipsis). Widths hold the cell padding, so the visible columns' widths add up to the table.
A second label beside the name in the same cell (an asset's type) is shown only when the cell has
room for both (the cell is a size container): at the floor the name gets the width, and the label moves
into the name's tooltip.

### Radii

| Role                      | Token             | px  |
| ------------------------- | ----------------- | --- |
| Small (chips inside text) | `--radius-sm`     | 4   |
| Controls, chips           | `--radius-md`     | 6   |
| Cards, menus              | `--radius-lg`     | 8   |
| Dialogs (open: 10 or 8)   | `--dialog-radius` | 8   |

### Popups

Menus, popovers, select lists, tooltips and date pickers keep 16 px from every
screen edge (`FLOATING_COLLISION_PADDING` in `src/components/ui/floating.ts`,
passed by every kit wrapper), at least the safe area, and 16 px above a fixed
bottom row such as the bulk bar. A popup lines up with its trigger's start
edge, and with the end edge only when the start would cross the screen gutter
or the edge of the drawer or dialog it was opened from; it slides inward when
neither fits, never to the edge. A menu is as wide as its content. Call sites do not set their own
`collisionPadding` or a fixed `align`; the one exception is a sheet opened from
the phone top bar (the account menu, notifications), which keeps the bar's
8 px. All rules: "Floating surfaces" in section 8.

### Decisions

| Date       | Decision                                                                                                                                                              | By                                                            |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| 2026-11-12 | Control scale 32 / 28, 36 on entry pages                                                                                                                              | Owner                                                         |
| 2026-11-13 | Text fields and selects share the row height (32), not 36                                                                                                             | Coordinator, under the owner's "do the best"                  |
| 2026-11-13 | Organization chip initials 12 px 600 (the 12 px floor holds)                                                                                                          | Design                                                        |
| 2026-11-13 | Phone heights = the live UI (36, small 32, large 40; fields 36 with 16 px text), compact button content, 44 px as an invisible touch target, icon-only buttons square | Owner, after viewing the preview and the live UI on his phone |
| 2026-11-15 | Popups keep 16 px from every screen edge (phone top-bar sheets keep the bar's 8 px, as the shell package set them)                                                    | Owner                                                         |
| 2026-11-15 | On a touch screen no popup focuses a text field on open (typing surfaces listed once); a picker sheet follows the visible viewport when the keyboard opens            | Owner                                                         |

## Entry pages

Pages without the app shell (sign-in, sign-up, password and e-mail links,
two-factor, organization choice, onboarding, invitations, application consent)
are built from `src/components/entry`, never from `Card` or a hand-rolled
wrapper:

- **`EntryFrame`** (the route group's layout): the brand, `<main>` in one
  column of `max-w-entry` (440px; `max-w-entry-wide`, 640px, for a page that
  lists things), then one footer line with the legal links that are
  configured, the "powered by" notice and the Language menu. It sets
  `data-control-scale="entry"`: every control is 36px.
- **`EntryCard`**: the surface (border, radius 8, padding 24, 14px between
  blocks). Below 640px the card is the screen: no border, no padding.
- **`EntryHeader`**: the page's only `<h1>` (`text-page`) and one muted line;
  `level={2}` for a second card or a step under a page title.
- **`EntryBanner`** (`info`, `ok`, `warn`, `danger`): ink on the status tint.
  `danger` and `warn` are `role="alert"`, `info` and `ok` are `role="status"`;
  a page passes `role` when the message must interrupt.
  Sign-in failures (a refused password, a locked or suspended account, the
  security check, a provider that could not start, an expired two-factor
  challenge) and the reason a session ended are one `EntryBanner` above the
  form: `role="alert"`, referenced by the form's `aria-describedby`, kept until
  the next attempt starts. Never a toast. The texts are the API code's message
  exactly as before; only where they are drawn is the entry page's.
- **`EntryDivider`**, **`EntryActions`** (stacked full-width, or `row` for a
  choice), **`EntryLine`** (centred secondary line), **`EntryNote`** (small
  print).
- One primary action per card, the teal fill (`<Button variant="signal">`):
  an entry page is one call to action. `signal` is for entry pages only; an
  app page's primary action stays the kit default (ink). Fields and buttons are the kit's and
  take no size, padding or text class from the page. Links are `TextLink`.
- Pages outside the `(auth)` group put themselves in the frame:
  `/invitations` (card width) and `/ownership-invitations` (`width="wide"`,
  the shared card with `surface="entry"`; My account keeps its own card).
  The account space hub `/welcome` keeps its account header and uses
  `EntryCard` + `EntryHeader level={2}` for its sections under the page's h1.
  The entry rows inside the app shell (`/activate`, the GitHub App setup
  page) keep `PageStack` with one `PageHeader` h1.
- Entry pages change how a flow looks, never what it does: no request,
  redirect, cookie, message text or autofill attribute changes with a restyle.

## 1. Page anatomy

Every page, top to bottom:

1. **`<Main>`** — never a hand-rolled wrapper, never `overflow-*` overrides.
2. **`<PageStack>`** holds every block of the page and owns every gap
   between them: 16px from the page header to its tabs, 24px between any two
   other blocks (header, tabs, banner, metric strip, list, card). Blocks carry
   no vertical margin (`mt-*`, `mb-*`, `space-y-*` between blocks); the stack
   zeroes any that remain. A block that renders `null` takes no gap; never wrap
   an optional block in an empty `<div>`. A tab panel or a component that
   renders several blocks returns its own `PageStack` (nested stacks keep the
   rhythm). `check-page-anatomy.sh` refuses a component that renders a
   `PageHeader` without a `PageStack`.
3. **`<PageHeader title description>`** — the only `<h1>` on the page.
   - Title: short noun ("Findings", "Scan profiles"), sentence case.
   - Description: one sentence saying what the page is for.
   - Actions (children): at most **one primary** button (`size="sm"`) plus up
     to **two** `variant="outline"` buttons. Anything more goes into a `⋯`
     "More" dropdown. Icon-only buttons need `aria-label` and a tooltip.
   - `titleAction`: one control on the title's own line, right after the title
     text and outside the h1, when the title itself is a choice (a chevron that
     switches between dashboards). Not a place for the page's actions.
4. **One tab row per page**, right under the header, no margins on it.
   - **Page tabs on a phone: one swipeable row with an edge fade, active tab kept in view** (owner 2026-11-21).
     The shared strip (`TabsList`, `SectionTabs`) never wraps onto lines and a page never adds its own wrap;
     it snaps, hides its scrollbar, and the layout check (spec 75) lets a strip marked `data-tab-strip`
     scroll while its fade shows. Toolbars, filters and action rows still may not scroll.
   - **Section tabs** when the sub-views are routes: the shared
     `<SectionTabs>` (or `<GatedSectionTabs>`), defined once in
     `src/config/section-tabs.ts` and passed as the sidebar item's `sections`
     (the sidebar shows ONE row for the section; the command palette lists
     each tab; never a third sidebar level).
   - **In-page tabs** (`<Tabs>`, underline style only, active tab in the URL)
     on detail pages, drawers and dialogs, or on a page without section tabs.
   - **Never a second tab row**, and never a segmented control under the tabs.
     A second level takes the form of what it is: a filter of the same rows
     is a filter token in the list toolbar (§3, list state); another view of
     the same rows is `ViewSwitcher` at the toolbar end; a sub-page is a route
     tab; work queues are a list of queues (Assets › Needs attention).
   - **Tab icons** are optional. When a strip has them: every tab has one or
     none does, each icon is a distinct lucide icon that says what the tab
     holds (no sparkles, wands, robots or brains), drawn by the strip at 16px
     with the default stroke in the tab's own text colour (muted, foreground
     when active), never coloured, filled or emoji; the label is always shown.
     Route tabs take the icon from `SectionTab.icon` only; in-page tab icons
     carry no `className`. A strip that mixes icons and none draws no icons.
   - **Tabs that do not fit** (a phone, a long section): `SectionTabs` drops
     the icons first, then moves the last tabs into a "More" menu at the end
     of the strip. The current tab is always one of the shown tabs; a label is
     never cut at the edge and the strip never scrolls sideways. In-page
     `<Tabs>` scroll with a fade on the hidden side and keep the active tab in
     full view: a tab under an edge's 2.5rem fade counts as hidden and is
     scrolled to the middle (at the ends, the strip stops at its edge).
5. **Sidebar**: the main sidebar collapses and its width can be resized
   (persisted per user, between 13rem and 20rem). Its links are the same in
   every organization. Settings and the admin console keep their own rail.

**Static reading pages** (legal documents, Open-source licenses) use the
frame in `src/components/static-page`. A page outside the app shell is one
`StaticPage`: the brand and Sign in on top, the sibling documents as route
tabs, the table of contents of the open document (beside the text from 768px,
above it below; it holds Print) and one `StaticArticle`, at most 720px wide:
the title is the page's only `<h1>` (`text-page`), each `StaticSection` an
`<h2>` (`text-section`) with its anchor, body text `text-body` on a 24px
line. Controls take the entry scale (36). A static page inside the app shell
keeps `Main` > `PageStack` > `PageHeader` and opens with a `StaticLead`
(16/24, at most 720px wide). The frame takes its words from the caller, so a
legal page stays server-rendered.

Checked in a browser on every route at 1440px and 390px by
`e2e/specs/31-page-rhythm.spec.ts` (gaps from bounding boxes, one tab row,
tab icons, strip rules, chips, empty pagination, name column width).

### Graph pages

Attack paths, Exposure chains and Exploration use `src/components/graph-page`:

- **Order**: the title row (`PageHeader`, with the Graph | List view switch and the page's primary action), one
  `GraphToolbar` (filters at the start; `GraphLegend`, `GraphNote` and other canvas actions at the end), then the
  graph in a `GraphFrame` that takes the rest of the window (never under 24rem, 30rem from 768 px). Cards that
  belong to the page (choke points, the score of a path) go under the graph, never beside it.
- **Detail**: the detail of a node opens over the page in `GraphNodeSheet` (click, or Enter on the focused
  node). Its `action` (the node's main way on, e.g. "View findings") is the first thing in it and has focus,
  so Enter twice follows it. Esc closes it and focus returns to the node. No panel stands beside a graph.
- **Keyboard and screen readers**: the canvas is one tab stop, the arrow keys follow the edges, and every page
  keeps the same content as a list or table (the List view, the default below 768 px).
- **Legend**: every mark drawn on the graph is in the legend; a legend never lists a mark the graph does not draw.

The scan workflow editor keeps its own editing layout (palette and step settings beside the canvas).

### Detail pages

A record's own page (a finding, an asset, a scan) is built from the detail
kit in `src/features/shared/components/detail/`; `/findings/[id]` is the
reference.

1. **`DetailPageHeader`** is the page's `page-header` block and its only
   `<h1>`. Above the title: the record's type and identifiers as chips, and
   `DetailPosition` ("2 of 27" with previous and next) when the record was
   opened from a list. Beside the title: `[More] [secondary] [primary]`, one
   primary action for the record's current state, at most two outline
   buttons, everything else in the More menu (`ActionMenu` entries, a sheet
   on a phone). Below 768 px the first line is the way back to the parent
   list ("‹ Findings") with the position at its end, the primary action
   leads the action row and takes the free width, and More closes it; a
   More with no buttons stays at the end of the title's line. The chips
   wrap onto lines and are never cut by the screen. Status, owner and dates
   are never in the header.
2. **In-page `<Tabs>`** right under the header, the active tab in the URL,
   counts in `TabsCount`.
3. **`PropertyList`** holds the record's properties: `PropertyGroup`s of
   `PropertyRow` label and value pairs (a `dl`), separated by a rule, no
   card. The value takes text, links, chips or a control (a status or
   assignee picker). The list follows its own width: one column in a rail,
   two columns when it sits under the header on a narrower page. Below
   768 px every row is a 44 px line with the value at its end (a 36 px
   control in it keeps the line at 44 px), and
   `PropertyFold` keeps the rows after the first group one tap away. A row
   with an empty value renders nothing.
   Read-only facts inside a panel (a source record, a score table) keep
   `KeyValueList` from `text-layout`; `PropertyList` is for the record's own
   properties, where a value can be a control.
4. **`DetailSectionList` / `DetailSectionBlock`** are the blocks of a tab
   panel: a section named by its `<h2>` (`text-section`), an optional count
   and mark after the title, controls at the end of the title row, one rule
   between blocks. The same title row heads a table or list inside the
   panel. `DetailFold` is a closed-by-default line ("Show output", "How
   this was scored") with a short note saying what it holds.
5. A detail opens over its list as a drawer (`DetailSheet`); a page never
   keeps a permanent side panel beside a list. The drawer and the page
   render the same section components.
6. Text that came from a scanner or a target is rendered by
   `UntrustedTextBlock` / `ScannerText`; a masked value keeps its Show
   control (permission, step-up, timed, audited) and is never removed.
   Anything an AI produced or changed carries `AIBadge`.

## 2. Headline numbers

- **One `<MetricStrip>`** per page, at most **5** tiles, and only where every
  tile is a link to the list it counts (`href`, overview pages) or a one-click
  filter of the list below (`onClick` + `active`, list pages). Never for facts
  (use `PropertyList`), configuration inventories, or inside a card.
- States that are usually zero or rarely acted on (canceled, blocked, timed
  out) are not tiles: they stay values of the list's status filter.
- A zero is a muted `0`, never hidden; an error is `—` with the reason as the
  tooltip; red or amber only for a positive count of a problem state.
- No corner icons, no default trend arrows, no `StatsCard` tile walls.
- **Phone**: compact tiles on a six-track grid, at most two rows (2 and 4
  tiles in halves, 3 in thirds, 5 as three thirds over two halves), a long
  label wraps to a second line; never a sideways scroll.
- **List first on a phone**: a strip above a list takes `listFirst`, so on a
  phone it follows the list (CSS order, nothing moves after hydration) and the
  first row starts within the top 45% of a 390x844 screen. A list page's
  description under the title is hidden on a phone for the same reason.
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
  - Joined to the search field (`ListSearch` `filter`): the join follows what is
    drawn at that width. A trigger hidden by a breakpoint leaves the field with
    four round corners; a drawn one squares only the two inner corners.
  - One filter entry per width on a list with Add filter (findings, assets):
    from 768 `AddFilterButton` is a separate square right after the search
    field, before the value tokens (Practice, State): it never changes size,
    so they never move it; its picker opens under it. Below 768 the Filters
    button joined to the field (`FilterPanelToggle sheetOnly`) is the entry and
    Add filter does not show. `f` opens Add filter: the picker calls
    `useAddFilterShortcut(onOpen, enabled)` (off in a field, a menu or a
    dialog, with a modifier key, under a modal and in Query mode).
  - Active filters show in `FilterChipsRow`; pass `onClearAll` while two or more
    can be removed and the row draws "Clear filters" after its chips, the same
    on every list. On a phone the chips wrap onto as many lines as they need (no
    sideways scroll, no "+N more": no chip is hidden) and a leading chip wider
    than the row shortens its text.
  - A list whose search takes query text has a status row, owned by
    `ListToolbar` (`data-slot="list-toolbar-status"`, handed to the field as
    `ListSearchStatusSlot`): the field says what is wrong with a refused text
    there, never in the toolbar row, so the toolbar row keeps its height in
    every state of the text. The row takes room only while there is a problem:
    one line of the chips row's height (32, 36 on a phone), on the chips row's
    line when one shows (the list does not move), a row of its own otherwise
    (the list moves by the row and its 8 px gap, as for the first chip), the
    last line on a phone. The text is cut on that line (in full in its title);
    its fix buttons keep their size. A page never draws this line itself.
  - The suggestions of a query field are as wide as the field from 768 px
    (28rem at most). Below 768 px they span the screen from gutter to gutter
    (the field shares its line with the mode toggle and the Filters button),
    under the field or above it when there is no room, about eight one-line
    rows; a field inside a dialog, sheet or popover keeps the field's width so
    the list stays inside it.
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
- **List state** (status, kind, direction of the rows: Pending / Approved /
  Rejected, Active / Resolved) is a **filter**, never a tab row and never a
  segmented control:
  - on a list with the Add-filter registry (findings, assets) it is one of
    its chips;
  - elsewhere it is `<FilterSelect>` from `@/features/shared` at the start of
    `toolbarStart`: a token that reads "Status: Pending", opens a menu of every
    value with its count (counted in the viewer's scope), can be cleared to
    all rows, and keeps its value in the URL (`useUrlFilter`, the page's
    default value when the parameter is absent); the room of its clear button
    is kept while nothing is chosen, so choosing a value never changes the
    token's width;
    its trigger and its clear button are the full height of the token, border
    included (36 px on a phone, 32 px from 768px), so neither is a smaller hit
    area than the controls beside it; the clear button is icon-only, so it is a
    square of that height (`aspect-square`), like every icon-only button;
    with `foldLabel` the key ("State:") folds away on a narrow toolbar and a
    select with nothing chosen then reads its key ("State") instead of "All"
    (its accessible name stays "State: All"), so two selects never both read
    "All";
  - an on/off filter ("Primary assets", "Internet-facing only") is
    `<FilterToggle>` from `@/features/shared` in `toolbarStart`: a token of the
    toolbar's height with `aria-pressed`, filled while on, one box in both
    states (Button variant `toggle`: the border stays, so turning it on moves
    nothing), an optional `shortLabel` for a phone and `disabledReason`; never
    a `Switch` with a label, and never a Button that swaps `outline` for
    `secondary` (they differ by the border);
  - common combinations are saved views or sidebar quick views;
  - `ViewSwitcher` (or a segmented control) is only for the view mode of the
    same rows (table, board, analytics) at the end of the toolbar.
  - on a phone (a toolbar under 28rem) the list comes first and no control
    sits unseen behind a sideways scroll: the filter tokens are not drawn in
    the toolbar. One Filters button (`FilterButton`, its count the tokens that
    filter: a `FilterSelect` with a chosen value, a pressed on/off token) holds
    them, joined to the search, or alone at the start of the first line on a
    list without a search. On a list with a facet panel it is the panel's
    sheet button and the tokens show at the top of that sheet
    (`FilterSheet`'s token host); otherwise `ListToolbar` draws the button and
    a sheet of the tokens itself. The tokens that filter stay drawn on the
    second line and wrap onto lines (never a strip that scrolls), so every
    filter in force is seen and cleared in place; the chips row follows them.
    The end actions (Views, Group, Export, Refresh) end the first line and the
    search keeps at least 12rem. A line that draws nothing takes no room.
    Every line starts with its content, left to right: no list shows a line
    holding only Views, or tokens pushed to the end of an empty line.
    Wrapped tokens rather than a sheet were weighed and refused: a list with
    three or four tokens then opens with three toolbar lines above its first
    card (#4193 keeps a phone toolbar to two), and the design board's phone
    lists show a Filters button with its count beside the search.
  - Owner decision 2026-11-20: on a phone no control stands alone on a list's
    title row, the list's "..." menu included. Refresh and the "..." menu are
    end actions of the toolbar (`toolbarEnd`); when a list has both, Refresh
    goes into the "..." menu. Desktop keeps the title-row placement. The layout
    check (spec 75) flags a lone control on the phone title row, a "..." menu
    included, with no exemption. A list that refreshes on its own needs no Refresh. A labelled end action (Export CSV) is `<ToolbarAction>` from
    `@/features/shared`, labelled from a 42rem toolbar and a named icon with a
    tooltip below it, so it fits beside the search.
    In Query mode on a phone the field takes the whole first line (its text
    keeps at least 55 % of the field at 375 px): the end actions step down to
    the second line's end and the tokens, inert in that mode, are not drawn.
  - a toolbar group that draws none of its controls at this width (the
    Display menu on a phone, tokens moved into the Filters sheet) takes no
    line: `ListToolbar` marks it `data-empty` and takes it out of the flow, so
    the first chip opens its own line (the list moves 44 px: the row and its
    gap) instead of sitting on a line an empty group already opened.
    An icon counts as drawn by its own box (an icon-only Add filter is not
    empty), and with the tokens out of the flow the chips get the whole second
    line; the end group stays at the end of the search's line before and
    after the first chip and in Query mode.
- Filters, search, sort, page and page size live in the URL
  (`useUrlFilter` / `useUrlFilterList`).
- **An empty list shows its empty state only**: no "Showing 0 - 0 of 0", no
  "Page 1 of 0". `DataTable` hides its footer at zero rows; a hand-built pager
  does the same, and never shows a page count below 1. It also draws no
  column headers and no select-all box at zero rows (empty or failed list);
  the headers stay while the list loads.
- **An automatic phone card is compact.** A table without `mobileRow` draws
  short lines of 20 px each, whatever its cells draw (one line, cut with an
  ellipsis); only the title may take two:
  - the title line: the row's name (the column of kind `name`, else the first
    column; never guessed from the values), up to two lines whatever width the
    table cell set for itself, then the status chip (the first column of kind
    `status` or `status-edit` the table keeps at every width, i.e. without
    `hideBelow`; else the first one), the row's checkbox and its row menu. Nothing
    wraps under the title: a status cell too wide for its place gets a line of
    its own under the title, and an actions cell wider than one icon button
    gets one trailing line at the end of the card;
  - one muted subtitle line: the first other column the page marked `asset`,
    `owner`, `id` or `text` (an unmarked column is never the subtitle); kept
    empty at its height on a row where it says nothing or repeats the title;
  - one line of at most two label/value fields: the first other columns that
    say something. A value that draws nothing or only a dash, or repeats the
    title, is left out (never a label over an empty value), so a later column
    takes its place. "0" is a value and stays; a switch is a value too.
    Key figures (columns of kind `number`, `risk`, `severity`, `priority`,
    `due`) take the two places before the other columns, so a count such as
    "Findings 0" is never pushed out by a descriptive column before it; the
    fields are still shown in column order.
    A chip value (a badge, chip or tag) is never cut: a field whose chip does
    not fit half the line takes the whole line, and the other field goes on
    the line under it.
    A list whose card needs more than that passes its own `mobileRow`. Such a
    card keeps the same rule for its title: the name shares its line only
    with the checkbox, a small mark and the row menu; a state with words
    ("Waiting for a sensor") goes on the line under the name, so the name is
    never squeezed into a narrow column beside it (`scan-mobile-card.tsx`).
- **A list drawn as cards (below 768px) has no numbered pager.** `DataTable`
  draws the footer itself (`data-table/phone-more-footer.tsx`): a full-width
  outline "Show 25 more" button (36) and a muted line "50 of 418" ("50 shown"
  without a known total). The button grows the page size by one step of 25
  through the list's own `onPaginationChange`, so the URL keeps `per_page`,
  the cards on screen do not move and the first new card takes the focus. A
  server-paged list stops at 100, the largest page the API returns, with a
  line that says to narrow the filters; a list paged in the browser has no
  cap. The page supplies nothing: its size check accepts the steps
  (`isPhonePageSize` in `lib/page-size-options.ts`, already in
  `useListParams`), and the desktop keeps Rows per page 25 / 50 / 100. A
  list with one fixed size (`pageSizeOptions` of one) keeps the pager.
- **A switch is a value on a phone card.** A field of the automatic phone card
  whose cell is only a switch (an "Enabled" column) reads "On" or "Off"
  beside it, kept in step with the switch, so no card shows a label over a
  bare control. The switch keeps its own name and state for a screen reader.
- Server-paginated tables pass `sorting`/`onSortingChange`; columns the API
  cannot sort set `enableSorting: false`.
- **Display > Columns names a column as its header reads**: `meta.label`, a
  string header, or the `title` of `DataTableColumnHeader`, in the page's
  language; never the column id. The phone card's field labels use the same
  name. A column with no header and no label (the row menu) is not listed.
- The first column is the row's name; row actions are the last column with
  `id: 'actions'` (both are pinned automatically).
- **The row's name is `RowNameLink`** where the row has a detail page: a real
  link built by a route builder or `safeHref`. A plain click opens the detail
  overlay; a modified click (Ctrl, Cmd, Shift, Alt), a middle click and "Open
  in new tab" follow the link.
- **Column kinds** (`meta.kind`, `KIND_LAYOUT` in `data-table/column-meta.ts`)
  set a column's alignment, width and first sort direction; a page overrides a
  width only for a measured reason:

  | Kind              | Align  | Width (px) | First sort |
  | ----------------- | ------ | ---------- | ---------- |
  | `name`            | start  | up to 520  | asc        |
  | `id`              | start  | 120        | asc        |
  | `priority`        | start  | 72         | desc       |
  | `risk`            | start  | 148        | desc       |
  | `severity`        | start  | 96         | desc       |
  | `status`          | start  | 128        | asc        |
  | `status-edit`     | start  | 140        | asc        |
  | `asset`           | start  | 200 to 280 | asc        |
  | `owner`           | start  | 160        | asc        |
  | `datetime-recent` | end    | 104        | desc       |
  | `date`            | end    | 112        | desc       |
  | `due`             | start  | 140        | asc        |
  | `number`          | end    | 72 to 96   | desc       |
  | `signals`         | start  | 140        | desc       |
  | `tags`            | start  | 160 to 240 | asc        |
  | `masked`          | start  | 200        | asc        |
  | `select`          | center | 40         | asc        |
  | `actions`         | center | 48         | asc        |
  | `decisions`       | end    | from page  | asc        |
  | `text`            | start  | by content | asc        |

  `decisions` is a queue's last column of decision buttons (Approve, Reject,
  More): end-aligned, as wide as the page's `width` says its buttons need.
  Any last column of labelled buttons (Cancel, Block, Check) is a `decisions`
  column, without `width` it is as wide as its buttons: the 48 px `actions`
  column holds the row menu or one icon button only, and cuts a labelled
  button at the frame's edge (`actions-column-buttons.test.ts`).

  `risk` holds the risk score badge: 148 fits its longest text ("Not yet
  scored") in both languages.

- **Column priority**: a column that may drop on a narrow screen sets
  `meta: { hideBelow: <table frame width in px> }`; `DataTable` hides it below
  that width instead of scrolling the table sideways. Set it from measured
  widths, as a running sum in the order columns should join (the asset list's
  `COLUMN_ROOM`), the checkbox and row actions columns included: with the
  default columns the row menu is whole inside the frame at scroll 0. A
  column the viewer turns on or off under Columns keeps that choice.
- **A chip is never cut by an ellipsis**: a column holding a chip is as wide
  as the chip's longest standard text in English and Vietnamese, or the chip
  has a defined short form (the Due / SLA chip counts to "999+").
- **One-line chip rows fold, never cut**: chips in a row that must stay on
  one line are whole or folded into a "+N" popover that lists them all.
  Fold by measured width with `useFitCount` (`foldToFit` is the shared rule,
  used by `FilterChipsRow` too); no chip shrinks or is clipped by its cell.
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
- **The header row** is one cell spanning every column, laid out as one
  wrapping line of three slots, never positioned over the columns:
  - identity (`renderHeader`): the group's name first (`font-medium`,
    foreground), then muted meta joined with commas (type, owner, CVSS,
    counts);
  - summary (`renderSummary`): a compact status mix such as `3 open`,
    `1 fixing`, `0 applied`, `2 resolved` as separate items with a dot
    coloured only when the number is above zero, and at most one mini bar
    (`% verified`);
  - actions (`renderActions`): buttons only, in their own slot that never
    shrinks, aligned to the end.

  When the header is too narrow for one line, the summary and then the
  actions move to the next line; nothing overflows the frame (an overflowing
  header widens the table and slides its buttons under the pinned row-actions
  column).

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

### Queues

A queue is a list where a person decides on requests (approvals, scoping decisions, access requests, review
queues). It is a list in everything a list has (title row with the view name and its one count, said once: when
the selected tab already shows the view's name and number, the row passes `titleHidden` and no count; toolbar,
`DataTable`, pager, phone cards, states) plus the queue add-on in `src/features/shared/components/queue`
(exported from `@/features/shared`; the platform console's queues use it too), which every queue uses
and no page rebuilds:

- **Decision controls** (`QueueDecisionActions`): at most two direct decisions (Approve and Reject, or the
  page's own labels) and one More for everything else, in the row's last column and on the phone card. Each
  button is announced by its own visible label and the item ("Approve {name}", "Merge {name}"); a page passes a
  whole accessible name where that does not read well ("Keep {name} separate"). A decision that asks the user to
  confirm their sign-in passes `stepUpHint`: the button carries a lock and the sentence on hover, on focus and as its
  description. Every place that decides the same request uses these controls (the approvals inbox, My Work, the
  finding page) with the same dialogs; there is no second decision component. Without the permission there is no decision control. New decisions and bulk decisions
  are not added by a page: they need their own design with gates, confirm and audit.
- **Four eyes**: nobody decides a request they made. The decision controls are absent and "Your request"
  stands in their place, with the reason on hover and focus in a table row and written out on a card. The
  server is the authority; the list only says so.
- **Reason dialog** (`QueueReasonDialog`): Reject, and any decision the queue asks a reason for. It shows
  what is decided, one required reason field with its length, and keeps the typed reason when the save fails.
- **Decide by** (`QueueDecideBy`): a calendar date (the exact time on hover); once it has passed, "Overdue"
  with the date in the danger tone. A closed request shows a dash.
- **Confirm and step-up** stay where the flow has them (a destructive confirm on Cancel request, a
  confirmation before a reminder, re-authentication on Approve). An undo toast only where the server can undo.
- **Announcements** (`useQueueAnnouncer`): every outcome (decided, refused, reminded, canceled) is written to
  one polite status region, beside the toast.
- **Empty** (`QueueEmpty`): first run (the queue never held a request), nothing waiting (decided requests
  exist; offers the way to them), no match (the lens left no row).
- **Phone** (`QueueCard`): a phone card of the list kit, balanced on both sides, with no line that holds
  one control alone:
  - the title line: the item's name (two lines at most) with its state chip at the end (`state`: Pending,
    the severity of a finding that waits to close);
  - the reason or evidence, two lines at most;
  - one line of key facts (`meta`: what is asked, by when, who asked; the last item gives way with an
    ellipsis) with the decision at its end: `QueueDecisionActions layout="compact"`, one main action (Approve,
    with its icon) and More, whose first item is the second decision (Reject). "Your request" reads as in a
    row. Where nothing can be decided (no permission, a decided request) a chevron to the item (`href`) holds
    the end instead, a pointer target only (the title is the link for the keyboard).
  - The title row of a queue whose tab already shows its name and count passes `titleHidden` and no count;
    with nothing else to draw it takes no room (the heading stays for assistive technology), and Refresh goes
    to the toolbar's end (`toolbarEnd`), never a line of its own.
  - `e2e/specs/75-layout-breaks.spec.ts` (`lopsided`) fails a phone card whose content stops short of its end
    and a title row line whose start is empty.
- A column whose value is the same on every row of the current lens (Status under Pending) is left out on
  that lens. Anything an AI proposed keeps its AI mark in the row, on the card and in the dialogs.

## 4. Cards and sections

- shadcn `<Card>`. A section inside a card: `<CardHeader>` with `<CardTitle>`
  (sentence case) and optional `<CardDescription>`.
- No card inside a card. Group related numbers with a divider or a grid, not a
  nested card.
- Section headings outside cards: `text-base font-semibold`, sentence case.

### Settings pages

Every settings page is built from the same parts (`@/features/shared`):

- **`SettingsPage`** is the frame: `Main`, `PageStack`, the `PageHeader` (the
  only h1; the phone bar repeats it once it scrolls away) and one column of
  sections at a reading width (`--settings-col`, class `max-w-settings`),
  16px apart. It also draws the three states every page shares: `state="loading"`
  (header and skeleton rows), `state="error"` (the failure with Retry; saved
  values are never replaced by defaults) and `readOnly` (the "View only"
  notice; the page disables its own controls). A settings page that is a list
  passes `wide` and uses the list kit unchanged. The header shares the column:
  on a form page it is as wide as the form (its actions end where the form
  ends), on a `wide` list page both use the full width.
- **`SettingsSection framed`** is a section: no card and no fill, a hairline
  above every section but the first, the title (`text-section`), one line of
  description, an optional quiet `meta` note ("Last changed by ...") and
  actions. The title keeps a 12rem basis, so a chevron, a switch or one short
  button stays on the title line of a phone; only actions that do not fit
  (two long buttons) wrap under it. Its children draw their own dividers:
  - `SettingsRow`: one setting per line, label and hint at the start, the
    control at the end. Below 45rem a switch or a short button stays at the
    end of the label's first line (the text keeps a 13rem basis); a control
    that does not fit beside it, and a `wide` control (a text field or
    select), goes under the text. `SettingsSwitchRow`
    is the row of an on / off setting: the label names the switch, the hint
    describes it.
  - `SettingsBlock` with `SettingsFieldGrid` and `SettingsField`: fields with
    the label above, as many columns as fit. `SettingsField` ties the label,
    the hint and the error to the control (`aria-describedby`,
    `aria-invalid`); an error is `role="alert"` text under the field.
- **Fields** are the kit's at the kit's sizes (32px; 36px with 16px text
  below 768px). A picker with a popover of its own (the time zone search)
  draws its trigger with `SELECT_TRIGGER_CLASS`, the select field's look. A secret the user types is a `SecretField` (masked, Show
  value / Hide value; a stored secret is never read back). A secret the
  server shows once is a `OneTimeSecretField` (masked, reveal, copy).
- **`SettingsSaveBar`** is the one save of a page: shown only while there are
  unsaved changes, pinned to the bottom of the column (a full-width bottom bar
  below 768px), with the count of changed settings, "What changes", a failed
  save said in the bar, Discard and Save (Ctrl/Cmd+S). Leaving with unsaved
  changes asks first. Never a save button per field. A setting that applies
  the moment it is switched does not use the bar: it says that it applies at
  once and confirms when it loosens protection.
- **`DangerZone`** is the last section, with one `DangerZoneItem` row per
  action: a ghost button with a destructive icon, a destructive
  `ConfirmDialog`, `typeToConfirm` for what cannot be undone. The red is on
  the action, not on a frame.

### Dashboard widgets

- Every dashboard widget renders in `WidgetFrame`
  (`src/components/dashboard-kit/widget-frame.tsx`): the metric name, one
  menu, the state body or the figures, and the freshness line (only when the
  figures are stale or their time differs from the page's).
- **One menu per widget**, the shared `ActionMenu` (an anchored menu, or a
  bottom sheet on a phone without room). Its items, each only when it applies:
  "Open list" (the list the figure counts, same filter), "Show table" /
  "Show chart" (a chart that has a table alternative registers it through
  `ChartOrTable`; the switch is not a second button in the body), "How this
  is counted" (the definition opens as a note inside the frame, with Close),
  then the host's own items (`menuItems`: an editor's Edit, Duplicate,
  Remove). A widget with no applicable item has no menu button. A preview that
  cannot be operated passes `menu={false}`.
- A visualization never draws its own loading, empty or error box: the frame
  owns every state (loading skeleton shaped like the result, no data yet with
  the next step, no results, not measured as a dash with the reason and never
  0, no access, module off, error with Retry and "The other widgets are not
  affected", partial, stale, scope changed). A state has an icon and words,
  never colour alone.
- Every chart has a text alternative: its one-sentence summary as the figure's
  accessible name, and its table one menu item away.

## 5. Typography

- Sentence case everywhere. No UPPERCASE eyebrows or labels.
- `font-mono` only for identifiers and code: CVE / rule / plugin IDs, hashes,
  IPs, ports, file paths, URLs, API keys, code snippets. Never for numbers,
  labels, statuses or prose.
- Numbers that line up use `tabular-nums`.
- Names and addresses (asset and host names, e-mail addresses, URLs, file and
  package names) wrap only at their separators: render them through
  `<BreakText>` with `break-words`. `break-all` breaks every word at any
  letter ("Paym|ents") and is kept for mono machine values (hashes, keys,
  tokens); `src/lib/__tests__/name-break-guard.test.ts` enforces it.
- A metadata line that must stay on one line (a phone card's "what it is"
  line) is `<MetaLine oneLine>`: every item but the last keeps its width, the
  last ends in an ellipsis with its text as a tooltip. Never `flex-nowrap` on a
  MetaLine: its items then shrink and break inside words ("IP Addres|s").
  System-written text (a description made by discovery) stays out of list
  cards and rows; it belongs to the detail view.
- Sizes come from the type roles in `src/styles/theme.css` (each sets size,
  line height and weight): `text-cap` 12/16 and `text-cap-m` 12/16 500
  (captions, chips, table headers, counts), `text-code` 12/20 with
  `font-mono`, `text-dense` 13/20 (cells, rows, sidebar, breadcrumbs, property
  values), `text-body` 14/20, `text-card-title` 14/20 600, `text-section` 16/24 600,
  `text-dialog` 20/28 600, `text-page` 24/32 600 (20/28 below 768px),
  `text-figure` 24/32 and `text-figure-lead` 32/40 (one step down on a phone),
  `text-hero` 48/56, `text-wall` 56/64. `text-title`, `text-meta`,
  `text-data` and `text-kpi` remain as aliases. Weights are 400, 500 and 600
  only (no `font-bold`). Nothing under 12px.
- Control heights and type sizes: see "Sizes" at the top.
- `scripts/check-design-tokens.sh` (run by `check-page-anatomy.sh`) refuses
  added lines with a raw colour, an arbitrary radius, shadow, line height,
  weight or tracking, `font-bold`, a height on a kit control, and raw
  `text-xs`/`text-sm`/... in the directories of `scripts/type-migrated.txt`
  (the list only grows). Escape a real exception with `design-ok: <reason>`.
- One text face and one mono, self-hosted: Inter (`font-sans`, with the
  single-storey a and open digits) and JetBrains Mono (`font-mono`). The
  files and their OFL licences are in `web/public/fonts`, declared in
  `src/styles/fonts.css` with Latin, Latin Extended and Vietnamese subsets;
  no font CDN (the CSP allows fonts from our own origin only). `Inter
Fallback` (a local Arial or Liberation Sans with Inter's average width,
  ascent and descent) follows Inter in the stack, so the swap from the
  fallback to Inter moves nothing; the console's root layout preloads the
  Inter files its first paint uses.

## 6. Colour

- Brand tokens (`src/styles/theme.css`): paper `#FAFAF9` ground and ink
  `#0A1628` text in light; ink ground and paper text in dark, with dark
  surfaces derived from the ink hue (never teal). The kit names
  (`background`, `card`, `primary`, `muted`, …) are aliases of these values.
  `primary` is ink (paper in dark), not teal.
- Teal marks the one place to act: `signal` (the focus ring, a page's one
  primary call to action), `signal-text` (links), `signal-ink` (text on a
  `signal` fill). Never a surface, heading, icon, chart series or tint.
  `brand` is the logo marker dot only.
- Extra surface tokens: `surface-raised` (hover, selected row),
  `surface-sunken` (wells), `border-subtle` (inner dividers),
  `border-strong` (inputs, 3:1), `fg-dim` (low-priority rows; a colour, never
  opacity).
- Radius by role: 4 px chips (`rounded-sm`), 6 px buttons and inputs
  (`rounded-md`), 8 px cards and dialogs (`rounded-lg`).
- `src/styles/__tests__/contrast.test.ts` checks the brand values and every
  text and control pair at WCAG AA in both themes.

- Theme tokens only (`bg-card`, `text-muted-foreground`, `border`,
  `text-destructive`, `bg-accent`, …). No palette literals (`text-amber-500`,
  `bg-blue-50`, `#ef4444`) for UI chrome — they break dark mode and the
  palette-drift gate rejects new ones.
- Status meaning has its own tokens, each with a dark-mode value:
  `success` (completed, passed), `warning` (pending, at risk, timed out),
  `info` (running, informational) and `destructive` (failed, errors). Use them
  as `text-success` or a tint such as `bg-warning/15 text-warning`.
- Errors that replace content use the shared `ErrorState` (a destructive
  `Alert` with Retry), never a hand-made red box. It reads "Couldn't load
  {what}" and, for a server failure or a bare code, "The server did not
  answer. Nothing was changed." (never the server's code). Inside a table
  frame it is start-aligned like every alert: icon, title, sentence and
  buttons share one edge.
- Severity: `SeverityBadge` / `src/lib/severity-colors.ts`, on the
  `sev-*` tokens (marks), `sev-*-text` (text at AA) and `sev-*-ink` (text on
  a solid mark). Severity colour is for severity only. Criticality:
  `src/lib/criticality-colors.ts`; its badge (`CriticalityBadge`) has one look
  everywhere, list rows and record headers alike: the level bars and the word on
  the neutral pill (`Tag levelOutline`), never a solid fill. Charts: the chart colour sources.

### Charts

- One chart library (recharts, loaded on demand through
  `src/components/charts`), and one set of defaults in
  `src/components/charts/chart-defaults.ts`: `CHART_AXIS` (tick labels 12 px
  in the muted ink, no axis line, no tick marks), `CHART_GRID` (horizontal
  dashed guides in the border colour), `CHART_BAR_CURSOR` / `CHART_LINE_CURSOR`
  (hover), `CHART_REFERENCE` (+ label) for markers and targets,
  `CHART_TOOLTIP_PROPS` and `CHART_HEIGHT`. A chart spreads these; it does not
  write its own axis, grid or tooltip colours.
- Series colours come from the `--viz-*` tokens by meaning: severity,
  priority, the eight categories, new against fixed, the sequential ramp.
  Teal (the action colour) never encodes data.
- Colour never carries the meaning alone: a series has its name in the legend
  or beside its mark, a state has an icon or a word, a not-prioritised part is
  hatched.
- Every chart has a one-sentence summary as its accessible name and a data
  table (a table view, or a visually hidden table).

## 7. States

- **Loading**: `<Skeleton>` shaped like the content it replaces. Spinners
  (`Loader2`) only inside buttons that are working. A `DataTable` draws as
  many placeholder rows as the list showed last time in this browser session
  (same page and table), else five, never more than its page size or than fit
  on the screen, and at least one (`data-table/loading-rows.ts`); it reads its frame
  width before the first paint, so columns do not move when the rows arrive.
- **Failed load**: a page that reads data shows `ErrorState` with Retry (or a
  `DataTable` `error` with `onRetry`) for every read that can fail, so a failed
  read never looks like an empty list or a row of zeros. The route guard
  `src/lib/__tests__/route-error-state-guard.test.ts` fails when a route page
  that fetches has none; its debt file `route-error-state-debt.json` lists the
  pages still to fix and can only shrink.
- **Navigating**: no `loading.tsx` inside `(dashboard)` (a test enforces it).
  Each page renders its own skeleton; a route-level loading file only adds a
  second, differently shaped skeleton and makes React hold the page back for
  300 ms. Navigation links in the sidebar, settings rail and breadcrumbs carry
  `NavPendingHint` (`src/components/layout/sidebar-link.tsx`): after 120 ms
  without the next page, the clicked row shows a moving bar and the window a
  top progress bar. Sidebar links use `SidebarLink`, which prefetches on hover
  or focus rather than on render.
- **Progress feedback, one kind each**:
  - route navigation: the top-of-window `NavProgressBar`
    (`src/components/layout/nav-progress.tsx`), for navigation only;
  - first load (no rows yet): skeletons (`isLoading` on `DataTable`, or the
    page's own skeleton);
  - data refresh (rows already on screen are re-read after a filter, sort or
    page change, or a background revalidation): `isRefreshing` on
    `DataTable`. It draws `TableRefreshBar`, a thin indeterminate bar on the
    top edge of the table frame, below the toolbar and the search box,
    absolutely positioned so nothing moves. It is a `progressbar` (pass
    `refreshingLabel` for a specific name) only while active, waits 120 ms so
    fast refetches stay quiet, and is a static faint line under reduced
    motion. A list that is not a `DataTable` puts `TableRefreshBar` as the
    first child of its own `relative` frame. Never draw a bar above the
    toolbar or between the toolbar and the frame.
- **Empty**: the shared `<EmptyState>` (icon, title, why it is empty and the
  next step, optional primary action, optional secondary link such as docs).
  **One filled button per screen**: the empty state's action is filled only
  when no other filled button is shown (`OneFilledAction`, before paint); beside
  the page's main action in the header it is an outline button. A page whose
  header has no main action in that state keeps it filled (Findings first run:
  "Run a scan"). It reaches a kit `Button` written in the action (also inside
  `Can`); a filled button drawn by a component of its own is reported by a
  warning outside production. The table's empty body follows the same rule.
  Three kinds, each worded for its case:
  - **no data yet** (first use): the setup action;
  - **no results** (filters active): "Clear filters"; a list that wants its
    own words passes `emptyState.noMatch` as `{ title, hint }` and `DataTable`
    keeps the icon, the layout and the Clear filters action;
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

- Every modal surface (Dialog, AlertDialog, Sheet) has one frame, in
  `src/components/ui/modal-layout.tsx`: a **fixed header** (title,
  description, `actions`, the close button), a **body that is the only part
  that scrolls**, and a **fixed footer** (the actions, always visible). The
  title, the close button and the primary action never scroll away.

  ```tsx
  <DialogContent size="lg">
    <DialogHeader>
      <DialogTitle>Add finding</DialogTitle>
      <DialogDescription>…</DialogDescription>
    </DialogHeader>
    <DialogForm onSubmit={submit}>
      <DialogBody className="space-y-4">…fields…</DialogBody>
      <DialogFooter>
        <Button variant="outline" type="button">
          Cancel
        </Button>
        <Button type="submit">Create</Button>
      </DialogFooter>
    </DialogForm>
  </DialogContent>
  ```

  - Never put `max-h-*`, `overflow-*`, `flex`/`grid`, `p-0` or `gap-*` on a
    `DialogContent` / `AlertDialogContent` / `SheetContent`, and never a
    `max-w-*` on a dialog: width is `size` — `sm` (28rem), `md` (32rem, the
    default; create / edit forms), `lg` (42rem; long forms), `xl` (56rem;
    editors, tables), `full` (a workspace, 90% of the screen), `screen` (a
    full-screen canvas editor, e.g. the workflow builder). Large editors:
    a full page. `modal-layout-governance.test.ts` fails on these.
  - The body scrolls between header and footer (`overscroll-contain`, so the
    page behind never moves). A divider shows under the header only while
    the body is scrolled, and above the footer only while there is more below.
    Avoid a second scroll box inside the body (a picker list may keep a
    bounded height of its own).
  - A form wraps body and footer (`DialogForm` / `SheetForm`): Enter in a
    field submits, the primary button is `type="submit"`. Footer order:
    secondary first, primary last (on phones the primary is on top, buttons
    are full width and 44px tall).
  - Initial focus is the body's first field (never the close button); on a
    touch screen the body itself, so the keyboard does not pop up uninvited.
    Esc closes and focus returns to the trigger. Confirmations
    (`AlertDialog`) have no close button and open on Cancel.
  - Phones (under `sm`): a dialog is a bottom sheet, full width, as tall as
    its content up to the visible screen. It stays above the on-screen
    keyboard (`useKeyboardInset`: the visual viewport is measured, the
    surface lifted, the focused field scrolled back into view), and the
    footer clears the home indicator (`env(safe-area-inset-bottom)`). No
    motion under reduced motion.
  - Long forms may label groups inside the body with plain section headings;
    never a second fixed bar.

- A dialog laid out edge to edge (split panes, a tinted aside) still uses the
  frame: the panes go in the body (`<DialogBody className="p-0">`). The older
  `<DialogHeaderBar>` + `focusDialogBody` pattern (Install sensor, Edit
  sensor) is being moved onto `DialogHeader` + `DialogBody`; do not use it for
  new dialogs. The close button stays on the dialog surface, never on a
  tinted region; a secondary panel is inset (margin + radius), not bled to
  the edge.
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
  - A bulk or irreversible act passes `preview` (a sentence with the count, plus
    the first five names and "and N more"), so the user sees what will change
    before confirming. An act that is recorded or approved passes `reason`
    (`required` keeps Confirm disabled until it has text); `handleConfirm`
    receives the trimmed reason. Typed confirmation, preview and reason combine.
  - A request held for approval shows the shared `AwaitingApprovalBand` on the
    object (what is waiting, who asked and why, Cancel request behind a
    confirmation, the approver's buttons). Do not build a second band.
  - The step-up dialog says the action continues right away once the identity
    is confirmed; it never describes the act.

### Forms, wizards and form dialogs

The shared pieces are in `src/features/shared/components/forms/`.

- **Form layout.** One column (`FormStack`; a page form is capped at 45rem with `page`), 16 px between fields,
  short fields side by side in a `FormRow`, a `FormSection` (line above, 14/20 600 title) for a named group. A
  `FormField` puts the label (13/20 500) above its control, help (12/16 muted) under it and the error (12/16 500,
  danger text, with an icon) under the field it belongs to. A field is required unless it says "Optional" after
  its label; there is no asterisk. `FormField` gives the control its id and ties label, help and error to it
  (`aria-describedby`, `aria-invalid`, `aria-required`); the error is a live `role="alert"`. A group of controls
  (radio cards, checkboxes) is `FormField group`: a fieldset named by its legend. The react-hook-form kit
  (`components/ui/form.tsx`) has the same type and gaps.
- **Wizard.** `WizardFrame` is a dialog (`xl`, 56rem; a full-height sheet on a phone) with ONE height for every
  step, so the header, the step strip and the footer never move while a person goes through the steps. The strip
  (`WizardSteps`) is a navigation landmark with an ordered list of buttons, drawn as the tab strip: every step
  opens at any time, the current one has `aria-current="step"`, and each shows its state in one fixed 20 px box
  (its number, a check when complete, a warning when it has problems; more than one problem adds a count badge
  that takes no room), with the state in the accessible name ("Targets, 2 problems"). On a phone the strip
  scrolls sideways and keeps the current step in view. The footer is one row: the summary line at the start (it
  opens the whole summary above the row), then Back (ghost), Next (primary) and, on the last step, the primary
  action; on a phone the summary has its own line and the buttons share one row. While the primary action is
  disabled the footer names the first problem with a link to its step. Ctrl/Cmd+Enter runs the primary action or
  goes to the first problem; a step change moves focus to the step's heading ("Step 2 of 5: Targets").
- **Form dialog.** `FormDialog` is the frame of a create or edit dialog: title, optional description, a body that
  scrolls, and a footer with Cancel (ghost) and one primary action (a verb). It is a form: Enter submits. A failed
  submit shows above the actions as an alert; the reason for a disabled primary action is read with the button.
  Sizes are the dialog sizes (`md` by default, `lg` for long forms, `xl` for editors). A result view inside the same
  dialog (after a submit that keeps the dialog open) passes `cancelLabel={null}`: its one action (Done) closes it.
- **Leaving with unsaved changes.** A dialog form asks before it closes (`dirty` on `FormDialog`, or
  `useDiscardPrompt`): Keep editing, Discard, and Keep as draft where the form keeps a draft. A page form renders
  `LeaveGuard`: the browser asks on reload or close, and an in-app link is held until the person chooses. A
  settings form gets the same from `SettingsSaveBar`.

### Floating surfaces

Every anchored surface (menu, popover, select list, tooltip, date picker) gets
these rules from the kit wrappers in `src/components/ui` (`floating.ts`); call
sites pass nothing for them.

| Rule        | What the kit does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Side        | Below the trigger; above it when the room below is shorter than the popup and the room above is larger. Beside the trigger (left or right) only for sidebar flyouts and submenus.                                                                                                                                                                                                                                                                                                                                               |
| Alignment   | Measured when it opens (and when its size changes): the popup's start edge on the trigger's start edge, unless the popup would then cross the room it has: the screen less its gutter, or, when it fits there, the drawer, sheet or dialog its trigger sits in (8 px inside its edges). Then the end edge when that fits, else the edge with more room. A trigger at the end of a row ends up end-aligned by that collision, not by where it is on the screen. Logical, so a right-to-left page mirrors. Tooltips stay centred. |
| Gutter      | 16 px from every screen edge, at least the safe area (notch, home indicator); with a fixed bottom row shown (the bulk bar of selected rows, registered with `useFloatingObstruction`), 16 px above that row. Phone top-bar sheets: 8.                                                                                                                                                                                                                                                                                           |
| Keyboard    | Placement uses the visible viewport, so a popup stays above the on-screen keyboard.                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Height      | At most the room on its side; more content scrolls inside, with an 8 px shade (`scroll-cue`) at the edge where there is more. Select lists keep their scroll arrows.                                                                                                                                                                                                                                                                                                                                                            |
| Width       | A menu is as wide as its content: at least its trigger or 128 px (160 px when it shows icons), at most 360 px or the screen less both gutters (343 px at 375, 288 at 320). A call site sets a width only when its content needs one (hint lines, a search field, shell designs); `floating-width-guard.test.ts` lists those with the reason. Popovers and select lists: never wider than the screen less both gutters, never narrower than the trigger.                                                                         |
| Trigger     | A select list opens under (or above) its trigger, never laid over it.                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Headings    | A menu heading over exactly one item is hidden: the item says it. A label over no items (the signed-in account) stays.                                                                                                                                                                                                                                                                                                                                                                                                          |
| Shortcuts   | Shortcut hints in menus are hidden under a coarse pointer (phones, touch tablets).                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Tooltips    | Open after 400 ms of rest, 100 ms to the next one; never the only place information lives.                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Motion      | No open or close animation under reduced motion.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Fixed align | Only the shell's design-fixed menus pass `align` (`floating-align-guard.test.ts` lists them).                                                                                                                                                                                                                                                                                                                                                                                                                                   |

#### Action menus: `ActionMenu`

A "⋯" menu (row, card, page-header More, toolbar More, bulk More) is one
`ActionMenu` (`src/components/ui/action-menu.tsx`): the call site passes the
items (label, `onSelect` or `href`, optional `group`, `icon`, `destructive`,
`disabledReason`, `shortcut`, or a `kind: 'sub'` submenu), the trigger, the
object's name (`title`) and the sheet's purpose (`label`).

- A menu never holds one item: a single non-destructive action with an icon
  renders as that button, in the trigger's place and size. A lone destructive
  action (Delete, Remove, Revoke, Disable) is exempt: it stays behind the "⋯"
  trigger, the one menu that may hold a single item, and a row's other direct
  action joins that menu. See `findings-list.md`, "More menu".
- From 768 px up it is the anchored menu: rows 32 (44 under a coarse pointer),
  an unavailable item dimmed with its reason on hover or focus (and as a second
  line under a coarse pointer), shortcuts with a fine pointer only.
- Below 768 px the menu chooses by fit, measured each time it opens
  (`action-menu-fit.ts`); the call site never chooses:

  | Phone menu                                                                                                                                                                         | Shown as                                                                 |
  | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
  | At most 6 items (unavailable items count; dividers and a single heading do not), no submenu, no text field, every label within 2 lines, fits above or below the trigger unscrolled | Anchored menu: rows 44, 16 px gutter, placed like every anchored surface |
  | Anything else (more items, a submenu, a longer label, no room beside the trigger)                                                                                                  | Bottom sheet                                                             |

- The bottom sheet: the object's name as the title and a close button in a
  48 px header, rows 48 with 16 px text, no icons, groups split by a divider,
  the destructive group last in red, a submenu opened in place with a Back row,
  at least 16 px (or the safe area) under the last row, and its bottom on the
  visible screen's bottom, above a browser toolbar. It closes on the close
  button, Escape (one level back first), a tap on the scrim, a swipe down or a
  chosen action; the focus returns to the trigger. Its code loads only when a
  phone needs it.
- On a phone (and under a coarse pointer at any width) an unavailable item's
  reason is visible text under its label, in the menu and in the sheet.
- The items decide nothing about access: hide an item the user may not use,
  and give an item that does not apply a `disabledReason`. Both renderers use
  the same items, so an item is never enabled on one width and disabled on the
  other. A destructive item's `onSelect` opens the confirmation; it never acts
  directly.
- Content rules (`normalizeActionItems`): groups in the order given,
  destructive items last on their own, a group heading only for two items or
  more in a menu of two groups or more, icons for every item or none, empty
  submenus dropped, no menu at all when no item is left. A `section` sets
  items apart with a divider and no heading.
- A click on the trigger or inside the menu or sheet never reaches a clickable
  row or card around it.
- Only a small wrapper is in a page's first-load code: the menu loads right
  after the page shows (the trigger is marked busy until then), and a press
  made before it is in opens the menu or the sheet when it arrives.

`ActionMenu` users: the page-header More and the list's More beside Refresh (Findings: on a
phone "Select" first in a section of its own, from `usePhoneSelectMode`, then the page actions and
"Copy link"), every table row menu
(`DataTableRowActions`: items gated by `permission` or `route` are hidden from
a user who may not use them, `separatorBefore` starts a section, a disabled
item without its own reason says "Not available right now", `title` is the
row's name), the finding row and card menu (`FindingRowMenu`, titled with the
finding) and the bulk bar's More (`BulkActionBar` `more` and the data table's
`bulk.more` take `ActionMenuEntry[]`, titled with the selection count), the
detail drawer's More (`DetailHeader` `menu`, titled with the record) and the
"⋯" menus of the list pages (scans, workflows, automations, exceptions,
controls, dashboards, approvals, notification outbox, members, asset group) and
of the feature screens (role members, comments, asset owners, inventory rows,
related assets, the dashboard header and widget editor, finding header and
sub-statuses, pentest campaigns and steps, remediation campaigns and tasks,
repositories, SCM connections, the vulnerability page).
`action-menu-guard.test.ts` fails on a hand-built `DropdownMenu` whose trigger
holds a More icon; menus that are not action menus (breadcrumb levels, editor
formatting, a menu of choices) are listed there with the reason.

- A control that moves into the toolbar from 640 px up (the dashboard's
  Customize) is an item of the menu only below that width (`useIsBelowSm`); a
  choice among values (the dashboard's refresh schedule) is a submenu of the
  menu at every width, the saved value marked "(current)".

By surface and width (phone < 768 px, tablet 768 to 1023, desktop 1024 and up):

| Surface                                                          | Desktop and tablet                      | Phone                                                         |
| ---------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------- |
| Action menus "⋯" (`ActionMenu`)                                  | Anchored menu, rows 32 (44 under touch) | Bottom sheet titled with the object's name, rows 48, no icons |
| Account menu, notifications                                      | Anchored to the trigger's end           | Top sheet under the bar, 8 px from the edges                  |
| Choice menus without search (theme, sort, group, views), selects | Anchored, rows 32                       | Anchored                                                      |
| Pickers with a search field (`ResponsivePopover`)                | Anchored popover                        | Sheet, keyboard-aware                                         |
| Submenus                                                         | One level, as a flyout                  | Opened in place inside the sheet, with a Back row             |

#### Focus on open: no keyboard until the user taps a field

On a touch screen (a coarse pointer that cannot hover, `isTouchPrimary()` in
`src/components/ui/touch-focus.ts`) a popover, picker, sheet or dialog never
focuses a text field when it opens, so the on-screen keyboard does not cover
the options before the user has seen them. Focus goes to the surface: the
option list of a picker (the first option active, so Enter and the arrow keys
of an attached keyboard work) or the dialog body. The keyboard opens when the
user taps the field. With a mouse or trackpad the field gets focus on open.

- The kit applies it: the focus trap of `PopoverContent`, `DialogContent`,
  `SheetContent`, and `autoFocus` on `Input`, `Textarea` and `CommandInput`
  that appear with any of them (and with `AlertDialogContent`). A field that
  appears later, after a tap inside the open surface (Edit name, a picked
  filter field), keeps its `autoFocus`: the user asked to type. Call sites
  pass nothing.
- Exceptions, surfaces whose one purpose is typing, are listed once in
  `TOUCH_TYPING_SURFACES` (command palettes, step-up confirmation, typed
  confirmation, one-field forms such as a new name or a label) and opt in
  with `typingSurface`. `touch-focus-guard.test.ts` lists every opt-in, every
  raw `<input autoFocus>` and every `onOpenAutoFocus` that moves focus
  itself; a new one fails until it is reviewed.
- A picker with a search field on a phone (`ResponsivePopover`, used by Add
  filter and by the assignee picker `AssigneeSelect`): the field is
  pinned at the top of the sheet, the list scrolls under it with sticky group
  headings, rows 44. When the keyboard opens the sheet sits on it and is never
  taller than the visible part of the screen (`--modal-kb`, `--modal-vvh` from
  `visualViewport`), so the field and the rows under it stay in view even
  when the browser pans the page. At least 16 px (or the safe area) under the
  last row while the keyboard is down. Enter picks the highlighted option; the
  clear button empties the field without taking its focus; closing the sheet
  blurs the field so the keyboard closes with it.

## 9. Responsiveness

- Must work from 1000px wide with the sidebar expanded: nothing clipped, no
  page-level horizontal scroll (a wide table scrolls inside its own frame).
- Grids collapse: `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4` style, never a
  fixed column count without breakpoints.
- `e2e/specs/75-layout-breaks.spec.ts` checks the lists and their overlays at
  390, 1024, 1280 and 1440 px with long English and Vietnamese data: no text over
  text or a control, no word broken inside, nothing cut without an ellipsis,
  no button or link whose label a frame cuts ("Manage" shown as "Mana"),
  one control height per row, no English left in vi, no label without a value.
  Stored text shown as written (a dashboard's description) sits in an element
  with `translate="no"`, which the English check skips.
