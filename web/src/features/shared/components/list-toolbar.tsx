'use client'

import * as React from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { ListSearch, type ListSearchProps, type ListSearchStatusSlot } from './list-search'
import { FilterButton, FilterPanelToggle, type FilterPanelToggleProps } from './filter-button'
import { FilterSheet, claimFilterSheetTokens, useFilterSheetTokensHost } from './filter-sheet'

/**
 * The one toolbar above a list (research/244 §2.4, research/267). `DataTable`
 * renders it from its `search` / `filterToggle` / `toolbarStart` /
 * `toolbarEnd` / `toolbarBelow` props; a list that is not a table (a card grid,
 * a settings section) renders it directly, so both look, wrap and answer the
 * keyboard the same.
 *
 * Slots, in this order on every page:
 * - `search` + `filter`: the list's search box, with the filter trigger (when
 *   the list has a filter panel) joined to its start. Always the first
 *   control, so the search sits at the same place on every list. A list with a
 *   filter trigger and no search shows the trigger alone in that place.
 * - `start`: filter tokens that follow the search (`FilterSelect` "Status:
 *   Open", at most two selects on a list without "Add filter", a lens).
 * - `end`: saved views, group, export, refresh, then the Display menu
 *   (density, columns), always last.
 * - `below`: the active filter chips, in their own full-width row 8px under
 *   the toolbar, so the toolbar keeps one height. Pass a `FilterChipsRow`:
 *   one line with a locked chip first, the chips (the rest folded into "+N
 *   more"), Add filter and Clear right after them, the count at the end. On a
 *   phone the locked chip takes a line of its own above the rest.
 * - the status row: on a list whose search takes query text, the line under
 *   the toolbar where the query field says what is wrong with a refused text
 *   (its problem, the column, its fixes). The toolbar owns it and hands it to
 *   the field (`ListSearchStatusSlot`), so the toolbar row keeps its height
 *   whatever the text's state. It takes room only while there is a problem:
 *   one line of the chips row's height, beside the chips row when one shows
 *   (the list does not move), a row of its own otherwise (the list moves by
 *   that row and the gap, as for the first chip). On a phone it is a line of
 *   its own under the actions.
 *
 * Gaps are the toolbar's (8px between controls, 8px to the chips row); a slot
 * adds no margins of its own. The start group asks for at least 12rem; when it
 * and the end group do not fit on one line the whole end group moves to its
 * own line, so the search box is never squeezed under a lone button. Below
 * 28rem of toolbar width (a phone) the start group always takes the whole
 * first line, so the end buttons never cut the search placeholder short. The
 * row is a size container: controls switch their labels to icons by the
 * toolbar's own width (`@xl/toolbar:`); the view controls (Views, Group, Display) show their labels from a 64rem toolbar (`iconOnlyBelow="@5xl/toolbar"`).
 *
 * Below 28rem (a phone) the list comes first: the `start` tokens are not drawn
 * in the toolbar, where they would sit in a sideways strip that hides what
 * does not fit. One Filters button (with the count of tokens that filter)
 * holds them: joined to the search, or alone at the start of the first line
 * without a search. It opens the list's filter sheet (`filterToggle`: the
 * tokens show at the top of the facet sheet) or, without a facet panel, a
 * sheet of the tokens. The tokens that filter (a chosen value, a pressed
 * toggle) stay drawn on the second line and wrap onto lines, never scroll, so
 * every filter in force is seen and cleared in place. The first line holds the
 * search (or the Filters button) and the `end` icon actions (Views, Group) at
 * its end; the page's chips row (`below`) follows. Every line starts with its
 * content: no line holds controls pushed to its end alone, and a line with
 * nothing to draw takes no room. The search keeps at least 12rem beside the
 * actions. The layout is the same with and without a chips row (the toolbar
 * always sits in its region).
 *
 * Keyboard (the first toolbar on the page answers): `/` focuses the search;
 * `f` opens the filters (the filter trigger) on a list without "Add filter",
 * whose own popover answers `f` there.
 */
export interface ListToolbarProps {
  /** The list's search box. */
  search?: ListSearchProps
  /**
   * The list's facet panel: renders the one filter trigger (side panel from
   * `lg`, sheet below), joined to the search.
   */
  filterToggle?: FilterPanelToggleProps
  /** A filter trigger that opens a sheet or popover (`FilterButton`), when there is no panel. */
  filter?: React.ReactNode
  /** Filter tokens after the search: `FilterSelect`, at most two selects, a lens. */
  start?: React.ReactNode
  /** Saved views, group, export, refresh, Display menu. */
  end?: React.ReactNode
  /** The active filter chips (`FilterChipsRow`): a full-width row under the toolbar. */
  below?: React.ReactNode
  className?: string
}

const EDITABLE =
  'input, textarea, select, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="menu"], [role="dialog"], [role="alertdialog"]'

function isVisible(el: Element | null): el is HTMLElement {
  if (!(el instanceof HTMLElement)) return false
  // `checkVisibility` is false for display:none (a breakpoint-hidden twin of
  // the filter trigger) and its subtree. Environments without it (jsdom)
  // count every element as visible.
  return typeof el.checkVisibility === 'function' ? el.checkVisibility() : true
}

/** The first visible toolbar on the page owns the list shortcuts. */
function isFirstToolbar(el: HTMLElement): boolean {
  const all = Array.from(document.querySelectorAll('[data-slot="list-toolbar"]'))
  // On a phone a toolbar with a chips row is `display: contents` (no box of
  // its own): its region tells whether it shows.
  return all.find((t) => isVisible(t.closest('[data-slot="list-toolbar-region"]') ?? t)) === el
}

function useListShortcuts(ref: React.RefObject<HTMLDivElement | null>) {
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key !== '/' && e.key !== 'f') return
      const target = e.target as HTMLElement | null
      if (target?.closest?.(EDITABLE)) return
      const root = ref.current
      if (!root || !isFirstToolbar(root)) return
      // A modal on top owns the keyboard.
      if (document.querySelector('[role="dialog"][data-state="open"], [role="alertdialog"]')) return
      if (e.key === '/') {
        const input = root.querySelector<HTMLInputElement>('[data-slot="list-search-input"]')
        if (!isVisible(input)) return
        e.preventDefault()
        input.focus()
        input.select()
        return
      }
      // "Add filter" answers `f` itself where the list has one.
      if (document.querySelector('[aria-keyshortcuts="f"]:not([data-slot="filter-button"])')) return
      const trigger = Array.from(
        root.querySelectorAll<HTMLButtonElement>('[data-slot="filter-button"]')
      ).find(isVisible)
      if (!trigger) return
      e.preventDefault()
      trigger.click()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [ref])
}

/**
 * Whether the toolbar must fold its labels to fit one line: true once the
 * start group wraps or the end group drops under it (long translations, a
 * side panel open), back to false once the toolbar is wider than where it
 * folded (so the two states never flip back and forth). Read by the base
 * chips' keys and the view controls' labels through `data-fold`.
 */
function useToolbarFold(
  toolbarRef: React.RefObject<HTMLDivElement | null>,
  startRef: React.RefObject<HTMLDivElement | null>,
  endRef: React.RefObject<HTMLDivElement | null>
) {
  const [fold, setFold] = React.useState(false)
  const foldedAt = React.useRef(0)
  React.useLayoutEffect(() => {
    const bar = toolbarRef.current
    if (!bar || typeof ResizeObserver === 'undefined') return
    const check = () => {
      const width = bar.getBoundingClientRect().width
      // A phone lends the toolbar's controls to its region (no box): two
      // fixed lines there, nothing to fold.
      if (width === 0) return setFold(false)
      if (fold) {
        if (width > foldedAt.current + 24) setFold(false)
        return
      }
      const start = startRef.current
      const items = start
        ? Array.from(
            start.querySelectorAll<HTMLElement>(
              ':scope > *, :scope > [data-slot=list-toolbar-tokens] > *'
            )
          ).filter((el) => getComputedStyle(el).display !== 'contents' && el.offsetWidth > 0)
        : []
      const tops = items.map((el) => el.getBoundingClientRect().top)
      const endTop = endRef.current?.getBoundingClientRect().top
      const wrapped =
        (tops.length > 1 && Math.max(...tops) - Math.min(...tops) > 4) ||
        (endTop !== undefined && tops.length > 0 && endTop - Math.min(...tops) > 4)
      if (wrapped) {
        foldedAt.current = width
        setFold(true)
      }
    }
    check()
    const ro = new ResizeObserver(check)
    ro.observe(bar)
    return () => ro.disconnect()
  }, [toolbarRef, startRef, endRef, fold])
  return fold
}

/**
 * A group of controls that draws none of them (every control hidden at this
 * width: the Display menu on a phone, tokens moved into the Filters sheet)
 * takes no line: it is marked `data-empty` and leaves the flow (absolute, no
 * size), so it never wraps onto a line of its own, where the first chip would
 * then sit instead of opening a new line. Its controls keep their boxes, so the
 * mark goes as soon as one is drawn again (width change, new control).
 */
const EMPTY_GROUP_CLASS =
  'data-[empty]:pointer-events-none data-[empty]:absolute data-[empty]:size-0 data-[empty]:overflow-hidden'

// An icon counts by its own box: the shapes inside it are often a line with no
// area (an icon-only Add filter draws only such lines), which is not "nothing".
function drawsSomething(group: HTMLElement): boolean {
  return Array.from(group.querySelectorAll<Element>('*')).some((el) => {
    const icon = el.closest('svg')
    if (icon ? icon !== el : el.children.length > 0) return false
    return Array.from(el.getClientRects()).some((r) => r.width > 0 && r.height > 0)
  })
}

function useEmptyGroups(
  region: React.RefObject<HTMLElement | null>,
  groups: React.RefObject<HTMLElement | null>[]
) {
  React.useLayoutEffect(() => {
    const root = region.current
    if (!root) return
    const mark = () => {
      for (const ref of groups) {
        const group = ref.current
        if (!group) continue
        const empty = !drawsSomething(group)
        if (empty !== group.hasAttribute('data-empty')) group.toggleAttribute('data-empty', empty)
      }
    }
    mark()
    // No observers (an old browser, a test without them): the first mark stays.
    if (typeof ResizeObserver === 'undefined' || typeof MutationObserver === 'undefined') return
    const resize = new ResizeObserver(mark)
    resize.observe(root)
    const mutation = new MutationObserver(mark)
    for (const ref of groups) {
      if (ref.current) {
        mutation.observe(ref.current, {
          subtree: true,
          childList: true,
          attributes: true,
          attributeFilter: ['class', 'hidden', 'style'],
        })
      }
    }
    return () => {
      resize.disconnect()
      mutation.disconnect()
    }
  })
}

/**
 * The phone layout (below a 28rem toolbar), a grid of three columns: the
 * tokens, the rest of the line, the end group. Every line starts with its
 * content, left to right; no line holds controls pushed to its end alone.
 * Line 1: lead (columns 1-2) or, with no search, the tokens (1), then the end
 * group (3). Line 2: the tokens (1), then the chips (2-3; the whole line when
 * no token is drawn). Line 3: the query field's problem. The first chip opens
 * line 2 after the tokens or fills it alone, so it never moves a token. The
 * gaps are margins of the drawn controls, never grid gaps, so a line or a
 * column that draws nothing (an empty group is out of the flow) takes no room.
 */
const PHONE = {
  layout:
    '@max-md/toolbar:grid @max-md/toolbar:grid-cols-[auto_minmax(0,1fr)_auto] @max-md/toolbar:gap-0',
  lead: '@max-md/toolbar:col-start-1 @max-md/toolbar:col-end-3 @max-md/toolbar:row-start-1 @max-md/toolbar:flex @max-md/toolbar:min-w-0 @max-md/toolbar:gap-2',
  // Line 2: only the tokens that filter (a chosen value, a pressed toggle),
  // wrapping onto lines, never a sideways strip; the others are in the
  // Filters sheet. Pure CSS, so the server's first paint is the final one.
  // The margin is the drawn tokens', so a line of hidden tokens takes no room.
  tokens:
    '@max-md/toolbar:col-start-1 @max-md/toolbar:col-end-4 @max-md/toolbar:row-start-2 @max-md/toolbar:flex @max-md/toolbar:min-w-0 @max-md/toolbar:flex-wrap @max-md/toolbar:items-center @max-md/toolbar:gap-x-2 @max-md/toolbar:*:mt-2 @max-md/toolbar:*:max-w-full @max-md/toolbar:[&>*:not([data-filtered=true],[aria-pressed=true]):not(:has([data-filtered=true],[aria-pressed=true]))]:hidden',
  end: '@max-md/toolbar:col-start-3 @max-md/toolbar:row-start-1 @max-md/toolbar:ms-2 @max-md/toolbar:max-w-[calc(100cqw-12rem)]',
  // The page's chips row: line 2, or line 3 under the token chips.
  below:
    '@max-md/toolbar:col-start-1 @max-md/toolbar:col-end-4 @max-md/toolbar:row-start-2 @max-md/toolbar:mt-2 @max-md/toolbar:group-has-[[data-slot=list-toolbar-tokens]:not([data-empty])]/toolbar:row-start-3',
  // Query mode: the field takes the whole first line; the end group steps
  // down to the second line's end (the tokens, inert in this mode, are out).
  leadQuery: '@max-md/toolbar:col-end-4',
  endQuery:
    '@max-md/toolbar:row-start-2 @max-md/toolbar:mt-2 @max-md/toolbar:ms-0 @max-md/toolbar:justify-self-end',
  status:
    '@max-md/toolbar:col-start-1 @max-md/toolbar:col-end-4 @max-md/toolbar:row-start-4 @max-md/toolbar:mt-2',
}

/** A token that filters: a select with a chosen value, a pressed on/off token. */
const FILTERING = '[data-filtered="true"], [aria-pressed="true"]'

/**
 * How many tokens filter (the Filters button's count on a phone), read from
 * the tokens group, so every token that carries the kit's marks counts, and
 * kept in step by an observer (a value chosen in the sheet updates it).
 */
function useFilteringCount(group: React.RefObject<HTMLElement | null>, enabled: boolean) {
  const [count, setCount] = React.useState(0)
  React.useLayoutEffect(() => {
    const root = group.current
    if (!enabled || !root) return
    const read = () => setCount(root.querySelectorAll(FILTERING).length)
    read()
    if (typeof MutationObserver === 'undefined') return
    const mo = new MutationObserver(read)
    mo.observe(root, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['aria-pressed', 'data-filtered'],
    })
    return () => mo.disconnect()
  }, [group, enabled])
  return count
}

export function ListToolbar({
  search,
  filterToggle,
  filter: filterProp,
  start,
  end,
  below,
  className,
}: ListToolbarProps) {
  const { t } = useTranslation()
  const ownerId = React.useId()
  // A phone holds the tokens in a sheet: the facet sheet when the list has a
  // panel (the toolbar claims its token host when its button opens it), else
  // a sheet of the tokens opened by the toolbar's own Filters button.
  const phoneSheet = !!start && !filterToggle && !filterProp
  const [sheetOpen, setSheetOpen] = React.useState(false)
  const facetHost = useFilterSheetTokensHost(ownerId)
  const onOpenFacetSheet = filterToggle?.onOpenSheet
  const toggle = React.useMemo(
    () =>
      filterToggle && start
        ? {
            ...filterToggle,
            onOpenSheet: () => {
              claimFilterSheetTokens(ownerId)
              onOpenFacetSheet?.()
            },
          }
        : filterToggle,
    [filterToggle, start, ownerId, onOpenFacetSheet]
  )
  const tokensRef = React.useRef<HTMLDivElement>(null)
  const filtering = useFilteringCount(tokensRef, phoneSheet)
  const phoneFilter = phoneSheet ? (
    <FilterButton
      className="@md/toolbar:hidden"
      data-phone-filters=""
      onClick={() => setSheetOpen(true)}
      aria-haspopup="dialog"
      activeCount={filtering}
    />
  ) : null
  const filter = toggle ? <FilterPanelToggle {...toggle} /> : (filterProp ?? phoneFilter)
  const ref = React.useRef<HTMLDivElement>(null)
  useListShortcuts(ref)

  // The status row of the query field: the editor draws its problem line
  // into it and says when it has one.
  const hasQuery = !!search?.query
  const queryActive = !!search?.query?.active
  const [statusHost, setStatusHost] = React.useState<HTMLDivElement | null>(null)
  const [statusDrawn, setStatusDrawn] = React.useState(false)
  const statusSlot = React.useMemo<ListSearchStatusSlot>(
    () => ({ host: statusHost, onDrawnChange: setStatusDrawn }),
    [statusHost]
  )
  const statusShown = queryActive && statusDrawn

  const lead = search ? (
    <ListSearch {...search} filter={filter} statusSlot={hasQuery ? statusSlot : undefined} />
  ) : (
    filter
  )
  const startRef = React.useRef<HTMLDivElement>(null)
  const endRef = React.useRef<HTMLDivElement>(null)
  const fold = useToolbarFold(ref, startRef, endRef)
  const regionRef = React.useRef<HTMLDivElement>(null)
  useEmptyGroups(regionRef, [tokensRef, endRef])
  // One alignment in both modes (centre: controls of a few px more, such as
  // a bordered view switch, share the row's centre line), and the tokens
  // stay in Query mode, so switching modes never re-flows the row. `top`
  // marks Query mode (the tokens go inert).
  const top = !!search?.query?.active
  const toolbar = (
    <div
      ref={ref}
      data-testid="data-table-toolbar"
      data-slot="list-toolbar"
      className={cn(
        'flex flex-wrap gap-2',
        'items-center',
        // The size container is the region around it (same width), with or
        // without a chips row, so the first chip changes no box. Below 28rem
        // (a phone) the toolbar lends its controls to the region's grid: the
        // search and the end group share the first line, the chips and tokens
        // the second.
        'min-w-0 basis-full @max-md/toolbar:contents'
      )}
    >
      {lead || start ? (
        // No min-w-0: the group must not shrink below its widest control, or a
        // button spills over the search box beside it. It wraps instead.
        <div
          ref={startRef}
          data-slot="list-toolbar-start"
          className={cn(
            'flex flex-[1_1_12rem] flex-wrap gap-2 @max-md/toolbar:contents',
            // Top: every control is one height, and a taller field (the
            // expanded query editor) moves no token.
            'items-start'
          )}
        >
          {lead ? (
            // A phone gives the search (or the lone filter trigger) the start
            // of the first line, the end group the rest of it.
            <div
              data-slot="list-toolbar-lead"
              className={cn('contents', PHONE.lead, top && PHONE.leadQuery)}
            >
              {lead}
            </div>
          ) : null}
          {start ? (
            // A phone draws no tokens here: they are in the Filters sheet.
            // In Query mode the text owns the filter: the tokens stay in their
            // place, dimmed and inert (no focus, no click, no `f`), so the
            // switch moves nothing (the end group never re-flows up a line).
            <div
              ref={tokensRef}
              data-slot="list-toolbar-tokens"
              data-inactive={top ? '' : undefined}
              inert={top || undefined}
              className={cn(
                top && '*:opacity-50',
                'contents',
                PHONE.tokens,
                // Query mode: the text owns the filter, the phone draws no token.
                top && '@max-md/toolbar:hidden',
                EMPTY_GROUP_CLASS
              )}
            >
              {start}
            </div>
          ) : null}
        </div>
      ) : null}
      {end ? (
        // Never wider than the toolbar: its controls wrap instead of running
        // past the edge (kept on one line, two links on a scan's runs ran off
        // the left edge in Vietnamese). On a phone it ends the search's line
        // and leaves the search at least 12rem.
        <div
          ref={endRef}
          data-slot="list-toolbar-end"
          className={cn(
            'ms-auto flex max-w-full shrink-0 flex-wrap justify-end gap-2',
            // At the row's top: a start group that grows (two lines, the
            // expanded query editor) never moves Views, Group and Display.
            'items-center self-start',
            PHONE.end,
            top && search && PHONE.endQuery,
            EMPTY_GROUP_CLASS
          )}
        >
          {end}
        </div>
      ) : null}
    </div>
  )

  // Mounted while the field is in Query mode. At rest it draws no box (the
  // line in it is read out, not shown), so it adds no gap; with a problem it
  // is one line of the chips row's height.
  const status = queryActive ? (
    <div
      ref={setStatusHost}
      data-slot="list-toolbar-status"
      data-drawn={statusShown ? '' : undefined}
      className={
        statusShown
          ? cn(
              'flex h-control min-w-0 items-center max-md:h-control-touch',
              below
                ? // Beside the chips row; a phone gives it the last line.
                  'flex-[1_1_0%]'
                : // A row of its own under the toolbar; on a phone after line 2.
                  'basis-full',
              PHONE.status
            )
          : 'contents'
      }
    />
  ) : null

  return (
    // The region is the size container, so the toolbar's controls answer by
    // the same width when the toolbar box is lent out (a phone). A container
    // query never styles the container itself, so the layout is the box inside.
    <div
      ref={regionRef}
      data-slot="list-toolbar-region"
      data-fold={fold ? 'true' : undefined}
      className={cn('group/toolbar @container/toolbar min-w-0', className)}
    >
      <div
        data-slot="list-toolbar-layout"
        className={cn('flex min-w-0 flex-wrap items-center gap-2', PHONE.layout)}
      >
        {toolbar}
        {below ? (
          <div
            data-testid="data-table-toolbar-below"
            data-slot="list-toolbar-below"
            className={cn(
              // Hidden while it holds nothing to show: an empty row, or a chips row
              // whose only (leading) chip renders nothing.
              'flex min-w-0 basis-full flex-wrap items-center gap-2 empty:hidden has-[>[data-bare]_[data-slot=filter-chips-lead]:empty]:hidden',
              // A phone: the start of the second line; the whole line when no
              // token is drawn there.
              PHONE.below,
              // With a problem shown the row is as wide as what it holds (the
              // leading chip, at most half the line as before) and the problem
              // takes the rest of the line: the list does not move.
              statusShown &&
                '@md/toolbar:max-w-[50%] @md/toolbar:flex-[0_0_auto] @md/toolbar:[&_[data-slot=filter-chips-leading]]:max-w-full'
            )}
          >
            {below}
          </div>
        ) : null}
        {status}
      </div>
      {phoneSheet ? (
        <FilterSheet
          open={sheetOpen}
          onOpenChange={setSheetOpen}
          title={t('common.filters', 'Filters')}
        >
          <div data-slot="list-toolbar-sheet-tokens" className="flex flex-wrap items-center gap-2">
            {start}
          </div>
        </FilterSheet>
      ) : null}
      {facetHost && start ? createPortal(start, facetHost) : null}
    </div>
  )
}
