'use client'

import * as React from 'react'
import { cn } from '@/lib/utils'
import { EDGE_FADE_X_CLASS, useTabStripScroll } from '@/components/ui/tabs'
import { ListSearch, type ListSearchProps } from './list-search'
import { FilterPanelToggle, type FilterPanelToggleProps } from './filter-button'

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
 * Below 28rem (a phone) the toolbar is two lines, never more: the search alone
 * on the first; on the second the `start` tokens and the chips row at the
 * start, the `end` icon actions pinned at the end. Nothing wraps: tokens that
 * do not fit scroll sideways in their strip (with a fade on an edge that hides
 * more), and so do the chips (`FilterChipsRow`).
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

export function ListToolbar({
  search,
  filterToggle,
  filter: filterProp,
  start,
  end,
  below,
  className,
}: ListToolbarProps) {
  const filter = filterToggle ? <FilterPanelToggle {...filterToggle} /> : filterProp
  const ref = React.useRef<HTMLDivElement>(null)
  useListShortcuts(ref)

  const lead = search ? <ListSearch {...search} filter={filter} /> : filter
  const tokensRef = React.useRef<HTMLDivElement>(null)
  useTabStripScroll(tokensRef, !!start)
  const startRef = React.useRef<HTMLDivElement>(null)
  const endRef = React.useRef<HTMLDivElement>(null)
  const fold = useToolbarFold(ref, startRef, endRef)
  // In Query mode a problem line may sit under the field: the row aligns on
  // the controls' top edge (all one height), so nothing moves when it shows.
  const top = !!search?.query?.active
  const toolbar = (
    <div
      ref={ref}
      data-testid="data-table-toolbar"
      data-slot="list-toolbar"
      className={cn(
        'flex flex-wrap gap-2',
        top ? 'items-start' : 'items-center',
        // The size container: the toolbar itself, or with a chips row the
        // region around it (same width). Below 28rem (a phone) that toolbar
        // lends its controls to the region: the search keeps the first line
        // and the end group joins the chips row, one row fewer before the data.
        below ? 'min-w-0 basis-full @max-md/toolbar:contents' : 'group/toolbar @container/toolbar',
        className
      )}
      data-fold={!below && fold ? 'true' : undefined}
    >
      {lead || start ? (
        // No min-w-0: the group must not shrink below its widest control, or a
        // button spills over the search box beside it. It wraps instead.
        <div
          ref={startRef}
          data-slot="list-toolbar-start"
          className={cn(
            'flex flex-[1_1_12rem] flex-wrap gap-2 @max-md/toolbar:contents',
            top ? 'items-start' : 'items-center'
          )}
        >
          {search ? (
            // A phone gives the search its own line.
            <div
              data-slot="list-toolbar-lead"
              className="contents @max-md/toolbar:flex @max-md/toolbar:min-w-0 @max-md/toolbar:basis-full @max-md/toolbar:gap-2"
            >
              {lead}
            </div>
          ) : (
            lead
          )}
          {start ? (
            // A phone keeps the tokens on the actions' line in a strip that
            // scrolls sideways instead of wrapping (edge fade when more is
            // hidden). With a chips row they follow the chips, beside the
            // icon actions (Add filter stays with them), and take at most 60%
            // of the line so the chips keep room.
            <div
              ref={tokensRef}
              data-slot="list-toolbar-tokens"
              className={cn(
                'contents @max-md/toolbar:flex @max-md/toolbar:flex-nowrap @max-md/toolbar:items-center @max-md/toolbar:gap-2 @max-md/toolbar:*:max-w-none @max-md/toolbar:*:shrink-0',
                // The padding keeps focus rings inside the scroll box.
                'no-scrollbar @max-md/toolbar:-my-1 @max-md/toolbar:min-w-0 @max-md/toolbar:overflow-x-auto @max-md/toolbar:overscroll-x-contain @max-md/toolbar:py-1',
                EDGE_FADE_X_CLASS,
                below
                  ? '@max-md/toolbar:order-last @max-md/toolbar:max-w-[60%] @max-md/toolbar:flex-[0_1_auto]'
                  : '@max-md/toolbar:flex-[1_1_0%]'
              )}
            >
              {start}
            </div>
          ) : null}
        </div>
      ) : null}
      {end ? (
        // Never wider than the toolbar: on a phone its controls wrap onto a
        // second line instead of running past the edge.
        <div
          ref={endRef}
          data-slot="list-toolbar-end"
          className={cn(
            'ms-auto flex max-w-full shrink-0 flex-wrap justify-end gap-2 @max-md/toolbar:flex-nowrap',
            top ? 'items-start' : 'items-center',
            below && '@max-md/toolbar:order-last'
          )}
        >
          {end}
        </div>
      ) : null}
    </div>
  )

  if (!below) return toolbar
  return (
    // The region is a size container under the same name, so the toolbar's
    // controls answer by the same width when the toolbar box is lent out.
    <div
      data-slot="list-toolbar-region"
      data-fold={fold ? 'true' : undefined}
      className="group/toolbar @container/toolbar flex min-w-0 flex-wrap items-center gap-2"
    >
      {toolbar}
      <div
        data-testid="data-table-toolbar-below"
        data-slot="list-toolbar-below"
        // Hidden while it holds nothing to show: an empty row, or a chips row
        // whose only (leading) chip renders nothing.
        className="flex min-w-0 basis-full flex-wrap items-center gap-2 empty:hidden has-[>[data-bare]_[data-slot=filter-chips-lead]:empty]:hidden @max-md/toolbar:min-w-0 @max-md/toolbar:flex-[1_1_0%]"
      >
        {below}
      </div>
    </div>
  )
}
